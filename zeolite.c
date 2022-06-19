#include "zeolite.h"

#include <err.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PROTOCOL "zeolite1"
#define PROTOCOL_LEN (sizeof(PROTOCOL))
#define B64_VARIANT sodium_base64_VARIANT_ORIGINAL

#define safe(x) { \
	zeolite_error ret = x; \
	if(ret != SUCCESS) { \
		warnx("%s:%d: %s", __FILE__, __LINE__, zeolite_error_str(ret)); \
		return ret; \
	}}

static unsigned char* cipher_storage = NULL;
static unsigned char* msg_storage    = NULL;

static zeolite_error my_send(
	int fd, const void* ptr, size_t len, int flags
) {
	while(len > 0) {
		ssize_t ret = send(fd, ptr, len, flags);
		if(ret < 1) return SEND_ERROR;
		ptr += ret;
		len -= ret;
	}
	return SUCCESS;
}

static zeolite_error my_recv(int fd, void* ptr, size_t len) {
	ssize_t ret = recv(fd, ptr, len, MSG_WAITALL);
	if(ret == 0) return EOF_ERROR;
	if((size_t) ret != len) return RECV_ERROR;
	return SUCCESS;
}

int zeolite_init() {
	return sodium_init();
}

void zeolite_free() {
	free(cipher_storage);
	free(msg_storage);
	cipher_storage = NULL;
	msg_storage    = NULL;
}

zeolite_error zeolite_create(zeolite* z) {
	return
		crypto_sign_keypair(z->sign_pk, z->sign_sk) == 0
		? SUCCESS : KEYGEN_ERROR;
}

zeolite_error zeolite_create_channel(
	const zeolite* z, zeolite_channel* c,
	int fd, zeolite_trust_callback cb
) {
	c->fd = fd;

	// exchange & check protocol
	char other_protocol[PROTOCOL_LEN] = {0};

	safe(my_send(fd, PROTOCOL, PROTOCOL_LEN, 0));
	safe(my_recv(fd, other_protocol, PROTOCOL_LEN));
	if(strncmp(PROTOCOL, other_protocol, PROTOCOL_LEN) != 0)
		return PROTOCOL_ERROR;

	// exchange public signing keys (client identification)
	safe(my_send(fd, z->sign_pk,  sizeof(z->sign_pk), 0));
	safe(my_recv(fd, c->other_pk, sizeof(c->other_pk)));

	// Check whether we should trust this client
	if(cb(c->other_pk) != 0) return TRUST_ERROR;

	// create, sign & exchange ephemeral keys (for shared key transfer)
	zeolite_eph_pk eph_pk;
	zeolite_eph_sk eph_sk;
	unsigned long long eph_msg_len = crypto_sign_BYTES + sizeof(eph_pk);
	unsigned char      eph_msg[eph_msg_len];

	if(crypto_box_keypair(eph_pk, eph_sk) != 0) return KEYGEN_ERROR;
	if(crypto_sign(eph_msg, NULL, eph_pk,
		sizeof(eph_pk), z->sign_sk) != 0) return SIGN_ERROR;
	safe(my_send(fd, eph_msg, eph_msg_len, 0));

	// read & verify signed ephemeral public key
	zeolite_eph_sk other_eph_pk;

	safe(my_recv(fd, eph_msg, eph_msg_len));
	if(crypto_sign_open(other_eph_pk, NULL,
		eph_msg, eph_msg_len, c->other_pk) != 0) return VERIFY_ERROR;

	// create, encrypt & send symmetric sender key
	zeolite_sym_k  send_k;
	zeolite_sym_k  recv_k;
	unsigned char  full_sym_msg[crypto_box_NONCEBYTES
		+ crypto_box_MACBYTES + sizeof(send_k)];
	unsigned char* nonce = full_sym_msg;
	unsigned char* ciphertext = full_sym_msg + crypto_box_NONCEBYTES;

	crypto_secretstream_xchacha20poly1305_keygen(send_k);
	randombytes_buf(nonce, crypto_box_NONCEBYTES);
	if(crypto_box_easy(ciphertext, send_k, sizeof(send_k),
		nonce, other_eph_pk, eph_sk) != 0) return ENCRYPT_ERROR;
	safe(my_send(fd, full_sym_msg, sizeof(full_sym_msg), 0));

	// receive & decrypt symmetric receiver key
	safe(my_recv(fd, full_sym_msg, sizeof(full_sym_msg)));
	if(crypto_box_open_easy(recv_k,
		ciphertext, crypto_box_MACBYTES + sizeof(send_k),
		nonce, other_eph_pk, eph_sk) != 0) return DECRYPT_ERROR;

	// init stream states
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

	if(crypto_secretstream_xchacha20poly1305_init_push(
		&c->send_state, header, send_k) != 0) return ENCRYPT_ERROR;
	safe(my_send(fd, header, sizeof(header), 0));
	safe(my_recv(fd, header, sizeof(header)));
	if(crypto_secretstream_xchacha20poly1305_init_pull(
		&c->recv_state, header, recv_k
	) != 0) return DECRYPT_ERROR;

	return SUCCESS;
}

static zeolite_error _zeolite_channel_send(
	zeolite_channel* c,
	const unsigned char* msg,
	size_t len,
	char tag
) {
	size_t cipher_len = len + crypto_secretstream_xchacha20poly1305_ABYTES;
	cipher_storage = realloc(cipher_storage, cipher_len); // TODO sould we realloc everytime?

	safe(my_send(c->fd, &len, sizeof(len), MSG_MORE));
	if(crypto_secretstream_xchacha20poly1305_push(
		&c->send_state, cipher_storage, NULL, msg, len, NULL, 0, tag
	) != 0) return ENCRYPT_ERROR;
	safe(my_send(c->fd, cipher_storage, cipher_len, 0));
	return SUCCESS;
}

zeolite_error zeolite_channel_send(
	zeolite_channel* c,
	const unsigned char* msg,
	size_t len
) {
	return _zeolite_channel_send(c, msg, len, 0);
}

zeolite_error zeolite_channel_rekey(zeolite_channel* c) {
	return _zeolite_channel_send(c, (unsigned char*) "", 0,
		crypto_secretstream_xchacha20poly1305_TAG_REKEY);
}

zeolite_error zeolite_channel_close(zeolite_channel* c) {
	int ret = _zeolite_channel_send(c, (unsigned char*) "", 0,
		crypto_secretstream_xchacha20poly1305_TAG_FINAL);
	close(c->fd);
	return ret;
}

zeolite_error zeolite_channel_recv(
	zeolite_channel* c,
	unsigned char** msg,
	size_t* len
) {
	*msg = NULL;
	*len = 0;
	safe(my_recv(c->fd, len, sizeof(*len)));

	size_t  cipher_len = *len + crypto_secretstream_xchacha20poly1305_ABYTES;
	cipher_storage = realloc(cipher_storage, cipher_len); // TODO sould we realloc everytime?
	msg_storage = realloc(msg_storage, *len); // TODO sould we realloc everytime?
	*msg = msg_storage;

	safe(my_recv(c->fd, cipher_storage, cipher_len));
	if(crypto_secretstream_xchacha20poly1305_pull(
		&c->recv_state, msg_storage, NULL,
		NULL, cipher_storage, cipher_len, NULL, 0
	) != 0) return DECRYPT_ERROR;
	return SUCCESS;
}

char* zeolite_enc_b64(const unsigned char* msg, size_t len) {
	size_t b64_len = sodium_base64_encoded_len(len, B64_VARIANT);
	char*  b64 = malloc(b64_len);

	return sodium_bin2base64(
		b64, b64_len,
		msg, len,
		B64_VARIANT
	);
}

size_t zeolite_dec_b64(const char* b64, size_t b64_len, unsigned char** msg) {
	size_t len = b64_len / 4 * 3;

	*msg = malloc(len);
	if(sodium_base642bin(
		*msg, len,
		b64, b64_len,
		NULL, &len,
		NULL, B64_VARIANT
	) != 0) return -1;
	return len;
}

const char* zeolite_error_str(zeolite_error e) {
	switch(e) {
	case SUCCESS:        return "Success";
	case EOF_ERROR:      return "End of stream reached";
	case RECV_ERROR:     return "Could not receive data";
	case SEND_ERROR:     return "Could not send data";
	case PROTOCOL_ERROR: return "Communications rotocol violation";
	case KEYGEN_ERROR:   return "Could not generate key(s)";
	case TRUST_ERROR:    return "Untrusted client";
	case SIGN_ERROR:     return "Could not sign data";
	case VERIFY_ERROR:   return "Invalid signature";
	case ENCRYPT_ERROR:  return "Could not encrypt data";
	case DECRYPT_ERROR:  return "Could not decrypt data";
	default:             return "Unknown error code";
	}
}

void zeolite_print_b64(const unsigned char* msg, size_t len) {
	char* b64 = zeolite_enc_b64(msg, len);

	puts(b64);
	free(b64);
}
