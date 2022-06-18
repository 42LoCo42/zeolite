#include "zeolite.h"

#include <errno.h>
#include <unistd.h>
#include <string.h>

#define PROTOCOL "zeolite1"
#define PROTOCOL_LEN (sizeof(PROTOCOL))
#define B64_VARIANT sodium_base64_VARIANT_ORIGINAL

int zeolite_init() {
	return sodium_init();
}

int zeolite_create_longterm_keys(zeolite* z) {
	return crypto_sign_keypair(z->sign_pk, z->sign_sk) == 0 ? SUCCESS : KEYGEN_ERROR;
}

int send(int fd, const void* ptr, size_t len) {
	while(len > 0) {
		ssize_t ret = write(fd, ptr, len);
		if(ret < 1) return SEND_ERROR;
		ptr += ret;
		len -= ret;
	}
	return SUCCESS;
}

int recv(int fd, void* ptr, size_t len) {
	ssize_t ret = read(fd, ptr, len);
	if((size_t) ret != len) {
		perror("");
		return RECV_ERROR;
	}
	return SUCCESS;
}

#define safe(x) { \
	int ret = x; \
	if(ret != SUCCESS) { \
		printf("%d\n", __LINE__); \
		return ret; \
	}}

int zeolite_create_channel(const zeolite* z, zeolite_channel* c, int fd) {
	c->fd = fd;

	// exchange & check protocol
	char other_protocol[PROTOCOL_LEN] = {0};

	safe(send(fd, PROTOCOL, PROTOCOL_LEN));
	safe(recv(fd, other_protocol, PROTOCOL_LEN));
	if(strncmp(PROTOCOL, other_protocol, PROTOCOL_LEN) != 0)
		return PROTOCOL_ERROR;

	// exchange public signing keys (client identification)
	safe(send(fd, z->sign_pk,  sizeof(z->sign_pk)));
	safe(recv(fd, c->other_pk, sizeof(c->other_pk)));

	// create, sign & exchange ephemeral keys (for shared key transfer)
	zeolite_eph_pk eph_pk;
	zeolite_eph_sk eph_sk;
	unsigned long long eph_msg_len = crypto_sign_BYTES + sizeof(eph_pk);
	unsigned char      eph_msg[eph_msg_len];

	if(crypto_box_keypair(eph_pk, eph_sk) != 0) return KEYGEN_ERROR;
	if(crypto_sign(eph_msg, NULL, eph_pk,
		sizeof(eph_pk), z->sign_sk) != 0) return SIGN_ERROR;
	safe(send(fd, eph_msg, eph_msg_len));

	// read & verify signed ephemeral public key
	zeolite_eph_sk other_eph_pk;

	safe(recv(fd, eph_msg, eph_msg_len));
	if(crypto_sign_open(other_eph_pk, NULL,
		eph_msg, eph_msg_len, c->other_pk) != 0) return VERIFY_ERROR;

	// create, encrypt & send symmetric sender key
	zeolite_sym_k  send_k;
	zeolite_sym_k  recv_k;
	unsigned char      full_sym_msg[
		crypto_box_NONCEBYTES + crypto_box_MACBYTES + sizeof(send_k)];
	unsigned char*     nonce = full_sym_msg;
	unsigned char*     ciphertext = full_sym_msg + crypto_box_NONCEBYTES;

	crypto_secretstream_xchacha20poly1305_keygen(send_k);
	randombytes_buf(nonce, crypto_box_NONCEBYTES);
	if(crypto_box_easy(ciphertext, send_k, sizeof(send_k),
		nonce, other_eph_pk, eph_sk) != 0) return ENCRYPT_ERROR;
	safe(send(fd, full_sym_msg, sizeof(full_sym_msg)));

	// receive & decrypt symmetric receiver key
	safe(recv(fd, full_sym_msg, sizeof(full_sym_msg)));
	if(crypto_box_open_easy(recv_k,
		ciphertext, crypto_box_MACBYTES + sizeof(send_k),
		nonce, other_eph_pk, eph_sk) != 0) return DECRYPT_ERROR;

	// init stream states
	unsigned char      header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

	if(crypto_secretstream_xchacha20poly1305_init_push(
		&c->send_state, header, send_k) != 0) return ENCRYPT_ERROR;
	safe(send(fd, header, sizeof(header)));
	safe(recv(fd, header, sizeof(header)));
	if(crypto_secretstream_xchacha20poly1305_init_pull(
		&c->recv_state, header, recv_k
	) != 0) return DECRYPT_ERROR;

	return SUCCESS;
}

int zeolite_channel_send(zeolite_channel* c, const unsigned char* msg, size_t len) {
	size_t         cipher_len = len + crypto_secretstream_xchacha20poly1305_ABYTES;
	unsigned char* ciphertext = malloc(cipher_len);

	if(crypto_secretstream_xchacha20poly1305_push(
		&c->send_state, ciphertext, NULL, msg, len, NULL, 0, 0
	) != 0) return ENCRYPT_ERROR;
	safe(send(c->fd, ciphertext, cipher_len));
	free(ciphertext);
	return SUCCESS;
}

int zeolite_channel_recv(zeolite_channel* c, unsigned char* msg, size_t len) {
	size_t         cipher_len = len + crypto_secretstream_xchacha20poly1305_ABYTES;
	unsigned char* ciphertext = malloc(cipher_len);

	safe(recv(c->fd, ciphertext, cipher_len));
	if(crypto_secretstream_xchacha20poly1305_pull(
		&c->recv_state, msg, NULL, NULL, ciphertext, cipher_len, NULL, 0
	) != 0) return DECRYPT_ERROR;
	free(ciphertext);
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
	printf("%p\n", *msg);
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
	case RECV_ERROR:     return "Could not receive data";
	case SEND_ERROR:     return "Could not send data";
	case PROTOCOL_ERROR: return "Communications rotocol violation";
	case KEYGEN_ERROR:   return "Could not generate key(s)";
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
