#include "zeolite.h"

#include <err.h>
#include <krimskrams/net.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PROTOCOL "zeolite1"
#define PROTOCOL_LEN (sizeof(PROTOCOL) - 1)
#define B64_VARIANT sodium_base64_VARIANT_ORIGINAL

#define errorVal(coro, val) {                                       \
	warnx("%s:%d: %s", __FILE__, __LINE__, zeolite_error_str(val)); \
	coro->result = (void*) (long) val;                              \
	krk_coro_error(coro);                                           \
}

static unsigned char* cipher_storage = NULL;
static unsigned char* msg_storage    = NULL;

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

void zeolite_create_channel(
	krk_coro_t* coro,
	const zeolite* z, zeolite_channel* c,
	int fd, zeolite_trust_callback cb
) {
	c->fd = fd;
	coro->result = (void*) PROTOCOL_ERROR;

	// exchange & check protocol
	char other_protocol[PROTOCOL_LEN] = {0};

	krk_net_writeAll(coro, fd, PROTOCOL, PROTOCOL_LEN);
	krk_net_readAll(coro, fd, other_protocol, PROTOCOL_LEN);
	if(strncmp(PROTOCOL, other_protocol, PROTOCOL_LEN) != 0)
		errorVal(coro, PROTOCOL_ERROR);

	// exchange public signing keys (client identification)
	krk_net_writeAll(coro, fd, (void*) z->sign_pk,  sizeof(z->sign_pk));
	krk_net_readAll(coro, fd, c->other_pk, sizeof(c->other_pk));

	// Check whether we should trust this client
	if(cb(c->other_pk) != SUCCESS) errorVal(coro, TRUST_ERROR);

	// create, sign & exchange ephemeral keys (for shared key transfer)
	zeolite_eph_pk eph_pk;
	zeolite_eph_sk eph_sk;
	unsigned long long eph_msg_len = crypto_sign_BYTES + sizeof(eph_pk);
	unsigned char      eph_msg[eph_msg_len];

	if(crypto_box_keypair(eph_pk, eph_sk) != 0) errorVal(coro, KEYGEN_ERROR);
	if(crypto_sign(eph_msg, NULL, eph_pk,
		sizeof(eph_pk), z->sign_sk) != 0) errorVal(coro, SIGN_ERROR);
	krk_net_writeAll(coro, fd, eph_msg, eph_msg_len);

	// read & verify signed ephemeral public key
	zeolite_eph_sk other_eph_pk;

	krk_net_readAll(coro, fd, eph_msg, eph_msg_len);
	if(crypto_sign_open(other_eph_pk, NULL,
		eph_msg, eph_msg_len, c->other_pk) != 0) errorVal(coro, VERIFY_ERROR);

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
		nonce, other_eph_pk, eph_sk) != 0) errorVal(coro, ENCRYPT_ERROR);
	krk_net_writeAll(coro, fd, full_sym_msg, sizeof(full_sym_msg));

	// receive & decrypt symmetric receiver key
	krk_net_readAll(coro, fd, full_sym_msg, sizeof(full_sym_msg));
	if(crypto_box_open_easy(recv_k,
		ciphertext, crypto_box_MACBYTES + sizeof(send_k),
		nonce, other_eph_pk, eph_sk) != 0) errorVal(coro, DECRYPT_ERROR);

	// init stream states
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

	if(crypto_secretstream_xchacha20poly1305_init_push(
		&c->send_state, header, send_k) != 0) errorVal(coro, ENCRYPT_ERROR);
	krk_net_writeAll(coro, fd, header, sizeof(header));
	krk_net_readAll(coro, fd, header, sizeof(header));
	if(crypto_secretstream_xchacha20poly1305_init_pull(
		&c->recv_state, header, recv_k
	) != 0) errorVal(coro, DECRYPT_ERROR);

	krk_coro_finish(coro, SUCCESS);
}

int zeolite_create_channel_now(
	const zeolite* z, zeolite_channel* channel,
	int sock, zeolite_trust_callback cb
) {
	return krk_coro_forceA(zeolite_create_channel, 4, z, channel, sock, cb);
}

static zeolite_error _zeolite_channel_send(
	krk_coro_t* coro,
	zeolite_channel* c,
	const unsigned char* msg,
	uint32_t len,
	char tag
) {
	uint32_t cipher_len = len + crypto_secretstream_xchacha20poly1305_ABYTES;
	unsigned char* cipher_storage = malloc(cipher_len);

	krk_net_writeAll(coro, c->fd, &len, sizeof(len));
	if(crypto_secretstream_xchacha20poly1305_push(
		&c->send_state, cipher_storage, NULL, msg, len, NULL, 0, tag
	) != 0) return ENCRYPT_ERROR;
	krk_net_writeAll(coro, c->fd, cipher_storage, cipher_len);
	free(cipher_storage);
	return SUCCESS;
}

zeolite_error zeolite_channel_send(
	krk_coro_t* coro,
	zeolite_channel* c,
	const unsigned char* msg,
	uint32_t len
) {
	return _zeolite_channel_send(coro, c, msg, len, 0);
}

zeolite_error zeolite_channel_rekey(krk_coro_t*coro, zeolite_channel* c) {
	return _zeolite_channel_send(coro, c, (unsigned char*) "", 0,
		crypto_secretstream_xchacha20poly1305_TAG_REKEY);
}

zeolite_error zeolite_channel_close(krk_coro_t* coro, zeolite_channel* c) {
	int ret = _zeolite_channel_send(coro, c, (unsigned char*) "", 0,
		crypto_secretstream_xchacha20poly1305_TAG_FINAL);
	close(c->fd);
	return ret;
}

zeolite_error zeolite_channel_recv(
	krk_coro_t* coro,
	zeolite_channel* c,
	unsigned char** msg,
	uint32_t* len
) {
	*msg = NULL;
	*len = 0;
	krk_net_readAll(coro, c->fd, len, sizeof(*len));

	uint32_t cipher_len = *len + crypto_secretstream_xchacha20poly1305_ABYTES;
	unsigned char* cipher_storage = malloc(cipher_len);
	unsigned char* msg_storage    = malloc(*len + 1);
	*msg = msg_storage;
	msg_storage[*len] = 0;

	krk_net_readAll(coro, c->fd, cipher_storage, cipher_len);
	if(crypto_secretstream_xchacha20poly1305_pull(
		&c->recv_state, msg_storage, NULL,
		NULL, cipher_storage, cipher_len, NULL, 0
	) != 0) {
		free(cipher_storage);
		return DECRYPT_ERROR;
	}
	free(cipher_storage);
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
	case PROTOCOL_ERROR: return "Communications protocol violation";
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

// MULTI SERVER STUFF

static zeolite*               instance           = NULL;
static zeolite_trust_callback trustCallback      = NULL;
static zeolite_handler_f      multiServerHandler = NULL;

static int errorHandler(krk_coro_t* coro, krk_eventloop_t* loop) {
	(void) coro;
	(void) loop;
	return -1;
}

static void acceptHandler(krk_coro_t* coro, krk_eventloop_t* loop, int fd) {
	loop->errorHandler = errorHandler;

	printf("accepting %d\n", fd);
	zeolite_channel c = {0};
	if(zeolite_create_channel_now(instance, &c, fd, trustCallback) < 0) {
		warnx("Could not create channel");
		krk_coro_error(coro);
	}

	if(multiServerHandler(coro, loop, &c) < 0) {
		krk_coro_error(coro);
	} else {
		krk_coro_finish(coro, NULL);
	}
}

int zeolite_multiServer(
	zeolite* z,
	const char* addr,
	const char* port,
	zeolite_trust_callback cb,
	zeolite_handler_f handler
) {
	instance           = z;
	trustCallback      = cb;
	multiServerHandler = handler;

	return krk_net_lookup(
		addr,
		port,
		(krk_net_lookup_try_f) krk_net_multiServer,
		(void*) acceptHandler
	);
}
