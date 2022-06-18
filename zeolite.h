#ifndef ZEOLITE_H
#define ZEOLITE_H

#include <sodium.h>
typedef unsigned char zeolite_sign_pk[crypto_sign_PUBLICKEYBYTES];
typedef unsigned char zeolite_sign_sk[crypto_sign_SECRETKEYBYTES];

typedef unsigned char zeolite_eph_pk[crypto_box_PUBLICKEYBYTES];
typedef unsigned char zeolite_eph_sk[crypto_box_SECRETKEYBYTES];

typedef unsigned char zeolite_sym_k[crypto_secretstream_xchacha20poly1305_KEYBYTES];

typedef enum {
	SUCCESS = 0,
	RECV_ERROR,
	SEND_ERROR,
	PROTOCOL_ERROR,
	KEYGEN_ERROR,
	SIGN_ERROR,
	VERIFY_ERROR,
	ENCRYPT_ERROR,
	DECRYPT_ERROR,
} zeolite_error;

typedef struct {
	zeolite_sign_pk sign_pk;
	zeolite_sign_sk sign_sk;
	zeolite_error last_error;
} zeolite;

typedef struct {
	int fd;
	zeolite_sign_pk other_pk;
	crypto_secretstream_xchacha20poly1305_state send_state;
	crypto_secretstream_xchacha20poly1305_state recv_state;
} zeolite_channel;

int zeolite_init();
int zeolite_create_longterm_keys(zeolite* z);
int zeolite_create_channel(const zeolite* z, zeolite_channel* c, int fd);
int zeolite_channel_send(zeolite_channel* c, const unsigned char* msg, size_t len);
int zeolite_channel_recv(zeolite_channel* c,       unsigned char* msg, size_t len);

char*  zeolite_enc_b64(const unsigned char* msg, size_t len);
size_t zeolite_dec_b64(const char* b64, size_t len, unsigned char** msg);

const char* zeolite_error_str(zeolite_error e);
void        zeolite_print_b64(const unsigned char* msg, size_t len);

#endif // ZEOLITE_H
