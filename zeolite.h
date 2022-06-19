#ifndef ZEOLITE_H
#define ZEOLITE_H

#include <sodium.h>

/// @file
/// @brief zeolite - A secure communications library

/// Public signature key, used for identification
typedef unsigned char zeolite_sign_pk[crypto_sign_PUBLICKEYBYTES];

/// Secret signature key, used for identification
typedef unsigned char zeolite_sign_sk[crypto_sign_SECRETKEYBYTES];

/// Public ephemeral key, used for symmetric key establishment
typedef unsigned char zeolite_eph_pk[crypto_box_PUBLICKEYBYTES];

/// Secret ephemeral key, used for symmetric key establishment
typedef unsigned char zeolite_eph_sk[crypto_box_SECRETKEYBYTES];

/// Symmetric key, used for channel communication
typedef unsigned char zeolite_sym_k[crypto_secretstream_xchacha20poly1305_KEYBYTES];


/// A trust callback should decide whether to trust a client.
///
/// It receives the public signature key of the client
/// that a channel is connecting to and should return
/// SUCCESS if the client is to be trusted.
/// Any other value is interpreted as distrust.
typedef int (*zeolite_trust_callback)(zeolite_sign_pk);

/// Errors of zeolite.
///
/// Use zeolite_error_str() to get a string.
typedef enum {
	SUCCESS = 0,
	EOF_ERROR,
	RECV_ERROR,
	SEND_ERROR,
	PROTOCOL_ERROR,
	KEYGEN_ERROR,
	TRUST_ERROR,
	SIGN_ERROR,
	VERIFY_ERROR,
	ENCRYPT_ERROR,
	DECRYPT_ERROR,
} zeolite_error;

/// A zeolite identity.
///
/// This stores your signature keys, which are intended
/// to be generated once and then saved externally.
/// Create it with zeolite_create().
///
/// Keep the private key secret at all costs,
/// for if an attacker gains access to it,
/// they can impersonate you!
/// However, due to the usage of Perfect Forward Secrecy,
/// past communications can't be decrypted unless their
/// ephemeral keys got leaked somehow.
typedef struct {
	zeolite_sign_pk sign_pk; ///< The public signature key
	zeolite_sign_sk sign_sk; ///< The secret signature key
} zeolite;

/// A zeolite secure communications channel.
///
/// On channel creation, zeolite communicates over the
/// supplied socket and tries to establish a shared
/// encryption state. If this succeeds, the created channel object
/// can be used for secure communication over the socket.
typedef struct {
	/// The file descriptor of the underlying socket
	int fd;

	/// The public signature key of the connected client
	zeolite_sign_pk other_pk;

	/// The encryption state of the sender
	crypto_secretstream_xchacha20poly1305_state send_state;

	/// The encryption state of the receiver
	crypto_secretstream_xchacha20poly1305_state recv_state;
} zeolite_channel;

/// Initialize the zeolite library.
/// @returns A negative number on error.
int zeolite_init();

/// Free internal storage areas of zeolite.
void zeolite_free();

/// Create a zeolite identity.
///
/// Call this function once for every identity in your project,
/// then save the generated keys externally (but in a safe location).
/// If you use different keys for an identity, your clients will
/// probably reject communication attempts.
zeolite_error zeolite_create(zeolite* z);

/// Create a zeolite channel.
///
/// This function requires a socket that is already connected
/// to your client. Zeolite will then establish a shared
/// encryption state with this client, provided the trust callback
/// returns SUCCESS.
zeolite_error zeolite_create_channel(
	const zeolite* z, zeolite_channel* c,
	int socket, zeolite_trust_callback cb
);

/// Send a message on a zeolite channel.
zeolite_error zeolite_channel_send(zeolite_channel* c, const unsigned char* msg, size_t len);

/// Rekey this channel.
zeolite_error zeolite_channel_rekey(zeolite_channel* c);

/// Close this channel.
zeolite_error zeolite_channel_close(zeolite_channel* c);

/// Receive a message from zeolite channel.
///
/// `msg` will be set to a pointer to the decrypted message.
/// `len` will be set to the size of the decrypted message.
zeolite_error zeolite_channel_recv(zeolite_channel* c, unsigned char** msg, size_t* len);

/// Encode something as base64. You must free the returned string.
char* zeolite_enc_b64(const unsigned char* msg, size_t len);

/// Decode a base64 string.
///
/// `msg` should be a pointer to a char*, which will be allocated
/// and filled with the decoded value. You must free it later.
/// @returns The size of the original string.
size_t zeolite_dec_b64(const char* b64, size_t len, unsigned char** msg);

/// A converter from zeolite error codes to strings.
const char* zeolite_error_str(zeolite_error e);

/// Prints a base64-encoded string to stdout.
void zeolite_print_b64(const unsigned char* msg, size_t len);

#endif // ZEOLITE_H
