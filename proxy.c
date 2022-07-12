#define _POSIX_C_SOURCE 200112L
#include <err.h>
#include <errno.h>
#include <krimskrams/net.h>
#include <unistd.h>

#include "zeolite.h"

zeolite_error trustAll(zeolite_sign_pk pk);

static struct {
	zeolite* z;
	char* connect_addr;
	char* connect_port;
	int encrypt;
} data;

typedef struct {
	krk_eventloop_t* loop;
	int toFD;
	int fromFD;
	zeolite_channel c;
} pairArgs;

void encrypt(krk_coro_t* coro, int fd, zeolite_channel* c) {
	for(;;) {
		char    msg[8192] = {0};
		ssize_t len = read(fd, msg, sizeof(msg));
		if(len < 0) {
			if(errno == EAGAIN || errno == EWOULDBLOCK) {
				krk_coro_yield(coro, NULL);
			} else {
				close(fd);
				close(c->fd);
				krk_coro_error(coro);
			}
		} else if(len == 0) {
			close(fd);
			close(c->fd);
			krk_coro_error(coro);
		} else {
			zeolite_channel_send(coro, c, (unsigned char*) msg, len);
		}
	}
}

void decrypt(krk_coro_t* coro, zeolite_channel* c, int fd) {
	for(;;) {
		char*    msg = NULL;
		uint32_t len = 0;
		zeolite_channel_recv(coro, c, (unsigned char**) &msg, &len);

		for(ssize_t i = 0; i < len;) {
			ssize_t ret = write(fd, msg + i, len - i);
			if(ret < 0) {
				if(errno == EAGAIN || errno == EWOULDBLOCK) {
					krk_coro_yield(coro, NULL);
				} else {
					close(fd);
					close(c->fd);
					krk_coro_error(coro);
				}
			} else if(len == 0) {
				close(c->fd);
				close(fd);
				krk_coro_error(coro);
			} else {
				i += ret;
			}
		}
	}
}

static void from(krk_coro_t* coro, krk_eventloop_t* loop, int fd) {
	(void) loop;
	(void) fd;

	pairArgs* args = coro->extra;
	if(data.encrypt) {
		decrypt(coro, &args->c, args->toFD);
	} else {
		encrypt(coro, args->fromFD, &args->c);
	}
}

static int tryConnect(const struct addrinfo* info, void* extra) {
	pairArgs* args = extra;

	if(info->ai_socktype != SOCK_STREAM) return -1;
	int sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
	if(sock < 0) return -1;
	if(connect(sock, info->ai_addr, info->ai_addrlen) < 0) {
		close(sock);
		return -1;
	}

	if(krk_eventloop_addFd(args->loop, sock, from, args) < 0) {
		close(sock);
		return -1;
	}

	args->fromFD = sock;
	return 0;
}

static void to(krk_coro_t* coro, krk_eventloop_t* loop, int fd) {
	pairArgs args = {
		.loop = loop,
		.toFD = fd,
		.fromFD = -1,
		.c = {0},
	};

	if(krk_net_lookup(
		data.connect_addr, data.connect_port,
		tryConnect, &args
	) < 0) {
		warn("Could not accept client %d", fd);
		krk_coro_error(coro);
	}

	printf("Accepted client %d and connection %d\n", args.toFD, args.fromFD);

	if(data.encrypt) {
		if(zeolite_create_channel_now(
			data.z, &args.c, args.fromFD, trustAll) != SUCCESS) {
				close(args.toFD);
				close(args.fromFD);
				krk_coro_error(coro);
		}
		encrypt(coro, args.toFD, &args.c);
	} else {
		if(zeolite_create_channel_now(
			data.z, &args.c, args.toFD, trustAll) != SUCCESS) {
				close(args.toFD);
				close(args.fromFD);
				krk_coro_error(coro);
		}
		decrypt(coro, &args.c, args.fromFD);
	}
}

void proxy(
	zeolite* z,
	char* listen_addr,  char* listen_port,
	char* connect_addr, char* connect_port,
	int encrypt
) {
	data.z = z;
	data.connect_addr = connect_addr;
	data.connect_port = connect_port;
	data.encrypt = encrypt;

	if(krk_net_lookup(
		listen_addr, listen_port,
		(krk_net_lookup_try_f) krk_net_multiServer,
		(void*) to
	) < 0) err(1, "Could not start proxy");
}
