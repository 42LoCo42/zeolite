#define _POSIX_C_SOURCE 200112L
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <krimskrams/eventloop.h>
#include <krimskrams/net.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "usage.h"
#include "zeolite.h"

#define safe(x, ...)  if(x) {warn(__VA_ARGS__);  return -1;}
#define safex(x, ...) if(x) {warnx(__VA_ARGS__); return -1;}

void proxy(
	zeolite* z,
	char* listen_addr,  char* listen_port,
	char* connect_addr, char* connect_port,
	int encrypt
);

void trust(zeolite_sign_pk pk);
void trust_file(const char* path);
zeolite_error trust_callback(zeolite_sign_pk pk);
void trust_clean();

static zeolite z;
static int    disableTrust = 0;
static char** cmd          = 0;

// UTILS

typedef struct {
	zeolite_channel* c;
	int readFD;
	int writeFD;
} extra;

__attribute__((noreturn)) void printUsage(const char* name) {
	errx(1, usage, name);
}

zeolite_error trustAll(zeolite_sign_pk pk) {
	char* b64 = zeolite_enc_b64(pk, sizeof(zeolite_sign_pk));
	fprintf(stderr, "other client is %s\n", b64);
	free(b64);
	return disableTrust ? SUCCESS : trust_callback(pk);
}

// HANDLERS

static void signalHandler(int sig) {
	switch(sig) {
		case SIGCHLD: waitpid(-1, NULL, 0); break;
	}
}

static int clientErrorHandler(krk_coro_t* coro, krk_eventloop_t* loop) {
	(void) coro;
	loop->running = 0;
	return -1;
}

static int testHandler(krk_coro_t* coro, krk_eventloop_t* loop, zeolite_channel* c) {
	puts("in test handler");
	char*    buf = NULL;
	uint32_t len = 0;

	zeolite_channel_recv(coro, c, (unsigned char**) &buf, &len);
	puts(buf);
	if(strncmp(buf, "quit", 4) == 0) {
		loop->running = 0;
	} else {
		zeolite_channel_send(coro, c, (unsigned char*) "abc\n", 4);
	}
	free(buf);
	return 0;
}

static void encryptHandler(krk_coro_t* coro, krk_eventloop_t* loop, int fd) {
	(void) loop;
	(void) fd;
	extra* e = coro->extra;

	for(;;) {
		unsigned char buf[8192] = {0};
		ssize_t got = krk_net_readAny(coro, e->readFD, buf, sizeof(buf));
		if(got == 0) {
			close(e->c->fd);
			close(e->readFD);
			close(e->writeFD);
		} else {
			zeolite_error err = zeolite_channel_send(coro, e->c, buf, got);
			if(err != SUCCESS) krk_coro_error(coro);
		}
	}
}

static void decryptHandler(krk_coro_t* coro, krk_eventloop_t* loop, int fd) {
	(void) loop;
	(void) fd;
	extra* e = coro->extra;

	for(;;) {
		unsigned char* buf = NULL;
		uint32_t       len = 0;
		zeolite_error err = zeolite_channel_recv(coro, e->c, &buf, &len);
		if(err != SUCCESS) {
			free(buf);
			krk_coro_error(coro);
		}
		krk_net_writeAll(coro, e->writeFD, buf, len);
		free(buf);
	}
}

// OPERATION MODES

static int commonSingular(int sock) {
	zeolite_channel c = {0};
	safe(zeolite_create_channel_now(&z, &c, sock, trustAll) < 0,
		"Could not create client channel");

	extra e = {
		.c       = &c,
		.readFD  = STDIN_FILENO,
		.writeFD = STDOUT_FILENO,
	};

	krk_eventloop_t loop = {0};
	loop.errorHandler = clientErrorHandler;
	krk_eventloop_addFd(&loop, STDIN_FILENO, encryptHandler, &e);
	krk_eventloop_addFd(&loop, sock,         decryptHandler, &e);
	krk_eventloop_run(&loop);
	return 0;
}

static int client(const struct addrinfo* info, void* unused) {
	(void) unused;
	if(info->ai_socktype != SOCK_STREAM) return -1;

	int sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
	safe(sock < 0, "Could not create client socket");

	safe(connect(sock, info->ai_addr, info->ai_addrlen) < 0,
		"Could not connect client socket");

	return commonSingular(sock);
}

static int single(const struct addrinfo* info, void* unused) {
	(void) unused;
	if(info->ai_socktype != SOCK_STREAM) return -1;

	int sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
	safe(sock < 0, "Could not create server socket");

	int yes = 1;
	safe(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0,
		"Could not set server socket to reuse address");

	safe(bind(sock, info->ai_addr, info->ai_addrlen) < 0,
		"Could not bind server socket");
	safe(listen(sock, 1) < 0, "Could not listen on server socket");

	int client = accept(sock, NULL, 0);
	safe(client < 0, "Could not accept client");

	return commonSingular(client);
}

int main(int argc, char** argv) {
	krk_coro_stack = 1 << 20;
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, signalHandler);

	int created = 0;
	const char* name = argv[0];
	for(;;) {
		char option = getopt(argc, argv, ":i:I:kt:T:");
		if(option == -1) break;
		switch(option) {
		case '?':
			warnx("Invalid option '%c'", optopt);
			printUsage(name);
		case ':':
			warnx("Option '%c' requires an argument", optopt);
			printUsage(name);

		case 'i':
			if(created) errx(1, "Identity source already specified");

			char* val = getenv(optarg);
			if(val == NULL) errx(1, "No such variable: %s", optarg);
			char* sep = strchr(val, '-');
			if(sep == NULL) errx(1, "No separator found in variable");
			sep++;

			char* key = NULL;
			zeolite_dec_b64(val, sep - val, (unsigned char**) &key);
			memcpy(z.sign_pk, key, sizeof(z.sign_pk));
			free(key);
			zeolite_dec_b64(sep, strlen(sep), (unsigned char**) &key);
			memcpy(z.sign_sk, key, sizeof(z.sign_sk));
			free(key);

			created = 1;
			break;
		case 'I':
			if(created) errx(1, "Identity source already specified");

			int file = open(optarg, O_RDONLY);
			if(file < 0) err(1, "Could not open %s", optarg);
			if(read(file, z.sign_pk, sizeof(z.sign_pk)) != sizeof(z.sign_pk))
				err(1, "Could not read public key");
			if(read(file, z.sign_sk, sizeof(z.sign_sk)) != sizeof(z.sign_sk))
				err(1, "Could not read secret key");
			close(file);

			created = 1;
			break;

		case 'k': disableTrust = 1; break;

		case 't':
			unsigned char* pk = NULL;
			zeolite_dec_b64(optarg, strlen(optarg), &pk);
			trust(pk);
			free(pk);
			break;
		case 'T': trust_file(optarg); break;
		}
	}

	int remaining = argc - optind;
	if(remaining == 0) printUsage(name);
	const char* mode = argv[optind];
	remaining--;

	if(zeolite_init() < 0) errx(1, "Could not load zeolite library");
	if(created == 0 && zeolite_create(&z) != SUCCESS)
		errx(1, "Could not create zeolite instance");

	if(strcmp(mode, "gen") == 0) {
		write(STDOUT_FILENO, z.sign_pk, sizeof(z.sign_pk));
		write(STDOUT_FILENO, z.sign_sk, sizeof(z.sign_sk));

		char* b64 = zeolite_enc_b64(z.sign_pk, sizeof(z.sign_pk));
		fprintf(stderr, "%s-", b64);
		free(b64);
		b64 = zeolite_enc_b64(z.sign_sk, sizeof(z.sign_sk));
		fprintf(stderr, "%s", b64);
		free(b64);
	} else {
		if(remaining < 2) printUsage(name);
		int ret = 0;
		krk_net_lookup_try_f cb = NULL;

		if(strcmp(mode, "client") == 0) {
			cb = client;
		} else if(strcmp(mode, "single") == 0) {
			cb = single;
		} else if(strcmp(mode, "multi") == 0) {
			if(remaining < 3) printUsage(name);
			cmd = &argv[optind + 3];
			ret = zeolite_multiServer(
				&z,
				argv[optind + 1],
				argv[optind + 2],
				trustAll,
				testHandler
			);
			goto end;
		} else if(strcmp(mode, "proxy") == 0) {
			if(remaining < 5) printUsage(name);

			char* listen_addr  = argv[optind + 1];
			char* listen_port  = argv[optind + 2];
			char* connect_addr = argv[optind + 3];
			char* connect_port = argv[optind + 4];
			char* mode_str     = argv[optind + 5];

			int encrypt;
			if(strcmp(mode_str, "encrypt") == 0)      encrypt = 1;
			else if(strcmp(mode_str, "decrypt") == 0) encrypt = 0;
			else {
				warnx("Invalid proxy mode: %s", mode_str);
				printUsage(name);
			}

			printf("Listening on %s:%s\n", listen_addr, listen_port);
			printf("Connecting to %s:%s\n", connect_addr, connect_port);
			printf("listen -> connect traffic will be %sed\n", mode_str);

			proxy(
				&z,
				listen_addr, listen_port,
				connect_addr, connect_port,
				encrypt
			);
			goto end;
		} else {
			warnx("Unknown mode %s", mode);
			printUsage(mode);
		}

		ret = krk_net_lookup(
			argv[optind + 1],
			argv[optind + 2],
			cb,
			NULL
		);
end:
		trust_clean();
		zeolite_free();
		return -ret;
	}
}
