#define _POSIX_C_SOURCE 200112L
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <err.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#include "zeolite.h"
#include "usage.h"

#define check(cond, ...) if(cond) {err(1, __VA_ARGS__);}
#define safe(x) { \
	int ret = x; \
	if(ret < 0) { \
		if(verbose) warn("On line %d", __LINE__); \
		return -1; \
	}}

typedef int (*addr_callback)(int fd, const struct addrinfo* info);

static zeolite z;
static int     disableTrust = 0;
static int     verbose      = 0;

__attribute__((noreturn)) void printUsage(const char* name) {
	errx(1, usage, name);
}

int trustAll(zeolite_sign_pk pk) {
	char* b64 = zeolite_enc_b64(pk, sizeof(zeolite_sign_pk));
	fprintf(stderr, "other client is %s\n", b64);
	free(b64);
	return SUCCESS;
}

char* addrToStr(const struct sockaddr* addr) {
	static char addrToStrBuf[INET6_ADDRSTRLEN];
	switch(addr->sa_family) {
	case AF_INET: inet_ntop(
			AF_INET, &((struct sockaddr_in*) addr)->sin_addr,
			addrToStrBuf, INET6_ADDRSTRLEN
		);
		break;
	case AF_INET6: inet_ntop(
			AF_INET6, &((struct sockaddr_in6*) addr)->sin6_addr,
			addrToStrBuf, INET6_ADDRSTRLEN
		);
		break;
	default:
		strcpy(addrToStrBuf, "Unknown AF");
	}
	return addrToStrBuf;
}

void lookup(int sock, const char* host, const char* port, addr_callback cb) {
	struct addrinfo* info = NULL;
	struct addrinfo* current = NULL;
	if(getaddrinfo(host, port, NULL, &info) != 0) errx(1, "Could not lookup host");
	current = info;
	for(;;) {
		if(verbose) printf("Trying address %s\n", addrToStr(current->ai_addr));

		if(cb(sock, current) == 0) break;
		current = current->ai_next;
		if(current == NULL) {
			warn("Could not execute mode; last error");
			break;
		}
	}
	freeaddrinfo(info);
}

int stdinLoop(int sock) {
	zeolite_create(&z);
	zeolite_channel c = {0};
	zeolite_create_channel(&z, &c, sock, trustAll);

	struct pollfd fds[] = {
		{.fd = STDIN_FILENO, .events = POLLIN, .revents = 0},
		{.fd = sock,         .events = POLLIN, .revents = 0},
	};

	for(;;) {
		if(poll(fds, 2, -1) < 1) return 1;

		if(fds[0].revents != 0) {
			if(fds[0].revents & POLLIN) {
				size_t len = 8192;
				unsigned char buf[len];
				ssize_t ret = read(STDIN_FILENO, buf, len);

				if(ret == 0) return 0;
				if(ret < 1) return 1;
				if(zeolite_channel_send(&c, buf, ret) != SUCCESS) return 1;
			}
			if(fds[0].revents & POLLHUP) return 0;
		}

		if(fds[1].revents != 0) {
			if(fds[1].revents & POLLIN) {
				size_t          len;
				unsigned char*  buf;
				zeolite_error e = zeolite_channel_recv(&c, &buf, &len);

				if(e == EOF_ERROR) return 0;
				if(e != SUCCESS)   return 1;
				write(STDOUT_FILENO, buf, len);
			}
			if(fds[1].revents & POLLHUP) return 0;
		}
	}

	return 0;
}

int client(int sock, const struct addrinfo* info) {
	safe(connect(sock, info->ai_addr, info->ai_addrlen));
	return stdinLoop(sock);
}

int single(int sock, const struct addrinfo* info) {
	int yes = 1;
	safe(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)));
	safe(bind(sock, info->ai_addr, info->ai_addrlen));
	safe(listen(sock, 1));

	int client = accept(sock, NULL, 0);
	safe(client);
	return stdinLoop(client);
}

int multi(int sock, const struct addrinfo* info) {
	(void) sock;
	(void) info;
	warnx("multi is TODO");
	return 1;
}

int main(int argc, char** argv) {
	const char* name = argv[0];
	for(;;) {
		char option = getopt(argc, argv, ":kt:T:v");
		if(option == -1) break;
		switch(option) {
		case '?':
			warnx("Invalid option '%c'", optopt);
			printUsage(name);
		case ':':
			warnx("Option '%c' requires an argument", optopt);
			printUsage(name);
		case 'k': disableTrust = 1; break;
		case 't': case 'T':
			printf("%s\n", optarg);
			break;
		case 'v': verbose = 1; break;
		}
	}

	int remaining = argc - optind;
	if(remaining == 0) printUsage(name);
	const char* mode = argv[optind];
	remaining--;

	if(zeolite_init() < 0) errx(1, "Could not load zeolite library");

	if(strcmp(mode, "gen") == 0) {
		zeolite_create(&z);
		printf("%.*s%.*s",
			(int) sizeof(z.sign_pk), z.sign_pk,
			(int) sizeof(z.sign_sk), z.sign_sk
		);
		char* b64 = zeolite_enc_b64(z.sign_pk, sizeof(z.sign_pk));
		fprintf(stderr, "%s", b64);
		free(b64);
		b64 = zeolite_enc_b64(z.sign_sk, sizeof(z.sign_sk));
		fprintf(stderr, "%s", b64);
		free(b64);
	} else {
		if(remaining < 2) printUsage(name);
		addr_callback cb = NULL;

		int sock = socket(AF_INET, SOCK_STREAM, 0);
		check(sock < 0, "Could not create socket");

		if(strcmp(mode, "client") == 0) {
			cb = client;
		} else if(strcmp(mode, "single") == 0) {
			cb = single;
		} else if(strcmp(mode, "multi") == 0) {
			if(remaining < 3) printUsage(name);
			cb = multi;
		} else {
			warnx("Unknown mode %s", mode);
			printUsage(mode);
		}

		lookup(sock, argv[optind + 1], argv[optind + 2], cb);
		zeolite_free();
	}
}
