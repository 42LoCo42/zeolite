#define _POSIX_C_SOURCE 200112L
#include <err.h>
#include <netdb.h>
#include <string.h>

#include "zeolite.h"

#define check(cond, ...) if(cond) {err(1, __VA_ARGS__);}

void usage(const char* name) {
	errx(1, "Usage: %s <client | server>", name);
}

int client(int sock) {
	struct addrinfo* info = NULL;
	struct addrinfo* current = NULL;
	check(getaddrinfo("localhost", "37812", NULL, &info) != 0, "Could not lookup host");
	current = info;
	while(current != NULL) {
		if(connect(sock, current->ai_addr, current->ai_addrlen) == 0) break;
		current = current->ai_next;
		check(current == NULL, "Could not connect to host");
	}
	freeaddrinfo(info);

	return sock;
}

int server(int sock) {
	int yes = 1;
	check(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0, "Could not set REUSEADDR");

	struct sockaddr_in addr = {
		.sin_family      = AF_INET,
		.sin_port        = htons(37812),
		.sin_addr.s_addr = 0,
	};
	check(bind(sock, (struct sockaddr*) &addr, sizeof(addr)) < 0, "Could not bind to port");

	check(listen(sock, 1) < 0, "Could not listen on port");

	int client = accept(sock, NULL, 0);
	check(client < 0, "Could not accept client");

	return client;
}

int trust(zeolite_sign_pk pk) {
	char* b64 = zeolite_enc_b64(pk, sizeof(zeolite_sign_pk));
	printf("Other client ID: %s\n", b64);
	free(b64);
	return SUCCESS;
}

int main(int argc, char** argv) {
	if(argc != 2) usage(argv[0]);

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	check(sock < 0, "Could not create socket");

	int comm;
	if(strcmp(argv[1], "client") == 0) {
		comm = client(sock);
	} else if(strcmp(argv[1], "server") == 0) {
		comm = server(sock);
	} else {
		usage(argv[0]);
	}

	if(zeolite_init() < 0) errx(1, "Could not load zeolite library");

	zeolite z = {0};
	zeolite_create(&z);

	char* b64 = zeolite_enc_b64(z.sign_pk, sizeof(zeolite_sign_pk));
	printf("My client ID:    %s\n", b64);
	free(b64);

	zeolite_channel c = {0};
	int e = zeolite_create_channel(&z, &c, comm, trust);
	printf("Channel creation: %s\n", zeolite_error_str(e));
	if(e != SUCCESS) return 1;

	const char* msg = "foobar";
	char buf[6] = {0};

	zeolite_channel_send(&c, (unsigned char*) msg, 6);
	zeolite_channel_recv(&c, (unsigned char*) buf, 6);
	printf("received: %s\n", buf);
}
