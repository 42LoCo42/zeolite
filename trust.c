#define _POSIX_C_SOURCE 200809L

#include <err.h>
#include <stdio.h>

#include "zeolite.h"

typedef struct _trust_list trust_list;

struct _trust_list {
	zeolite_sign_pk pk;
	trust_list* next;
};

static trust_list* head = NULL;
static trust_list* tail = NULL;

void trust(zeolite_sign_pk pk) {
	trust_list* new = malloc(sizeof(trust_list));
	if(new == NULL) err(1, "Could not allocate trust_list");

	if(tail == NULL) {
		head = new;
		tail = new;
	} else {
		tail->next = new;
		tail = new;
	}

	memcpy(new->pk, pk, sizeof(zeolite_sign_pk));
	new->next = NULL;
}

void trust_file(const char* path) {
	FILE* file = fopen(path, "r");

	for(;;) {
		char* b64 = NULL;
		size_t unused;
		ssize_t len = getline(&b64, &unused, file);
		if(len < 0) {
			free(b64);
			break;
		}

		unsigned char* key = NULL;
		zeolite_dec_b64(b64, len - 1, &key);
		free(b64);
		trust(key);
		free(key);
	}

	for(trust_list* ptr = head; ptr != NULL; ptr = ptr->next) {
		zeolite_print_b64(ptr->pk, sizeof(zeolite_sign_pk));
	}
	fclose(file);
}

zeolite_error trust_callback(zeolite_sign_pk pk) {
	for(trust_list* ptr = head; ptr != NULL; ptr = ptr->next) {
		if(memcmp(ptr->pk, pk, sizeof(zeolite_sign_pk)) == 0) return SUCCESS;
	}
	return TRUST_ERROR;
}

void trust_clean() {
	for(trust_list* ptr = head; ptr != NULL;) {
		trust_list* next = ptr->next;
		free(ptr);
		ptr = next;
	}
}
