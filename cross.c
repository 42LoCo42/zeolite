extern int* __errno(void);

int* __errno_location(void) {
	return __errno();
}
