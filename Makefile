CFLAGS := -std=c11 -Wall -Wextra -pedantic -Wno-pointer-arith $(CFLAGS)
LDFLAGS := -lsodium $(LDFLAGS)
OUTPUTS := libzeolite.so test
DESTDIR := /usr/local

all: $(OUTPUTS)

clean:
	$(RM) -f -- $(OUTPUTS)

runtest: $(OUTPUTS)
	./test server &
	./test client

install: $(OUTPUTS)
	install -Dm755 libzeolite.so $(DESTDIR)/lib/libzeolite.so
	install -Dm644 zeolite.h $(DESTDIR)/include/zeolite.h

libzeolite.so: zeolite.c
	$(CC) $(CFLAGS) -fPIC -shared $(LDFLAGS) $^ -o $@

test: test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -L. -lzeolite -Wl,-rpath,. $^ -o $@
