CFLAGS := -std=c11 -Wall -Wextra -pedantic -Wno-pointer-arith $(CFLAGS)
LDFLAGS := -lsodium $(LDFLAGS)
OUTPUTS := libzeolite.so test
DESTDIR := /
VALGRIND := valgrind \
	--leak-check=full --show-leak-kinds=all \
	--track-origins=yes --suppressions=valgrind.conf

all: $(OUTPUTS)

clean:
	$(RM)    -- $(OUTPUTS)
	$(RM) -r -- man xml

runtest: $(OUTPUTS)
	./test server &
	./test client

install: $(OUTPUTS)
	install -Dm755 libzeolite.so $(DESTDIR)/usr/lib/libzeolite.so
	install -Dm644 zeolite.h     $(DESTDIR)/usr/include/zeolite.h

doc:
	doxygen
	doxy2man \
		--nosort -o man \
		--pkg "The zeolite manual" \
		--short-pkg zeolite \
		xml/zeolite_8h.xml
		$<

installdoc: doc
	install -Dm644 -t $(DESTDIR)/usr/share/man/zeolite man/*

uninstall:
	$(RM)    -- $(DESTDIR)/usr/lib/libzeolite.so
	$(RM)    -- $(DESTDIR)/usr/include/zeolite.h
	$(RM) -r -- $(DESTDIR)/usr/share/man/zeolite

valgrind: $(OUTPUTS)
	$(VALGRIND) --log-file=server.log ./test server &
	$(VALGRIND) ./test client
	cat server.log
	rm server.log

libzeolite.so: zeolite.c
	$(CC) $(CFLAGS) -fPIC -shared $(LDFLAGS) $^ -o $@

test: test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -L. -lzeolite -Wl,-rpath,. $^ -o $@
