CFLAGS := -std=c11 -Wall -Wextra -pedantic -Wno-pointer-arith $(CFLAGS)
LDFLAGS := -lsodium $(LDFLAGS)
OUTPUTS := libzeolite.so test
DESTDIR := /

all: $(OUTPUTS)

clean:
	$(RM) -- $(OUTPUTS)

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

libzeolite.so: zeolite.c
	$(CC) $(CFLAGS) -fPIC -shared $(LDFLAGS) $^ -o $@

test: test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -L. -lzeolite -Wl,-rpath,. $^ -o $@
