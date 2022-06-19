CFLAGS   += -std=c11 -Wall -Wextra -pedantic -Wno-pointer-arith
LDFLAGS  += -lsodium
OUTPUTS  := libzeolite.so cli
DESTDIR  := /
VALGRIND := valgrind \
	--leak-check=full --show-leak-kinds=all \
	--track-origins=yes --suppressions=valgrind.conf

all: $(OUTPUTS)

clean:
	$(RM)    -- $(OUTPUTS) usage.h
	$(RM) -r -- man xml

runtest: $(OUTPUTS)
	free | ./cli single localhost 37812 &
	./cli -v client localhost 37812

install: $(OUTPUTS)
	install -Dm755 cli           $(DESTDIR)/usr/bin/zeolite
	install -Dm755 libzeolite.so $(DESTDIR)/usr/lib/libzeolite.so
	install -Dm644 zeolite.h     $(DESTDIR)/usr/include/zeolite.h

doc:
	doxygen
	doxy2man \
		--nosort -o man \
		--pkg "The zeolite manual" \
		--short-pkg zeolite \
		xml/zeolite_8h.xml

installdoc: doc
	install -Dm644 -t $(DESTDIR)/usr/share/man/man3/zeolite man/*

uninstall:
	$(RM)    -- $(DESTDIR)/usr/bin/zeolite
	$(RM)    -- $(DESTDIR)/usr/lib/libzeolite.so
	$(RM)    -- $(DESTDIR)/usr/include/zeolite.h
	$(RM) -r -- $(DESTDIR)/usr/share/man/zeolite

valgrind: $(OUTPUTS)
	free | $(VALGRIND) --log-file=server.log ./cli single localhost 37812 &
	$(VALGRIND) ./cli -v client localhost 37812
	cat server.log
	rm server.log

libzeolite.so: zeolite.c
	$(CC) $(CFLAGS) -fPIC -shared $(LDFLAGS) $^ -o $@

%: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -L. -lzeolite -Wl,-rpath,. $< -o $@

cli: cli.c usage.h

usage.h: usage.txt
	./txtToHeader.sh $< > $@
