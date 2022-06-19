#!/usr/bin/env bash
echo "const char ${1%.*}[] = {"
hexdump -bv usage.txt \
| head -n-1 \
| cut -b 8- \
| sed -E '
	s|\s*$||;
	s| ([^0])| 0\1|g;
	s|(.) |\1, |g;
	s|$|,|;
'
echo "0};"
