.PHONY: default build test

-include local.mak

default: build

UNAME=$(shell uname)

include $(UNAME).mak

BINDING=pcap.so

build: $(BINDING)

prefix=/usr/local

SODIR = $(DESTDIR)/$(prefix)/lib/lua/5.1/

.PHONY: install
install: $(BINDING)
	mkdir -p $(SODIR)
	install -t $(SODIR) $(BINDING)

CWARNS = -Wall \
  -pedantic \
  -Wcast-align \
  -Wnested-externs \
  -Wpointer-arith \
  -Wshadow \
  -Wwrite-strings

COPT=-O2 -DNDEBUG
CFLAGS=$(CWARNS) $(CDEFS) $(CLUA) $(LDFLAGS) $(shell pcap-config --cflags)
LDLIBS=$(LLUA) $(shell pcap-config --libs)

CC.SO := $(CC) $(COPT) $(CFLAGS)

%.so: %.c
	$(CC.SO) -o $@ $^ $(LDLIBS)

pcap.so: pcap.c

TNET=$(wildcard test-*.lua)
TOUT=$(TNET:.lua=.test)

echo:
	echo $(TOUT)

test: pcap.test $(TOUT)

%.test: %.lua net.so
	lua $<
	touch $@

%.test: %-test %.so
	lua $<
	touch $@

%.test: %-test net.so
	lua $<
	touch $@

doc: README.txt

.PHONY: README.txt
README.txt: README.txt.in pcap.c
	cp README.txt.in $@
	luadoc pcap.c >> $@

