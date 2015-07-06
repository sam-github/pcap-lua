.PHONY: default build test

-include local.mak

default: build

UNAME=$(shell uname)

include $(UNAME).mak

BINDING=pcap.so

build: $(BINDING)

prefix=/usr/local

SODIR = $(DESTDIR)/$(prefix)/lib/lua/5.1/

LIBDIR = $(DESTDIR)/$(prefix)/share/lua/5.1/
BINDIR = $(DESTDIR)/$(prefix)/bin/

.PHONY: install
install: $(BINDING)
	mkdir -p $(SODIR)
	install -t $(SODIR) $(BINDING)

.PHONY: install-all
install-all: install
	mkdir -p $(LIBDIR)
	mkdir -p $(BINDIR)
	install -t $(LIBDIR) pcapx.lua
	install -t $(BINDIR) pcap-recode pcap-dump pcap-split

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
	$(LUA) $<
	touch $@

%.test: %-test %.so
	$(LUA) $<
	touch $@

%.test: %-test net.so
	$(LUA) $<
	touch $@

doc: README.txt

.PHONY: README.txt
README.txt: README.txt.in pcap.c
	cp README.txt.in $@
	luadoc pcap.c >> $@

