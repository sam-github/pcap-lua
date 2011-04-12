.PHONY: default build test

-include local.mak

default: build

BINDING=pcap.so

UNAME=$(shell uname)

include $(UNAME).mak

build: $(BINDING)

prefix=/usr

SODIR = $(DESTDIR)$(prefix)/lib/lua/5.1/

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

DNETDEFS=$(shell dnet-config --cflags)
LNETDEFS=$(shell sh ../libnet/libnet-config --cflags --defines) 
COPT=-O2 -DNDEBUG -g
CFLAGS=$(CWARNS) $(CDEFS) $(CLUA) $(LDFLAGS) -I../libnet/include -L../libnet/src/.libs/
LDLIBS=$(LLUA)

LDDNET=$(shell dnet-config --libs)
LDLNET=$(shell sh ../libnet/libnet-config --libs)

CC.SO := $(CC) $(COPT) $(CFLAGS)

%.so: %.c
	$(CC.SO) -o $@ $^ $(LDLIBS)

pcap.so: pcap.c
pcap.so: LDLIBS+=-lpcap

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

