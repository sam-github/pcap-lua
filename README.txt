= pcap - a binding to libpcap

libpcap is the library behind the commonly use tcpdump utility. It allows
reading packet captures live from a network, as well as reading and writing
saved packet captures in "pcap" format. It has been ported to many operating
systems.

The binding doesn't implement the full libpcap API, just what we've needed so
far.

To build, see Makefile, it supports Linux and OS X.

To decode the packets, you might want to use libnet's lua bindings, see the
lua/ subdirectory of <https://github.com/sam-github/libnet>.

Homepage: <https://github.com/sam-github/pcap-lua>
Author: <sroberts@wurldtech.com>

If this doesn't do what you need,
<https://github.com/javierguerragiraldez/pcaplua> is a binding to a different
subset of libpcap's API. Also, it has tcp/ip parsing functions, whereas we use
libnet for that.


Documentation:

See below, extracted from in-source comments.




** pcap - a binding to libpcap

pcap._LIB_VERSION is the libpcap version string, as returned from pcap_lib_version().



-- cap = pcap.open_live(device, snaplen, promisc, timeout)

Open a source device to read packets from.

- device is the physical device (defaults to "any")
- snaplen is the size to capture, where 0 means max possible (defaults to 0)
- promisc is whether to set the device into promiscuous mode (default is false)
- timeout is the timeout for reads in seconds (default is 0, return if no packets available)



-- cap = pcap.open_dead([linktype, [caplen]])

linktype is one of the DLT_ numbers, and defaults to 1 ("DLT_EN10MB")
caplen is the maximum size of packet, and defaults to ...

caplen defaults to 0, meaning "no limit" (actually, its changed into
65535 internally, which is what tcpdump does)

Open a pcap that doesn't read from either a live interface, or an offline pcap
file. It can be used with cap:dump_open() to write a pcap file, or to compile a
BPF program.


-- cap = pcap.open_offline([fname])

fname defaults to "-", stdin.

Open a savefile to read packets from.

FIXME - in retrospect, fname defaulting to stdin causes unsuspecting users to
think this API is hanging, when they don't actually have a pcap on stdin...


-- dumper = cap:dump_open([fname])

fname defaults to "-", stdout.

Note that the dumper object is independent of the cap object, once
it's created.


-- cap = cap:set_filter(filter, nooptimize)

- filter is the filter string, see tcpdump or pcap-filter man page.
- nooptimize can be true if you don't want the filter optimized during compile
  (the default is to optimize).


-- capdata, timestamp, wirelen = cap:next()

Example:

    for capdata, timestamp, wirelen in cap.next, cap do
      print(timestamp, wirelen, #capdata)
    end

Returns capdata, timestamp, wirelen on sucess:

- capdata is the captured data
- timestamp is in seconds, theoretically to microsecond accuracy
- wirelen is the packets original length, the capdata may be shorter

Returns nil,emsg on falure, where emsg is:

- "timeout", timeout on a live capture
- "closed", no more packets to be read from a file
- ... some other string returned from pcap_geterr() describing the error


-- cap:destroy()

Manually destroy a cap object, freeing it's resources (this will happen on
garbage collection if not done explicitly).


-- dumper = dumper:dump(pkt, [timestamp, [wirelen]])

pkt to dump

timestamp of packet, defaults to 0, meaning the current time
wire length of packet, defaults to pkt's length

Returns self on sucess.
Returns nil and an error msg on failure.

Note that arguments are compatible with cap:next(), and that since
pcap_dump() doesn't return error indicators only the failure
values from cap:next() will ever be returned.


-- dumper = dumper:flush()

Flush all dumped packets to disk.

Returns self on sucess.
Returns nil and an error msg on failure.


-- dumper:destroy()

Manually destroy a dumper object, freeing it's resources (this will happen on
garbage collection if not done explicitly).


-- secs = pcap.tv2secs(seci, useci)

Combine seperate seconds and microseconds into one numeric seconds.


-- seci, useci = pcap.secs2tv(secs)

Split one numeric seconds into seperate seconds and microseconds.
