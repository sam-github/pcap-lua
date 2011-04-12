= pcap - a binding to libpcap

libpcap is the library behind the commonly use tcpdump utility. It allows
reading packet captures live from a network, as well as reading and writing
saved packet captures in "pcap" format. It has been ported to many operating
systems.

It doesn't implement the full libpcap interface, just what we've needed so far.

To build, see Makefile, it has only been used on Linux and OS X so far.

To decode the packets, you might want to use the lua bindings I've added to libnet, 
see the lua/ subdirectory of <https://github.com/sam-github/libnet>.


<https://github.com/javierguerragiraldez/pcaplua> is an alternative binding, it
supports a slightly different sub-sets of libpcap. Also, it has tcp/ip parsing
functions, whereas I use libnet for that.

I'm happy to take patches, of course, and might even add a feature if its easy.

Homepage: <https://github.com/sam-github/pcap-lua>
Author: <sroberts@wurldtech.com>

Documentation below, extracted from in-source comments.





** pcap - a binding to libpcap



-- dumper:destroy()

Manually destroy a dumper object, freeing it's resources (this will happen on
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


-- dumper = cap:dump_open([fname])

fname defaults to "-", stdout.

Note that the dumper object is independent of the cap object, once
it's created.


-- cap:destroy()

Manually destroy a cap object, freeing it's resources (this will happen on
garbage collection if not done explicitly).


-- capdata, timestamp, wirelen = cap:next()

Example:

for capdata, timestamp, wirelen in cap.next, cap do
  print(timestamp, wirelen, #capdata)
end


Returns:
  capdata, timestamp, wirelen
    captured data, the timestamp, the wire length
  nil, "timeout"            
    timeout on a live capture
  nil
    no more packets to be read from a file
  nil, emsg
    an error ocurred, emsg describes the error


-- cap = pcap.open_offline([fname])

fname defaults to "-", stdin.

Open a savefile to read packets from.

FIXME - in retrospect, fname defaulting to stdin causes unsuspecting users to
think this API is hanging, when they don't actually have a pcap on stdin...


-- cap = pcap.open_dead([linktype, [caplen]])

linktype is one of the DLT_ numbers, and defaults to 1 ("DLT_EN10MB")
caplen is the maximum size of packet, and defaults to ...

caplen defaults to 0, meaning "no limit" (actually, its changed into
65535 internally, which is what tcpdump does)

TODO should accept strings as the link type, or have a table of the link
types:
    pcap.DLT = { NULL = 0, EN10MB = 1, ... }

Open a pcap that doesn't read from either a live interface, or an offline pcap
file. It can be used to write a pcap file, or to compile a BPF program.
