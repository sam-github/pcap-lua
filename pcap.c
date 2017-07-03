/*
Copyright (C) 2010 Wurldtech Security Technologies All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED.IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
THE POSSIBILITY OF SUCH DAMAGE.
*/


/*-
** pcap - a binding to libpcap
*/

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <pcap.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#ifdef WIN32
#include <wt-win-common.h>
#endif

#if LUA_VERSION_NUM > 501
#define luaL_reg luaL_Reg
#endif

static double tv2secs(struct timeval* tv)
{
    double secs = tv->tv_sec;
    secs += (double)tv->tv_usec / 1000000.0;
    return secs;
}

static struct timeval* secs2tv(double secs, struct timeval* tv)
{
    double ipart = 0.0;
    double fpart = 0.0;

    fpart = modf(secs, &ipart);

    tv->tv_sec  = (long) ipart;

    fpart = modf(fpart * 1000000.0, &ipart);

    tv->tv_usec = (long) ipart;

    if(fpart > 0.5)
        tv->tv_usec += 1;

    return tv;
}

static struct timeval* opttimeval(lua_State* L, int argi, struct timeval* tv)
{
    if(lua_isnoneornil(L, argi)) {
#ifndef NDEBUG
        int e =
#endif
            gettimeofday(tv, NULL);
#ifndef NDEBUG
        assert(e == 0); /* can only fail due to argument errors */
#endif
    } else {
        double secs = luaL_checknumber(L, argi);
        secs2tv(secs, tv);
    }
    return tv;
}

static void v_obj_metatable(lua_State* L, const char* regid, const struct luaL_reg methods[])
{
    /* metatable = { ... methods ... } */
    luaL_newmetatable(L, regid);

#if LUA_VERSION_NUM > 501
    luaL_setfuncs(L, methods, 0);
#else
    luaL_register(L, NULL, methods);
#endif

    /* metatable["__index"] = metatable */
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    lua_pop(L, 1);
}


/* Registry IDs and helper functions */

#define L_PCAP_REGID "wt.pcap"
#define L_PCAP_DUMPER_REGID "wt.pcap_dumper"

static int pusherr(lua_State* L, pcap_t* cap)
{
    lua_pushnil(L);
    lua_pushstring(L, pcap_geterr(cap));
    return 2;
}

static pcap_t* checkpcap(lua_State* L)
{
    pcap_t** cap = luaL_checkudata(L, 1, L_PCAP_REGID);

    luaL_argcheck(L, *cap, 1, "pcap has been closed");

    return *cap;
}


static pcap_t** pushpcapopen(lua_State* L)
{
    pcap_t** cap = lua_newuserdata(L, sizeof(*cap));
    *cap = NULL;
    luaL_getmetatable(L, L_PCAP_REGID);
    lua_setmetatable(L, -2);
    return cap;
}

static int checkpcapopen(lua_State* L, pcap_t** cap, const char* errbuf)
{
    if (!*cap) {
        lua_pushnil(L);
        lua_pushstring(L, errbuf);
        return 2;
    }
    return 1;
}


/* Wrap pcap_t */

/*-
-- pcap.DLT = { EN10MB=DLT_EN10MB, [DLT_EN10MB] = "EN10MB", ... }

DLT is a table of common DLT types. The DLT number and name are mapped to each other.

DLT.EN10MB is Ethernet (of all speeds, the name is historical).
DLT.LINUX_SLL can occur when capturing on Linux with a device of "any".

See <http://www.tcpdump.org/linktypes.html> for more information.

The numeric values are returned by cap:datalink() and accepted as linktype values
in pcap.open_dead().
*/
/* In the table at the top of the stack, dlt, do:
 *    dlt[name] = number
 *    dlt[number] = name
 */
static void pcap_dlt_set(lua_State* L, const char* name, int number)
{
    lua_pushstring(L, name);
    lua_pushinteger(L, number);
    lua_settable(L, -3);

    lua_pushinteger(L, number);
    lua_pushstring(L, name);
    lua_settable(L, -3);
}

static void pcap_make_dlt(lua_State* L)
{
    lua_newtable(L);
#ifdef DLT_NULL
    pcap_dlt_set(L, "NULL", DLT_NULL);
#endif
#ifdef DLT_EN10MB
    pcap_dlt_set(L, "EN10MB", DLT_EN10MB);
#endif
#ifdef DLT_AX25
    pcap_dlt_set(L, "AX25", DLT_AX25);
#endif
#ifdef DLT_IEEE802
    pcap_dlt_set(L, "IEEE802", DLT_IEEE802);
#endif
#ifdef DLT_ARCNET
    pcap_dlt_set(L, "ARCNET", DLT_ARCNET);
#endif
#ifdef DLT_SLIP
    pcap_dlt_set(L, "SLIP", DLT_SLIP);
#endif
#ifdef DLT_PPP
    pcap_dlt_set(L, "PPP", DLT_PPP);
#endif
#ifdef DLT_FDDI
    pcap_dlt_set(L, "FDDI", DLT_FDDI);
#endif
#ifdef DLT_PPP_SERIAL
    pcap_dlt_set(L, "PPP_SERIAL", DLT_PPP_SERIAL);
#endif
#ifdef DLT_PPP_ETHER
    pcap_dlt_set(L, "PPP_ETHER", DLT_PPP_ETHER);
#endif
#ifdef DLT_ATM_RFC1483
    pcap_dlt_set(L, "ATM_RFC1483", DLT_ATM_RFC1483);
#endif
#ifdef DLT_RAW
    pcap_dlt_set(L, "RAW", DLT_RAW);
#endif
#ifdef DLT_C_HDLC
    pcap_dlt_set(L, "C_HDLC", DLT_C_HDLC);
#endif
#ifdef DLT_IEEE802_11
    pcap_dlt_set(L, "IEEE802_11", DLT_IEEE802_11);
#endif
#ifdef DLT_FRELAY
    pcap_dlt_set(L, "FRELAY", DLT_FRELAY);
#endif
#ifdef DLT_LOOP
    pcap_dlt_set(L, "LOOP", DLT_LOOP);
#endif
#ifdef DLT_LINUX_SLL
    pcap_dlt_set(L, "LINUX_SLL", DLT_LINUX_SLL);
#endif
#ifdef DLT_LTALK
    pcap_dlt_set(L, "LTALK", DLT_LTALK);
#endif
#ifdef DLT_PFLOG
    pcap_dlt_set(L, "PFLOG", DLT_PFLOG);
#endif
#ifdef DLT_PRISM_HEADER
    pcap_dlt_set(L, "PRISM_HEADER", DLT_PRISM_HEADER);
#endif
#ifdef DLT_IP_OVER_FC
    pcap_dlt_set(L, "IP_OVER_FC", DLT_IP_OVER_FC);
#endif
#ifdef DLT_SUNATM
    pcap_dlt_set(L, "SUNATM", DLT_SUNATM);
#endif
#ifdef DLT_IEEE802_11_RADIO
    pcap_dlt_set(L, "IEEE802_11_RADIO", DLT_IEEE802_11_RADIO);
#endif
#ifdef DLT_ARCNET_LINUX
    pcap_dlt_set(L, "ARCNET_LINUX", DLT_ARCNET_LINUX);
#endif
#ifdef DLT_APPLE_IP_OVER_IEEE1394
    pcap_dlt_set(L, "APPLE_IP_OVER_IEEE1394", DLT_APPLE_IP_OVER_IEEE1394);
#endif
#ifdef DLT_MTP2_WITH_PHDR
    pcap_dlt_set(L, "MTP2_WITH_PHDR", DLT_MTP2_WITH_PHDR);
#endif
#ifdef DLT_MTP2
    pcap_dlt_set(L, "MTP2", DLT_MTP2);
#endif
#ifdef DLT_MTP3
    pcap_dlt_set(L, "MTP3", DLT_MTP3);
#endif
#ifdef DLT_SCCP
    pcap_dlt_set(L, "SCCP", DLT_SCCP);
#endif
#ifdef DLT_DOCSIS
    pcap_dlt_set(L, "DOCSIS", DLT_DOCSIS);
#endif
#ifdef DLT_LINUX_IRDA
    pcap_dlt_set(L, "LINUX_IRDA", DLT_LINUX_IRDA);
#endif
#ifdef DLT_USER0
    pcap_dlt_set(L, "USER0", DLT_USER0);
#endif
#ifdef DLT_USER1
    pcap_dlt_set(L, "USER1", DLT_USER1);
#endif
#ifdef DLT_USER2
    pcap_dlt_set(L, "USER2", DLT_USER2);
#endif
#ifdef DLT_USER3
    pcap_dlt_set(L, "USER3", DLT_USER3);
#endif
#ifdef DLT_USER4
    pcap_dlt_set(L, "USER4", DLT_USER4);
#endif
#ifdef DLT_USER5
    pcap_dlt_set(L, "USER5", DLT_USER5);
#endif
#ifdef DLT_USER6
    pcap_dlt_set(L, "USER6", DLT_USER6);
#endif
#ifdef DLT_USER7
    pcap_dlt_set(L, "USER7", DLT_USER7);
#endif
#ifdef DLT_USER8
    pcap_dlt_set(L, "USER8", DLT_USER8);
#endif
#ifdef DLT_USER9
    pcap_dlt_set(L, "USER9", DLT_USER9);
#endif
#ifdef DLT_USER10
    pcap_dlt_set(L, "USER10", DLT_USER10);
#endif
#ifdef DLT_USER11
    pcap_dlt_set(L, "USER11", DLT_USER11);
#endif
#ifdef DLT_USER12
    pcap_dlt_set(L, "USER12", DLT_USER12);
#endif
#ifdef DLT_USER13
    pcap_dlt_set(L, "USER13", DLT_USER13);
#endif
#ifdef DLT_USER14
    pcap_dlt_set(L, "USER14", DLT_USER14);
#endif
#ifdef DLT_USER15
    pcap_dlt_set(L, "USER15", DLT_USER15);
#endif
#ifdef DLT_IEEE802_11_RADIO_AVS
    pcap_dlt_set(L, "IEEE802_11_RADIO_AVS", DLT_IEEE802_11_RADIO_AVS);
#endif
#ifdef DLT_BACNET_MS_TP
    pcap_dlt_set(L, "BACNET_MS_TP", DLT_BACNET_MS_TP);
#endif
#ifdef DLT_PPP_PPPD
    pcap_dlt_set(L, "PPP_PPPD", DLT_PPP_PPPD);
#endif
#ifdef DLT_GPRS_LLC
    pcap_dlt_set(L, "GPRS_LLC", DLT_GPRS_LLC);
#endif
#ifdef DLT_GPF_T
    pcap_dlt_set(L, "GPF_T", DLT_GPF_T);
#endif
#ifdef DLT_GPF_F
    pcap_dlt_set(L, "GPF_F", DLT_GPF_F);
#endif
#ifdef DLT_LINUX_LAPD
    pcap_dlt_set(L, "LINUX_LAPD", DLT_LINUX_LAPD);
#endif
#ifdef DLT_BLUETOOTH_HCI_H4
    pcap_dlt_set(L, "BLUETOOTH_HCI_H4", DLT_BLUETOOTH_HCI_H4);
#endif
#ifdef DLT_USB_LINUX
    pcap_dlt_set(L, "USB_LINUX", DLT_USB_LINUX);
#endif
#ifdef DLT_PPI
    pcap_dlt_set(L, "PPI", DLT_PPI);
#endif
#ifdef DLT_IEEE802_15_4
    pcap_dlt_set(L, "IEEE802_15_4", DLT_IEEE802_15_4);
#endif
#ifdef DLT_SITA
    pcap_dlt_set(L, "SITA", DLT_SITA);
#endif
#ifdef DLT_ERF
    pcap_dlt_set(L, "ERF", DLT_ERF);
#endif
#ifdef DLT_BLUETOOTH_HCI_H4_WITH_PHDR
    pcap_dlt_set(L, "BLUETOOTH_HCI_H4_WITH_PHDR", DLT_BLUETOOTH_HCI_H4_WITH_PHDR);
#endif
#ifdef DLT_AX25_KISS
    pcap_dlt_set(L, "AX25_KISS", DLT_AX25_KISS);
#endif
#ifdef DLT_LAPD
    pcap_dlt_set(L, "LAPD", DLT_LAPD);
#endif
#ifdef DLT_PPP_WITH_DIR
    pcap_dlt_set(L, "PPP_WITH_DIR", DLT_PPP_WITH_DIR);
#endif
#ifdef DLT_C_HDLC_WITH_DIR
    pcap_dlt_set(L, "C_HDLC_WITH_DIR", DLT_C_HDLC_WITH_DIR);
#endif
#ifdef DLT_FRELAY_WITH_DIR
    pcap_dlt_set(L, "FRELAY_WITH_DIR", DLT_FRELAY_WITH_DIR);
#endif
#ifdef DLT_IPMB_LINUX
    pcap_dlt_set(L, "IPMB_LINUX", DLT_IPMB_LINUX);
#endif
#ifdef DLT_IEEE802_15_4_NONASK_PHY
    pcap_dlt_set(L, "IEEE802_15_4_NONASK_PHY", DLT_IEEE802_15_4_NONASK_PHY);
#endif
#ifdef DLT_USB_LINUX_MMAPPED
    pcap_dlt_set(L, "USB_LINUX_MMAPPED", DLT_USB_LINUX_MMAPPED);
#endif
#ifdef DLT_FC_2
    pcap_dlt_set(L, "FC_2", DLT_FC_2);
#endif
#ifdef DLT_FC_2_WITH_FRAME_DELIMS
    pcap_dlt_set(L, "FC_2_WITH_FRAME_DELIMS", DLT_FC_2_WITH_FRAME_DELIMS);
#endif
#ifdef DLT_IPNET
    pcap_dlt_set(L, "IPNET", DLT_IPNET);
#endif
#ifdef DLT_CAN_SOCKETCAN
    pcap_dlt_set(L, "CAN_SOCKETCAN", DLT_CAN_SOCKETCAN);
#endif
#ifdef DLT_IPV4
    pcap_dlt_set(L, "IPV4", DLT_IPV4);
#endif
#ifdef DLT_IPV6
    pcap_dlt_set(L, "IPV6", DLT_IPV6);
#endif
#ifdef DLT_IEEE802_15_4_NOFCS
    pcap_dlt_set(L, "IEEE802_15_4_NOFCS", DLT_IEEE802_15_4_NOFCS);
#endif
#ifdef DLT_DBUS
    pcap_dlt_set(L, "DBUS", DLT_DBUS);
#endif
#ifdef DLT_DVB_CI
    pcap_dlt_set(L, "DVB_CI", DLT_DVB_CI);
#endif
#ifdef DLT_MUX27010
    pcap_dlt_set(L, "MUX27010", DLT_MUX27010);
#endif
#ifdef DLT_STANAG_5066_D_PDU
    pcap_dlt_set(L, "STANAG_5066_D_PDU", DLT_STANAG_5066_D_PDU);
#endif
#ifdef DLT_NFLOG
    pcap_dlt_set(L, "NFLOG", DLT_NFLOG);
#endif
#ifdef DLT_NETANALYZER
    pcap_dlt_set(L, "NETANALYZER", DLT_NETANALYZER);
#endif
#ifdef DLT_NETANALYZER_TRANSPARENT
    pcap_dlt_set(L, "NETANALYZER_TRANSPARENT", DLT_NETANALYZER_TRANSPARENT);
#endif
#ifdef DLT_IPOIB
    pcap_dlt_set(L, "IPOIB", DLT_IPOIB);
#endif
#ifdef DLT_MPEG_2_TS
    pcap_dlt_set(L, "MPEG_2_TS", DLT_MPEG_2_TS);
#endif
#ifdef DLT_NG40
    pcap_dlt_set(L, "NG40", DLT_NG40);
#endif
#ifdef DLT_NFC_LLCP
    pcap_dlt_set(L, "NFC_LLCP", DLT_NFC_LLCP);
#endif
#ifdef DLT_INFINIBAND
    pcap_dlt_set(L, "INFINIBAND", DLT_INFINIBAND);
#endif
#ifdef DLT_SCTP
    pcap_dlt_set(L, "SCTP", DLT_SCTP);
#endif
#ifdef DLT_USBPCAP
    pcap_dlt_set(L, "USBPCAP", DLT_USBPCAP);
#endif
#ifdef DLT_RTAC_SERIAL
    pcap_dlt_set(L, "RTAC_SERIAL", DLT_RTAC_SERIAL);
#endif
#ifdef DLT_BLUETOOTH_LE_LL
    pcap_dlt_set(L, "BLUETOOTH_LE_LL", DLT_BLUETOOTH_LE_LL);
#endif
#ifdef DLT_NETLINK
    pcap_dlt_set(L, "NETLINK", DLT_NETLINK);
#endif
#ifdef DLT_BLUETOOTH_LINUX_MONITOR
    pcap_dlt_set(L, "BLUETOOTH_LINUX_MONITOR", DLT_BLUETOOTH_LINUX_MONITOR);
#endif
#ifdef DLT_BLUETOOTH_BREDR_BB
    pcap_dlt_set(L, "BLUETOOTH_BREDR_BB", DLT_BLUETOOTH_BREDR_BB);
#endif
#ifdef DLT_BLUETOOTH_LE_LL_WITH_PHDR
    pcap_dlt_set(L, "BLUETOOTH_LE_LL_WITH_PHDR", DLT_BLUETOOTH_LE_LL_WITH_PHDR);
#endif
#ifdef DLT_PROFIBUS_DL
    pcap_dlt_set(L, "PROFIBUS_DL", DLT_PROFIBUS_DL);
#endif
#ifdef DLT_PKTAP
    pcap_dlt_set(L, "PKTAP", DLT_PKTAP);
#endif
#ifdef DLT_EPON
    pcap_dlt_set(L, "EPON", DLT_EPON);
#endif
#ifdef DLT_IPMI_HPM_2
    pcap_dlt_set(L, "IPMI_HPM_2", DLT_IPMI_HPM_2);
#endif
#ifdef DLT_ZWAVE_R1_R2
    pcap_dlt_set(L, "ZWAVE_R1_R2", DLT_ZWAVE_R1_R2);
#endif
#ifdef DLT_ZWAVE_R3
    pcap_dlt_set(L, "ZWAVE_R3", DLT_ZWAVE_R3);
#endif
#ifdef DLT_WATTSTOPPER_DLM
    pcap_dlt_set(L, "WATTSTOPPER_DLM", DLT_WATTSTOPPER_DLM);
#endif
#ifdef DLT_ISO_14443
    pcap_dlt_set(L, "ISO_14443", DLT_ISO_14443);
#endif
#ifdef DLT_RDS
    pcap_dlt_set(L, "RDS", DLT_RDS);
#endif
#ifdef DLT_USB_DARWIN
    pcap_dlt_set(L, "USB_DARWIN", DLT_USB_DARWIN);
#endif
#ifdef DLT_SDLC
    pcap_dlt_set(L, "SDLC", DLT_SDLC);
#endif
}


/*-
-- cap = pcap.open_live(device, snaplen, promisc, timeout)

Open a source device to read packets from.

- device is the physical device (defaults to "any")
- snaplen is the size to capture, where 0 means max possible (defaults to 0)
- promisc is whether to set the device into promiscuous mode (default is false)
- timeout is the timeout for reads in seconds (default is 0, return if no packets available)

*/
static int lpcap_open_live(lua_State *L)
{
    const char *device = luaL_optstring(L, 1, "any");
    int snaplen = luaL_optint(L, 2, 0);
    int promisc = lua_toboolean(L, 3);
    int to_ms = 1000 * luaL_optint(L, 4, 0); /* convert to milliseconds */
    pcap_t** cap = pushpcapopen(L);
    char errbuf[PCAP_ERRBUF_SIZE];
    if(snaplen == 0)
        snaplen = 0xffff;
    *cap = pcap_open_live(device, snaplen, promisc, to_ms, errbuf);
    return checkpcapopen(L, cap, errbuf);
}


/*-
-- cap = pcap.open_dead([linktype, [snaplen]])

- linktype is one of the DLT numbers, and defaults to pcap.DLT.EN10MB.
- snaplen is the maximum size of packet, and defaults to 65535 (also,
  a value of 0 is changed into 65535 internally, as tcpdump does).

Open a pcap that doesn't read from either a live interface, or an offline pcap
file. It can be used with cap:dump_open() to write a pcap file, or to compile a
BPF program.
*/
static int lpcap_open_dead(lua_State *L)
{
    int linktype = luaL_optint(L, 1, DLT_EN10MB);
    int snaplen = luaL_optint(L, 2, 0);
    pcap_t** cap = pushpcapopen(L);

    /* this is the value tcpdump uses, its way bigger than any known link size */
    if(!snaplen)
        snaplen = 0xffff;

    *cap = pcap_open_dead(linktype, snaplen);

    return checkpcapopen(L, cap, "open dead failed for unknown reason");
}


/*-
-- cap = pcap.open_offline(fname)

Open a savefile to read packets from.

An fname of "-" is a synonym for stdin.
*/
static int lpcap_open_offline(lua_State *L)
{
    const char *fname = luaL_checkstring(L, 1);
    pcap_t** cap = pushpcapopen(L);
    char errbuf[PCAP_ERRBUF_SIZE];
    *cap = pcap_open_offline(fname, errbuf);
    return checkpcapopen(L, cap, errbuf);
}


/*-
-- cap:close()

Manually close a cap object, freeing it's resources (this will happen on
garbage collection if not done explicitly).
*/
static int lpcap_close (lua_State *L)
{
    pcap_t** cap = luaL_checkudata(L, 1, L_PCAP_REGID);

    if(*cap)
        pcap_close(*cap);

    *cap = NULL;

    return 0;
}


/* Current libpcap says to use PCAP_NETMASK_UNKNOWN if you don't know the
   netmask, older libpcaps says to use 0, so we do one or the other
   depending on whether the macro exists.
   */
#ifndef PCAP_NETMASK_UNKNOWN
# define PCAP_NETMASK_UNKNOWN 0
#endif
/*-
-- cap = cap:set_filter(filter, nooptimize)

- filter is the filter string, see tcpdump or pcap-filter man page.
- nooptimize can be true if you don't want the filter optimized during compile
  (the default is to optimize).
*/
static int lpcap_set_filter(lua_State* L)
{
    pcap_t* cap = checkpcap(L);
    const char* filter = luaL_checkstring(L, 2);
    int optimize = !lua_toboolean(L, 3);
    bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN; /* TODO get device from registry, and call pcap_lookup_net()*/
    int ret = 0;
    struct bpf_program program = { 0 };

    ret = pcap_compile(cap, &program, filter, optimize, netmask);

    if(ret < 0) {
        return pusherr(L, cap);
    }

    ret = pcap_setfilter(cap, &program);

    pcap_freecode(&program);

    if(ret < 0) {
        return pusherr(L, cap);
    }

    lua_settop(L, 1);

    return 1;
}

/*-
-- num = cap:datalink()

Interpretation of the packet data requires knowing it's datalink type. This
function returns that as a number.

See pcap.DLT for more information.
*/
static int lpcap_datalink(lua_State* L)
{
    pcap_t* cap = checkpcap(L);
    lua_pushnumber(L, pcap_datalink(cap));
    return 1;
}

/*-
-- snaplen = cap:snapshot()

The snapshot length.

For a live capture, snapshot is the maximum amount of the packet that will be
captured, for writing of captures, it is the maximum size of a packet that can
be written.
*/
static int lpcap_snapshot(lua_State* L)
{
    pcap_t* cap = checkpcap(L);
    lua_pushnumber(L, pcap_snapshot(cap));
    return 1;
}

/*-
-- fd = cap:getfd()

Get a selectable file descriptor number which can be used to wait for packets.

Returns the descriptor number on success, or nil if no such descriptor is
available (see pcap_get_selectable_fd).
*/
#ifndef WIN32
static int lpcap_getfd(lua_State* L)
{
    pcap_t* cap = checkpcap(L);
    int fd = pcap_get_selectable_fd(cap);
    if(fd < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "not selectable");
        return 2;
    }
    lua_pushnumber(L, fd);
    return 1;
}
#endif

/*-
-- capdata, timestamp, wirelen = cap:next()

Example:

    for capdata, timestamp, wirelen in cap.next, cap do
      print(timestamp, wirelen, #capdata)
    end

Returns capdata, timestamp, wirelen on sucess:

- capdata is the captured data
- timestamp is in seconds, theoretically to microsecond accuracy
- wirelen is the packets original length, the capdata may be shorter

Returns nil,emsg on failure, where emsg is:

- "timeout", timeout on a live capture
- "closed", no more packets to be read from a file
- ... some other string returned from pcap_geterr() describing the error
*/
/* TODO cap:loop() -> function(cap) return cap.next, cap end */
static int pushpkt(lua_State* L, struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
    lua_pushlstring(L, (const char*)pkt_data, pkt_header->caplen);
    lua_pushnumber(L, tv2secs(&pkt_header->ts));
    lua_pushinteger(L, pkt_header->len);

    return 3;
}

static int lpcap_next(lua_State* L)
{
    pcap_t* cap = checkpcap(L);
    struct pcap_pkthdr* pkt_header = NULL;
    const u_char* pkt_data = NULL;
    int e = pcap_next_ex(cap, &pkt_header, &pkt_data);

    /* Note: return values don't have names, they are documented numerically
       in the man page. */
    switch(e) {
        case 1: /* success */
            return pushpkt(L, pkt_header, pkt_data);
        case 0: /* read live, and timeout occurred */
            lua_pushnil(L);
            lua_pushstring(L, "timeout");
            return 2;
        case -2: /* read from a savefile, and no more packets */
            lua_pushnil(L);
            lua_pushstring(L, "closed");
            return 2;
        case -1: /* an error occurred */
            return pusherr(L, cap);
    }
    return luaL_error(L, "unreachable");
}


/*-
-- sent = cap:inject(packet)

Injects packet.

Return is bytes sent on success, or nil,emsg on failure.
*/
#ifndef WIN32
static int lpcap_inject(lua_State* L)
{
    pcap_t* cap = checkpcap(L);
    size_t datasz = 0;
    const char* data = luaL_checklstring(L, 2, &datasz);

    int sent = pcap_inject(cap, data, datasz);

    if (sent < 0) {
        return pusherr(L, cap);
    }

    lua_pushinteger(L, sent);

    return 1;
}

#endif

/* Wrap pcap_dumper_t */

static pcap_dumper_t* checkdumper(lua_State* L)
{
    pcap_dumper_t** dumper = luaL_checkudata(L, 1, L_PCAP_DUMPER_REGID);

    luaL_argcheck(L, *dumper, 1, "pcap dumper has been closed");

    return *dumper;
}

/*-
-- dumper = cap:dump_open(fname)

Open a dump file to write packets to.

An fname of "-" is a synonym for stdout.

Note that the dumper object is independent of the cap object, once
it's created (so the cap object can be closed if its not going to
be used).
*/
static int lpcap_dump_open(lua_State *L)
{
    pcap_t* cap = checkpcap(L);
    const char* fname = luaL_checkstring(L, 2);
    pcap_dumper_t** dumper = lua_newuserdata(L, sizeof(*dumper));

    *dumper = NULL;

    luaL_getmetatable(L, L_PCAP_DUMPER_REGID);
    lua_setmetatable(L, -2);

    *dumper = pcap_dump_open(cap, fname);

    if (!*dumper) {
        return pusherr(L, cap);
    }

    return 1;
}


/*-
-- dumper:close()

Manually close a dumper object, freeing it's resources (this will happen on
garbage collection if not done explicitly).
*/
static int lpcap_dump_close (lua_State *L)
{
    pcap_dumper_t** dumper = luaL_checkudata(L, 1, L_PCAP_DUMPER_REGID);

    if(*dumper)
        pcap_dump_close(*dumper);

    *dumper = NULL;

    return 0;
}


/*-
-- dumper = dumper:dump(pkt, [timestamp, [wirelen]])

pkt is the packet to write to the dumpfile.

timestamp of packet, defaults to 0, meaning the current time.

wirelen was the original length of the packet before being truncated to header
(defaults to length of header, the correct value if it was not truncated).

If only the header of the packet is available, wirelen should be set to the
original packet length before it was truncated. Also, be very careful to not
write a header that is longer than the caplen (which will 65535 unless a
different value was specified in open_live or open_dead), the pcap file
will not be valid.

Returns self on sucess.
Returns nil and an error msg on failure.

Note that arguments are compatible with cap:next(), and that since
pcap_dump() doesn't return error indicators only the failure
values from cap:next() will ever be returned.
*/
/* TODO store the snaplen in dumper's environment, so we can check it here */
static int lpcap_dump(lua_State* L)
{
    pcap_dumper_t* dumper = checkdumper(L);
    const char* pkt;
    size_t caplen;
    size_t wirelen;
    struct pcap_pkthdr hdr;

    /* first check if we are echoing the nil,emsg from cap:next()
     * before checking our argument types
     */
    if(lua_isnil(L, 2) && lua_type(L, 3) == LUA_TSTRING) {
        return 2;
    }

    pkt = luaL_checklstring(L, 2, &caplen);
    opttimeval(L, 3, &hdr.ts);
    wirelen = luaL_optint(L, 4, caplen);

    luaL_argcheck(L, wirelen >= caplen, 4, "original wirelen cannot be less than current pkt length");

    hdr.caplen = caplen;
    hdr.len = wirelen;

    /* Note odd type signature for dumper, its because pcap_dump() is
     * designed to be called from a pcap_handler, where the dumper
     * is received as the user data.
     */
    pcap_dump((u_char*) dumper, &hdr, (u_char*)pkt);

    /* clear the stack above self, and return self */
    lua_settop(L, 1);

    return 1;
}

/*-
-- dumper = dumper:flush()

Flush all dumped packets to disk.

Returns self on sucess.
Returns nil and an error msg on failure.
*/
static int lpcap_flush(lua_State* L)
{
    pcap_dumper_t* dumper = checkdumper(L);
    int e = pcap_dump_flush(dumper);

    if(e == 0) {
        return 1;
    }

    lua_pushnil(L);
    lua_pushstring(L, strerror(errno));

    return 2;
}

/* timeval to second conversions */
/* These don't need to be external, but are useful to test timeval conversion from lua. */
/*-
-- secs = pcap.tv2secs(seci, useci)

Combine seperate seconds and microseconds into one numeric seconds.
*/
static int lpcap_tv2secs(lua_State* L)
{
    struct timeval tv;
    tv.tv_sec = (long)luaL_checknumber(L, 1);
    tv.tv_usec = (long)luaL_checknumber(L, 2);

    lua_pushnumber(L, tv2secs(&tv));
    return 1;
}

/*-
-- seci, useci = pcap.secs2tv(secs)

Split one numeric seconds into seperate seconds and microseconds.
*/
static int lpcap_secs2tv(lua_State* L)
{
    struct timeval tv;
    double secs = luaL_checknumber(L, 1);

    secs2tv(secs, &tv);
    lua_pushnumber(L, tv.tv_sec);
    lua_pushnumber(L, tv.tv_usec);
    return 2;
}

/*-
-- pcap._LIB_VERSION = ...

The libpcap version string, as returned from pcap_lib_version().
*/
static const luaL_reg pcap_module[] =
{
    {"open_live", lpcap_open_live},
    {"open_offline", lpcap_open_offline},
    {"open_dead", lpcap_open_dead},
    {"tv2secs", lpcap_tv2secs},
    {"secs2tv", lpcap_secs2tv},
    {NULL, NULL}
};

static const luaL_reg pcap_methods[] =
{
    {"__gc", lpcap_close},
    {"close", lpcap_close},
    {"dump_open", lpcap_dump_open},
    {"set_filter", lpcap_set_filter},
    {"datalink", lpcap_datalink},
    {"snapshot", lpcap_snapshot},
#ifndef WIN32
    {"getfd", lpcap_getfd},
#endif
    {"next", lpcap_next},
    /* TODO - wt_pcap.c also had a next_nonblocking(), I'm not sure why a setnonblocking() wasn't sufficient */
#ifndef WIN32
    {"inject", lpcap_inject},
#endif
    {NULL, NULL}
};

static const luaL_reg dumper_methods[] =
{
    {"__gc", lpcap_dump_close},
    {"close", lpcap_dump_close},
    {"dump", lpcap_dump},
    {"flush", lpcap_flush},
    {NULL, NULL}
};


int luaopen_pcap (lua_State *L)
{
    v_obj_metatable(L, L_PCAP_DUMPER_REGID, dumper_methods);
    v_obj_metatable(L, L_PCAP_REGID, pcap_methods);

#if LUA_VERSION_NUM > 501
    lua_newtable(L);
    luaL_setfuncs (L,pcap_module,0); //leaving global namespace clean in 5.2
#else
    luaL_register(L, "pcap", pcap_module);
#endif

    lua_pushstring(L, pcap_lib_version());
    lua_setfield(L, -2, "_LIB_VERSION");

    pcap_make_dlt(L);
    lua_setfield(L, -2, "DLT");

    return 1;
}

