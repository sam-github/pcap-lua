#include <assert.h>
#include <errno.h>
#include <math.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

int main(int argc, char* argv[])
{
    char* source = argv[1];
    int snaplen = 0;
    int promisc = 0;
    int to_ms = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    printf("version %s\n", pcap_lib_version());

    pcap_t* cap = pcap_open_live(source, snaplen, promisc, to_ms, errbuf);
    
    if(!cap) {
        printf("error %s\n", errbuf);
        return 1;
    }

    struct pcap_pkthdr* pkt_header = NULL;
    const u_char* pkt_data = NULL;
    int e = pcap_next_ex(cap, &pkt_header, &pkt_data);

    printf("return %d error? %s\n", e, pcap_geterr(cap));

    return 0;
}

