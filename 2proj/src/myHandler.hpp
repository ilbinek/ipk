#ifndef __MYpcapHANDLER__
#define __MYpcapHANDLER__

#include <pcap/pcap.h>
#include <net/ethernet.h>

void myHandlePacket(u_char *useless, const struct pcap_pkthdr* header, const u_char* data);

#endif