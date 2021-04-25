#include <iostream>
#include "myHandler.hpp"
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <ctime>
#include <chrono>
#include <iomanip>
#include <sstream>
#include "arp.h"

#define SIZE_ETHERNET 14
#define SIZE_IPV6HEAD 40
#define TH_OFF(th)	(((th)->th_x2 & 0xf0) >> 4)

void printPayload(const u_char *payload, int size);
std::string getTime(struct timeval tv);
void printMac(const u_char *c);

/* 
    contains edited code from https://www.devdungeon.com/content/using-libpcap-c#packet-info
    and http://www.tcpdump.org/
*/
void myHandlePacket(u_char *useless, const struct pcap_pkthdr* header, const u_char* data) {    
    const struct ether_header *h = (struct ether_header *) data;

    // Get IPs etc...
    //u_short off = ntohs(ipHeader->ip_off);
    

    if (ntohs(h->ether_type) == ETHERTYPE_IP) {
        const struct ip *ipHeader;
        u_int size_ip;
        ipHeader = (struct ip*) (data + SIZE_ETHERNET);
        size_ip = ipHeader->ip_hl * 4;

        if (size_ip < 20) {
            std::cerr << "INVALID IP HEADER" << std::endl;
            return;
        }
        u_char protocol = ipHeader->ip_p;

        if (protocol == IPPROTO_TCP) {
            const struct tcphdr *tcp = (struct tcphdr*) (data + SIZE_ETHERNET + size_ip);
            // +HELPER
            /*const u_char *tcp_header;
            tcp_header = data + SIZE_ETHERNET + size_ip;
            int size_tcp = ((*(tcp_header + 12)) & 0xF0) >> 4;
            size_tcp *= 4;
            // -HELPER
            if (size_tcp < 20) {
                std::cerr << "INVALID TCP HEADER" << std::endl;
                return;
            }*/

            // Print first line
            std::cout << getTime(header->ts) << " " << inet_ntoa(ipHeader->ip_src) << " : " << tcp->th_sport << " > " << inet_ntoa(ipHeader->ip_dst) << " : " << tcp->th_dport << ", length " << header->caplen << " bytes" << std::endl;

            //payload = (u_char *)(data + SIZE_ETHERNET + size_ip + size_tcp);
            //int payloadSize = ntohs(ipHeader->ip_hl) - (size_ip + size_tcp);
            //int payloadSize = header->caplen - (size_ip + size_tcp);
            printPayload(data, header->caplen);
        } else if (protocol == IPPROTO_UDP) {
            const struct udphdr *udp = (struct udphdr*) (data + SIZE_ETHERNET + size_ip);
            std::cout << getTime(header->ts) << " " << inet_ntoa(ipHeader->ip_src) << " : " << udp->uh_sport << " > " << inet_ntoa(ipHeader->ip_dst) << " : " << udp->uh_dport << ", length " << header->caplen << " bytes" << std::endl;
            printPayload(data, header->caplen);
        } else if (protocol == IPPROTO_ICMP) {
            std::cout << getTime(header->ts) << " " << inet_ntoa(ipHeader->ip_src) <<  " > " << inet_ntoa(ipHeader->ip_dst) << ", length " << header->caplen << " bytes" << std::endl;
            printPayload(data, header->caplen);
        }
    } else if (ntohs(h->ether_type) == ETHERTYPE_IPV6) {
        const struct ip6_hdr *ipHeader;
        ipHeader = (struct ip6_hdr*) (data + SIZE_ETHERNET);
        u_char protocol = ipHeader->ip6_ctlun.ip6_un1.ip6_un1_nxt;

        char ipSrc[INET6_ADDRSTRLEN];
        char ipDst[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &ipHeader->ip6_src, ipSrc, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ipHeader->ip6_dst, ipDst, INET6_ADDRSTRLEN);
        
        if (protocol == IPPROTO_TCP) {
            // IPv6 TCP
            const struct tcphdr *tcp = (struct tcphdr*) (data + SIZE_ETHERNET + SIZE_IPV6HEAD);
            

            std::cout << getTime(header->ts) << " " << ipSrc << " : " << tcp->th_sport << " > " << ipDst << " : " << tcp->th_dport << ", length " << header->caplen << " bytes" << std::endl;
            printPayload(data, header->caplen);
        } else if (protocol == IPPROTO_UDP) {
            // IPv6 UDP
            const struct udphdr *udp = (struct udphdr*) (data + SIZE_ETHERNET + SIZE_IPV6HEAD);

            std::cout << getTime(header->ts) << " " << ipSrc << " : " << udp->uh_sport << " > " << ipDst << " : " << udp->uh_dport << ", length " << header->caplen << " bytes" << std::endl;
            printPayload(data, header->caplen);
        } else if (protocol == IPPROTO_ICMPV6) {
            // IPv6 ICMPv6
            std::cout << getTime(header->ts) << " " << ipSrc <<  " > " << ipDst << ", length " << header->caplen << " bytes" << std::endl;
            printPayload(data, header->caplen);
        }

    } else if (ntohs(h->ether_type) == ETHERTYPE_ARP) {
        const struct arp *arp = (struct arp*) (data + SIZE_ETHERNET);
        // Print mac
        std::cout << getTime(header->ts) << " " ;
        printMac(data + 6);
        std::cout <<  " > ";
        printMac(data);
        std::cout << ", length " << header->caplen << " bytes" << std::endl;

        printPayload(data, header->caplen);
    }
    //std::cout << "END " << ntohs(h->ether_type) << std::endl;
    std::cout << std::endl;
}

void printAscii(const u_char *payload, int size, int offset) {
    // space
    std::cout << "\t";

    // Print chars if printable
    for (int j = 0; j + offset < size && j < 16; j++) {
        if (isprint(payload[offset + j])) {
            printf("%c", payload[offset + j]);
        } else {
            printf(".");
        }
    }
    // Jump to new line
    std::cout << std::endl;
}

void printPayload(const u_char *payload, int size) {
    int i = 0;
    while (i < size) {
        // Print Offset
        printf("0x%x\t", i);

        // Print 10 bytes
        int j = 0;
        for (; i + j < size && j < 16; j++) {
            u_char tmp = payload[i + j];
            printf("%02x ", tmp);
        }
        if (j < 16) {
            for (; j < 16; j++) {
                printf("   ");
            }
        }

        printAscii(payload, size, i);

        i += 16;
    }

}

void printMac(const u_char *c) {
    for (int i = 0; i < 5; i++) {
        printf("%02X:", c[i] & 0xFF);
    }
    printf("%02X", c[5] & 0xFF);
}

/* Edited from https://stackoverflow.com/a/2409054 */
std::string getTime(struct timeval tv) {
    time_t nowtime = tv.tv_sec;
    char tmbuf[64], buf[64];
    struct tm *nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%dT%H:%M:%S", nowtm);
    auto s = std::to_string(tv.tv_usec);
    char tmp[4];
    tmp[0] = s[0];
    tmp[1] = s[1];
    tmp[2] = s[2];
    tmp[3] = '\0';
    snprintf(buf, sizeof(buf), "%s.%s", tmbuf, tmp);
    std::string ret = "";
    ret.append(buf);
    auto off = nowtm->tm_gmtoff / 3600;
    char c[6];
    sprintf(c, "+%02d:00", off);
    ret.append(c);
    return ret;
}