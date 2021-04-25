#include <iostream>
#include <string>
#include <getopt.h>
#include "argparse.hpp"
#include <pcap.h>
#include "myHandler.hpp"
#include <sstream>

//#define _DEBUG_

void handleCtrlC(int s){
    
}

int main (int argc, char **argv) {
    auto parser = new ArgParse();
    parser->parse(argc, argv);

    char p[10];
    sprintf(p, "%d", parser->getPort());
    #ifdef _DEBUG_
        if (parser->isPortSpecified()) {
            std::cout << "Port: " << parser->getPort() << std::endl;
            sprintf(p, "%d", parser->getPort());
        }

        if (parser->getInterface().compare("")) {
            std::cout << "Interface: " << parser->getInterface() << std::endl;
        }

        if (parser->isProtocolSpecified()) {
            std::cout << "TCP: " << parser->getTcp() << std::endl;
            std::cout << "UDP: " << parser->getUdp() << std::endl;
            std::cout << "ICMP: " << parser->getIcmp() << std::endl;
            std::cout << "ARP: " << parser->getArp() << std::endl;
        } else {
            std::cout << "All protocols" << std::endl;
        }
        
        std::cout << "Number: " << parser->getNumber() << std::endl;
    #endif

    // Check if all I need to do is list interfaces
    char errorBuf[PCAP_ERRBUF_SIZE];
    if (!parser->getInterface().compare("")) {
        pcap_if_t *interfaces;
        int i=0;
        if(pcap_findalldevs(&interfaces,errorBuf)==-1) {
            std::cerr << errorBuf << std::endl;
            delete parser;
            return 1;   
        }
        pcap_if_t *tmp;
        for(tmp = interfaces; tmp; tmp=tmp->next) {
            std::cout << tmp->name << std::endl;
        }
        delete parser;
        return 0;
    }



    bpf_u_int32 mask;
    bpf_u_int32 net;
    bpf_program filter;
    if (pcap_lookupnet(parser->getInterface().c_str(), &net, &mask, errorBuf) == -1) {
        // Mask error
        net = 0;
        mask = 0;
    }

    // Try to hook the device
    auto device = pcap_open_live(parser->getInterface().c_str(), BUFSIZ, 1, 64, errorBuf);
    if (device == NULL) {
        std::cerr << "Couldn't open device " << parser->getInterface() << std::endl << errorBuf << std::endl;
        delete parser;
        return 53;
    }

    // Setup filters

    std::string f = "tcp or udp or icmp or icmp6";

    if (parser->isProtocolSpecified() || parser->isPortSpecified()) {
        f = "";
    }

    if (parser->getTcp()) {
        f.append("tcp");
        if (parser->isPortSpecified()) {
            f.append(" port ");
            f.append(p);
            //f.append(parser->getPort());
        }
    }
    if (parser->getUdp()) {
        if (f.compare("")) {
            f.append(" or ");
        }
        f.append("udp");
        if (parser->isPortSpecified()) {
            f.append(" port ");
            f.append(p);
            //f.append(parser->getPort());
        }
    }
    if (parser->getIcmp()) {
        if (f.compare("")) {
            f.append(" or ");
        }
        f.append("icmp or icmp6");
    }
    if (parser->getArp()) {
        if (f.compare("")) {
            f.append(" or ");
        }
        f.append("arp");
    }
    if (parser->isPortSpecified()) {
        if (f.compare("")) {
            f.append(" and port ");
            f.append(p);
        }
        f.append("port ");
        f.append(p);
    }

    #ifdef _DEBUG_
    std::cout << f << std::endl;
    #endif

    if (pcap_compile(device, &filter, f.c_str(), 0, net) == -1) {
        delete parser;
        return 54;
    }

    if (pcap_setfilter(device, &filter) == -1) {
        delete parser;
        return 55;
    }

    // Sniff sniff sniff, just like Scoopy
    if (pcap_loop(device, parser->getNumber(), myHandlePacket, NULL) < 0) {
        delete parser;
        return 1;
    }
    delete parser;
    pcap_close(device);
    return 0;
}