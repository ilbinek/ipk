#include "argparse.hpp"

void printHelp() {
    std::cout << "PRINTING HELP" << std::endl;
    std::cout << "usage:\n\t./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}" << std::endl;
}

void ArgParse::parse(int argc, char **argv) {
    bool inter = false;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (!arg.compare("-h") || !arg.compare("--help")) {
            printHelp();
            exit(0);
        } else if (!arg.compare("-i") || !arg.compare("--interface")) {
            // Interface parsing
            inter = true;
            if ((i + 1) < argc) {
                std::string tmp = argv[i + 1];
                if (tmp.rfind("-", 0) != 0) {
                    interface = tmp;
                    i++;
                }
            }
        } else if (!arg.compare("-t") || !arg.compare("--tcp")) {
            protocolSpecified = true;
            tcp = true;
        } else if (!arg.compare("-u") || !arg.compare("--udp")) {
            protocolSpecified = true;
            udp = true;
        } else if (!arg.compare("--arp")) {
            protocolSpecified = true;
            arp = true;
        } else if (!arg.compare("--icmp")) {
            protocolSpecified = true;
            icmp = true;
        } else if (!arg.compare("-n") || !arg.compare("--num")) {
            if ((i + 1) < argc) {
                std::string tmp = argv[i + 1];
                if (tmp.rfind("-", 0) != 0) {
                    try {
                        number = stol(tmp);
                        i++;
                    }
                    catch(const std::exception& e) {
                        std::cerr << e.what() << '\n';
                        exit(1);
                    }
                }
            }
        } else if (!arg.compare("-p")) {
            portSpecified = true;
            if ((i + 1) < argc) {
                std::string tmp = argv[i + 1];
                if (tmp.rfind("-", 0) != 0) {
                    try {
                        port = (int) stol(tmp);
                        if (port < 0 || port > 65353) {
                            std::cerr << "Port out of bounds" << std::endl;
                            exit(10);
                        }
                        i++;
                    }
                    catch(const std::exception& e) {
                        std::cerr << e.what() << '\n';
                        exit(1);
                    }
                }
            }
        } else {
            std::cerr << "Unknown argumnet" << std::endl;
            exit(20);
        }
    }
    if (!inter) {
        std::cerr << "-i or --interface missing" << std::endl;
        exit(1);
    }
}

bool ArgParse::isPortSpecified() {
    return portSpecified;
}

bool ArgParse::isProtocolSpecified() {
    return protocolSpecified;
}

int ArgParse::getPort() {
    return port;
}

bool ArgParse::getTcp() {
    return tcp;
}

bool ArgParse::getUdp() {
    return udp;
}

bool ArgParse::getIcmp() {
    return icmp;
}

bool ArgParse::getArp() {
    return arp;
}

int ArgParse::getNumber() {
    return number;
}

std::string ArgParse::getInterface() {
    return interface;
}