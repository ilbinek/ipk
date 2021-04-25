# ifndef _ARGPARSE_
# define _ARGPARSE_

#include <string>
#include <iostream>

class ArgParse {       // The class
    public:
        void parse(int argc, char **argv);

        std::string getInterface();
        bool isPortSpecified();
        int getPort();
        bool isProtocolSpecified();
        bool getTcp();
        bool getUdp();
        bool getIcmp();
        bool getArp();
        int getNumber();

    private:
        std::string interface = "";
        bool portSpecified = false;
        bool protocolSpecified = false;
        int port = 0;
        bool tcp = false;
        bool udp = false;
        bool icmp = false;
        bool arp = false;
        int number = 1;
};

#endif