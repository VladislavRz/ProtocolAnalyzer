#include <iostream>
#include <Packet.h>
#include <PcapFileDevice.h>

#include "settings.h"
#include "dhcpv4parser.h"
#include "sslparser.h"
#include "httpparser.h"
#include "sipparser.h"
#include "ldapparser.h"
#include "smtpparser.h"
#include "dnsparser.h"


int main(int argc, char* argv[])
{

    pcpp::RawPacket rawPacket;
    pcpp::Packet packet;
    // pcpp::PcapFileReaderDevice reader("/Users/larz/Documents/МГТУ/НИР/pcaps/aaa.pcap");
    pcpp::PcapFileReaderDevice reader("/Users/larz/Documents/МГТУ/НИР/pcaps/Wireshark-tutorial-identifying-hosts-and-users-1-of-5.pcap");

    if (!reader.open())
    {
        std::cerr<< "Error opening the pcap file" << std::endl;
        return 1;
    }

    while (reader.getNextPacket(rawPacket)) {

        packet = pcpp::Packet(&rawPacket);

        if (packet.isPacketOfType(pcpp::DHCP)) {
            DHCPv4Parser parser(packet);
            parser.parse();

        }

        if (packet.isPacketOfType(pcpp::SSL)) {
            SSLParser parser(packet);
            parser.parse();

        }

        if (packet.isPacketOfType(pcpp::HTTPRequest)) {
            HTTPParser parser(packet);
            parser.parse();

        }

        if (packet.isPacketOfType(pcpp::SIP)) {
            SIPParser parser(packet);
            parser.parse();
        }

        if (packet.isPacketOfType(pcpp::LDAP)) {
            LDAPParser parser (packet);
            parser.parse();
        }

        if (packet.isPacketOfType(pcpp::SMTP)) {
            SMTPParser parser (packet);
            parser.parse();
        }

        if (packet.isPacketOfType(pcpp::DNS)) {
            DNSParser parser (packet);
            parser.parse();
        }

        // if (parser) {
        //     parser.parse();
        // }

    }

    reader.close();

    return 0;
}
