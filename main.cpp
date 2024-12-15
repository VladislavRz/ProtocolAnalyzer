#include <Packet.h>
#include <PcapFileDevice.h>
#include <time.h>

#include "dhcpv4parser.h"
#include "sslparser.h"
#include "httpparser.h"
#include "sipparser.h"
#include "ldapparser.h"
#include "smtpparser.h"
#include "dnsparser.h"

#define VERSION "1.0"

void argparse(int argc, char* argv[], std::string& filename, std::string& hostname) {
    if (argc <= 2) {
        std::cout << "Usage: " << argv[0] << " <input file> <sensor>" << std::endl;
        std::cout << "Version: " << VERSION << std::endl;
        throw "Incorrect input arguments!";
    }

    filename = argv[1];
    hostname = argv[2];
}

void run(pcpp::PcapFileReaderDevice& reader, std::string& hostname, std::string& delimeter) {
    pcpp::RawPacket rawPacket;
    pcpp::Packet packet;

    if(!reader.getNextPacket(rawPacket)) {
        throw "Unable read first packet.";
    }

    do {

        packet = pcpp::Packet(&rawPacket);


        if (packet.isPacketOfType(pcpp::DHCP)) {
            DHCPv4Parser parser(packet);
            parser.parse(hostname, delimeter);

        }

        if (packet.isPacketOfType(pcpp::SSL)) {
            SSLParser parser(packet);
            parser.parse(hostname, delimeter);

        }

        if (packet.isPacketOfType(pcpp::HTTPRequest)) {
            HTTPParser parser(packet);
            parser.parse(hostname, delimeter);

        }

        if (packet.isPacketOfType(pcpp::SIP)) {
            SIPParser parser(packet);
            parser.parse(hostname, delimeter);
        }

        if (packet.isPacketOfType(pcpp::LDAP)) {
            LDAPParser parser (packet);
            parser.parse(hostname, delimeter);
        }

        if (packet.isPacketOfType(pcpp::SMTP)) {
            SMTPParser parser (packet);
            parser.parse(hostname, delimeter);
        }

        if (packet.isPacketOfType(pcpp::DNS)) {
            DNSParser parser (packet);
            parser.parse(hostname, delimeter);
        }

    } while (reader.getNextPacket(rawPacket));
}

int main(int argc, char* argv[]) {

    // /Users/larz/Documents/МГТУ/НИР/pcaps/Wireshark-tutorial-identifying-hosts-and-users-1-of-5.pcap
    std::string filename;
    std::string hostname;
    std::string delimeter = "#,";
    pcpp::IPcapDevice::PcapStats stats;

    clock_t start = clock();
    try {

        // Parse program arguments
        argparse(argc, argv, filename, hostname);

        // Open .pcap file
        pcpp::PcapFileReaderDevice reader(filename);
        if (!reader.open()) {
            throw "Error opening the pcap file: " + filename;
        }

        std::cout << "Start parse " + filename << std::endl;

        // Parse .pcap file
        run(reader, hostname, delimeter);

        // Get statistic and close .pcap file
        reader.getStatistics(stats);
        reader.close();

        std::cerr << "Read " << stats.packetsRecv << " packets successfully and "
                  << stats.packetsDrop << " packets could not be read." << std::endl;

    } catch (const char* error_msg) {

        std::cerr << error_msg << std::endl;
    }

    clock_t end = clock();
    double timer = static_cast<double>((start - end)/CLOCKS_PER_SEC);
    std::cerr << "The time " << timer << " seconds." << std::endl;

    return 0;
}
