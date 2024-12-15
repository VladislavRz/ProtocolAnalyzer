#include <DnsLayer.h>

#include "packetparser.h"

#ifndef DNSPARSER_H
#define DNSPARSER_H

class DNSParser: public PacketParser {

public:
    DNSParser(pcpp::Packet& packet);
    ~DNSParser() = default;

    std::string parse_domain_name() override;
    std::string parse_type() override;
    std::string parse_res_type() override;
    std::string parse_data() override;
};

#endif // DNSPARSER_H
