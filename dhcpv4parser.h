#include <DhcpLayer.h>

#include "packetparser.h"

#ifndef DHCPV4PARSER_H
#define DHCPV4PARSER_H

class DHCPv4Parser: public PacketParser {

public:
    DHCPv4Parser(pcpp::Packet& packet);
    ~DHCPv4Parser() = default;

    std::string parse_domain_name() override;
    std::string parse_type() override;
    std::string parse_res_type() override;
    std::string parse_data() override;

};

#endif // DHCPV4PARSER_H
