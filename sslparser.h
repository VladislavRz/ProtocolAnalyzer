#include <SSLLayer.h>

#include "packetparser.h"

#ifndef SSLPARSER_H
#define SSLPARSER_H

class SSLParser: public PacketParser {

public:
    SSLParser(pcpp::Packet& packet);
    ~SSLParser() = default;

    std::string parse_domain_name() override;
    std::string parse_type() override;
    std::string parse_res_type()override;
    std::string parse_data()override;
};

#endif // SSLPARSER_H
