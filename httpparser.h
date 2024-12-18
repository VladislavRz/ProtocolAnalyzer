#include <HttpLayer.h>

#include "packetparser.h"

#ifndef HTTPPARSER_H
#define HTTPPARSER_H

class HTTPParser: public PacketParser {

public:

    HTTPParser(pcpp::Packet& packet);
    ~HTTPParser() = default;

    std::vector<std::string> parse_domain_name() override;
    std::string parse_type() override;
    std::string parse_res_type() override;
    std::string parse_data() override;

};

#endif // HTTPPARSER_H
