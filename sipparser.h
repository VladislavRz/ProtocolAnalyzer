#include <SipLayer.h>

#include "packetparser.h"

#ifndef SIPPARSER_H
#define SIPPARSER_H

class SIPParser: public PacketParser {

public:
public:
    SIPParser(pcpp::Packet& packet);
    ~SIPParser() = default;

    std::string parse_domain_name() override;
    std::string parse_type() override;
    std::string parse_res_type() override;
    std::string parse_data() override;
    std::string split_hostname(std::string& hostname, std::string begin, std::string close);
};

#endif // SIPPARSER_H
