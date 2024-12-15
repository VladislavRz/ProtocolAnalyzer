#include <SmtpLayer.h>

#include "packetparser.h"

#ifndef SMTPPARSER_H
#define SMTPPARSER_H

class SMTPParser: public PacketParser {

public:
    SMTPParser(pcpp::Packet& packet);
    ~SMTPParser() = default;

    std::string parse_domain_name() override;
    std::string parse_type() override;
    std::string parse_res_type() override;
    std::string parse_data() override;
    std::string split_domain(std::string& hostname);
};

#endif // SMTPPARSER_H
