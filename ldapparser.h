#include <LdapLayer.h>

#include "packetparser.h"

#ifndef LDAPPARSER_H
#define LDAPPARSER_H

class LDAPParser: public PacketParser {

public:
    LDAPParser(pcpp::Packet& packet);
    ~LDAPParser() = default;

    std::string parse_domain_name() override;
    std::string parse_type() override;
    std::string parse_res_type() override;
    std::string parse_data() override;

};

#endif // LDAPPARSER_H
