#include <Packet.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <iostream>
#include <vector>

#ifndef PACKETPARSER_H
#define PACKETPARSER_H

class PacketParser {

protected:

    pcpp::Packet _packet;


public:

    PacketParser(pcpp::Packet& packet);
    virtual ~PacketParser() = default;

    virtual std::vector<std::string> parse_domain_name() = 0;
    virtual std::string parse_type() = 0;
    virtual std::string parse_res_type() = 0;
    virtual std::string parse_data() = 0;

    long parse_datetime();
    std::string parse_src_ip();
    std::string parse_dst_ip();

    void parse(const std::string& hostname, const std::string& delimeter);
    void print_result(const std::string& hostname, long& datetime, std::string& src_ip,
                      std::string& dst_ip, std::string& type, std::string& domain_name,
                      std::string& res_type, int& data_len, std::string& data, const std::string& delimeter) const;

};


#endif // PACKETPARSER_H
