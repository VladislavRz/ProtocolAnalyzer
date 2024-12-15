#include "dnsparser.h"

DNSParser::DNSParser(pcpp::Packet& packet):PacketParser(packet) {}

std::string DNSParser::parse_domain_name() {
    std::string server_name;
    pcpp::DnsLayer* dns_packet = nullptr;
    pcpp::DnsQuery* dns_query = nullptr;
    pcpp::DnsResource* dns_answer = nullptr;

    dns_packet = this->_packet.getLayerOfType<pcpp::DnsLayer>();
    if (dns_packet == nullptr) { return server_name; }

    dns_query = dns_packet->getFirstQuery();
    if (dns_query == nullptr) { return server_name; }

    server_name = dns_query->getName();

    return server_name;
}

std::string DNSParser::parse_type() { return "dns"; }

std::string DNSParser::parse_res_type() { return "dns_query"; }

std::string DNSParser::parse_data() { return ""; }
