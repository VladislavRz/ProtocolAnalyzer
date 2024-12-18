#include "dnsparser.h"

DNSParser::DNSParser(pcpp::Packet& packet):PacketParser(packet) {}

std::vector<std::string> DNSParser::parse_domain_name() {
    std::vector<std::string> server_names;
    std::string hostname;
    pcpp::DnsLayer* dns_packet = nullptr;
    pcpp::DnsQuery* dns_query = nullptr;
    pcpp::DnsResource* dns_answer = nullptr;

    dns_packet = this->_packet.getLayerOfType<pcpp::DnsLayer>();
    if (dns_packet == nullptr) { return server_names; }

    dns_query = dns_packet->getFirstQuery();
    if (dns_query == nullptr) { return server_names; }

    while(dns_query) {
        hostname = dns_query->getName();
        if (!hostname.empty()) { server_names.push_back(hostname); }
        dns_query = dns_packet->getNextQuery(dns_query);
    }

    return server_names;
}

std::string DNSParser::parse_type() { return "dns"; }

std::string DNSParser::parse_res_type() { return "dns_query"; }

std::string DNSParser::parse_data() { return ""; }
