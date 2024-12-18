#include "httpparser.h"

HTTPParser::HTTPParser(pcpp::Packet& packet):PacketParser(packet) {}

std::vector<std::string> HTTPParser::parse_domain_name() {

    std::vector<std::string> server_names;
    std::string hostname;
    pcpp::HttpRequestLayer* http_packet = nullptr;

    http_packet = this->_packet.getLayerOfType<pcpp::HttpRequestLayer>();
    if (http_packet == nullptr) { return server_names; }

    hostname = http_packet->getFieldByName("Host")->getFieldValue();
    if (!hostname.empty()) { server_names.push_back(hostname); }

    return server_names;
}

std::string HTTPParser::parse_type() { return "http"; }

std::string HTTPParser::parse_res_type() { return "http_request"; }

std::string HTTPParser::parse_data() {

    std::string data;
    pcpp::HttpRequestLayer* http_packet = nullptr;

    http_packet = this->_packet.getLayerOfType<pcpp::HttpRequestLayer>();
    if (http_packet == nullptr) { return data; }

    data = http_packet->getUrl();

    return data;
}
