#include "httpparser.h"

HTTPParser::HTTPParser(pcpp::Packet& packet):PacketParser(packet) {}

std::string HTTPParser::parse_domain_name() {

    std::string server_name;
    pcpp::HttpRequestLayer* http_packet = nullptr;

    http_packet = this->_packet.getLayerOfType<pcpp::HttpRequestLayer>();
    if (http_packet == nullptr) { return server_name; }

    server_name = http_packet->getFieldByName("Host")->getFieldValue();

    return server_name;
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
