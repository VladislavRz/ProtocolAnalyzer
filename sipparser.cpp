#include "sipparser.h"

SIPParser::SIPParser(pcpp::Packet& packet):PacketParser(packet) {}

std::string SIPParser::parse_domain_name() {

    std::string server_name;
    pcpp::SipLayer* sip_packet = nullptr;
    sip_packet = this->_packet.getLayerOfType<pcpp::SipLayer>();
    if (sip_packet == nullptr) { return server_name; }

    server_name = sip_packet->getFieldByName("To")->getFieldValue();

    return split_hostname(server_name, "@", ">");
}

std::string SIPParser::parse_type() { return "sip"; }

std::string SIPParser::parse_res_type() {

    if (this->_packet.isPacketOfType(pcpp::SIPRequest)) { return "sip_request"; }

    return "sip_response";
}

std::string SIPParser::parse_data() {
    std::string data;
    pcpp::SipLayer* sip_packet = nullptr;
    sip_packet = this->_packet.getLayerOfType<pcpp::SipLayer>();
    if (sip_packet == nullptr) { return data; }

    data = sip_packet->getFieldByName("To")->getFieldValue();

    return split_hostname(data, "<", ">");
}

std::string SIPParser::split_hostname(std::string& hostname, std::string&& begin, std::string&& close) {

    std::string result;
    int start = hostname.find(begin);
    int end = hostname.find(close);

    if (start != std::string::npos && end != std::string::npos) {
        result = hostname.substr(start + 1, end - start -1);
    }

    return result;
}
