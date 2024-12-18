#include "dhcpv4parser.h"


DHCPv4Parser::DHCPv4Parser(pcpp::Packet& packet):PacketParser(packet) {}

std::vector<std::string> DHCPv4Parser::parse_domain_name() {

    std::vector<std::string> server_names;
    std::string hostname;
    pcpp::DhcpLayer* dhcp_packet = nullptr;

    dhcp_packet = this->_packet.getLayerOfType<pcpp::DhcpLayer>();
    if (dhcp_packet == nullptr) { return server_names; }



    hostname = dhcp_packet->getOptionData(pcpp::DHCPOPT_HOST_NAME).getValueAsString().c_str();
    if(!hostname.empty()) { server_names.push_back(hostname); }
    hostname = dhcp_packet->getOptionData(pcpp::DHCPOPT_DOMAIN_NAME).getValueAsString().c_str();
    if(!hostname.empty()) { server_names.push_back(hostname); }

    return server_names;
}

std::string DHCPv4Parser::parse_type() { return "dhcp4"; }

std::string DHCPv4Parser::parse_res_type() {
    pcpp::DhcpMessageType msg_type;
    std::string res_type;
    pcpp::DhcpLayer* dhcp_packet = nullptr;

    dhcp_packet = this->_packet.getLayerOfType<pcpp::DhcpLayer>();
    if (dhcp_packet == nullptr) { return res_type; }

    msg_type = dhcp_packet->getMessageType();

    if (msg_type == pcpp::DHCP_REQUEST) {
        res_type = "dhcp_request";
    } else if (msg_type == pcpp::DHCP_DISCOVER) {
        res_type = "dhcp_discover";
    } else if (msg_type == pcpp::DHCP_OFFER) {
        res_type = "dhcp_offer";
    } else if (msg_type == pcpp::DHCP_ACK) {
        res_type = "dhcp_ack";
    }

    return res_type;
}

std::string DHCPv4Parser::parse_data() {
    std::string data;
    pcpp::DhcpLayer* dhcp_packet = nullptr;

    dhcp_packet = this->_packet.getLayerOfType<pcpp::DhcpLayer>();
    if (dhcp_packet == nullptr) { return data; }

    data = "client_mac{" + dhcp_packet->getClientHardwareAddress().toString() + "}";


    return data;
}
