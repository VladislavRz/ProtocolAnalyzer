#include "dhcpv4parser.h"


DHCPv4Parser::DHCPv4Parser(pcpp::Packet& packet):PacketParser(packet) {}

std::string DHCPv4Parser::parse_domain_name() {

    std::string server_name;
    pcpp::DhcpLayer* dhcp_packet = nullptr;

    dhcp_packet = this->_packet.getLayerOfType<pcpp::DhcpLayer>();
    if (dhcp_packet == nullptr) { return server_name; }

    if (dhcp_packet->getMessageType() == pcpp::DHCP_REQUEST) {

        server_name = dhcp_packet->getOptionData(pcpp::DHCPOPT_HOST_NAME).getValueAsString();

    }

    return server_name;
}

std::string DHCPv4Parser::parse_type() { return "dhcp4"; }

std::string DHCPv4Parser::parse_res_type() { return "dhcp_request"; }

std::string DHCPv4Parser::parse_data() { return ""; }
