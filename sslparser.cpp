#include "sslparser.h"

SSLParser::SSLParser(pcpp::Packet& packet):PacketParser(packet) {}

std::vector<std::string> SSLParser::parse_domain_name() {
    std::vector<std::string> server_names;
    std::string hostname;
    pcpp::SSLClientHelloMessage* hello_msg = nullptr;
    pcpp::SSLHandshakeLayer* ssl_packet = nullptr;
    pcpp::SSLServerNameIndicationExtension* sni_ext = nullptr;

    ssl_packet = this->_packet.getLayerOfType<pcpp::SSLHandshakeLayer>();
    if (ssl_packet == nullptr) { return server_names; }

    hello_msg = ssl_packet->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
    if (hello_msg == nullptr) { return server_names; }

    sni_ext = hello_msg->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();

    if (sni_ext != nullptr) {

        hostname = sni_ext->getHostName();
        if (!hostname.empty()) { server_names.push_back(hostname); }

    }

    return server_names;

}

std::string SSLParser::parse_type() { return "ssl"; }

std::string SSLParser::parse_res_type() { return "sni"; }

std::string SSLParser::parse_data() { return ""; }

