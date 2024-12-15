#include "sslparser.h"

SSLParser::SSLParser(pcpp::Packet& packet):PacketParser(packet) {}

std::string SSLParser::parse_domain_name() {
    std::string server_name;
    pcpp::SSLClientHelloMessage* hello_msg = nullptr;
    pcpp::SSLHandshakeLayer* ssl_packet = nullptr;
    pcpp::SSLServerNameIndicationExtension* sni_ext = nullptr;

    ssl_packet = this->_packet.getLayerOfType<pcpp::SSLHandshakeLayer>();
    if (ssl_packet == nullptr) { return server_name; }

    hello_msg = ssl_packet->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
    if (hello_msg == nullptr) { return server_name; }

    sni_ext = hello_msg->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();

    if (sni_ext != nullptr) {

        server_name = sni_ext->getHostName();

    }

    return server_name;

}

std::string SSLParser::parse_type() { return "ssl"; }

std::string SSLParser::parse_res_type() { return "sni"; }

std::string SSLParser::parse_data() { return ""; }

