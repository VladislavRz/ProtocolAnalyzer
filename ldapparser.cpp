#include "ldapparser.h"

LDAPParser::LDAPParser(pcpp::Packet& packet):PacketParser(packet) {}

std::vector<std::string> LDAPParser::parse_domain_name() {
    std::vector<std::string> server_names;
    std::string hostname;
    pcpp::LdapLayer* ldap_packet = nullptr;
    void* ldap_res_pkt = nullptr;

    ldap_packet = this->_packet.getLayerOfType<pcpp::LdapLayer>();
    if (ldap_packet == nullptr) { return server_names; }

    switch (ldap_packet->getLdapOperationType()) {

    case pcpp::LdapOperationType::BindRequest:
        ldap_res_pkt = this->_packet.getLayerOfType<pcpp::LdapBindRequestLayer>();
        if (ldap_res_pkt != nullptr) {
            hostname = static_cast<pcpp::LdapBindRequestLayer*>(ldap_res_pkt)->getName();
            if (!hostname.empty()) { server_names.push_back(hostname); }
        }

        break;

    case pcpp::LdapOperationType::BindResponse:
        ldap_res_pkt = this->_packet.getLayerOfType<pcpp::LdapBindResponseLayer>();
        if (ldap_res_pkt != nullptr) {
            hostname = static_cast<pcpp::LdapBindResponseLayer*>(ldap_res_pkt)->getMatchedDN();
            if (!hostname.empty()) { server_names.push_back(hostname); }
        }

        break;

    case pcpp::LdapOperationType::AddResponse:

        ldap_res_pkt = this->_packet.getLayerOfType<pcpp::LdapAddResponseLayer>();
        if (ldap_res_pkt != nullptr) {
            hostname = static_cast<pcpp::LdapAddResponseLayer*>(ldap_res_pkt)->getMatchedDN();
            if (!hostname.empty()) { server_names.push_back(hostname); }
        }

        break;

    case pcpp::LdapOperationType::SearchResultDone:

        ldap_res_pkt = this->_packet.getLayerOfType<pcpp::LdapSearchResultDoneLayer>();
        if (ldap_res_pkt != nullptr) {
            hostname = static_cast<pcpp::LdapSearchResultDoneLayer*>(ldap_res_pkt)->getMatchedDN();
            if (!hostname.empty()) { server_names.push_back(hostname); }
        }

        break;

    case pcpp::LdapOperationType::CompareResponse:

        ldap_res_pkt = this->_packet.getLayerOfType<pcpp::LdapCompareResponseLayer>();
        if (ldap_res_pkt != nullptr) {
            hostname = static_cast<pcpp::LdapCompareResponseLayer*>(ldap_res_pkt)->getMatchedDN();
            if (!hostname.empty()) { server_names.push_back(hostname); }
        }

        break;

    case pcpp::LdapOperationType::DeleteResponse:

        ldap_res_pkt = this->_packet.getLayerOfType<pcpp::LdapDeleteResponseLayer>();
        if (ldap_res_pkt != nullptr) {
            hostname = static_cast<pcpp::LdapDeleteResponseLayer*>(ldap_res_pkt)->getMatchedDN();
            if (!hostname.empty()) { server_names.push_back(hostname); }
        }

        break;

    case pcpp::LdapOperationType::ModifyDNResponse:

        ldap_res_pkt = this->_packet.getLayerOfType<pcpp::LdapModifyDNResponseLayer>();
        if (ldap_res_pkt != nullptr) {
            hostname = static_cast<pcpp::LdapModifyDNResponseLayer*>(ldap_res_pkt)->getMatchedDN();
            if (!hostname.empty()) { server_names.push_back(hostname); }
        }

        break;

    case pcpp::LdapOperationType::ModifyResponse:

        ldap_res_pkt = this->_packet.getLayerOfType<pcpp::LdapModifyResponseLayer>();
        if (ldap_res_pkt != nullptr) {
            hostname = static_cast<pcpp::LdapModifyResponseLayer*>(ldap_res_pkt)->getMatchedDN();
            if (!hostname.empty()) { server_names.push_back(hostname); }
        }

        break;
    default:
        break;
    }

    return server_names;
}

std::string LDAPParser::parse_type() { return "ldap"; }

std::string LDAPParser::parse_res_type() {
    std::string data;
    pcpp::LdapLayer* ldap_packet = nullptr;

    ldap_packet = this->_packet.getLayerOfType<pcpp::LdapLayer>();
    if (ldap_packet == nullptr) { return data; }
    data = ldap_packet->getLdapOperationType().toString();

    return data;
}

std::string LDAPParser::parse_data() { return ""; }
