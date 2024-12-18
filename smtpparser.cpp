#include "smtpparser.h"

SMTPParser::SMTPParser(pcpp::Packet& packet):PacketParser(packet) {}

std::vector<std::string> SMTPParser::parse_domain_name() {
    std::vector<std::string> server_names;
    std::string host;
    pcpp::SmtpResponseLayer::SmtpStatusCode status;
    pcpp::SmtpResponseLayer* smtp_packet = nullptr;

    smtp_packet = this->_packet.getLayerOfType<pcpp::SmtpResponseLayer>();
    if (!smtp_packet) { return server_names; }

    status = smtp_packet->getStatusCode();

    if ((status == pcpp::SmtpResponseLayer::SmtpStatusCode::SERVICE_READY) ||
        (status == pcpp::SmtpResponseLayer::SmtpStatusCode::SERVICE_CLOSE)) {

        host = smtp_packet->getStatusOption();
        host = this->split_domain(host);
        if (!host.empty()) { server_names.push_back(host); }
    }

    return server_names;
}

std::string SMTPParser::parse_type() { return "smtp_response"; }

std::string SMTPParser::parse_res_type() {
    std::string res_type;
    pcpp::SmtpResponseLayer::SmtpStatusCode status;
    pcpp::SmtpResponseLayer* smtp_packet = nullptr;

    smtp_packet = this->_packet.getLayerOfType<pcpp::SmtpResponseLayer>();
    if (!smtp_packet) { return res_type; }

    status = smtp_packet->getStatusCode();

    if (status == pcpp::SmtpResponseLayer::SmtpStatusCode::SERVICE_READY) {
        res_type = "smtp_service_ready_code";
    } else if (status == pcpp::SmtpResponseLayer::SmtpStatusCode::SERVICE_CLOSE) {
        res_type = "smtp_service_close_code";
    }

    return res_type;
}

std::string SMTPParser::parse_data() { return ""; }

std::string SMTPParser::split_domain(std::string& hostname) {
    std::string result;
    char splitter = ' ';
    int index = hostname.find(splitter);

    if (index != std::string::npos) {
        result = hostname.substr(0, index);
    }

    return result;
}
