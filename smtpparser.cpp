#include "smtpparser.h"

SMTPParser::SMTPParser(pcpp::Packet& packet):PacketParser(packet) {}

std::string SMTPParser::parse_domain_name() {
    std::string server_name;
    std::string host;
    pcpp::SmtpResponseLayer::SmtpStatusCode status;
    pcpp::SmtpResponseLayer* smtp_packet = nullptr;

    smtp_packet = this->_packet.getLayerOfType<pcpp::SmtpResponseLayer>();
    if (!smtp_packet) { return server_name; }

    status = smtp_packet->getStatusCode();

    if ((status == pcpp::SmtpResponseLayer::SmtpStatusCode::SERVICE_READY) ||
        (status == pcpp::SmtpResponseLayer::SmtpStatusCode::SERVICE_CLOSE)) {

        host = smtp_packet->getStatusOption();
        server_name = this->split_domain(host);
    }

    return server_name;
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
