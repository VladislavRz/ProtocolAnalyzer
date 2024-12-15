#include "packetparser.h"


PacketParser::PacketParser(pcpp::Packet& packet):_packet(packet) {}

void PacketParser::parse() {

    std::string delimeter = DELIMETER;
    std::string hostname = HNAME;
    std::string domain_name = parse_domain_name();

    if (domain_name.empty()) { return; }

    long datetime = parse_datetime();
    std::string src_ip = parse_src_ip();
    std::string dst_ip = parse_dst_ip();
    std::string type = parse_type();
    std::string res_type = parse_res_type();
    std::string data = parse_data();
    int data_len = data.empty() ? domain_name.length() : data.length();
    print_result(hostname, datetime, src_ip, dst_ip, type, domain_name, res_type, data_len, data, delimeter);
}

long PacketParser::parse_datetime() {

    return this->_packet.getRawPacket()->getPacketTimeStamp().tv_sec;
}

std::string PacketParser::parse_src_ip() {

    std::string src_ip;

    if (this->_packet.isPacketOfType(pcpp::IPv4)) {

        src_ip = this->_packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address().toString();

    } else if (this->_packet.isPacketOfType(pcpp::IPv6)) {

        src_ip = this->_packet.getLayerOfType<pcpp::IPv6Layer>()->getSrcIPv6Address().toString();

    } else {

        std::cerr << "Не удалось получить IP адреса отправителя. Вероятно, пакет не является IP пакетом." << std::endl;

    }

    return src_ip;
}

std::string PacketParser::parse_dst_ip() {

    std::string dst_ip;

    if (this->_packet.isPacketOfType(pcpp::IPv4)) {

        dst_ip = this->_packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address().toString();

    } else if (this->_packet.isPacketOfType(pcpp::IPv6)) {

        dst_ip = this->_packet.getLayerOfType<pcpp::IPv6Layer>()->getDstIPv6Address().toString();

    } else {

        std::cerr << "Не удалось получить IP адрес получателя. Вероятно, пакет не является IP пакетом." << std::endl;

    }

    return dst_ip;
}

void PacketParser::print_result(std::string& hostname, long& datetime, std::string& src_ip,
                                std::string& dst_ip, std::string& type, std::string& domain_name,
                                std::string& res_type, int& data_len, std::string& data, std::string& delimeter) const {

    std::cout << hostname << delimeter
              << datetime << delimeter
              << src_ip << delimeter
              << dst_ip << delimeter
              << type << delimeter
              << domain_name << delimeter
              << res_type << delimeter
              << data_len << delimeter
              << data << std::endl;
}
