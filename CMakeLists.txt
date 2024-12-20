cmake_minimum_required(VERSION 3.16)

project(ProtocolAnalyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(ProtocolAnalyzer main.cpp
    packetparser.h packetparser.cpp

    dhcpv4parser.h dhcpv4parser.cpp
    sslparser.h sslparser.cpp
    httpparser.h httpparser.cpp
    sipparser.h sipparser.cpp
    ldapparser.h ldapparser.cpp
    smtpparser.h smtpparser.cpp
    dnsparser.h dnsparser.cpp
    test_pcaps/dhcp_http_ssl.pcap test_pcaps/dns.pcap test_pcaps/sip.pcap test_pcaps/smtp.pcap

)

find_package(PcapPlusPlus REQUIRED)
target_link_libraries(ProtocolAnalyzer PUBLIC PcapPlusPlus::Pcap++)

include(GNUInstallDirs)
install(TARGETS ProtocolAnalyzer
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
