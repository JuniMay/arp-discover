cmake_minimum_required(VERSION 3.10)
project(arp_discover C)

set(CMAKE_C_STANDARD 11)

if(WIN32)
    # npcap sdk at Documents/npcap-sdk
    include_directories("C:/Users/$(USERNAME)/Documents/npcap-sdk/Include")
    link_directories("C:/Users/$(USERNAME)/Documents/npcap-sdk/Lib/ARM64")
    set(PCAP_LIBRARY wpcap wsock32 ws2_32)
else()
    find_library(PCAP_LIBRARY pcap)
endif()

add_executable(arp_discover src/main.c)
target_link_libraries(arp_discover ${PCAP_LIBRARY})
