#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>

#if defined(_MSC_VER)
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
// no deprecated warning
#pragma warning(disable : 4996)
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#endif

typedef uint32_t ipv4_addr_t;

typedef struct {
  uint8_t addr[6];
} mac_addr_t;

/// Ethernet header, 14 octets.
typedef struct {
  /// Destination MAC address
  mac_addr_t dst_mac;
  /// Source MAC address
  mac_addr_t src_mac;
  /// Ether type or length
  uint16_t ether_type;
} ethernet_header_t;

/// ARP header, 28 octets.
#if defined(_MSC_VER)
#pragma pack(push, 1)
#endif
typedef struct {
  /// Hardware type
  uint16_t hardware_type;
  /// Protocol type
  uint16_t protocol_type;
  /// Langth of MAC address
  uint8_t mac_addr_len;
  /// Length of IP address
  uint8_t ip_addr_len;
  /// Operation
  uint16_t operation;
  /// Sender MAC address
  mac_addr_t sender_mac;
  /// Sender IP address
  ipv4_addr_t sender_ip;
  /// Target MAC address
  mac_addr_t target_mac;
  /// Target IP address
  ipv4_addr_t target_ip;
}
#if defined(__GNUC__) || defined(__clang__)
__attribute__((packed))
#endif
arp_packet_t;

void send_arp_request(
  pcap_t* handle,
  const ipv4_addr_t src_ip,
  const mac_addr_t* src_mac,
  const ipv4_addr_t dst_ip
) {
  // uint8_t packet[sizeof(ethernet_header_t) + sizeof(arp_packet_t)];
  uint8_t packet[sizeof(ethernet_header_t) + sizeof(arp_packet_t)];

  ethernet_header_t* ethernet_header = (ethernet_header_t*)packet;
  arp_packet_t* arp_packet =
    (arp_packet_t*)(packet + sizeof(ethernet_header_t));

  // fill ethernet header
  memcpy(ethernet_header->dst_mac.addr, "\xff\xff\xff\xff\xff\xff", 6);
  memcpy(ethernet_header->src_mac.addr, src_mac->addr, 6);
  ethernet_header->ether_type = htons(0x0806);

  // fill arp header
  // this is ethernet
  arp_packet->hardware_type = htons(0x0001);
  // this is ipv4
  arp_packet->protocol_type = htons(0x0800);
  arp_packet->mac_addr_len = 6;
  arp_packet->ip_addr_len = 4;
  // this is arp request
  arp_packet->operation = htons(0x0001);
  memcpy(arp_packet->sender_mac.addr, src_mac->addr, 6);
  arp_packet->sender_ip = src_ip;
  memcpy(arp_packet->target_mac.addr, "\x00\x00\x00\x00\x00\x00", 6);
  arp_packet->target_ip = dst_ip;

  // send packet
  if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
    fprintf(stderr, "error in pcap_sendpacket: %s\n", pcap_geterr(handle));
  }

  printf("sent arp request\n");

  return;
}

void listen_arp(pcap_t* handle, ipv4_addr_t expected_ip, mac_addr_t* mac) {
  while (true) {
    struct pcap_pkthdr* header;
    const uint8_t* packet;
    int result = pcap_next_ex(handle, &header, &packet);

    if (result == -1) {
      fprintf(stderr, "error in pcap_next_ex: %s\n", pcap_geterr(handle));
      return;
    }

    if (header->caplen == 0) {
      continue;
    }

    ethernet_header_t* ethernet_header = (ethernet_header_t*)packet;
    arp_packet_t* arp_packet =
      (arp_packet_t*)(packet + sizeof(ethernet_header_t));

    if (
      // thernet frame type is arp
      ntohs(ethernet_header->ether_type) == 0x0806 &&
      // arp operation is reply
      ntohs(arp_packet->operation) == 0x0002 &&
      // target ip is expected ip
      arp_packet->sender_ip == expected_ip
    ) {
      printf("received arp reply\n");
      memcpy(mac->addr, arp_packet->sender_mac.addr, 6);

      // show info
      printf("sender mac: ");
      for (size_t i = 0; i < 6; i++) {
        printf("%02x", mac->addr[i]);
        if (i != 5) {
          printf(":");
        }
      }
      printf("\n");

      // sender ip
      uint8_t a = arp_packet->sender_ip & 0xff;
      uint8_t b = (arp_packet->sender_ip >> 8) & 0xff;
      uint8_t c = (arp_packet->sender_ip >> 16) & 0xff;
      uint8_t d = (arp_packet->sender_ip >> 24) & 0xff;

      printf("sender ip: %u.%u.%u.%u\n", a, b, c, d);

      return;
    }
  }
}

int get_host_mac(pcap_if_t* device, ipv4_addr_t ip, mac_addr_t* mac) {
#if defined(_MSC_VER)
  // get mac address
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_create(device->name, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "error in pcap_create: %s\n", errbuf);
    return 1;
  }

  pcap_set_promisc(handle, 1);
  pcap_set_snaplen(handle, 65535);
  pcap_set_timeout(handle, 1000);

  if (pcap_activate(handle) != 0) {
    fprintf(stderr, "error in pcap_activate: %s\n", pcap_geterr(handle));
    return 1;
  }

  // the pseudo source mac address
  mac_addr_t pseudo_src_mac;
  // 10.10.10.10
  // just a random ip address
  ipv4_addr_t pseudo_src_ipv4_addr = 0x0a0a0a0a;
  // set mac to be f0:f0:f0:f0:f0:f0
  memset(&pseudo_src_mac, 0xf0, sizeof(pseudo_src_mac));
  // send arp request
  send_arp_request(handle, pseudo_src_ipv4_addr, &pseudo_src_mac, ip);
  // listen arp reply
  listen_arp(handle, ip, mac);

  pcap_close(handle);
  return 0;
#else
  struct ifaddrs* ifaddrs;
  if (getifaddrs(&ifaddrs) == -1) {
    fprintf(stderr, "error in getifaddrs\n");
    return 1;
  }

  // compare name
  for (struct ifaddrs* ifaddr = ifaddrs; ifaddr != NULL;
       ifaddr = ifaddr->ifa_next) {
    if (strcmp(ifaddr->ifa_name, device->name) == 0) {
      // compare family
      if (ifaddr->ifa_addr->sa_family == AF_LINK) {
        struct sockaddr_dl* sockaddr_dl = (struct sockaddr_dl*)ifaddr->ifa_addr;
        memcpy(mac->addr, LLADDR(sockaddr_dl), 6);
        freeifaddrs(ifaddrs);
        return 0;
      }
    }
  }

  freeifaddrs(ifaddrs);
  fprintf(stderr, "cannot find mac address\n");
  return 1;
#endif
}

int main() {
  printf("sizeof(ethernet_header_t) = %zu\n", sizeof(ethernet_header_t));
  printf("sizeof(arp_packet_t) = %zu\n", sizeof(arp_packet_t));

  assert(sizeof(ethernet_header_t) == 14);
  assert(sizeof(arp_packet_t) == 28);

  pcap_if_t* alldevs;

  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    return 1;
  }

  size_t device_count = 1;
  for (pcap_if_t* device = alldevs; device != NULL; device = device->next) {
    printf("%3zu %20s %s\n", device_count, device->name, device->description);
    device_count++;
  }

  printf("total: %zu devices\n", device_count - 1);

  // choose one device to capture
  size_t device_number;
  printf("enter device number: ");
  scanf("%zu", &device_number);

  if (device_number >= device_count) {
    fprintf(stderr, "invalid device number\n");
    return 1;
  }

  // get device
  pcap_if_t* device = alldevs;
  for (size_t i = 0; i < device_number - 1; i++) {
    device = device->next;
  }

  pcap_addr_t* address;

  // get the first ipv4 address
  for (address = device->addresses;
       address != NULL && address->addr->sa_family != AF_INET;
       address = address->next)
    ;

  printf("selected device: %s\n", device->name);

  ipv4_addr_t host_ip = ((struct sockaddr_in*)address->addr)->sin_addr.s_addr;

  printf(
    "host ip: %u.%u.%u.%u\n", (host_ip >> 0) & 0xff, (host_ip >> 8) & 0xff,
    (host_ip >> 16) & 0xff, (host_ip >> 24) & 0xff
  );

  // get host mac address
  mac_addr_t host_mac;
  if (get_host_mac(device, host_ip, &host_mac) != 0) {
    return 1;
  }

  printf("host mac: ");
  for (size_t i = 0; i < 6; i++) {
    printf("%02x", host_mac.addr[i]);
    if (i != 5) {
      printf(":");
    }
  }
  printf("\n");

  // Now we have the mac address of the host. We can use it to send arp request
  // to the target.

  char target_ip_str[16];
  ipv4_addr_t target_ip;
  printf("enter target ip: ");
  scanf("%s", target_ip_str);
  if (inet_pton(AF_INET, target_ip_str, &target_ip) != 1) {
    fprintf(stderr, "invalid ip address\n");
    return 1;
  }

  printf(
    "target ip: %u.%u.%u.%u\n", (target_ip >> 0) & 0xff,
    (target_ip >> 8) & 0xff, (target_ip >> 16) & 0xff, (target_ip >> 24) & 0xff
  );

  // open handle
  pcap_t* handle = pcap_create(device->name, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "error in pcap_create: %s\n", errbuf);
    return 1;
  }

  pcap_set_promisc(handle, 1);
  pcap_set_snaplen(handle, 65535);
  pcap_set_timeout(handle, 1000);

  if (pcap_activate(handle) != 0) {
    fprintf(stderr, "error in pcap_activate: %s\n", pcap_geterr(handle));
    return 1;
  }

  // get target mac address
  mac_addr_t target_mac;
  send_arp_request(handle, host_ip, &host_mac, target_ip);
  listen_arp(handle, target_ip, &target_mac);
  // show info
  printf("target mac: ");
  for (size_t i = 0; i < 6; i++) {
    printf("%02x", target_mac.addr[i]);
    if (i != 5) {
      printf(":");
    }
  }
  printf("\n");

  pcap_close(handle);
  pcap_freealldevs(alldevs);

  return 0;
}