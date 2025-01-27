#ifndef SRC_ETHERNET_H
#define SRC_ETHERNET_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>

typedef unsigned char Mac_address[6];

#include "util.h"
#include "hardware.h"

#define ETHERNET_UPPER_PRTOCOL_IPV4 0x0800
#define ETHERNET_UPPER_PRTOCOL_ARP 0x0806
#define ETHERNET_UPPER_PRTOCOL_IPV6 0x86DD

typedef struct
{
    Mac_address dst_address;
    Mac_address src_address;
    uint16_t protocol;

    unsigned char *data;
    size_t data_length;

} Ethernet_packet;

// 以太网帧的处理函数
typedef struct
{
    uint16_t protocol_type;
    void (*handler)(unsigned char *, size_t, const char *const, Mac_address);
} Ethernet_handler;

#define ETHERNET_HANDLER_MAX_ENTRY 100
typedef struct
{
    uint32_t current_num;
    Ethernet_handler entries[ETHERNET_HANDLER_MAX_ENTRY];
} Ethernet_handler_table;

void broadcast_ethernet(const unsigned char *const data, size_t data_size, uint16_t protocol_type, const char *const ingoing_interface);

void send_via_ethernet(const char *const interface, const Mac_address *const dst_addr,
                       const unsigned char *const data, size_t data_size, uint16_t protocol_type);

void register_frame_handler(uint16_t protocol_type, void (*handler)(unsigned char *, size_t, const char *const, Mac_address));

void listen_interfaces(const char **const interfaces, uint32_t interface_num);

#endif