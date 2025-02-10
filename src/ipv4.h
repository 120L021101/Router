#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "ethernet.h"
#include "arp.h"

#define IPV4_UPPER_PROTOCOL_ICMP 1
#define IPV4_UPPER_PROTOCOL_TCP 6
#define IPV4_UPPER_PROTOCOL_UDP 17
#define IPV4_UPPER_PROTOCOL_OSPF 89

typedef unsigned char IPV4_address[4];
typedef unsigned char IPV4_mask[4];

typedef struct
{
    uint8_t version_ihl;    // 4 位版本 + 4 位头部长度 (Version | IHL)
    uint8_t tos;            // 类型服务 (Type of Service)
    uint16_t total_length;  // 总长度 (Total Length)
    uint16_t id;            // 标识符 (Identification)
    uint16_t flags_offset;  // 标志 (Flags) + 片偏移 (Fragment Offset)
    uint8_t ttl;            // 生存时间 (Time to Live)
    uint8_t protocol;       // 协议 (Protocol)
    uint16_t checksum;      // 头部校验和 (Header Checksum)
    IPV4_address src_addr;  // 源地址 (Source Address)
    IPV4_address dest_addr; // 目标地址 (Destination Address)
    // 可选部分
    uint8_t options[0]; // 选项 (Options), 可选部分

    unsigned char *data;
    size_t data_length;
} Ipv4_packet;

char is_ipv4_addr_equal(IPV4_address addr1, IPV4_address addr2);

char is_ipv4_addr_mask_equal(IPV4_address addr1, IPV4_address addr, IPV4_mask mask);

char is_broadcast_ipv4(IPV4_address addr, IPV4_mask mask);

char is_the_same_subnet_ipv4(IPV4_address addr1, IPV4_address addr2, IPV4_mask mask);

void ipv4_handler(unsigned char *data, size_t, const char *const, Mac_address);

void send_ipv4_packet(unsigned char *data, size_t data_length, IPV4_address src_addr, IPV4_address dst_addr);

#define REGISTER_IPV4                                                      \
    do                                                                     \
    {                                                                      \
        register_frame_handler(ETHERNET_UPPER_PRTOCOL_IPV4, ipv4_handler); \
    } while (0)

// IPV4报文的处理函数
typedef struct
{
    uint16_t protocol_type;
    void (*handler)(unsigned char *, size_t, Ipv4_packet *);
} Ipv4_handler;

#define IPV4_HANDLER_MAX_ENTRY 100
typedef struct
{
    uint32_t current_num;
    Ipv4_handler entries[IPV4_HANDLER_MAX_ENTRY];
} Ipv4_handler_table;

void register_ipv4_packet_handler(uint16_t protocol_type, void (*handler)(unsigned char *, size_t, Ipv4_packet *));

#endif