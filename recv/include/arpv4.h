// arp.h
#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include "ethernet.h"
#include "ipv4.h"
#include "err.h"

#define ARP_HARDWARE_TYPE_ETHERNET 1
#define ARP_PROTOCOL_TYPE_IP 0x0800
#define ARP_REQUEST 1
#define ARP_REPLY 2

typedef struct {
    uint16_t hardware_type;      // 硬件类型
    uint16_t protocol_type;      // 协议类型
    uint8_t hardware_addr_len;   // 硬件地址长度
    uint8_t protocol_addr_len;   // 协议地址长度
    uint16_t operation;           // 操作类型（请求或应答）
    uint8_t sender_hardware_addr[6];  // 发送方硬件地址
    uint32_t sender_protocol_addr;     // 发送方协议地址
    uint8_t target_hardware_addr[6];  // 目标硬件地址
    uint32_t target_protocol_addr;     // 目标协议地址
} Arp_header;

Arp_header *parse_arp_header(ethernet_frame *eth_frame);

// 如果记录有该arp，则填充
unsigned char fill_if_contains_arp(Ipv4_arp_table *ipv4_arp_table, Arp_header *arp_header);

size_t construct_arpv4_packet(Arp_header *arp_header, unsigned char *packet);

unsigned char is_arpv4_reply(Arp_header *arp_header);

Arp_header *request_ipv4_mac_addr(uint32_t sender_ipv4_addr, uint8_t *sender_mac_addr, uint32_t target_ipv4_addr);
#endif // ARP_H
