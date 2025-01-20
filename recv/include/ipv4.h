// ipv4.h
#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <ifaddrs.h>
#include "ethernet.h"
#include "pkg_sender.h"
#include "pkg_rcver.h"

typedef struct _ipv4_header {
    uint8_t ihl : 4;               // 头部长度
    uint8_t version : 4;           // 版本
    uint8_t tos;                    // 类型服务
    uint16_t total_length;          // 总长度
    uint16_t identification;        // 标识
    uint16_t flags_offset;          // 标志和片偏移
    uint8_t ttl;                    // 生存时间
    uint8_t protocol;               // 协议
    uint16_t checksum;              // 头部校验和
    uint32_t src_addr;              // 源 IP 地址
    uint32_t dest_addr;             // 目的 IP 地址
} ipv4_header;

ipv4_header *parse_ipv4_frame(const ethernet_frame* const eth_frame);

typedef struct {
    uint32_t dest_ip_addr;
    unsigned char dest_mac_addr[6];
} Ipv4_arp_entry;

#define MAX_ARP_ENTRIES 1000

typedef struct {
    Ipv4_arp_entry *entries[MAX_ARP_ENTRIES];
    size_t count;
} Ipv4_arp_table;

void add_ipv4_arp_entry(Ipv4_arp_table *ipv4_arp_table, uint32_t dest_ip_addr, unsigned char *dest_mac_addr);

// 根据协议地址查找mac地址，若无，返回NULL
unsigned char *find_ipv4_mac_byarp(Ipv4_arp_table *ipv4_arp_table, uint32_t dest_ip_addr); 

Ipv4_arp_table *create_ipv4_arp_table(Pkg_sender *pkgsender);

void show_ipv4_arp_table(Ipv4_arp_table *ipv4_arp_table);

unsigned char if_ipv4_send_to_myself(Pkg_receiver *pkg_receiver, uint32_t dest_ipv4_addr);

size_t construct_ipv4_hdr(unsigned char *ipv4_packet, ipv4_header *input_hdr);

#endif // IPV4_H
