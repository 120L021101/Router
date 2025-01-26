#include "ethernet.h"
#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <stdlib.h>

#define ARP_OPCODE_REQEUST 1
#define ARP_OPCODE_REPLY 2

#define HARDWARE_TYPE 1 // ethernet

// ARP数据包结构体定义
typedef struct
{
    uint16_t hardware_type;
    uint16_t protocol_space;
    uint8_t byte_length_of_hardware_addr;
    uint8_t byte_length_of_protocol_addr;
    uint16_t opcode;

    Mac_address sender_hardware_address;    // MAC地址
    unsigned char *sender_protocol_address; // 协议地址，由于IPV6可能大于64bit，所以设置成字符数组形式

    Mac_address target_hardware_address;    // MAC地址
    unsigned char *target_protocol_address; // 协议地址
} ARP_packet_data;

// 创建和释放ARP数据包
ARP_packet_data *new_ARP_packet();
void release_ARP_packet(ARP_packet_data *arp_packet_data);

// ARP表项结构体定义
typedef struct
{
    uint32_t protocol_type;
    unsigned char *protocol_address;
    uint32_t address_length;
    Mac_address hardware_address;
} ARP_table_entry;

#define MAX_ARP_ENTRY_NUM 100

// ARP表结构体定义
typedef struct
{
    uint32_t current_num;
    ARP_table_entry table_entries[MAX_ARP_ENTRY_NUM];
} ARP_table;

Mac_address *lookup_hardware_address_by_arp(uint32_t protocol_type, unsigned char *protocol_address, uint32_t address_length);

ARP_packet_data *parse_arp_data(unsigned char *, size_t);
void arp_handler(unsigned char *data, size_t);

#define REGISTER_ARP                                                     \
    do                                                                   \
    {                                                                    \
        register_frame_handler(ETHERNET_UPPER_PRTOCOL_ARP, arp_handler); \
    } while (0)

#endif
