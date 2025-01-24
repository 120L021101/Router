#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <stdlib.h>

#define ARP_OPCODE_REQEUST 1
#define ARP_OPCODE_REPLY 2

// ARP数据包结构体定义
typedef struct
{
    uint16_t hardware_address;
    uint16_t protocol_space;
    uint8_t byte_length_of_hardware_addr;
    uint8_t byte_length_of_protocol_addr;
    uint16_t opcode;

    uint64_t sender_hardware_address;       // MAC地址
    unsigned char *sender_protocol_address; // 协议地址，由于IPV6可能大于64bit，所以设置成字符数组形式

    uint64_t target_hardware_address;       // MAC地址
    unsigned char *target_protocol_address; // 协议地址
} ARP_packet_data;

// 创建和释放ARP数据包
ARP_packet_data *new_ARP_packet();
void release_ARP_packet(ARP_packet_data *arp_packet_data);

// 获取和设置函数声明
uint16_t get_hardware_address(ARP_packet_data *arp_packet_data);
void set_hardware_address(ARP_packet_data *arp_packet_data, uint16_t hardware_address);

uint16_t get_protocol_space(ARP_packet_data *arp_packet_data);
void set_protocol_space(ARP_packet_data *arp_packet_data, uint16_t protocol_space);

uint8_t get_byte_length_of_hardware_addr(ARP_packet_data *arp_packet_data);
void set_byte_length_of_hardware_addr(ARP_packet_data *arp_packet_data, uint8_t length);

uint8_t get_byte_length_of_protocol_addr(ARP_packet_data *arp_packet_data);
void set_byte_length_of_protocol_addr(ARP_packet_data *arp_packet_data, uint8_t length);

uint16_t get_opcode(ARP_packet_data *arp_packet_data);
void set_opcode(ARP_packet_data *arp_packet_data, uint16_t opcode);

uint64_t get_sender_hardware_address(ARP_packet_data *arp_packet_data);
void set_sender_hardware_address(ARP_packet_data *arp_packet_data, uint64_t address);

unsigned char *get_sender_protocol_address(ARP_packet_data *arp_packet_data);
void set_sender_protocol_address(ARP_packet_data *arp_packet_data, unsigned char *address);

uint64_t get_target_hardware_address(ARP_packet_data *arp_packet_data);
void set_target_hardware_address(ARP_packet_data *arp_packet_data, uint64_t address);

unsigned char *get_target_protocol_address(ARP_packet_data *arp_packet_data);
void set_target_protocol_address(ARP_packet_data *arp_packet_data, unsigned char *address);

// ARP表项结构体定义
typedef struct
{
    uint32_t protocol_type;
    unsigned char *protocol_address;
    uint32_t address_length;
    uint64_t hardware_address;
} ARP_table_entry;

#define MAX_ARP_ENTRY_NUM 100

// ARP表结构体定义
typedef struct
{
    uint32_t current_num;
    ARP_table_entry table_entries[MAX_ARP_ENTRY_NUM];
} ARP_table;

uint64_t lookup_hardware_address_by_arp(uint32_t protocol_type, unsigned char *protocol_address, uint32_t address_length);

#endif
