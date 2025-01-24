#include "arp.h"
#include <string.h> // 用于 memcpy 或者类似操作

// 初始化arp_table
ARP_table arp_table;

// 创建新的ARP数据包
ARP_packet_data *new_ARP_packet()
{
    return (ARP_packet_data *)malloc(sizeof(ARP_packet_data));
}

// 释放ARP数据包
void release_ARP_packet(ARP_packet_data *arp_packet_data)
{
    free(arp_packet_data);
}

// 获取硬件地址
uint16_t get_hardware_address(ARP_packet_data *arp_packet_data)
{
    return arp_packet_data->hardware_address;
}

// 设置硬件地址
void set_hardware_address(ARP_packet_data *arp_packet_data, uint16_t hardware_address)
{
    arp_packet_data->hardware_address = hardware_address;
}

// 获取协议空间
uint16_t get_protocol_space(ARP_packet_data *arp_packet_data)
{
    return arp_packet_data->protocol_space;
}

// 设置协议空间
void set_protocol_space(ARP_packet_data *arp_packet_data, uint16_t protocol_space)
{
    arp_packet_data->protocol_space = protocol_space;
}

// 获取硬件地址字节长度
uint8_t get_byte_length_of_hardware_addr(ARP_packet_data *arp_packet_data)
{
    return arp_packet_data->byte_length_of_hardware_addr;
}

// 设置硬件地址字节长度
void set_byte_length_of_hardware_addr(ARP_packet_data *arp_packet_data, uint8_t length)
{
    arp_packet_data->byte_length_of_hardware_addr = length;
}

// 获取协议地址字节长度
uint8_t get_byte_length_of_protocol_addr(ARP_packet_data *arp_packet_data)
{
    return arp_packet_data->byte_length_of_protocol_addr;
}

// 设置协议地址字节长度
void set_byte_length_of_protocol_addr(ARP_packet_data *arp_packet_data, uint8_t length)
{
    arp_packet_data->byte_length_of_protocol_addr = length;
}

// 获取操作码
uint16_t get_opcode(ARP_packet_data *arp_packet_data)
{
    return arp_packet_data->opcode;
}

// 设置操作码
void set_opcode(ARP_packet_data *arp_packet_data, uint16_t opcode)
{
    arp_packet_data->opcode = opcode;
}

// 获取发送方硬件地址
uint64_t get_sender_hardware_address(ARP_packet_data *arp_packet_data)
{
    return arp_packet_data->sender_hardware_address;
}

// 设置发送方硬件地址
void set_sender_hardware_address(ARP_packet_data *arp_packet_data, uint64_t address)
{
    arp_packet_data->sender_hardware_address = address;
}

// 获取发送方协议地址
unsigned char *get_sender_protocol_address(ARP_packet_data *arp_packet_data)
{
    return arp_packet_data->sender_protocol_address;
}

// 设置发送方协议地址
void set_sender_protocol_address(ARP_packet_data *arp_packet_data, unsigned char *address)
{
    for (int i = 0; i < arp_packet_data->byte_length_of_protocol_addr; ++i)
    {
        arp_packet_data->sender_protocol_address[i] = address[i];
    }
}

// 获取目标方硬件地址
uint64_t get_target_hardware_address(ARP_packet_data *arp_packet_data)
{
    return arp_packet_data->target_hardware_address;
}

// 设置目标方硬件地址
void set_target_hardware_address(ARP_packet_data *arp_packet_data, uint64_t address)
{
    arp_packet_data->target_hardware_address = address;
}

// 获取目标方协议地址
unsigned char *get_target_protocol_address(ARP_packet_data *arp_packet_data)
{
    return arp_packet_data->target_protocol_address;
}

// 设置目标方协议地址
void set_target_protocol_address(ARP_packet_data *arp_packet_data, unsigned char *address)
{
    for (int i = 0; i < arp_packet_data->byte_length_of_protocol_addr; ++i)
    {
        arp_packet_data->target_protocol_address[i] = address[i];
    }
}

uint64_t lookup_hardware_address_by_arp(uint32_t protocol_type, unsigned char *protocol_address, uint32_t address_length)
{
    for (int i = 0; i < arp_table.current_num; ++i)
    {
        // 协议号不对
        if (arp_table.table_entries[i].protocol_type != protocol_type)
            continue;

        // 判断协议地址是否完全一样
        int j;
        for (j = 0; j < address_length; ++i)
            if (arp_table.table_entries[i].protocol_address[j] != protocol_address[j])
                break;

        if (j == address_length)
            return arp_table.table_entries[i].hardware_address;
    }

    // 没有找到，发送ARP REQUEST

    return 0;
}
