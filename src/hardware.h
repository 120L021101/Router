#ifndef HARDWARE_H
#define HARDWARE_H

#include "ipv4.h"

typedef unsigned char IPV4_address[4];
typedef unsigned char IPV4_mask[4];

// 构建接口与硬件地址的关系对
typedef struct
{
    unsigned char *name;
    Mac_address mac_address;
} Interface_address_pair;

// 接口地址查询表
#define MAX_INTERFACE_PAIR_NUM 100
typedef struct
{
    uint32_t current_num;
    Interface_address_pair entries[MAX_INTERFACE_PAIR_NUM];
} Interface_table;

void init_hardware_interfaces(const char **const interfaces, uint32_t interface_num);

Mac_address *get_interface_hardware_address(const char *name);

#define INIT_HARDWARE(interfaces, interface_num)             \
    do                                                       \
    {                                                        \
        init_hardware_interfaces(interfaces, interface_num); \
    } while (0)

// 通过接口名字得到接口的ipv4地址
void get_ipv4_by_interface(const char *const interface, IPV4_address ipv4_address, IPV4_mask ipv4_mask);

#endif