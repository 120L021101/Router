#ifndef HARDWARE_H
#define HARDWARE_H

#include "ethernet.h"

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

void init_hardware_interfaces();

Mac_address *get_interface_hardware_address(const char *name);

#define INIT_HARDWARE               \
    do                              \
    {                               \
        init_hardware_interfaces(); \
    } while (0)

#endif