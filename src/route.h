#ifndef ROUTE_H
#define ROUTE_H

#include "ipv4.h"
#include "hardware.h"

typedef struct
{
    uint32_t route_type;
    unsigned char *route_address;
    uint32_t address_length;
    unsigned char *route_mask;
    const char *interface;
    uint32_t priority;
} Route_entry;

#define MAX_ROUTE_ENTRY 100

typedef struct
{
    uint32_t current_num;
    Route_entry entries[MAX_ROUTE_ENTRY];
} Route_table;

void init_route(const char *const interfaces, uint32_t interface_num);

#define INIT_ROUTE(interfaces, interface_num)  \
    do                                         \
    {                                          \
        init_route(interfaces, interface_num); \
    } while (0)

// 查找路由表项，返回接口名称
const char *lookup_route(unsigned char *address, uint32_t address_length, uint32_t protocol);

#endif
