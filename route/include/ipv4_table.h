// ipv4_table.h
#ifndef IPV4_TABLE_H
#define IPV4_TABLE_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_INTERFACES 10

typedef struct _IPv4RouteEntry{
    uint32_t destination;    // 目的网络地址（IPv4）
    uint32_t subnet_mask;    // 子网掩码
    uint32_t next_hop;       // 下一跳地址
    char *outgoing_interface; // 出接口
    int metric;              // 路由度量
    char *route_type;        // 路由类型
} IPv4RouteEntry;

typedef struct _IPv4RoutingTable{
    IPv4RouteEntry entries[MAX_INTERFACES]; // 存储的路由条目
    int count;                          // 当前路由条目的数量
} IPv4RoutingTable;

IPv4RoutingTable *create_ipv4_routing_table();

int add_route(IPv4RoutingTable *table, uint32_t destination, uint32_t subnet_mask, uint32_t next_hop, 
                const char *interface, int metric, const char *type);

IPv4RouteEntry *lookup_route(IPv4RoutingTable *table, uint32_t destination);

int delete_route(IPv4RoutingTable *table, uint32_t destination);

void show_ipv4_route_table(IPv4RoutingTable *table);

#endif // IPV4_TABLE_H
