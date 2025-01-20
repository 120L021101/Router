#include "ipv4_table.h"

int add_route(IPv4RoutingTable *table, uint32_t destination, uint32_t subnet_mask, uint32_t next_hop, const char *interface, int metric, const char *type) {
    if (table->count >= MAX_INTERFACES) {
        return -1; // 路由表已满
    }

    IPv4RouteEntry *entry = &table->entries[table->count++];
    entry->destination = destination;
    entry->subnet_mask = subnet_mask;
    entry->next_hop = next_hop;
    entry->outgoing_interface = strdup(interface); // 复制字符串
    entry->metric = metric;
    entry->route_type = strdup(type); // 复制字符串

    return 0; // 成功
}

IPv4RouteEntry *lookup_route(IPv4RoutingTable *table, uint32_t destination) {
    destination = ((destination & 0xFF) << 24) 
                 |((destination & 0xFF00) << 8) 
                 |((destination & 0xFF0000) >> 8) 
                 |((destination & 0xFF000000) >> 24)
    ;
    fprintf(stdout, "[ROUTE LOOKUP] looking for: ");
    fprintf(stdout, "%d.%d.%d.%d\n", 
                    (destination >> 24) & 0xFF,
                    (destination >> 16) & 0xFF,
                    (destination >> 8) & 0xFF,
                    (destination) & 0xFF
    );
    for (int i = 0; i < table->count; i++) {
        if ((destination & table->entries[i].subnet_mask) == (table->entries[i].destination & table->entries[i].subnet_mask)) {
            return &table->entries[i]; // 找到匹配的路由条目
        }
    }
    return NULL; // 没有找到匹配的路由
}

int delete_route(IPv4RoutingTable *table, uint32_t destination) {
    for (int i = 0; i < table->count; i++) {
        if (table->entries[i].destination == destination) {
            // 删除该条目，后续条目上移
            for (int j = i; j < table->count - 1; j++) {
                table->entries[j] = table->entries[j + 1];
            }
            table->count--;
            return 0; // 成功
        }
    }
    return -1; // 未找到该条目
}


IPv4RoutingTable *create_ipv4_routing_table() {
    IPv4RoutingTable *ipv4RoutingTable = (IPv4RoutingTable *)malloc(sizeof(IPv4RoutingTable));
    // add_route(ipv4RoutingTable,
    //           0, 0, (192 << 24) | (168 << 16) | (2 << 8) | (2), "veth3", 1, "default");
    ipv4RoutingTable->count = 0;
    fprintf(stdout, "create ipv4 routing table successfully\n");
    return ipv4RoutingTable;
}

void show_ipv4_route_table(IPv4RoutingTable *table) {
    for (int i = 0; i < table->count; ++i) {
        uint32_t destination = table->entries[i].destination;    
        uint32_t subnet_mask = table->entries[i].subnet_mask;    
        uint32_t next_hop = table->entries[i].next_hop;       
        char *outgoing_interface = table->entries[i].outgoing_interface;
        int metric = table->entries[i].metric;              
        char *route_type = table->entries[i].route_type;
        fprintf(stdout, "[ROUTING ITEM]: %d.%d.%d.%d\t", (destination >> 24) & 0xFF, 
                                                (destination >> 16) & 0xFF, 
                                                (destination >> 8) & 0xFF, 
                                                (destination) & 0xFF); 
        fprintf(stdout, "%d.%d.%d.%d\t", (subnet_mask >> 24) & 0xFF, 
                                (subnet_mask >> 16) & 0xFF, 
                                (subnet_mask >> 8) & 0xFF, 
                                (subnet_mask) & 0xFF); 
        
        fprintf(stdout, "%d.%d.%d.%d\t", (next_hop >> 24) & 0xFF, 
                                (next_hop >> 16) & 0xFF, 
                                (next_hop >> 8) & 0xFF, 
                                (next_hop) & 0xFF); 
        fprintf(stdout, "%s\t", outgoing_interface);
        fprintf(stdout, "%d\t", metric);
        fprintf(stdout, "%s\n", route_type);
    }
    return;
}