#include "route.h"

#define ROUTE_LOG_PREFIX "[ROUTE:] "

Route_table route_table;

extern Interface_table interface_table;

static void show_table()
{
    printf(ROUTE_LOG_PREFIX "===========================ROUTE TABLE ENTRIES============================\n");

    for (int i = 0; i < route_table.current_num; ++i)
    {
        Route_entry *entry = &route_table.entries[i];
        printf(ROUTE_LOG_PREFIX "%d\t%d\t%2X\t", i, entry->priority, entry->route_type);
        for (int j = 0; j < entry->address_length; ++j)
        {
            printf("%d.", entry->route_address[j]);
        }
        printf("\t");
        for (int j = 0; j < entry->address_length; ++j)
        {
            printf("%d.", entry->route_mask[j]);
        }
        printf("\t");
        printf("%s\n", entry->interface);
    }

    printf(ROUTE_LOG_PREFIX "==========================================================================\n");
}

const char *lookup_route(unsigned char *address, uint32_t address_length, uint32_t protocol)
{
    for (int i = 0; i < route_table.current_num; ++i)
    {
        Route_entry *entry = &route_table.entries[i];
        if (entry->route_type != protocol)
            continue;
        if (entry->address_length != address_length)
            continue;

        if (protocol == ETHERNET_UPPER_PRTOCOL_IPV4)
        {
            // mask
            unsigned char mask_address[4];
            int j;
            for (j = 0; j < sizeof(IPV4_address); ++j)
            {
                mask_address[j] = address[j] & entry->route_mask[j];
                if (mask_address[j] != entry->route_address[j])
                    break;
            }
            if (j == sizeof(IPV4_address))
            {
                return entry->interface;
            }
        }
    }
    return NULL;
}

void init_route(const char *const interfaces, uint32_t interface_num)
{
    route_table.current_num = 0;
    // 为每个ipv4子网安装一个默认的路由
    for (int i = 0; i < interface_table.current_num; ++i)
    {
        Interface_address_pair *entry = &interface_table.entries[i];
        IPV4_address ipv4_addr;
        IPV4_mask ipv4_mask;
        get_ipv4_by_interface(entry->name, ipv4_addr, ipv4_mask);
        for (int j = 0; j < sizeof(IPV4_address); ++j)
        {
            ipv4_addr[j] &= ipv4_mask[j];
        }
        // 先查找是否已经加过了
        unsigned char if_exist = 0;
        for (int idx = 0; idx < route_table.current_num; ++idx)
        {
            Route_entry *route_entry = &route_table.entries[idx];
            if (route_entry->route_type != ETHERNET_UPPER_PRTOCOL_IPV4)
                continue;
            if (route_entry->address_length != sizeof(IPV4_address))
                continue;
            unsigned char flag = 1;
            for (int j = 0; j < sizeof(IPV4_address); ++j)
                if (route_entry->route_address[j] != ipv4_addr[j])
                {
                    flag = 0;
                    break;
                }

            if (flag)
            {
                if_exist = 1;
                break;
            }
        }
        if (if_exist)
            continue;

        Route_entry *route_entry = &route_table.entries[route_table.current_num++];
        route_entry->interface = entry->name;
        route_entry->priority = 1;
        route_entry->route_address = malloc(sizeof(IPV4_address));
        route_entry->address_length = sizeof(IPV4_address);
        memcpy(route_entry->route_address, ipv4_addr, sizeof(IPV4_address));
        route_entry->route_type = ETHERNET_UPPER_PRTOCOL_IPV4;
        route_entry->route_mask = malloc(sizeof(IPV4_mask));
        memcpy(route_entry->route_mask, ipv4_mask, sizeof(IPV4_mask));
    }
    show_table();
}
