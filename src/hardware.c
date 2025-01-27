#include "hardware.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

Interface_table interface_table;

#define HARDWARE_LOG_PREFIX "[HARDWARE INIT]: "

// 获取接口的 MAC 地址
static Mac_address *get_mac_address(const char *iface)
{
    struct ifreq ifr;
    int sockfd;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1)
    {
        perror(HARDWARE_LOG_PREFIX "Socket creation failed");
        return NULL;
    }

    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1)
    {
        // perror(HARDWARE_LOG_PREFIX "ioctl SIOCGIFHWADDR failed");
        close(sockfd);
        return NULL;
    }

    unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    printf(HARDWARE_LOG_PREFIX "Interface: %s, MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", iface,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    close(sockfd);
    Mac_address *ret_address = (Mac_address *)malloc(sizeof(Mac_address));
    for (int i = 0; i < 6; ++i)
    {
        (*ret_address)[i] = mac[i];
    }
    return ret_address;
}

void init_hardware_interfaces(const char **const interfaces, uint32_t interface_num)
{
    interface_table.current_num = 0;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取所有的网络接口
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, HARDWARE_LOG_PREFIX "Error in pcap_findalldevs: %s\n", errbuf);
    }

    // 遍历每个网络接口
    for (d = alldevs; d != NULL; d = d->next)
    {
        for (int j = 0; j < interface_num; ++j)
        {
            if (!strcmp(interfaces[j], d->name))
            {
                // 获取该接口的 MAC 地址
                Mac_address *mac_address = get_mac_address(d->name);
                interface_table.entries[interface_table.current_num].name = (char *)malloc(100);
                strcpy(interface_table.entries[interface_table.current_num].name, d->name);
                if (mac_address)
                {
                    printf(HARDWARE_LOG_PREFIX "Interface Name: %s\n", interface_table.entries[interface_table.current_num].name);
                    memcpy(interface_table.entries[interface_table.current_num++].mac_address, *mac_address, sizeof(Mac_address));
                }

                break;
            }
        }
    }
    // 释放内存
    pcap_freealldevs(alldevs);
    printf(HARDWARE_LOG_PREFIX "共找到了 %d 条有效接口\n", interface_table.current_num);
}

Mac_address *get_interface_hardware_address(const char *name)
{
    for (int i = 0; i < interface_table.current_num; ++i)
    {
        if (strcmp(interface_table.entries[i].name, name))
            continue;
        return &(interface_table.entries[i].mac_address);
    }
    return NULL;
}

void get_ipv4_by_interface(const char *const interface, IPV4_address ipv4_address, IPV4_mask ipv4_mask)
{
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    pcap_addr_t *address;

    pcap_findalldevs(&alldevs, NULL);

    // 遍历所有接口
    for (dev = alldevs; dev != NULL; dev = dev->next)
    {
        if (strcmp(dev->name, interface))
            continue;
        // printf("%s %s\n", dev->name, interface);
        // 遍历该接口的所有地址
        for (address = dev->addresses; address != NULL; address = address->next)
        {
            // printf("%d %d\n", address->addr->sa_family, AF_INET);
            // 只查找IPv4地址
            if (address->addr->sa_family == AF_INET)
            {
                struct sockaddr_in *ipv4_addr_in = (struct sockaddr_in *)address->addr;
                struct in_addr inet_addr = ipv4_addr_in->sin_addr;
                ipv4_address[0] = inet_addr.s_addr & 0xFF;
                ipv4_address[1] = (inet_addr.s_addr >> 8) & 0xFF;
                ipv4_address[2] = (inet_addr.s_addr >> 16) & 0xFF;
                ipv4_address[3] = (inet_addr.s_addr >> 24) & 0xFF;
            }

            // 获取子网掩码
            if (ipv4_mask != NULL && address->broadaddr != NULL)
            {
                struct sockaddr_in *netmask_in = (struct sockaddr_in *)address->broadaddr;
                struct in_addr netmask_addr = netmask_in->sin_addr;
                // ipv4_mask[0] = netmask_addr.s_addr & 0xFF;
                // ipv4_mask[1] = (netmask_addr.s_addr >> 8) & 0xFF;
                // ipv4_mask[2] = (netmask_addr.s_addr >> 16) & 0xFF;
                // ipv4_mask[3] = (netmask_addr.s_addr >> 24) & 0xFF;
                ipv4_mask[0] = ipv4_mask[1] = ipv4_mask[2] = 0xFF;
                // printf("%d.%d.%d.%d\n", ipv4_mask[0], ipv4_mask[1], ipv4_mask[2], ipv4_mask[3]);
            }
        }
    }

    pcap_freealldevs(alldevs);
}