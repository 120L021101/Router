#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#include "arp.h"
#include "ethernet.h"
#include "hardware.h"
#include "util.h"
#include "ipv4.h"
#include "route.h"
#include "udp.h"
#include "icmp.h"

#define MAIN_LOG_PREFIX "[MAIN]: "

#define REGIESTER_PACKET_HANDLER \
    do                           \
    {                            \
        REGISTER_ARP;            \
        REGISTER_IPV4;           \
        REGISTER_UDP_IN_IPV4;    \
        REGISTER_ICMP_IN_IPV4;   \
    } while (0)

// uint16_t icmp_checksum2(uint16_t *data, int len)
// {
//     data[1] = 0;
//     uint32_t sum = 0;
//     while (len > 1)
//     {
//         sum += ntohs(*data++);
//         len -= 2;
//     }
//     if (len == 1)
//         sum += *(uint8_t *)data;
//     while (sum >> 16)
//         sum = (sum & 0xFFFF) + (sum >> 16);
//     return (uint16_t)(~sum); // 取反码
// }

uint16_t ip_checksum2(void *vdata, size_t length)
{
    uint16_t *data = (uint16_t *)vdata;
    data[5] = 0;
    uint32_t sum = 0;
    while (length > 1)
    {
        sum += ntohs(*data++);
        length -= 2;
    }
    if (length == 1)
        sum += *(uint8_t *)data;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum); // 取反码
}

int main(int argc, char *argv[])
{
    // unsigned char data[] = {
    //     0x45, 0x00, 0x00, 0x54, // 版本 & 头部长度, 服务类型, 总长度
    //     0xC1, 0xA7, 0x40, 0x00, // 标识符, 标志 & 片偏移
    //     0x40, 0x01, 0xF5, 0xAD, // TTL, 协议 (ICMP), 头部校验和
    //     0xC0, 0xA8, 0x01, 0x02, // 源 IP 地址 (192.168.1.2)
    //     0xC0, 0xA8, 0x01, 0x01  // 目标 IP 地址 (192.168.1.1)
    // };
    // size_t data_length = 20;

    // uint16_t checksum = ip_checksum2(data, data_length);
    // printf("%2X%2X\n", (checksum & 0xFF00) >> 8, checksum & 0xFF);

    srand(time(NULL));

    if (argc < 2)
    {
        printf("Usage: %s -i <interface1> [interface2] [interface3] ...\n", argv[0]);
        return 1;
    }

    uint32_t interface_num = 0;
    const char **interfaces = parse_interfaces(argc, argv, &interface_num);

    INIT_UTIL;
    INIT_HARDWARE(interfaces, interface_num);
    INIT_ROUTE(interfaces, interface_num);
    REGIESTER_PACKET_HANDLER;

    listen_interfaces(interfaces, interface_num);

    for (int i = 0; i < 10; ++i)
        init_ipv4_subnet_arp();

    const char *const interface = "eth0";
    IPV4_address ipv4_address;
    get_ipv4_by_interface(interface, ipv4_address, NULL);
    printf(MAIN_LOG_PREFIX "%d.%d.%d.%d\n", ipv4_address[0], ipv4_address[1], ipv4_address[2], ipv4_address[3]);

    while (1)
        ;

    return 0;
}