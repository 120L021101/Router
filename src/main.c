#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

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

int main(int argc, char *argv[])
{
    // unsigned char data[] = {
    //     0x08, 0x00, 0x5D, 0xB0, 0x00, 0x08, 0x00, 0x09,
    //     0x6E, 0x13, 0xAA, 0x67, 0x00, 0x00, 0x00, 0x00,
    //     0xBD, 0xF0, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
    //     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    //     0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    //     0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    //     0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    //     0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
    // size_t data_length = 64;

    // uint16_t checksum = icmp_checksum2(data, data_length);
    // printf("%2X%2X\n", (checksum & 0xFF00) >> 8, checksum & 0xFF);

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