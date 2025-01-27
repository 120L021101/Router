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

#define MAIN_LOG_PREFIX "[MAIN]: "

#define REGIESTER_PACKET_HANDLER \
    do                           \
    {                            \
        REGISTER_ARP;            \
    } while (0)

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s -i <interface1> [interface2] [interface3] ...\n", argv[0]);
        return 1;
    }

    uint32_t interface_num = 0;
    const char **interfaces = parse_interfaces(argc, argv, &interface_num);

    INIT_UTIL;
    INIT_HARDWARE(interfaces, interface_num);
    REGIESTER_PACKET_HANDLER;

    listen_interfaces(interfaces, interface_num);

    unsigned char addr[4] = {192, 168, 1, 2};
    while (1)
    {
        Mac_address *raddr = lookup_hardware_address_by_arp(0x0800, addr, 4);
        for (int i = 0; i < 1000000; ++i)
            ;
        if (raddr == NULL)
            continue;
        printf(MAIN_LOG_PREFIX "address is: %2X.%2X.%2X.%2X.%2X.%2X\n", (*raddr)[0],
               (*raddr)[1], (*raddr)[2], (*raddr)[3], (*raddr)[4], (*raddr)[5]);
        break;
    }

    const char *const interface = "eth0";
    IPV4_address ipv4_address;
    get_ipv4_by_interface(interface, ipv4_address);
    printf(MAIN_LOG_PREFIX "%d.%d.%d.%d\n", ipv4_address[0], ipv4_address[1], ipv4_address[2], ipv4_address[3]);

    while (1)
        ;

    return 0;
}