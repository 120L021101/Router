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

#define MAIN_LOG_PREFIX "[MAIN]: "

#define REGIESTER_PACKET_HANDLER \
    do                           \
    {                            \
        REGISTER_ARP;            \
    } while (0)

int main()
{
    INIT_UTIL;
    INIT_HARDWARE;
    REGIESTER_PACKET_HANDLER;

    listen_interfaces();

    unsigned char addr[4] = {172, 27, 208, 1};
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