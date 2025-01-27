#include "udp.h"

#define UDP_LOG_PREFIX "[UDP:] "

void udp_packet_ipv4_handler(unsigned char *data, size_t data_length, IPV4_address src_addr)
{
    printf(UDP_LOG_PREFIX "received udp from %d.%d.%d.%d\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
    return;
}