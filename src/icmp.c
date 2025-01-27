#include "icmp.h"

#define ICMP_LOG_PREFIX "[ICMP:] "

void icmp_packet_ipv4_handler(unsigned char *data, size_t data_length, IPV4_address src_addr)
{
    printf(ICMP_LOG_PREFIX "received icmp from %d.%d.%d.%d\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
}