#ifndef ICMP_H
#define ICMP_H

#include "ipv4.h"

void icmp_packet_ipv4_handler(unsigned char *data, size_t data_length, IPV4_address src_addr);

#define REGISTER_ICMP_IN_IPV4                                                             \
    do                                                                                    \
    {                                                                                     \
        register_ipv4_packet_handler(IPV4_UPPER_PROTOCOL_ICMP, icmp_packet_ipv4_handler); \
    } while (0)

#endif