#ifndef UDP_H
#define UDP_H

#include "ipv4.h"

void udp_packet_ipv4_handler(unsigned char *data, size_t data_length, IPV4_address src_addr);

#define REGISTER_UDP_IN_IPV4                                                            \
    do                                                                                  \
    {                                                                                   \
        register_ipv4_packet_handler(IPV4_UPPER_PROTOCOL_UDP, udp_packet_ipv4_handler); \
    } while (0)

#endif