#ifndef ICMP_H
#define ICMP_H

#include "ipv4.h"

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DESTINATION_UNREACHABLE 1
#define ICMP_TYPE_SOURCE_QUENCH 4
#define ICMP_TYPE_REDIRECT 5
#define ICMP_TYPE_ECHO 8
#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_TYPE_PARAMETER_PROBLEM 12
#define ICMP_TYPE_TIMESTAMP 13
#define ICMP_TYPE_TIMESTAMP_REPLY 14
#define ICMP_TYPE_INFORMATION_REQUEST 15
#define ICMP_TYPE_INFORMATION_REPLY 16

#define ICMP_LOG_PREFIX "[ICMP:] "

#define ICMP_TYPE_LOG(icmp_type)                                                  \
    do                                                                            \
    {                                                                             \
        switch (icmp_type)                                                        \
        {                                                                         \
        case (ICMP_TYPE_ECHO_REPLY):                                              \
            printf(ICMP_LOG_PREFIX "this is a ECHO_REPLY packet\n");              \
            break;                                                                \
        case (ICMP_TYPE_DESTINATION_UNREACHABLE):                                 \
            printf(ICMP_LOG_PREFIX "this is a DESTINATION_UNREACHABLE packet\n"); \
            break;                                                                \
        case (ICMP_TYPE_ECHO):                                                    \
            printf(ICMP_LOG_PREFIX "this is a ECHO packet\n");                    \
        }                                                                         \
    } while (0)

typedef struct _
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq_num;
    unsigned char *data;
    size_t data_length;
} Icmp_packet;

void icmp_packet_ipv4_handler(unsigned char *data, size_t data_length, Ipv4_packet *ipv4_packet);

#define REGISTER_ICMP_IN_IPV4                                                             \
    do                                                                                    \
    {                                                                                     \
        register_ipv4_packet_handler(IPV4_UPPER_PROTOCOL_ICMP, icmp_packet_ipv4_handler); \
    } while (0)

#endif