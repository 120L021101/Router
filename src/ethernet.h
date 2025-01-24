#ifndef SRC_ETHERNET_H
#define SRC_ETHERNET_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>

typedef unsigned char Mac_address[6];

#include "util.h"
#include "hardware.h"

#define ETHERNET_UPPER_PRTOCOL_IPV4 0x0800
#define ETHERNET_UPPER_PRTOCOL_ARP 0x0806
#define ETHERNET_UPPER_PRTOCOL_IPV6 0x86DD

typedef struct
{
    Mac_address dst_address;
    Mac_address src_address;
    uint16_t protocol;

    unsigned char *data;

    uint32_t crc_checksum;
} Ethernet_packet;

void broadcast_ethernet(const unsigned char *const data, size_t data_size, uint16_t protocol_type);

#endif