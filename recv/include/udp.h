// udp.h
#ifndef UDP_H
#define UDP_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <ifaddrs.h>
#include "ethernet.h"
#include "pkg_sender.h"
#include "pkg_rcver.h"


typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
} Udp_header;


// 解析出Udp协议报文的头部
Udp_header *parse_udp_header(const unsigned char *data);


#endif // UDP_H