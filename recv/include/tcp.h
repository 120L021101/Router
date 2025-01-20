// tcp.h
#ifndef TCP_H
#define TCP_H

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
    uint32_t sequence_number;
    uint32_t ack_number;
    uint8_t data_offset;
    uint8_t reserved;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
    unsigned char *options;
    unsigned char *data;
} Tcp_packet;


// 解析出Tcp协议报文的头部
Tcp_packet *parse_tcp_packet(const unsigned char *data, size_t data_length);


#endif // TCP_H