// icmpv4h
#ifndef ICMPV4_H
#define ICMPV4_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define ICMP_TYPE_ECHO_REPLY        0
#define ICMP_TYPE_DEST_UNREACHABLE  3
#define ICMP_TYPE_SOURCE_QUENCH     4
#define ICMP_TYPE_REDIRECT          5
#define ICMP_TYPE_ECHO_REQUEST      8
#define ICMP_TYPE_TIME_EXCEEDED     11
#define ICMP_TYPE_PARAMETER_PROBLEM 12
#define ICMP_TYPE_TIMESTAMP_REQUEST 13
#define ICMP_TYPE_TIMESTAMP_REPLY   14
#define ICMP_TYPE_INFO_REQUEST      15
#define ICMP_TYPE_INFO_REPLY        16
#define ICMP_TYPE_ADDRESS_MASK_REQ  17
#define ICMP_TYPE_ADDRESS_MASK_REP  18

// ICMP报文头部
struct icmp_header {
    uint8_t type;       // 类型字段
    uint8_t code;       // 代码字段
    uint16_t checksum;  // 校验和
};

// Echo请求和回复消息的数据格式
struct icmp_echo {
    uint16_t id;        // 标识符
    uint16_t sequence;  // 序列号
    unsigned char *data; // 可选数据
    size_t data_length; // 可选数据长度
};

// Destination Unreachable, Time Exceeded和Parameter Problem
struct icmp_error {
    uint32_t unused;    // 未使用的字段，通常为0
    uint32_t original_ip; // 导致错误的IP头部片段
};

// Timestamp请求和回复消息的数据格式
struct icmp_timestamp {
    uint16_t id;        // 标识符
    uint16_t sequence;  // 序列号
    uint32_t originate_timestamp;
    uint32_t receive_timestamp;
    uint32_t transmit_timestamp;
};

// ICMP报文结构体，包含不同的报文类型
typedef struct _Icmpv4_packet {
    struct icmp_header header;  // 通用头部
    union {
        struct icmp_echo echo;           // Echo请求/回复
        struct icmp_error error;         // 错误报文
        struct icmp_timestamp timestamp; // 时间戳请求/回复
        uint8_t data[1];                 // 默认数据字段
    } message;
} Icmpv4_packet;


Icmpv4_packet *parse_icmpv4_packet(const unsigned char *packet, size_t packet_size);

#endif // ICMPV4_H