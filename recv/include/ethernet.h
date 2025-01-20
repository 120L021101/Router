// ethernet.h
#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct _ethernet_frame {
    uint8_t dest_mac[6];    // 目的 MAC 地址
    uint8_t src_mac[6];     // 源 MAC 地址
    uint16_t ether_type;     // 类型字段
    uint8_t *payload;   // 有效载荷
    size_t payload_size; // 有效载荷长度
    uint32_t fcs;            // 帧校验序列
} ethernet_frame;

ethernet_frame *parse_ethernet_frame(const u_char *frame, size_t frame_size);

#endif // ETHERNET_H
