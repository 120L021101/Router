#include "arpv4.h"

static uint32_t reverse_bytes(uint32_t value) {
    return ((value >> 24) & 0xff) |      // byte 3
           ((value << 8) & 0xff0000) |   // byte 2
           ((value >> 8) & 0xff00) |     // byte 1
           ((value << 24) & 0xff000000); // byte 0
}

Arp_header *parse_arp_header(ethernet_frame *eth_frame) {

    Arp_header *arp_header = (Arp_header *)malloc(sizeof(Arp_header));
    IFERR_REPORT_AND_EXIT(arp_header, "Failed to allocate memory for ARP header");

    // 从以太网帧的有效载荷中提取 ARP 报文
    uint8_t *payload = eth_frame->payload;

    arp_header->hardware_type = ntohs(*(uint16_t *)payload);
    arp_header->protocol_type = ntohs(*(uint16_t *)(payload + 2));
    arp_header->hardware_addr_len = *(payload + 4);
    arp_header->protocol_addr_len = *(payload + 5);
    arp_header->operation = ntohs(*(uint16_t *)(payload + 6));

    memcpy(arp_header->sender_hardware_addr, payload + 8, 6);
    arp_header->sender_protocol_addr = reverse_bytes(ntohl(*(uint32_t *)(payload + 14)));
    memcpy(arp_header->target_hardware_addr, payload + 18, 6);
    arp_header->target_protocol_addr = reverse_bytes(ntohl(*(uint32_t *)(payload + 24)));

    return arp_header;
}

static void swap_sender_target(Arp_header *arp_header) {
    for (size_t i = 0; i < 6; ++i) {
        uint8_t temp = arp_header->target_hardware_addr[i];
        arp_header->target_hardware_addr[i] = arp_header->sender_hardware_addr[i];
        arp_header->sender_hardware_addr[i] = temp;
    } 
    uint32_t temp2 = arp_header->target_protocol_addr;
    arp_header->target_protocol_addr = arp_header->sender_protocol_addr;
    arp_header->sender_protocol_addr = temp2;
}

unsigned char fill_if_contains_arp(Ipv4_arp_table *ipv4_arp_table, Arp_header *arp_header) {
    char *mac_addr = find_ipv4_mac_byarp(ipv4_arp_table, arp_header->target_protocol_addr);
    // 命中记录
    if (mac_addr != NULL) {
        memcpy(arp_header->target_hardware_addr, mac_addr, 6);
        arp_header->operation = 2;
        swap_sender_target(arp_header);
        return 1;
    }
    return 0;
}

size_t construct_arpv4_packet(Arp_header *arp_header, unsigned char *packet) {
    size_t packet_size = 28;

    *(uint16_t *)(packet) = htons(arp_header->hardware_type);
    *(uint16_t *)(packet + 2) = htons(arp_header->protocol_type);
    *(packet + 4) = arp_header->hardware_addr_len;
    *(packet + 5) = arp_header->protocol_addr_len;
    *(uint16_t *)(packet + 6) = htons(arp_header->operation);
    memcpy(packet + 8, arp_header->sender_hardware_addr, 6);
    *(uint32_t *)(packet + 14) = reverse_bytes(htonl(arp_header->sender_protocol_addr));
    memcpy(packet + 18, arp_header->target_hardware_addr, 6);
    *(uint32_t *)(packet + 24) = reverse_bytes(htonl(arp_header->target_protocol_addr));

    return packet_size;
}

unsigned char is_arpv4_reply(Arp_header *arp_header) {
    return arp_header->protocol_type == 2;
}

Arp_header *request_ipv4_mac_addr(uint32_t sender_ipv4_addr, uint8_t *sender_mac_addr, 
                                            uint32_t target_ipv4_addr) {
    Arp_header *arp_header = (Arp_header *)malloc(sizeof(Arp_header));
    
    arp_header->hardware_type = htons(1); // 硬件类型：以太网（1)
    arp_header->protocol_type = htons(0x0800); // 协议类型：IPv4（0x0800）
    arp_header->hardware_addr_len = 6; // 硬件地址长度：以太网 MAC 地址为 6 字节
    arp_header->protocol_addr_len = 4; // 协议地址长度：IPv4 地址为 4 字节
    arp_header->operation = htons(1); // 操作类型：请求（1）

    // 填充发送方的 MAC 和 IP 地址
    memcpy(arp_header->sender_hardware_addr, sender_mac_addr, 6); // 发送方 MAC 地址
    arp_header->sender_protocol_addr = sender_ipv4_addr; // 发送方 IP 地址

    // 目标硬件地址和目标协议地址初始化为 0（未知）
    memset(arp_header->target_hardware_addr, 0, 6); // 目标 MAC 地址为未知
    arp_header->target_protocol_addr = target_ipv4_addr; // 目标 IP 地址

    fprintf(stdout, "I WANT TO REQUEST %d.%d.%d.%d mac address\n",
            (target_ipv4_addr & 0xFF000000) >> 24,
            (target_ipv4_addr & 0x00FF0000) >> 16,
            (target_ipv4_addr & 0x0000FF00) >> 8,
            (target_ipv4_addr & 0xFF));

    return arp_header; // 返回填充好的 ARP 请求头部
}