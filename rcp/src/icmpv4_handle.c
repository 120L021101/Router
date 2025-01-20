#include "icmpv4_handle.h"

// typedef struct _ipv4_header {
//     uint8_t ihl : 4;               // 头部长度
//     uint8_t version : 4;           // 版本
//     uint8_t tos;                    // 类型服务
//     uint16_t total_length;          // 总长度
//     uint16_t identification;        // 标识
//     uint16_t flags_offset;          // 标志和片偏移
//     uint8_t ttl;                    // 生存时间
//     uint8_t protocol;               // 协议
//     uint16_t checksum;              // 头部校验和
//     uint32_t src_addr;              // 源 IP 地址
//     uint32_t dest_addr;             // 目的 IP 地址
// } ipv4_header;


uint16_t swap_endian(uint16_t val) {  
    return (val >> 8) | (val << 8);  
}  

static uint16_t compute_checksum(Icmpv4_packet * icmpv4_packet) {
    uint32_t sum = 0;

    // sum += icmpv4_packet->header.code;
    sum += (*(uint16_t *)(&icmpv4_packet->header.type));
    sum += (icmpv4_packet->message.echo.id);
    sum += (icmpv4_packet->message.echo.sequence);
    sum += swap_endian(*(uint16_t *)(&icmpv4_packet->message.echo.data_length));
    sum += swap_endian(*((uint16_t *)(&icmpv4_packet->message.echo.data_length) + 1));

    // fprintf(stdout, "[JIAOYANHE]: %2X\n", (*(uint16_t *)(&icmpv4_packet->header.type)));
    // fprintf(stdout, "[JIAOYANHE]: %2X\n", (icmpv4_packet->message.echo.id));
    // fprintf(stdout, "[JIAOYANHE]: %2X\n", swap_endian(icmpv4_packet->message.echo.sequence));
    // fprintf(stdout, "[JIAOYANHE]: %2X\n", swap_endian(*(uint16_t *)(&icmpv4_packet->message.echo.data_length)));
    // fprintf(stdout, "[JIAOYANHE]: %2X\n", swap_endian(*((uint16_t *)(&icmpv4_packet->message.echo.data_length) + 1)));

    for (int i = 0; i < 28; ++i) {
        sum += swap_endian(*(uint16_t *)(icmpv4_packet->message.echo.data + 2 * i));
        // fprintf(stdout, "[JIAOYANHE]: %2X\n", swap_endian(*(uint16_t *)(icmpv4_packet->message.echo.data + 2 * i)));
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return swap_endian((uint16_t)(~sum));
}

static uint16_t compute_ipv4_checksum(ipv4_header *ipv4_hdr) {
    // 初始化和
    uint32_t sum = 0;

    // 逐16位加和，IPv4 头部大小为20字节
    uint16_t *buffer = (uint16_t *)ipv4_hdr;
    for (size_t i = 0; i < sizeof(ipv4_header) / 2; i++) {
        sum += *buffer++;
    }

    // 处理进位
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    // 返回反转后的校验和
    return (uint16_t)(~sum);
}

void process_icmpv4_packet(Pkg_sender *pkg_sender, Icmpv4_packet *icmpv4_packet, ipv4_header *ipv4_hdr,
                            const char *dev_name, unsigned char *dst_mac_addr) {
    fprintf(stdout, "[RCP ICMP HANLDER] start\n");

    ipv4_header reply_ipv4_hdr;// = (ipv4_header *)malloc(sizeof(ipv4_header));    

    Icmpv4_packet icmpv4_echo_reply_packet;
    memset(&icmpv4_echo_reply_packet, 0, sizeof(icmpv4_echo_reply_packet));

    switch (icmpv4_packet->header.type) {
    case ICMP_TYPE_ECHO_REQUEST: // echo request
        fprintf(stdout, "[RCP ICMP HANLDER] start, %d, %d, %d, %d\n", icmpv4_packet->header.type,
                                    ICMP_TYPE_ECHO_REQUEST, icmpv4_packet->message.echo.id,
                                    icmpv4_packet->message.echo.sequence);

        // 设置echo reply报文header字段与data
        icmpv4_echo_reply_packet.header.code = 0;
        icmpv4_echo_reply_packet.header.type = ICMP_TYPE_ECHO_REPLY;

        icmpv4_echo_reply_packet.message.echo.id = icmpv4_packet->message.echo.id;
        icmpv4_echo_reply_packet.message.echo.sequence = icmpv4_packet->message.echo.sequence;
                
        icmpv4_echo_reply_packet.message.echo.data = (unsigned char *)malloc(56);
        memcpy(icmpv4_echo_reply_packet.message.echo.data, icmpv4_packet->message.echo.data, 56);

        icmpv4_echo_reply_packet.header.checksum = 0;
        icmpv4_echo_reply_packet.header.checksum = compute_checksum(&icmpv4_echo_reply_packet);

        reply_ipv4_hdr.version = ipv4_hdr->version;
        reply_ipv4_hdr.ihl = ipv4_hdr->ihl;
        reply_ipv4_hdr.tos = ipv4_hdr->tos;
        reply_ipv4_hdr.total_length = htons(20 + 8 + 56); // IPv4 + ICMP总长度
        reply_ipv4_hdr.identification = ipv4_hdr->identification;
        reply_ipv4_hdr.flags_offset = ipv4_hdr->flags_offset;
        reply_ipv4_hdr.ttl = 64;
        reply_ipv4_hdr.protocol = IPPROTO_ICMP;
        reply_ipv4_hdr.src_addr = ipv4_hdr->dest_addr; // 源地址变为原来的目的地址
        reply_ipv4_hdr.dest_addr = ipv4_hdr->src_addr; // 目的地址变为原来的源地址

        reply_ipv4_hdr.checksum = 0;
        reply_ipv4_hdr.checksum = compute_ipv4_checksum(&reply_ipv4_hdr);

        fprintf(stdout, "[RCP ICMPV4 ECHO] REPLY ID %d FROM %d TO %d \n", icmpv4_echo_reply_packet.message.echo.id,
                                reply_ipv4_hdr.src_addr, reply_ipv4_hdr.dest_addr);

        fprintf(stdout, "[RCP ICMPV4 ECHO] payload data is :\n");
        for (int i = 0; i < 56; ++i) {
            fprintf(stdout, "%02X ", icmpv4_packet->message.echo.data[i]);
        }
        fprintf(stdout, "\n");

        fprintf(stdout, "[RCP ICMPV4 ECHO] Source IP Address: %u.%u.%u.%u\n",
           reply_ipv4_hdr.src_addr & 0xFF,
           (reply_ipv4_hdr.src_addr >> 8) & 0xFF,
           (reply_ipv4_hdr.src_addr >> 16) & 0xFF,
           (reply_ipv4_hdr.src_addr >> 24) & 0xFF);
        fprintf(stdout, "[RCP ICMPV4 ECHO] Destination IP Address: %u.%u.%u.%u\n",
           reply_ipv4_hdr.dest_addr & 0xFF,
           (reply_ipv4_hdr.dest_addr >> 8) & 0xFF,
           (reply_ipv4_hdr.dest_addr >> 16) & 0xFF,
           (reply_ipv4_hdr.dest_addr >> 24) & 0xFF);

        unsigned char ipv4_packet[sizeof(ipv4_header) + 
                                  sizeof(struct icmp_header) + 
                                  60];
        fprintf(stdout, "[RCP ICMPV4 ECHO]: reply packet is size of : %ld\n", sizeof(ipv4_header) + 
                                  sizeof(struct icmp_header) + 
                                  60);
        memcpy(ipv4_packet, &reply_ipv4_hdr, sizeof(ipv4_header));
        unsigned char *pointer = ipv4_packet + sizeof(ipv4_header);
        memcpy(pointer, &icmpv4_echo_reply_packet.header, sizeof(struct icmp_header));
        pointer += sizeof(struct icmp_header);
        *(uint16_t *)pointer = ntohs(icmpv4_echo_reply_packet.message.echo.id);
        pointer += 2;
        *(uint16_t *)pointer = ntohs(icmpv4_echo_reply_packet.message.echo.sequence);
        pointer += 2;
        memcpy(pointer, icmpv4_packet->message.echo.data, 56);

        fprintf(stdout, "[RCP ICMPV4 ECHO]: id is %d\n", *(uint16_t *)(ipv4_packet + 24));
        // char dest[6] = {0x02, 0x16, 0x61, 0x44, 0xf4, 0x17};
        pkg_send(pkg_sender, ipv4_packet, sizeof(ipv4_packet), 0x0800, dev_name, dst_mac_addr);
        fprintf(stdout, "[RCP ICMPV4 ECHO]: packet sent from %s!!\n", dev_name);
        break;
    }
    // free(reply_ipv4_hdr);
}