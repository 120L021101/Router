#include "icmp.h"

#define ICMP_LOG_PREFIX "[ICMP:] "

uint16_t icmp_checksum(uint16_t *data, int len)
{
    data[1] = 0;
    uint32_t sum = 0;
    while (len > 1)
    {
        sum += ntohs(*data++);
        len -= 2;
    }
    if (len == 1)
        sum += *(uint8_t *)data;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum); // 取反码
}

// 从字符数组解析icmp数据包
static Icmp_packet *parse_icmp_packet(unsigned char *data, size_t data_length)
{
    Icmp_packet *icmp_packet = (Icmp_packet *)malloc(sizeof(Icmp_packet));

    icmp_packet->type = *data;
    icmp_packet->code = *(data + 1);
    icmp_packet->checksum = ntohs(*(uint16_t *)(data + 2));
    icmp_packet->id = ntohs(*(uint16_t *)(data + 4));
    icmp_packet->seq_num = ntohs(*(uint16_t *)(data + 6));

    icmp_packet->data = data_length >= 8 ? data + 8 : NULL;
    icmp_packet->data_length = data_length - 8;

    return icmp_packet;
}

static unsigned char *encode_icmp_packet(Icmp_packet *icmp_packet)
{
    return NULL;
}

// echo数据包处理函数
static void icmp_echo_handler(const Icmp_packet *const icmp_packet, const Ipv4_packet *ipv4_packet)
{
    printf(ICMP_LOG_PREFIX "replying ECHO\n");
    IPV4_address src_addr, dst_addr;
    memcpy(src_addr, ipv4_packet->dest_addr, sizeof(IPV4_address));
    memcpy(dst_addr, ipv4_packet->src_addr, sizeof(IPV4_address));

    Icmp_packet *const echo_reply = (Icmp_packet *)malloc(sizeof(Icmp_packet));

    echo_reply->type = ICMP_TYPE_ECHO_REPLY;
    echo_reply->code = 0;

    echo_reply->id = icmp_packet->id;
    echo_reply->seq_num = icmp_packet->seq_num;

    size_t data_length = 8 + icmp_packet->data_length;
    unsigned char *data = malloc(data_length /*1 + 1 + 2 + 2 + 2*/);
    data[0] = echo_reply->type;
    data[1] = echo_reply->code;
    *(uint16_t *)(data + 4) = htons(echo_reply->id);
    *(uint16_t *)(data + 6) = htons(echo_reply->seq_num);
    *(uint16_t *)(data + 2) = 0;
    // data
    memcpy(data + 8, icmp_packet->data, icmp_packet->data_length);

    *(uint16_t *)(data + 2) = htons(icmp_checksum(data, data_length));

    printf(ICMP_LOG_PREFIX "send echo reply packet\n");
    send_ipv4_packet(data, data_length, src_addr, dst_addr);

    free(echo_reply);
    return;
}

void icmp_packet_ipv4_handler(unsigned char *data, size_t data_length, Ipv4_packet *ipv4_packet)
{
    printf(ICMP_LOG_PREFIX "received icmp from %d.%d.%d.%d\n", ipv4_packet->src_addr[0],
           ipv4_packet->src_addr[1],
           ipv4_packet->src_addr[2],
           ipv4_packet->src_addr[3]);

    Icmp_packet *icmp_packet = parse_icmp_packet(data, data_length);

    ICMP_TYPE_LOG(icmp_packet->type);

    switch (icmp_packet->type)
    {
    case (ICMP_TYPE_ECHO):
        icmp_echo_handler(icmp_packet, ipv4_packet);
        break;
    }

    free(icmp_packet);
}