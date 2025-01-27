#include "ipv4.h"

#define IPV4_LOG_PREFIX "[IPV4:] "

Ipv4_handler_table ipv4_handler_table;

char is_ipv4_addr_equal(IPV4_address addr1, IPV4_address addr2)
{
    for (int i = 0; i < sizeof(IPV4_address); ++i)
    {
        if (addr1[i] != addr2[i])
            return 0;
    }
    return 1;
}

char is_ipv4_addr_mask_equal(IPV4_address addr1, IPV4_address addr, IPV4_mask mask)
{
    for (int i = 0; i < sizeof(IPV4_address) && mask[i]; ++i)
    {
        if ((addr1[i] & mask[i]) != (addr[i] & mask[i]))
            return 0;
    }
    return 1;
}

char is_broadcast_ipv4(IPV4_address addr, IPV4_mask mask)
{
    IPV4_address addr2;
    for (int i = 0; i < sizeof(IPV4_address); ++i)
    {
        addr2[i] = (~mask[i]) & addr[i];
    }

    // 判断是否是以全1结尾
    for (int i = sizeof(IPV4_address) - 1; i >= 0; --i)
    {
        if (addr2[i] == 0xFF)
            continue;
        int zero_starts = 0;
        while (zero_starts < 8)
        {
            if ((addr2[i] & (0x1 << (8 - zero_starts - 1))) == 0)
                zero_starts++;
            else
                break;
        }
        int one_ends = 0;
        while (one_ends < 8)
        {
            if (addr2[i] & (0x1 << one_ends))
                one_ends++;
            else
                break;
        }
        return (one_ends + zero_starts) == 8;
    }
    return 1;
}

char is_the_same_subnet_ipv4(IPV4_address addr1, IPV4_address addr2, IPV4_mask mask)
{
    IPV4_address mask_addr1, mask_addr2;
    for (int i = 0; i < sizeof(IPV4_address); ++i)
    {
        mask_addr1[i] = addr1[i] & mask[i];
        mask_addr2[i] = addr2[i] & mask[i];
        if (mask_addr1[i] != mask_addr2[i])
            return 0;
    }
    return 1;
}

static Ipv4_packet *parse_ipv4_packet(unsigned char *data, size_t data_length)
{
    Ipv4_packet *packet = malloc(sizeof(Ipv4_packet));

    packet->version_ihl = *(data + 0);
    packet->tos = *(data + 1);
    packet->total_length = ntohs(*(uint16_t *)(data + 2));
    packet->id = ntohs(*(uint16_t *)(data + 4));
    packet->flags_offset = ntohs(*(uint16_t *)(data + 6));
    packet->ttl = *(data + 8);
    packet->protocol = *(data + 9);
    packet->checksum = ntohs(*(uint16_t *)(data + 10));
    memcpy(packet->src_addr, data + 12, sizeof(IPV4_address));
    memcpy(packet->dest_addr, data + 16, sizeof(IPV4_address));
    packet->data_length = data_length - 20;
    packet->data = malloc(packet->data_length);
    memcpy(packet->data, data + 20, packet->data_length);
    return packet;
}

void register_ipv4_packet_handler(uint16_t protocol_type, void (*handler)(unsigned char *, size_t, IPV4_address))
{
    uint32_t num = ipv4_handler_table.current_num;
    ipv4_handler_table.entries[num].protocol_type = protocol_type;
    ipv4_handler_table.entries[num].handler = handler;
    ipv4_handler_table.current_num = num + 1;
}

void ipv4_handler(unsigned char *data, size_t data_length, const char *const ingoing_interface, Mac_address sender_eth_addr)
{
    printf(IPV4_LOG_PREFIX "start parsing ipv4 packet\n");
    Ipv4_packet *packet_in = parse_ipv4_packet(data, data_length);
    printf(IPV4_LOG_PREFIX "protocol is %d\n", packet_in->protocol);

    // deliver
    for (int i = 0; i < ipv4_handler_table.current_num; ++i)
    {
        Ipv4_handler *handler = &ipv4_handler_table.entries[i];
        if (handler->protocol_type == packet_in->protocol)
        {
            handler->handler(packet_in->data, packet_in->data_length, packet_in->src_addr);
        }
    }
}
