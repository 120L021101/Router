#include "ipv4.h"

#define IPV4_LOG_PREFIX "[IPV4:] "

Ipv4_handler_table ipv4_handler_table;
extern Interface_table interface_table;

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

void register_ipv4_packet_handler(uint16_t protocol_type, void (*handler)(unsigned char *, size_t, Ipv4_packet *))
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
            handler->handler(packet_in->data, packet_in->data_length, packet_in);
        }
    }

    free(packet_in);
}

uint16_t ip_checksum(void *vdata, size_t length)
{
    uint16_t *data = (uint16_t *)vdata;
    uint32_t sum = 0;
    while (length > 1)
    {
        sum += ntohs(*data++);
        length -= 2;
    }
    if (length == 1)
        sum += *(uint8_t *)data;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum); // 取反码
}

static unsigned char *encode_ipv4_packet(Ipv4_packet *packet)
{
    unsigned char *data = malloc(20 + packet->data_length);
    data[0] = packet->version_ihl;
    data[1] = packet->tos;
    *(uint16_t *)(data + 2) = htons(packet->total_length);
    *(uint16_t *)(data + 4) = htons(packet->id);
    *(uint16_t *)(data + 6) = htons(packet->flags_offset);
    data[8] = packet->ttl;
    data[9] = packet->protocol;
    *(uint16_t *)(data + 10) = 0; // checksum
    memcpy(data + 12, packet->src_addr, sizeof(IPV4_address));
    memcpy(data + 16, packet->dest_addr, sizeof(IPV4_address));

    memcpy(data + 20, packet->data, packet->data_length);

    // on the header only
    *(uint16_t *)(data + 10) = htons(ip_checksum(data, 20));

    return data;
}

void send_ipv4_packet(unsigned char *data, size_t data_length, IPV4_address src_addr, IPV4_address dst_addr)
{
    Ipv4_packet *const sent_packet = (Ipv4_packet *)malloc(sizeof(Ipv4_packet));
    memset(sent_packet, 0, sizeof(Ipv4_packet));
    sent_packet->data = data;
    sent_packet->data_length = data_length;
    memcpy(sent_packet->dest_addr, dst_addr, sizeof(IPV4_address));
    memcpy(sent_packet->src_addr, src_addr, sizeof(IPV4_address));
    sent_packet->protocol = IPV4_UPPER_PROTOCOL_ICMP;
    sent_packet->total_length = 20 + data_length;
    sent_packet->ttl = 0x40;
    sent_packet->version_ihl = 0x45;
    sent_packet->flags_offset = 0x4000;
    sent_packet->id = (uint16_t)rand();

    unsigned char *data_sent = encode_ipv4_packet(sent_packet);

    Mac_address *dst_mac;

    while ((dst_mac = lookup_hardware_address_by_arp(
                ETHERNET_UPPER_PRTOCOL_IPV4,
                dst_addr,
                sizeof(IPV4_address))) == NULL)
        ;

    for (int i = 0; i < interface_table.current_num; ++i)
    {
        Interface_address_pair *entry = &interface_table.entries[i];
        IPV4_address interface_addr;
        get_ipv4_by_interface(entry->name, interface_addr, NULL);
        if (is_ipv4_addr_equal(interface_addr, src_addr))
        {
            printf(IPV4_LOG_PREFIX "INTERFACE: %s MAC_ADDRESS: %2X.%2X.%2X.%2X.%2X.%2X TO: %d.%d.%d.%d FROM: %d.%d.%d.%d\n",
                   entry->name, dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
                   dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3],
                   src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
            send_via_ethernet(entry->name, dst_mac, data_sent, 20 + data_length, ETHERNET_UPPER_PRTOCOL_IPV4);
            break;
        }
    }

    free(sent_packet);
}