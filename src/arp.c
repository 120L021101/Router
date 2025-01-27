#include "arp.h"
#include "ethernet.h"
#include <string.h> // 用于 memcpy 或者类似操作

#define ARP_LOG_PREFIX "[ARP]: "

extern Interface_table interface_table;

// 初始化arp_table
ARP_table arp_table;

// 创建新的ARP数据包
ARP_packet_data *new_ARP_packet()
{
    return (ARP_packet_data *)malloc(sizeof(ARP_packet_data));
}

// 释放ARP数据包
void release_ARP_packet(ARP_packet_data *arp_packet_data)
{
    free(arp_packet_data);
}

static unsigned char *encode_arp_packet(const ARP_packet_data *const arp_packet_data,
                                        size_t *ret_size)
{
    *ret_size = 8 + 2 * (arp_packet_data->byte_length_of_hardware_addr +
                         arp_packet_data->byte_length_of_protocol_addr);
    unsigned char *const ret_arr = malloc(sizeof(unsigned char) * (*ret_size));

    *(uint16_t *)(ret_arr + 0) = htons(arp_packet_data->hardware_type);
    *(uint16_t *)(ret_arr + 2) = htons(arp_packet_data->protocol_space);
    *(uint8_t *)(ret_arr + 4) = arp_packet_data->byte_length_of_hardware_addr;
    *(uint8_t *)(ret_arr + 5) = arp_packet_data->byte_length_of_protocol_addr;
    *(uint16_t *)(ret_arr + 6) = htons(arp_packet_data->opcode);

    // printf("%2x %2x %2x %2x %2x %2x\n", arp_packet_data->sender_hardware_address[0],
    //        arp_packet_data->sender_hardware_address[1],
    //        arp_packet_data->sender_hardware_address[2],
    //        arp_packet_data->sender_hardware_address[3],
    //        arp_packet_data->sender_hardware_address[4],
    //        arp_packet_data->sender_hardware_address[5]);
    memcpy(ret_arr + 8, arp_packet_data->sender_hardware_address, sizeof(Mac_address));

    memcpy(ret_arr + 8 + sizeof(Mac_address), arp_packet_data->sender_protocol_address,
           arp_packet_data->byte_length_of_protocol_addr);

    memcpy(ret_arr + 8 + sizeof(Mac_address) + arp_packet_data->byte_length_of_protocol_addr,
           arp_packet_data->target_hardware_address, sizeof(Mac_address));

    memcpy(ret_arr + 8 + 2 * sizeof(Mac_address) + arp_packet_data->byte_length_of_protocol_addr,
           arp_packet_data->target_protocol_address, arp_packet_data->byte_length_of_protocol_addr);

    return ret_arr;
}

static void arp_reply(ARP_packet_data *request_packet, Mac_address hardware_address, uint32_t address_length,
                      const char *const req_in_interface, Mac_address sender_addr)
{
    ARP_packet_data *reply_packet = malloc(sizeof(ARP_packet_data));

    memcpy(reply_packet, request_packet, sizeof(ARP_packet_data));

    reply_packet->opcode = ARP_OPCODE_REPLY;

    // swap sender and target protocol address
    for (int i = 0; i < reply_packet->byte_length_of_protocol_addr; ++i)
    {
        int temp = reply_packet->target_protocol_address[i];
        reply_packet->target_protocol_address[i] = reply_packet->sender_protocol_address[i];
        reply_packet->sender_protocol_address[i] = temp;
    }

    memcpy(reply_packet->target_hardware_address, reply_packet->sender_hardware_address, sizeof(Mac_address));

    memcpy(reply_packet->sender_hardware_address, hardware_address, sizeof(Mac_address));

    // set sender hardware address

    size_t packet_size = 0;

    unsigned char *encoded_packet = encode_arp_packet(reply_packet, &packet_size);

    send_via_ethernet(req_in_interface, sender_addr, encoded_packet, packet_size, ETHERNET_UPPER_PRTOCOL_ARP);

    free(reply_packet);
}

static void arp_request(uint32_t protocol_type, unsigned char *protocol_address, uint32_t address_length)
{
    ARP_packet_data arp_packet_data;
    arp_packet_data.opcode = ARP_OPCODE_REQEUST;
    arp_packet_data.hardware_type = HARDWARE_TYPE;
    arp_packet_data.protocol_space = protocol_type;

    arp_packet_data.byte_length_of_hardware_addr = 6;
    arp_packet_data.byte_length_of_protocol_addr = address_length;

    memset(arp_packet_data.target_hardware_address, 0, sizeof(Mac_address));

    arp_packet_data.target_hardware_address;
    arp_packet_data.target_protocol_address = protocol_address;

    // 广播，并设置发送方的Mac地址与协议地址
    for (int i = 0; i < interface_table.current_num; ++i)
    {
        memcpy(arp_packet_data.sender_hardware_address,
               interface_table.entries[i].mac_address,
               sizeof(Mac_address));
        switch (protocol_type)
        {
        case (0x0800):
            arp_packet_data.sender_protocol_address = malloc(sizeof(4));
            get_ipv4_by_interface(interface_table.entries[i].name,
                                  arp_packet_data.sender_protocol_address);
            break;
        default:
            break;
        }
        size_t packet_size = 0;
        unsigned char *packet = encode_arp_packet(&arp_packet_data, &packet_size);
        const char *const interface = interface_table.entries[i].name;
        Mac_address dst_addr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        send_via_ethernet(interface, &dst_addr, packet, packet_size, ETHERNET_UPPER_PRTOCOL_ARP);
    }
}

Mac_address *lookup_hardware_address_by_arp(uint32_t protocol_type, unsigned char *protocol_address, uint32_t address_length)
{
    for (int i = 0; i < arp_table.current_num; ++i)
    {
        // 协议号不对
        if (arp_table.table_entries[i].protocol_type != protocol_type)
            continue;

        // 判断协议地址是否完全一样
        int j;
        for (j = 0; j < address_length; ++j)
            if (arp_table.table_entries[i].protocol_address[j] != protocol_address[j])
                break;

        if (j == address_length)
            return &arp_table.table_entries[i].hardware_address;
    }

    // 没有找到，发送ARP REQUEST
    arp_request(protocol_type, protocol_address, address_length);

    return NULL; // NULL 让客户端重试，如果未来有多线程功能，这个部分可以通过不断检查表来实现
}

ARP_packet_data *parse_arp_data(unsigned char *data, size_t data_length)
{
    ARP_packet_data *ret_arp_packet = malloc(sizeof(ARP_packet_data));
    // parse fields
    ret_arp_packet->hardware_type = ntohs(*(uint16_t *)data);
    ret_arp_packet->protocol_space = ntohs(*(uint16_t *)(data + 2));
    ret_arp_packet->byte_length_of_hardware_addr = *(data + 4);
    ret_arp_packet->byte_length_of_protocol_addr = *(data + 5);
    ret_arp_packet->opcode = ntohs(*(uint16_t *)(data + 6));

    // 解析发送端的物理地址，6字节
    memcpy(ret_arp_packet->sender_hardware_address, data + 8, sizeof(Mac_address));

    // 解析发送端的协议地址，byte_length_of_protocol_addr
    ret_arp_packet->sender_protocol_address = malloc(ret_arp_packet->byte_length_of_protocol_addr);
    memcpy(ret_arp_packet->sender_protocol_address, data + 8 + sizeof(Mac_address),
           ret_arp_packet->byte_length_of_protocol_addr);

    // 解析target的物理地址
    memcpy(ret_arp_packet->target_hardware_address,
           data + 8 + sizeof(Mac_address) + ret_arp_packet->byte_length_of_protocol_addr, sizeof(Mac_address));

    // 解析target的协议地址
    ret_arp_packet->target_protocol_address = malloc(ret_arp_packet->byte_length_of_protocol_addr);
    memcpy(ret_arp_packet->target_protocol_address,
           data + 8 + 2 * sizeof(Mac_address) + ret_arp_packet->byte_length_of_protocol_addr,
           ret_arp_packet->byte_length_of_protocol_addr);

    return ret_arp_packet;
}

static void show_table()
{
    printf(ARP_LOG_PREFIX "===========================\n");
    for (int i = 0; i < arp_table.current_num; ++i)
    {
        ARP_table_entry *entry = &arp_table.table_entries[i];
        printf(ARP_LOG_PREFIX "%d: %d, %2X.%2X.%2X.%2X.%2X.%2X %d.%d.%d.%d \n", i, entry->protocol_type,
               entry->hardware_address[0], entry->hardware_address[1], entry->hardware_address[2],
               entry->hardware_address[3], entry->hardware_address[4], entry->hardware_address[5],
               entry->protocol_address[0], entry->protocol_address[1], entry->protocol_address[2], entry->protocol_address[3]);
    }
    printf(ARP_LOG_PREFIX "===========================\n");
}

void arp_handler(unsigned char *data, size_t data_length, const char *const ingoing_interface, Mac_address sender_eth_addr)
{
    printf(ARP_LOG_PREFIX "start parsing arp\n");
    ARP_packet_data *arp_packet_data = parse_arp_data(data, data_length);
    printf(ARP_LOG_PREFIX "%2X.%2X.%2X.%2X.%2X.%2X\n", arp_packet_data->sender_hardware_address[0],
           arp_packet_data->sender_hardware_address[1],
           arp_packet_data->sender_hardware_address[2],
           arp_packet_data->sender_hardware_address[3],
           arp_packet_data->sender_hardware_address[4],
           arp_packet_data->sender_hardware_address[5]);
    printf(ARP_LOG_PREFIX "%2X.%2X.%2X.%2X.%2X.%2X\n", arp_packet_data->target_hardware_address[0],
           arp_packet_data->target_hardware_address[1],
           arp_packet_data->target_hardware_address[2],
           arp_packet_data->target_hardware_address[3],
           arp_packet_data->target_hardware_address[4],
           arp_packet_data->target_hardware_address[5]);
    printf(ARP_LOG_PREFIX "%d.%d.%d.%d\n", arp_packet_data->sender_protocol_address[0],
           arp_packet_data->sender_protocol_address[1],
           arp_packet_data->sender_protocol_address[2],
           arp_packet_data->sender_protocol_address[3]);

    printf(ARP_LOG_PREFIX "%d.%d.%d.%d\n", arp_packet_data->target_protocol_address[0],
           arp_packet_data->target_protocol_address[1],
           arp_packet_data->target_protocol_address[2],
           arp_packet_data->target_protocol_address[3]);

    printf(ARP_LOG_PREFIX "finish parsing arp\n");

    if (arp_packet_data->opcode == ARP_OPCODE_REQEUST)
    {
        // 检查是否是本机地址
        for (int i = 0; i < interface_table.current_num; ++i)
        {
            Interface_address_pair *pair = &interface_table.entries[i];
            IPV4_address ipv4_addr;
            int j = 0;
            switch (arp_packet_data->protocol_space)
            {
            case ETHERNET_UPPER_PRTOCOL_IPV4:
                /* code */
                get_ipv4_by_interface(pair->name, ipv4_addr);
                for (j = 0; j < arp_packet_data->byte_length_of_protocol_addr; ++j)
                {
                    if (ipv4_addr[j] != arp_packet_data->target_protocol_address[j])
                        break;
                }
                if (j == arp_packet_data->byte_length_of_protocol_addr)
                {
                    printf(ARP_LOG_PREFIX "ip address is %d.%d.%d.%d\n", ipv4_addr[0], ipv4_addr[1], ipv4_addr[2], ipv4_addr[3]);
                    arp_reply(arp_packet_data, pair->mac_address, sizeof(Mac_address), ingoing_interface, sender_eth_addr);
                }
                break;

            default:
                break;
            }
        }
    }
    else if (arp_packet_data->opcode == ARP_OPCODE_REPLY)
    {
        // 首先检查这个数据项是否已经在表中存在了
        char flag = 0;
        for (int i = 0; i < arp_table.current_num; ++i)
        {
            ARP_table_entry *entry = &arp_table.table_entries[i];
            if (entry->protocol_type != arp_packet_data->protocol_space)
                continue;

            // 判断协议地址是否相同
            if (entry[i].address_length != arp_packet_data->byte_length_of_protocol_addr)
                continue;

            flag = 1;
            for (int j = 0; j < entry[i].address_length; ++j)
                if (entry[i].protocol_address[j] != arp_packet_data->sender_protocol_address[j])
                {
                    flag = 0;
                    break;
                }

            if (!flag)
                continue;

            // hit，replace item
            for (int j = 0; j < entry[i].address_length; ++j)
                entry[i].protocol_address[j] = arp_packet_data->sender_protocol_address[j];

            break;
        }
        if (!flag)
        {
            // 没有命中，新增条目
            ARP_table_entry *new_entry = &arp_table.table_entries[arp_table.current_num++];
            new_entry->address_length = arp_packet_data->byte_length_of_protocol_addr;
            new_entry->protocol_type = arp_packet_data->protocol_space;
            memcpy(new_entry->hardware_address, arp_packet_data->sender_hardware_address, sizeof(Mac_address));
            new_entry->protocol_address = malloc(arp_packet_data->byte_length_of_protocol_addr);
            memcpy(new_entry->protocol_address, arp_packet_data->sender_protocol_address, arp_packet_data->byte_length_of_protocol_addr);
        }
    }

    free(arp_packet_data);

    // show_table();
    return;
}