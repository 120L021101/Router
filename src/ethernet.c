#include "ethernet.h"

#define ETHERNET_LOG_PREFIX "[ETHERNET]: "

extern Interface_table interface_table;

static int send_packet(const unsigned char *packet, int len, const char *interface_name)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 打开网络接口 eth0
    handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Error opening device %s: %s\n", interface_name, errbuf);
        return -1;
    }

    // 发送数据包
    if (pcap_sendpacket(handle, packet, len) != 0)
    {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    printf("Packet sent successfully on interface %s\n", interface_name);

    // 关闭 pcap 句柄
    pcap_close(handle);
    return 0;
}

void broadcast_ethernet(const unsigned char *const data, size_t data_size, uint16_t protocol_type)
{
    unsigned char *ethernet_frame = (unsigned char *)malloc(14 + data_size);

    // 设置目标地址
    memset(ethernet_frame, 0xFF, sizeof(Mac_address));

    // 设置协议号
    *(uint16_t *)(ethernet_frame + 2 * sizeof(Mac_address)) = htons(protocol_type);

    // 拷贝负载
    memcpy(ethernet_frame + 14, data, data_size);

    for (int i = 0; i < interface_table.current_num; ++i)
    {
        const char *interface_name = interface_table.entries[i].name;
        const Mac_address *src_addr = &interface_table.entries[i].mac_address;
        if (!strcmp("lo", interface_name))
            continue;
        // 设置源地址
        memcpy(ethernet_frame + sizeof(Mac_address), *src_addr, sizeof(Mac_address));
        send_packet(ethernet_frame, 14 + data_size, interface_name);
    }
}