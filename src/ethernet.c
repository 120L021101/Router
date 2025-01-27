#include "ethernet.h"

#define ETHERNET_LOG_PREFIX "[ETHERNET]: "

extern Interface_table interface_table;

Ethernet_handler_table ethernet_handler_table;

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
    // 关闭 pcap 句柄
    pcap_close(handle);
    return 0;
}

void broadcast_ethernet(const unsigned char *const data, size_t data_size, uint16_t protocol_type, const char *const ingoing_interface)
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
        if (!strcmp("lo", interface_name) || (ingoing_interface && !strcmp(ingoing_interface, interface_name)))
            continue;
        // 设置源地址
        memcpy(ethernet_frame + sizeof(Mac_address), *src_addr, sizeof(Mac_address));
        send_packet(ethernet_frame, 14 + data_size, interface_name);
    }

    free(ethernet_frame);
}

void send_via_ethernet(const char *const interface, const Mac_address *const dst_addr,
                       const unsigned char *const data, size_t data_size, uint16_t protocol_type)
{
    unsigned char *ethernet_frame = (unsigned char *)malloc(14 + data_size);

    // 设置目标地址
    memcpy(ethernet_frame, *dst_addr, sizeof(Mac_address));

    // 设置协议号
    *(uint16_t *)(ethernet_frame + 2 * sizeof(Mac_address)) = htons(protocol_type);

    // 拷贝负载
    memcpy(ethernet_frame + 14, data, data_size);

    for (int i = 0; i < interface_table.current_num; ++i)
    {
        const char *interface_name = interface_table.entries[i].name;
        const Mac_address *src_addr = &interface_table.entries[i].mac_address;
        if (!strcmp("lo", interface_name) || strcmp(interface_name, interface))
            continue;
        // 设置源地址
        memcpy(ethernet_frame + sizeof(Mac_address), *src_addr, sizeof(Mac_address));
        send_packet(ethernet_frame, 14 + data_size, interface_name);
        break;
    }
}

void register_frame_handler(uint16_t protocol_type, void (*handler)(unsigned char *, size_t, const char *const, Mac_address))
{
    uint32_t num = ethernet_handler_table.current_num;
    ethernet_handler_table.entries[num].protocol_type = protocol_type;
    ethernet_handler_table.entries[num].handler = handler;
    ethernet_handler_table.current_num = num + 1;
}

static Ethernet_packet *parse_ethernet(const unsigned char *packet, size_t packet_length)
{
    Ethernet_packet *ethernet_packet = malloc(sizeof(Ethernet_packet));

    memcpy(ethernet_packet->dst_address, packet, 6);
    memcpy(ethernet_packet->src_address, packet + 6, 6);
    ethernet_packet->protocol = ntohs(*(uint16_t *)(packet + 12));
    ethernet_packet->data = packet + 14;
    ethernet_packet->data_length = packet_length - 14;

    // printf(ETHERNET_LOG_PREFIX "protocol is: %2X\n", ethernet_packet->protocol);

    return ethernet_packet;
}

// 判断两个mac地址是否相同
static char ethernet_addr_equal(const Mac_address *const mac1, const Mac_address *const mac2)
{
    for (int i = 0; i < 6; ++i)
    {
        if ((*mac1)[i] != (*mac2)[i])
            return 0;
    }
    return 1;
}

static char is_broadcast(const Mac_address *const mac_addr)
{
    for (int i = 0; i < 6; ++i)
    {
        if ((*mac_addr)[i] != 0xFF)
            return 0;
    }
    return 1;
}

static char if_send_to_me_explicitly(const Mac_address *const mac_addr)
{
    for (int i = 0; i < interface_table.current_num; ++i)
    {
        Interface_address_pair *entry = &interface_table.entries[i];
        if (ethernet_addr_equal(&entry->mac_address, mac_addr))
            return 1;
    }
    return 0;
}

static char if_me_sent_frame(const Mac_address *const mac_addr)
{
    return if_send_to_me_explicitly(mac_addr);
}

// 处理数据包的回调函数
static void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    Ethernet_packet *ethernet_packet = parse_ethernet(packet, pkthdr->len);

    // 过滤掉不发给自己的数据包
    // 1. 自己发的，肯定不是发给自己的
    if (if_me_sent_frame(&ethernet_packet->src_address))
    {
        return;
    }
    // 2. 如果不是广播地址，判断一下是否是发给自己的
    else if (!is_broadcast(&ethernet_packet->dst_address) &&
             !if_send_to_me_explicitly(&ethernet_packet->dst_address))
    {
        return;
    }
    // 3. 如果是广播地址，那么首先需要把这个给广播出去再处理
    else if (is_broadcast(&ethernet_packet->dst_address))
    {
        broadcast_ethernet(ethernet_packet->data, ethernet_packet->data_length, ethernet_packet->protocol, user);
    }

    printf(ETHERNET_LOG_PREFIX "[接口: %s] 捕获到数据包！长度: %d 字节\n", (char *)user, pkthdr->len);

    printf(ETHERNET_LOG_PREFIX "captured packet protocol is: %d\n", ethernet_packet->protocol);
    for (int i = 0; i < ethernet_handler_table.current_num; ++i)
    {
        if (ethernet_handler_table.entries[i].protocol_type == ethernet_packet->protocol)
        {
            ethernet_handler_table.entries[i].handler(
                ethernet_packet->data,
                ethernet_packet->data_length,
                user, ethernet_packet->src_address);
            break;
        }
    }
    printf("---------------------------------\n");
}

// 每个线程监听一个接口
static void *interface_listener(void *arg)
{
    char *dev = (char *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    // 进入捕获循环，永久循环
    pcap_loop(handle, -1, packet_handler, (unsigned char *)dev);

    pcap_close(handle);
    return NULL;
}

// 监听所有网络接口
void listen_interfaces(const char **const interfaces, uint32_t interface_num)
{
    pthread_t threads[100];
    char *dev_names[100];
    int i = 0;

    for (i = 0; i < interface_table.current_num; ++i)
    {
        dev_names[i] = interface_table.entries[i].name;
        if (!strcmp("lo", dev_names[i]))
            continue;

        for (int j = 0; j < interface_num; ++j)
        {
            if (!strcmp(dev_names[i], interfaces[j]))
            {
                printf(ETHERNET_LOG_PREFIX "starts listening %s\n", dev_names[i]);
                pthread_create(&threads[i], NULL, interface_listener, dev_names[i]);
                break;
            }
        }
    }

    // for (int j = 0; j < i; j++)
    // {
    //     pthread_join(threads[j], NULL);
    // }
}