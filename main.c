#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <pthread.h>

// 初始化配置
#include "route_init.h"

// 接收器
#include "pkg_rcver.h"
#include "ethernet.h"
#include "ipv4.h"
#include "arpv4.h"
#include "icmpv4.h"
#include "udp.h"
#include "tcp.h"

// 转发平面
#include "ipv4_table.h"

// 中央处理单元, 回环目的地
#include "icmpv4_handle.h"
#include "tcp_handle.h"
#include "pcep_handle.h"

// 发送器
#include "pkg_sender.h"
#include "send.h"

static const char *get_dev_name_from_index(unsigned int index);

static IPv4RoutingTable *ipv4RoutingTable = NULL;
static Pkg_receiver *pkg_receiver = NULL;
static Pkg_sender *pkg_sender = NULL;
static Ipv4_arp_table *ipv4_arp_table = NULL;
static Tcp_handler *tcp_handler = NULL;

static void TableInit() {
    ipv4RoutingTable = create_ipv4_routing_table();
    tcp_handler = create_tcp_handler();
    // 未来扩展其它表
}

static void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("[MAIN]: 捕获到数据包，长度: %d\n", header->len);
    ethernet_frame *eth_frame = parse_ethernet_frame(packet, header->len);

    //过滤掉不发送给自己的帧
    if (!filter_package(pkg_receiver, eth_frame)) {
        return;
    }
    ipv4_header *ipv4_hdr = NULL;
    Arp_header *arp_header = NULL;
    Icmpv4_packet *icmpv4_packet = NULL;
    Udp_header *udp_header = NULL; 
    Tcp_packet *tcp_packet = NULL;
    // pcap_t *handle = (pcap_t *)args;
    unsigned int receiver_index = *(unsigned int *)args;
    // 构造ipv4_packet报文
    unsigned char sent_ipv4_packet[header->len - 14];
    switch (eth_frame->ether_type) {
    case 0x0800:
        ipv4_hdr = parse_ipv4_frame(eth_frame);
        // arp 自学习
        add_ipv4_arp_entry(ipv4_arp_table, ipv4_hdr->src_addr, eth_frame->src_mac);
        show_ipv4_arp_table(ipv4_arp_table);

        // 是否回环?
        unsigned char if_loopback = if_ipv4_send_to_myself(pkg_receiver, ipv4_hdr->dest_addr);
        fprintf(stdout, "[IPv4] upper protocol is %d\n", ipv4_hdr->protocol);
        switch (ipv4_hdr->protocol) {
        // 处理ICMPv4
        case 1:

            icmpv4_packet = parse_icmpv4_packet(packet + 14 + 20, header->len - 14 - 20);

            if (if_loopback) {
                process_icmpv4_packet(pkg_sender, icmpv4_packet, ipv4_hdr, 
                        get_dev_name_from_index(receiver_index), eth_frame->src_mac);
                goto packet_handler_end;
            } else {

            }
            break;
        // 处理TCP
        case 6:
            tcp_packet = parse_tcp_packet(packet + 14 + 20, header->len - 14 - 20);
            
            if (if_loopback) {
                fprintf(stdout, "[MAIN]: IS TCP LOOBACK\n");
                process_tcp_packet(tcp_handler, ipv4RoutingTable, ipv4_arp_table, 
                                    pkg_sender, ipv4_hdr, tcp_packet);
                goto packet_handler_end;
            } else {

            }

            break;

        // 处理UDP
        case 17:
            udp_header = parse_udp_header(packet + 14 + 20);
            if (if_loopback) {
                // 暂不处理
                goto packet_handler_end;
            } else {

            }
            break;
        default:
            break;
        }
        // 查表转发
        IPv4RouteEntry *ipv4RouteEntry = lookup_route(ipv4RoutingTable, ipv4_hdr->dest_addr);

        unsigned char* dest_mac_addr = find_ipv4_mac_byarp(ipv4_arp_table, ipv4_hdr->dest_addr);
        if (dest_mac_addr == NULL) {
            for (size_t i = 0; i < pkg_sender->devices_num; ++i) {
                Arp_header *arp_header = request_ipv4_mac_addr(get_ip_address(pkg_sender->devices_name[i]),
                    pkg_sender->devices_mac_addr[i], ipv4_hdr->dest_addr);
                
                unsigned char arp_packet[28];
                construct_arpv4_packet(arp_header, arp_packet);
                pkg_send_with_null_mac(pkg_sender, arp_packet, 28, 0x0806, 
                                            pkg_sender->devices_name[i]);
                free(arp_header);
            }
            // 找不到目的mac, 运行arp
            fprintf(stdout, "[MAIN_IPV4]: Not Resent and Reprocess!\n");
            // 发给自己
            pkg_send_myself(pkg_sender, packet + 14, header->len - 14, 0x0800, 
                        get_dev_name_from_index(receiver_index), eth_frame->src_mac, eth_frame->dest_mac);
            goto packet_handler_end;
            return ;
        }
        construct_ipv4_hdr(sent_ipv4_packet, ipv4_hdr);
        memcpy(sent_ipv4_packet + 20, packet + 14 + 20, header->len - 14 - 20);
        pkg_send(pkg_sender, sent_ipv4_packet, header->len - 14, 0x0800, 
                    ipv4RouteEntry->outgoing_interface, dest_mac_addr);
        break;
    case 0x0806:
        arp_header = parse_arp_header(eth_frame);
        fprintf(stdout, "[ARP PRO]: sender mac addr is %02X-%02X-%02X-%02X-%02X-%02X\n",
                    arp_header->sender_hardware_addr[0], arp_header->sender_hardware_addr[1],
                    arp_header->sender_hardware_addr[2], arp_header->sender_hardware_addr[3],
                    arp_header->sender_hardware_addr[4], arp_header->sender_hardware_addr[5]);
                    
        fprintf(stdout, "[ARP PRO]: target mac addr is %02X-%02X-%02X-%02X-%02X-%02X\n",
                    arp_header->target_hardware_addr[0], arp_header->target_hardware_addr[1],
                    arp_header->target_hardware_addr[2], arp_header->target_hardware_addr[3],
                    arp_header->target_hardware_addr[4], arp_header->target_hardware_addr[5]);

        fprintf(stdout, "[ARP PRO]: sender ip addr is %d.%d.%d.%d\n",
                    (arp_header->sender_protocol_addr & 0xFF000000) >> 24,
                    (arp_header->sender_protocol_addr & 0x00FF0000) >> 16,
                    (arp_header->sender_protocol_addr & 0x0000FF00) >> 8,
                    (arp_header->sender_protocol_addr & 0x000000FF));

        fprintf(stdout, "[ARP PRO]: target ip addr is %d.%d.%d.%d\n",
                    (arp_header->target_protocol_addr & 0xFF000000) >> 24,
                    (arp_header->target_protocol_addr & 0x00FF0000) >> 16,
                    (arp_header->target_protocol_addr & 0x0000FF00) >> 8,
                    (arp_header->target_protocol_addr & 0x000000FF));

        unsigned char arp_packet[28];
        // arp 自学习
        if (is_arpv4_reply(arp_header))
            add_ipv4_arp_entry(ipv4_arp_table, arp_header->target_protocol_addr, arp_header->target_hardware_addr);

        add_ipv4_arp_entry(ipv4_arp_table, arp_header->sender_protocol_addr, arp_header->sender_hardware_addr);
        show_ipv4_arp_table(ipv4_arp_table);

        unsigned char succ = 0;
        if (!is_arpv4_reply(arp_header)) 
            succ = fill_if_contains_arp(ipv4_arp_table, arp_header);
        
        construct_arpv4_packet(arp_header, arp_packet);
        pkg_send(pkg_sender, arp_packet, 28, 0x0806,
                    get_dev_name_from_index(receiver_index), succ ? eth_frame->src_mac : NULL);

        break;
    }
packet_handler_end:;
    free(eth_frame);
    if (ipv4_hdr) free(ipv4_hdr);
    if (arp_header) free(arp_header);
    if (udp_header) free(udp_header);
    if (tcp_packet) free(tcp_packet);
}

// 捕获数据包的线程函数
void *capture_packets(void *arg) {
    unsigned int receiver_index = *(unsigned int *)arg; 
    // pcap_t *handle = (pcap_t *)arg;
    pcap_loop(pkg_receiver->devices[receiver_index], 100, packet_handler, arg); // 传递接口索引
}

int main(int argc, char *argv[]) {

    int i;
    int devs_index = -1;
    int crt_index = -1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-devs") == 0) {
            devs_index = i + 1; // 记录-devs后一个位置
        }
        if (strcmp(argv[i], "-crt") == 0) {
            crt_index = i + 1; // 记录-crt后一个位置
        }
    }


    TableInit();
    init_rcp_pcep();

    // 检查是否有设备
    if (devs_index == -1 || devs_index >= argc || crt_index == -1 || crt_index >= argc) {
        printf("[USAGE]: 请提供设备名称，例如: -devs eth0 veth1\n");
        printf("[USAGE]: 请提供默认路由配置，例如: -crt router1.json\n");
        return 1;
    }

    config_ipv4_table(ipv4RoutingTable, argv[crt_index]);

    // pcap_t *handles[10];
    size_t dev_num = argc - devs_index;
    pthread_t threads[10]; 

    // pkg_rcver_init(handles, (const char**)argv + devs_index, dev_num);
    pkg_receiver = pkg_rcver_init((const char**)argv + devs_index, dev_num);
    pkg_sender = pkg_sender_init((const char**)argv + devs_index, dev_num);
    ipv4_arp_table = create_ipv4_arp_table(pkg_sender);
    show_ipv4_arp_table(ipv4_arp_table);

    // 创建线程并发捕获多个接口
    for (i = 0; i < dev_num; i++) {
        pthread_create(&threads[i], NULL, capture_packets, &i);
    }

    for (i = 0; i < dev_num; i++) {
        pthread_join(threads[i], NULL);
        // pcap_close(handles[i]); // 关闭句柄
    }

    return 0;
}

const char *get_dev_name_from_index(unsigned int index) {
    fprintf(stdout, "[ARP]: in dev name is %s\n", pkg_receiver->devices_name[index]);
    return pkg_receiver->devices_name[index];
}