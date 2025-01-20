#include "ipv4.h"

static uint32_t get_device_ip(const char *device_name) {
    struct ifaddrs *ifaddr, *ifa;
    uint32_t ip_address = 0; // 初始化为0，表示未找到地址

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 0; // 返回0表示错误
    }

    // 遍历所有接口
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        // 只处理活动的IPv4接口
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && 
                strcmp(ifa->ifa_name, device_name) == 0) {
            // 将IP地址转换为uint32_t
            ip_address = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
            break; // 找到地址后退出循环
        }
    }

    freeifaddrs(ifaddr);
    return ip_address; // 返回uint32_t类型的IP地址
}

ipv4_header *parse_ipv4_frame(const ethernet_frame* const eth_frame) {

    ipv4_header *header = (ipv4_header *)malloc(sizeof(ipv4_header));
    memcpy(header, eth_frame->payload, sizeof(ipv4_header));

    // 提取并打印各个字段
    // printf("Version: %u\n", header->version);
    // printf("IHL: %u (header length: %u bytes)\n", header->ihl, header->ihl * 4);
    // printf("Type of Service: %u\n", header->tos);
    // printf("Total Length: %u\n", ntohs(header->total_length));
    // printf("Identification: %u\n", ntohs(header->identification));
    // printf("Flags and Fragment Offset: %u\n", ntohs(header->flags_offset));
    printf("[IPV4] Time to Live: %u\n", header->ttl);
    printf("[IPV4] Protocol: %u\n", header->protocol);
    printf("[IPV4] Header Checksum: %u\n", ntohs(header->checksum));
    printf("[IPV4] Source IP Address: %u.%u.%u.%u\n",
           header->src_addr & 0xFF,
           (header->src_addr >> 8) & 0xFF,
           (header->src_addr >> 16) & 0xFF,
           (header->src_addr >> 24) & 0xFF);
    printf("[IPV4] Destination IP Address: %u.%u.%u.%u\n",
           header->dest_addr & 0xFF,
           (header->dest_addr >> 8) & 0xFF,
           (header->dest_addr >> 16) & 0xFF,
           (header->dest_addr >> 24) & 0xFF);

    return header;
}

static uint32_t swap_endian(uint32_t ip_addr) {
    return (ip_addr & 0xFF) << 24 |
            (ip_addr & 0xFF00) << 8 |
            (ip_addr & 0xFF0000) >> 8 |
            (ip_addr & 0xFF000000) >> 24;
}

void add_ipv4_arp_entry(Ipv4_arp_table *ipv4_arp_table, uint32_t dest_ip_addr, unsigned char *dest_mac_addr) {
    dest_ip_addr = swap_endian(dest_ip_addr);
    // 尝试更新
    for (size_t i = 0; i < ipv4_arp_table->count; ++i) {
        if (ipv4_arp_table->entries[i]->dest_ip_addr == dest_ip_addr) {
            memcpy(ipv4_arp_table->entries[i]->dest_mac_addr, dest_mac_addr, sizeof(unsigned char) * 6);
            return;
        }
    }
    
    Ipv4_arp_entry *ipv4_arp_entry = (Ipv4_arp_entry *)malloc(sizeof(Ipv4_arp_entry));
    ipv4_arp_entry->dest_ip_addr = dest_ip_addr;
    memcpy(ipv4_arp_entry->dest_mac_addr, dest_mac_addr, sizeof(unsigned char) * 6);
    ipv4_arp_table->entries[ipv4_arp_table->count ++] = ipv4_arp_entry;
}

unsigned char *find_ipv4_mac_byarp(Ipv4_arp_table *ipv4_arp_table, uint32_t dest_ip_addr) {
    dest_ip_addr = swap_endian(dest_ip_addr);
    fprintf(stdout, "[ARP]: start searching %d.%d.%d.%d in %ld items\n", 
        (dest_ip_addr & 0xFF000000) >> 24, (dest_ip_addr & 0xFF0000) >> 16,
        (dest_ip_addr & 0xFF00) >> 8, dest_ip_addr & 0xFF, ipv4_arp_table->count);
        
    show_ipv4_arp_table(ipv4_arp_table);
    for (size_t i = 0; i < ipv4_arp_table->count; ++i) {
        // fprintf(stdout, "%u %u\n", ipv4_arp_table->entries[i]->dest_ip_addr, dest_ip_addr);
        if (ipv4_arp_table->entries[i]->dest_ip_addr == dest_ip_addr) {
            return ipv4_arp_table->entries[i]->dest_mac_addr;
        }
    }
    return NULL;
}

Ipv4_arp_table *create_ipv4_arp_table(Pkg_sender *pkgsender) {
    Ipv4_arp_table *ipv4_arp_table = (Ipv4_arp_table *)malloc(sizeof(Ipv4_arp_table));
    ipv4_arp_table->count = 0;
    for (size_t i = 0; i < pkgsender->devices_num; ++i) {
        Ipv4_arp_entry *ipv4_arp_entry = (Ipv4_arp_entry *)malloc(sizeof(Ipv4_arp_entry));
        memcpy(ipv4_arp_entry->dest_mac_addr, pkgsender->devices_mac_addr[i], 6);
        ipv4_arp_entry->dest_ip_addr = get_device_ip(pkgsender->devices_name[i]);
        add_ipv4_arp_entry(ipv4_arp_table, get_device_ip(pkgsender->devices_name[i]),
                             pkgsender->devices_mac_addr[i]);
    }
    fprintf(stdout, "[ARP]: create ipv4 arp table successfully, items count: %ld\n", pkgsender->devices_num);
    show_ipv4_arp_table(ipv4_arp_table);

    return ipv4_arp_table;
}


void show_ipv4_arp_table(Ipv4_arp_table *ipv4_arp_table) {
    if (ipv4_arp_table == NULL) {
        return ;
    }
    for (int i = 0; i < ipv4_arp_table->count; ++i) {
        uint32_t ip_addr = ipv4_arp_table->entries[i]->dest_ip_addr;
        printf("[ARP_TABLE]: %d.%d.%d.%d\t\t", (ip_addr & 0xFF000000) >> 24,
                                    (ip_addr & 0x00FF0000) >> 16,
                                    (ip_addr & 0x0000FF00) >> 8,
                                    ip_addr & 0xFF);

        unsigned char *dest_mac_addr = ipv4_arp_table->entries[i]->dest_mac_addr;

        // 打印MAC地址
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
            dest_mac_addr[0], dest_mac_addr[1], dest_mac_addr[2],
            dest_mac_addr[3], dest_mac_addr[4], dest_mac_addr[5]);
    }
}

unsigned char if_ipv4_send_to_myself(Pkg_receiver *pkg_receiver, uint32_t dest_ipv4_addr) {
    for (size_t i = 0; i < pkg_receiver->devices_num; ++i) {
        if (dest_ipv4_addr == get_device_ip(pkg_receiver->devices_name[i])) {
            return 1;
        }
    }
    return 0;
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

size_t construct_ipv4_hdr(unsigned char *ipv4_packet, ipv4_header *input_hdr) {
    ipv4_header ipv4_hdr;
    memset(&ipv4_hdr, 0, sizeof(ipv4_header));
    memcpy(&ipv4_hdr, input_hdr, sizeof(ipv4_header));
    ipv4_hdr.ttl -= 1;
    if (ipv4_hdr.ttl == 0) {
        return 0;
    }
    ipv4_hdr.checksum = 0;
    ipv4_hdr.checksum = compute_ipv4_checksum(&ipv4_hdr);
    memcpy(ipv4_packet, &ipv4_hdr, sizeof(ipv4_header));
    return sizeof(ipv4_header);
}