#include "pkg_sender.h"


uint32_t get_ip_address(const char *interface_name) {
    int sockfd;
    struct ifreq ifr;
    uint32_t ip_addr = 0;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket error");
        return 0; 
    }

    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl error");
        close(sockfd);
        return 0;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    ip_addr = addr->sin_addr.s_addr;  // 返回网络字节序的IP地址

    close(sockfd);
    return ip_addr;
}

static int get_mac_address(const char *interface_name, unsigned char *mac_address) {
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // 使用ioctl获取MAC地址
    ioctl(sockfd, SIOCGIFHWADDR, &ifr);

    memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6 * sizeof(unsigned char));

    close(sockfd);
    return 0;
}


Pkg_sender *pkg_sender_init(const char **dev_names, size_t dev_num) {
    fprintf(stdout, "[SENDER]: start initialize pkg sender\n");
    Pkg_sender *pkg_sender = (Pkg_sender *)malloc(sizeof(Pkg_sender));
    pkg_sender->devices_num = dev_num;
    pkg_sender->devices = (pcap_t **)malloc(sizeof(pcap_t *) * pkg_sender->devices_num);
    pkg_sender->devices_name = (const char **)malloc(sizeof(char *) * pkg_sender->devices_num);
    pkg_sender->devices_mac_addr = (unsigned char **)malloc(sizeof(unsigned *) * pkg_sender->devices_num);

    for (size_t i = 0; i < dev_num; ++i) {
        pkg_sender->devices[i] = pcap_open_live(dev_names[i], BUFSIZ, 1, 1000, NULL);
        pkg_sender->devices_name[i] = dev_names[i];
        pkg_sender->devices_mac_addr[i] = (unsigned char*)malloc(sizeof(unsigned char) * 6);
        get_mac_address(
            pkg_sender->devices_name[i],
            pkg_sender->devices_mac_addr[i]
        );
        printf("[SENDER]: %s mac address is ", pkg_sender->devices_name[i]);
        for (int j = 0; j < 6; j++) {
            printf("%02x", pkg_sender->devices_mac_addr[i][j]);
            if (j < 5) {
                printf(":");
            }
        }
        printf("\n");
    }
    fprintf(stdout, "[SENDER]: successfully initialize pkg sender\n");

    return pkg_sender;
}

Pkg_sender *create_pkg_sender() {
    Pkg_sender *pkg_sender = (Pkg_sender *)malloc(sizeof(Pkg_sender));
    pkg_sender->devices_num = 0;

    pcap_if_t *alldevs;  // 存储找到的设备
    pcap_if_t *device;   // 遍历设备时使用的指针
    char errbuf[PCAP_ERRBUF_SIZE];  // 错误缓冲区

    // 查找所有网络设备
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        // ERR_REPORT_AND_EXIT("无法获取设备列表: \n");
    }

    // 遍历并打印每个设备的信息
    for (device = alldevs; device != NULL; device = device->next) {
        pkg_sender->devices_num ++;
        printf("[SENDER]: %s - %s\n", device->name, device->description ? device->description : "无描述");
    }
    pkg_sender->devices = (pcap_t **)malloc(sizeof(pcap_t *) * pkg_sender->devices_num);
    pkg_sender->devices_name = (const char **)malloc(sizeof(char *) * pkg_sender->devices_num);
    pkg_sender->devices_mac_addr = (unsigned char **)malloc(sizeof(unsigned *) * pkg_sender->devices_num);
    int i = 0;
    for (device = alldevs; device != NULL; device = device->next) {
        pkg_sender->devices[i] = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
        pkg_sender->devices_name[i] = device->name;
        pkg_sender->devices_mac_addr[i] = (unsigned char*)malloc(sizeof(unsigned char) * 6);
        get_mac_address(
            pkg_sender->devices_name[i],
            pkg_sender->devices_mac_addr[i]
        );
        printf("[SENDER]: %s mac address is ", pkg_sender->devices_name[i]);
        for (int j = 0; j < 6; j++) {
            printf("%02x", pkg_sender->devices_mac_addr[i][j]);
            if (j < 5) {
                printf(":");
            }
        }
        printf("\n");
        i++;
    }

    return pkg_sender;
}