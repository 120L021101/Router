#include "pkg_rcver.h"
#include "err.h"


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

Pkg_receiver *pkg_rcver_init(const char **dev_names, size_t dev_num) {
    Pkg_receiver *pkg_receiver = (Pkg_receiver *)malloc(sizeof(Pkg_receiver));
    pkg_receiver->devices_num = dev_num;
    pkg_receiver->devices = (pcap_t **)malloc(sizeof(pcap_t *) * dev_num);
    pkg_receiver->devices_name = (const char **)malloc(sizeof(const char *) * dev_num);
    fprintf(stdout, "[RECEIVER]: start initialize pkg receiver\n");
    for (size_t i = 0; i < dev_num; ++i) {
        pkg_receiver->devices[i] = pcap_open_live(dev_names[i], BUFSIZ, 1, 1000, NULL);
        pkg_receiver->devices_name[i] = dev_names[i];
        IFERR_REPORT_AND_EXIT(pkg_receiver->devices[i], "无法打开设备");
        printf("[RECEIVER]: opened %s successfully\n", dev_names[i]);
    }
    fprintf(stdout, "[RECEIVER]: successfully initialize pkg receiver\n");
    return pkg_receiver;
}

unsigned char filter_package(Pkg_receiver *pkg_receiver, ethernet_frame *eth_frame) {
    // 检验是否是本机发送的报文
    for (int i = 0; i < pkg_receiver->devices_num; ++i) {
        unsigned char is_same = 1;
        unsigned char device_mac_addr[6];
        get_mac_address(pkg_receiver->devices_name[i], device_mac_addr);
        for (int j = 0; j < 6; ++j) {
            if (device_mac_addr[i] != eth_frame->src_mac[i]) {
                is_same = 0;
                break;
            }
        }
        if (is_same) {
            return 0;
        }
    }
    return 1;
}

// pcap_t * pkg_rcver_init() {
//     pcap_if_t *alldevs;  // 存储找到的设备
//     pcap_if_t *device;   // 遍历设备时使用的指针
//     char errbuf[PCAP_ERRBUF_SIZE];  // 错误缓冲区

//     // 查找所有网络设备
//     if (pcap_findalldevs(&alldevs, errbuf) == -1) {
//         fprintf(stderr, "无法获取设备列表: %s\n", errbuf);
//         exit(-1);
//     }

//     // 遍历并打印每个设备的信息
//     printf("找到的网络设备:\n");
//     for (device = alldevs; device != NULL; device = device->next) {
//         printf("%s - %s\n", device->name, device->description ? device->description : "无描述");
//     }

//     pcap_t *handle = pcap_open_live(alldevs->next->next->name, BUFSIZ, 1, 1000, errbuf);
//     if (handle == NULL) {
//         fprintf(stderr, "无法打开设备 %s: %s\n", alldevs->next->next->name, errbuf);
//         pcap_freealldevs(alldevs);
//         exit(-1);
//     }


//     // struct bpf_program fp;
//     // char filter_exp[] = "ip and inbound";  // 过滤表达式
//     // if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
//     //     fprintf(stderr, "无法编译过滤器 %s: %s\n", filter_exp, pcap_geterr(handle));
//     //     pcap_freealldevs(alldevs);
//     //     pcap_close(handle);
//     //     exit(-1);
//     // }
//     // if (pcap_setfilter(handle, &fp) == -1) {
//     //     fprintf(stderr, "无法设置过滤器 %s: %s\n", filter_exp, pcap_geterr(handle));
//     //     pcap_freealldevs(alldevs);
//     //     pcap_close(handle);
//     //     exit(-1);
//     // }

//     // pcap_freecode(&fp); // 释放已编译的过滤器


//     // // 释放设备列表
//     // pcap_freealldevs(alldevs);
//     return handle;



//     // pcap_t *handle;
//     // char *dev;
//     // char errbuf[PCAP_ERRBUF_SIZE];

//     // dev = pcap_lookupdev(errbuf);
//     // IFERR_REPORT_AND_EXIT(dev, "无法找到设备");

//     // handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
//     // IFERR_REPORT_AND_EXIT(handle, "无法打开设备");

//     // return handle;
// }