#include "send.h"

static unsigned int calculate_crc32(const u_char *frame, size_t frame_size) {
    return crc32(0, frame, frame_size);
}

void pkg_send_with_null_mac(Pkg_sender *pkg_sender, const u_char *packet, size_t packet_size, 
            uint16_t protocol_type, const char *outgoing_interface) {
    unsigned char source_mac[6];
    unsigned char *dest_addr = (unsigned char *)"\xff\xff\xff\xff\xff\xff";

    size_t frame_size = packet_size + 14;
    unsigned char *frame = (unsigned char*)malloc(frame_size * sizeof(unsigned char));
    memcpy(frame + 14, packet, packet_size);

    // 查找对应网卡的MAC地址
    for (int i = 0; i < pkg_sender->devices_num; ++i) {
        if (strcmp(pkg_sender->devices_name[i], outgoing_interface) == 0) {
            memcpy(source_mac, pkg_sender->devices_mac_addr[i], 6);
            break;
        }
    }

    // 填充帧的源地址和目的地址
    memcpy((u_char *)frame + 0, dest_addr, 6);
    memcpy((u_char *)frame + 6, source_mac, 6);
    *(uint16_t *)(frame + 12) = ntohs(protocol_type);

    for (int i = 0; i < pkg_sender->devices_num; ++i) {
        if (strcmp(pkg_sender->devices_name[i], outgoing_interface) == 0) {
            fprintf(stdout, "[SENDER]: successfully sent null broadcast\n");
            pcap_inject(pkg_sender->devices[i], frame, frame_size);
            break;
        }
    }
    free(frame);
}

void pkg_send_myself(Pkg_sender *pkg_sender, const u_char *packet, size_t packet_size, uint16_t protocol_type,
               const char *outgoing_interface, unsigned char *src_mac_addr, unsigned char *dest_mac_addr) {
    unsigned char *dest_addr;

    size_t frame_size = packet_size + 14;
    unsigned char *frame = (unsigned char*)malloc(frame_size * sizeof(unsigned char));
    memcpy(frame + 14, packet, packet_size);

    // 设置目的地址
    unsigned char is_broadcast = dest_mac_addr == NULL;
    if (is_broadcast) {
        dest_addr = (unsigned char *)"\xff\xff\xff\xff\xff\xff"; // 广播 MAC 地址
    } else {
        dest_addr = dest_mac_addr;
    }

    // 填充帧的源地址和目的地址
    memcpy((u_char *)frame + 0, dest_addr, 6);
    memcpy((u_char *)frame + 6, src_mac_addr, 6);
    *(uint16_t *)(frame + 12) = ntohs(protocol_type);

    // 计算校验和并填充
    // unsigned int crc = calculate_crc32(frame, frame_size - 4); // 计算前 4 字节未填充 CRC
    // memcpy((u_char *)frame + frame_size - 4, &crc, 4); // 填充 CRC 校验和

    for (int i = 0; i < pkg_sender->devices_num; ++i) {
        if (!is_broadcast && strcmp(pkg_sender->devices_name[i], outgoing_interface) == 0) {
            fprintf(stdout, "[SENDER]: successfully sent\n");
            pcap_inject(pkg_sender->devices[i], frame, frame_size);
            break;
        }
        if (is_broadcast && strcmp(pkg_sender->devices_name[i], outgoing_interface)) {
            fprintf(stdout, "[SENDER]: successfully broadcast\n");
            pcap_inject(pkg_sender->devices[i], frame, frame_size);
            continue;
        }
    }
    free(frame);           
}

void pkg_send(Pkg_sender *pkg_sender, const u_char *packet, size_t packet_size, uint16_t protocol_type, 
               const char *outgoing_interface, unsigned char *dest_mac_addr) {
    unsigned char source_mac[6];
    unsigned char *dest_addr;

    size_t frame_size = packet_size + 14;
    unsigned char *frame = (unsigned char*)malloc(frame_size * sizeof(unsigned char));
    memcpy(frame + 14, packet, packet_size);

    // 查找对应网卡的MAC地址
    for (int i = 0; i < pkg_sender->devices_num; ++i) {
        if (strcmp(pkg_sender->devices_name[i], outgoing_interface) == 0) {
            memcpy(source_mac, pkg_sender->devices_mac_addr[i], 6);
            break;
        }
    }
    // 设置目的地址
    unsigned char is_broadcast = dest_mac_addr == NULL;
    if (is_broadcast) {
        dest_addr = (unsigned char *)"\xff\xff\xff\xff\xff\xff"; // 广播 MAC 地址
    } else {
        dest_addr = dest_mac_addr;
    }

    // 填充帧的源地址和目的地址
    memcpy((u_char *)frame + 0, dest_addr, 6);
    memcpy((u_char *)frame + 6, source_mac, 6);
    *(uint16_t *)(frame + 12) = ntohs(protocol_type);

    // 计算校验和并填充
    // unsigned int crc = calculate_crc32(frame, frame_size - 4); // 计算前 4 字节未填充 CRC
    // memcpy((u_char *)frame + frame_size - 4, &crc, 4); // 填充 CRC 校验和

    for (int i = 0; i < pkg_sender->devices_num; ++i) {
        if (!is_broadcast && strcmp(pkg_sender->devices_name[i], outgoing_interface) == 0) {
            fprintf(stdout, "[SENDER]: successfully sent\n");
            pcap_inject(pkg_sender->devices[i], frame, frame_size);
            break;
        }
        if (is_broadcast && strcmp(pkg_sender->devices_name[i], outgoing_interface)) {
            fprintf(stdout, "[SENDER]: successfully broadcast\n");
            pcap_inject(pkg_sender->devices[i], frame, frame_size);
            continue;
        }
    }
    free(frame);
}