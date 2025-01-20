#include "tcp.h"

Tcp_packet *parse_tcp_packet(const unsigned char *data, size_t data_length) {
    Tcp_packet *tcp_packet = (Tcp_packet *)malloc(sizeof(Tcp_packet));
    memset(tcp_packet, 0, sizeof(Tcp_packet));

    tcp_packet->source_port         = htons(*(uint16_t *)(data + 0));    
    tcp_packet->destination_port    = htons(*(uint16_t *)(data + 2));    
    tcp_packet->sequence_number     = ntohl(*(uint32_t *)(data + 4)); // 使用 ntohl 而非 swap
    tcp_packet->ack_number          = ntohl(*(uint32_t *)(data + 8)); 
    tcp_packet->data_offset         = (data[12] >> 4); // 只提取高 4 位
    tcp_packet->reserved            = data[12] & 0x0E;
    tcp_packet->flags               = data[13]; // 暂时不要URG了
    tcp_packet->window_size         = htons(*(uint16_t *)(data + 14));
    tcp_packet->checksum            = htons(*(uint16_t *)(data + 16));
    tcp_packet->urgent_pointer      = htons(*(uint16_t *)(data + 18)); 

    // 计算 header_length，单位为字节
    size_t header_length = tcp_packet->data_offset * 4;
    if (header_length == 20) {
        tcp_packet->options = NULL;
    } else {
        tcp_packet->options = (unsigned char *)malloc(sizeof(unsigned char) * 
                                                    (header_length - 20));  
        memcpy(tcp_packet->options, data + 20, (header_length - 20) * sizeof(unsigned char));
    }
    if (data_length - header_length == 0) {
        tcp_packet->data = NULL; 
    } else {
        tcp_packet->data = malloc(sizeof(unsigned char) * (data_length - header_length));
        memcpy(tcp_packet->data, data + header_length, data_length - header_length);
    }

    fprintf(stdout, "[TCP] SOURCE PORT IS %d\n", tcp_packet->source_port);
    fprintf(stdout, "[TCP] DESTINATION PORT IS %d\n", tcp_packet->destination_port);
    fprintf(stdout, "[TCP] SEQUENCE NUMBER IS %d\n", tcp_packet->sequence_number);
    fprintf(stdout, "[TCP] ACK NUMBER IS %d\n", tcp_packet->ack_number);
    fprintf(stdout, "[TCP] HEADER LENGTH IS %ld\n", header_length);
    fprintf(stdout, "[TCP] DATA LENTGH IS %ld \n", data_length - header_length);

    return tcp_packet;
}
