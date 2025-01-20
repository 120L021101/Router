#include "udp.h"


Udp_header *parse_udp_header(const unsigned char *data) {
    Udp_header *udp_header = (Udp_header *)malloc(sizeof(Udp_header));
    memset(udp_header, 0, sizeof(Udp_header));

    udp_header->source_port = htons(*(uint16_t *)(data + 0));
    udp_header->destination_port = htons(*(uint16_t *)(data + 2));
    udp_header->length = htons(*(uint16_t *)(data + 4));
    udp_header->checksum = htons(*(uint16_t *)(data + 6));

    fprintf(stdout, "[UDP] SOURCE PORT IS %d\n", udp_header->source_port);
    fprintf(stdout, "[UDP] DESTINATION PORT IS %d\n", udp_header->source_port);
    fprintf(stdout, "[UDP] LENGTH IS %d\n", udp_header->source_port);
    fprintf(stdout, "[UDP] CHECK SUM IS %d\n", udp_header->source_port);

    return udp_header; 
}
