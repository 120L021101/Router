#include "icmpv4.h"


static struct icmp_header *parse_icmpv4_header_packet(const unsigned char *packet) {
    struct icmp_header *icmp_hdr = (struct icmp_header *)malloc(sizeof(struct icmp_header));

    icmp_hdr->type = *(uint8_t *)packet;
    icmp_hdr->code = *(uint8_t *)(packet + 1);
    icmp_hdr->checksum = *(uint16_t *)(packet + 2);
    
    return icmp_hdr;
}

static struct icmp_echo *parse_icmpv4_echo_packet(const unsigned char *packet) {
    const unsigned char *packet_start = packet + 4;
    struct icmp_echo *echo = (struct icmp_echo*)malloc(sizeof(struct icmp_echo));

    echo->id = ntohs(*(uint16_t *)packet_start);
    echo->sequence = ntohs(*(uint16_t *)(packet_start + 2));

    echo->data = (unsigned char *)malloc(sizeof(unsigned char) * 56);

    memcpy(echo->data, packet_start + 4, 56 * sizeof(unsigned char));
    echo->data_length = 56;
    
    return echo;
}

Icmpv4_packet *parse_icmpv4_packet(const unsigned char *packet, size_t packet_size) {
    Icmpv4_packet *icpmv4_packet = (Icmpv4_packet *)malloc(sizeof(Icmpv4_packet));

    icpmv4_packet->header = *parse_icmpv4_header_packet(packet);
    fprintf(stdout, "[ICMPv4]: type is: %d\n", icpmv4_packet->header.type);

    // struct icmp_echo *echo;
    switch (icpmv4_packet->header.code) {
    case ICMP_TYPE_ECHO_REPLY:
    case ICMP_TYPE_ECHO_REQUEST: 
        fprintf(stdout, "[ICMPv4]: size if %ld\n", packet_size);
        icpmv4_packet->message.echo = *parse_icmpv4_echo_packet((unsigned char *)packet);
        fprintf(stdout, "[ICMPv4]: id is %d\n", icpmv4_packet->message.echo.id);
        break;
    }

    return icpmv4_packet;
}