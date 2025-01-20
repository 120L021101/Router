#include "ethernet.h"
#include "err.h"

ethernet_frame *parse_ethernet_frame(const u_char *frame, size_t frame_size) {
    // TESTERR_REPORT_AND_EXIT(frame_size < 64, 
    //     "Frame size is too small.\n"
    // );
    TESTERR_REPORT_AND_EXIT(frame_size >  1518, 
        "[ETHERNET]: Frame size is too big.\n"
    );

    ethernet_frame *eth_frame = (ethernet_frame *)malloc(sizeof(ethernet_frame));

    memcpy(eth_frame->dest_mac, frame, 6); 
    // for (size_t i = 0; i < 6; ++i) {
    //     eth_frame->dest_mac[i] = frame[5 - i];
    //     eth_frame->src_mac[i] = (frame + 6)[5 - i];
    // }   
    printf("[ETHERNET]: Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_frame->dest_mac[0], eth_frame->dest_mac[1], eth_frame->dest_mac[2],
           eth_frame->dest_mac[3], eth_frame->dest_mac[4], eth_frame->dest_mac[5]);

    memcpy(eth_frame->src_mac, frame + 6, 6);
    printf("[ETHERNET]: Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_frame->src_mac[0], eth_frame->src_mac[1], eth_frame->src_mac[2],
           eth_frame->src_mac[3], eth_frame->src_mac[4], eth_frame->src_mac[5]);

    printf("[ETHERNET]: EtherType: 0x%04x\n", ntohs(*(uint16_t *)(frame + 12)));
    eth_frame->ether_type = ntohs(*(uint16_t *)(frame + 12));

    eth_frame->payload_size = frame_size - 14;
    eth_frame->payload = (uint8_t *)malloc(sizeof(uint8_t) * eth_frame->payload_size);
    memcpy(eth_frame->payload, frame + 14, eth_frame->payload_size);

    eth_frame->fcs = *(uint32_t *)(frame + frame_size - 2);

    return eth_frame;
}