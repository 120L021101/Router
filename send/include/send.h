// send.h
#ifndef SEND_H
#define SEND_H

#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h> 
#include <arpa/inet.h>
#include "err.h"
#include "pkg_sender.h"

void pkg_send(Pkg_sender *pkg_sender, const u_char *frame, size_t frame_size, uint16_t protocol_type, \
                const char *outgoing_interface, unsigned char *dest_mac_addr);

void pkg_send_with_null_mac(Pkg_sender *pkg_sender, const u_char *packet, size_t packet_size, 
            uint16_t protocol_type, const char *outgoing_interface);

void pkg_send_myself(Pkg_sender *pkg_sender, const u_char *packet, size_t packet_size, uint16_t protocol_type,
               const char *outgoing_interface, unsigned char *src_mac_addr, unsigned char *dest_mac_addr);

#endif // SEND_H

