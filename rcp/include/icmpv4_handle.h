// icmpv4_handle.h
#ifndef ICMPV4_HANDLE_H
#define ICMPV4_HANDLE_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "pkg_sender.h"
#include "icmpv4.h"
#include "send.h"
#include "ipv4.h"

void process_icmpv4_packet(Pkg_sender *pkg_sender, Icmpv4_packet *icmpv4_packet, ipv4_header *ipv4_hdr,
                            const char *dev_name, unsigned char *dst_mac_addr);

#endif