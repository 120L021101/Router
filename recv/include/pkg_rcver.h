#ifndef PKG_RCVER_H
#define PKG_RCVER_H

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ethernet.h"

typedef struct {
    pcap_t **devices;
    const char **devices_name;
    // unsigned char **devices_mac_addr;
    size_t devices_num;
} Pkg_receiver;

Pkg_receiver *pkg_rcver_init(const char **dev_names, size_t dev_num);

unsigned char filter_package(Pkg_receiver *pkg_receiver, ethernet_frame *eth_frame);

#endif
