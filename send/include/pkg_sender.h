// pkg_sender.h
#ifndef PKG_SENDER_H
#define PKG_SENDER_H

#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "err.h"

typedef struct {
    pcap_t **devices;
    const char **devices_name;
    unsigned char **devices_mac_addr;
    size_t devices_num;
} Pkg_sender;

Pkg_sender *create_pkg_sender();

Pkg_sender *pkg_sender_init(const char **dev_names, size_t dev_num);

uint32_t get_ip_address(const char *interface_name);

#endif

