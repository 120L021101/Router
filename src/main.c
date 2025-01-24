#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "arp.h"
#include "ethernet.h"
#include "hardware.h"
#include "util.h"

#define MAIN_LOG_PREFIX "[MAIN]: "

int main()
{
    INIT_UTIL;
    INIT_HARDWARE;

    unsigned char data[1000];
    for (int i = 0; i < 1000; ++i)
    {
        data[i] = 0x1f;
    }
    broadcast_ethernet(data, 1000, 0x0800);

    return 0;
}