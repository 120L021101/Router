#ifndef IPV4_H
#define IPV4_H

typedef unsigned char IPV4_address[4];
typedef unsigned char IPV4_mask[4];

char is_ipv4_addr_equal(IPV4_address addr1, IPV4_address addr2);

char is_ipv4_addr_mask_equal(IPV4_address addr1, IPV4_address addr, IPV4_mask mask);

char is_broadcast_ipv4(IPV4_address addr, IPV4_mask mask);

#endif