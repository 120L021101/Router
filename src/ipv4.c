#include "ipv4.h"

char is_ipv4_addr_equal(IPV4_address addr1, IPV4_address addr2)
{
    for (int i = 0; i < sizeof(IPV4_address); ++i)
    {
        if (addr1[i] != addr2[i])
            return 0;
    }
    return 1;
}

char is_ipv4_addr_mask_equal(IPV4_address addr1, IPV4_address addr, IPV4_mask mask)
{
    for (int i = 0; i < sizeof(IPV4_address) && mask[i]; ++i)
    {
        if ((addr1[i] & mask[i]) != (addr[i] & mask[i]))
            return 0;
    }
    return 1;
}

char is_broadcast_ipv4(IPV4_address addr, IPV4_mask mask)
{
    IPV4_address addr2;
    for (int i = 0; i < sizeof(IPV4_address); ++i)
    {
        addr2[i] = (~mask[i]) & addr[i];
    }

    // 判断是否是以全1结尾
    for (int i = sizeof(IPV4_address) - 1; i >= 0; --i)
    {
        if (addr2[i] == 0xFF)
            continue;
        int zero_starts = 0;
        while (zero_starts < 8)
        {
            if ((addr2[i] & (0x1 << (8 - zero_starts - 1))) == 0)
                zero_starts++;
            else
                break;
        }
        int one_ends = 0;
        while (one_ends < 8)
        {
            if (addr2[i] & (0x1 << one_ends))
                one_ends++;
            else
                break;
        }
        return (one_ends + zero_starts) == 8;
    }
    return 1;
}