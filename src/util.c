#include "util.h"

const char **const parse_interfaces(int argc, char *argv[], uint32_t *ret_nums)
{
    char **interfaces = NULL;
    *ret_nums = 0;

    // 查找 "-i" 参数
    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[1], "-i") == 0)
        {
            int j = i + 1;
            while (j < argc && argv[j][0] != "-")
                j++;

            *ret_nums = j - i - 1;
            interfaces = malloc(*ret_nums * sizeof(char *));
            int idx = 0;
            // 遍历所有接口参数
            for (++i; i < j; i++)
                interfaces[idx++] = argv[i];

            break;
        }
    }

    return interfaces;
}

// 预计算的 CRC32 查找表（使用多项式 0xEDB88320）
uint32_t crc32_table[256];

void init_crc32_table()
{
    uint32_t polynomial = 0xEDB88320;
    for (uint32_t i = 0; i < 256; i++)
    {
        uint32_t crc = i;
        for (uint8_t j = 0; j < 8; j++)
        {
            if (crc & 1)
                crc = (crc >> 1) ^ polynomial;
            else
                crc >>= 1;
        }
        crc32_table[i] = crc;
    }
}

uint32_t calculate_crc32(const unsigned char *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFF; // 初始值

    for (size_t i = 0; i < len; i++)
    {
        uint8_t index = (crc ^ data[i]) & 0xFF;
        crc = (crc >> 8) ^ crc32_table[index];
    }

    return crc ^ 0xFFFFFFFF; // 取反输出
}