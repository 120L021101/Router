#include "util.h"

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