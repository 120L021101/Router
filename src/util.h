#ifndef SRC_UTIL_H
#define SRC_UTIL_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// 初始化 CRC32 查找表
void init_crc32_table();

// **计算 CRC32 校验和**
uint32_t calculate_crc32(const unsigned char *data, size_t len);

// 解析接口名
const char **const parse_interfaces(int argc, char *argv[], uint32_t *ret_nums);

#define INIT_UTIL           \
    do                      \
    {                       \
        init_crc32_table(); \
    } while (0)

#endif
