// route_init.h
// #ifndef ROUTE_INIT_H
// #define ROUTE_INIT_H

#include "route_init.h"

static uint32_t swap_endian(uint32_t ip_addr) {
    return ((ip_addr & 0xFF) << 24)
         | ((ip_addr & 0xFF00) << 8)
         | ((ip_addr & 0xFF0000) >> 8)
         | ((ip_addr & 0xFF000000) >> 24);
}

// 函数将点分十进制的IP字符串转换为uint32_t  
static uint32_t ip_to_uint32(const char *ip) {  
    // printf("%s\n", ip);
    struct in_addr addr;  
    inet_pton(AF_INET, ip, &addr);  
    uint32_t swap_addr = swap_endian(addr.s_addr);

    // fprintf(stdout, "%d.%d.%d.%d\n", (swap_addr >> 24) & 0xFF, (swap_addr >> 16) & 0xFF, 
    //                         (swap_addr >> 8) & 0xFF, (swap_addr) & 0xFF);
    return swap_addr;  
}  
  
// 函数读取文件内容到字符串中  
static char* read_file(const char *filename) {  
    FILE *file = fopen(filename, "rb");  
    if (!file) {  
        perror("Failed to open file");  
        return NULL;  
    }  
  
    fseek(file, 0, SEEK_END);  
    long length = ftell(file);  
    fseek(file, 0, SEEK_SET);  
  
    char *content = (char *)malloc(length + 1);  
    if (!content) {  
        perror("Failed to allocate memory");  
        fclose(file);  
        return NULL;  
    }  
  
    fread(content, 1, length, file);  
    content[length] = '\0'; // 确保字符串以null结尾  
  
    fclose(file);  
    return content;  
}  

void config_ipv4_table(IPv4RoutingTable *ipv4RouteTable, const char *filename) {
    char *json_content = read_file(filename);  
    if (!json_content) {  
        exit(1);  
    }  
  
    // 解析JSON字符串  
    cJSON *json = cJSON_Parse(json_content);  
    free(json_content); // 解析完成后释放文件内容内存  
  
    if (json == NULL) {  
        printf("Error parsing JSON: [%s]\n", cJSON_GetErrorPtr());  
        return ;  
    }  
  
    // 确保JSON是一个数组  
    if (!cJSON_IsArray(json)) {  
        printf("Not a JSON array\n");  
        cJSON_Delete(json);  
        return ;  
    }  
  
    // 遍历数组中的每一个对象  
    cJSON *json_item = NULL;  
    cJSON_ArrayForEach(json_item, json) {  
        if (cJSON_IsObject(json_item)) {  
            cJSON *destination = cJSON_GetObjectItem(json_item, "destination");  
            cJSON *subnet_mask = cJSON_GetObjectItem(json_item, "subnet_mask");  
            cJSON *next_hop = cJSON_GetObjectItem(json_item, "next_hop");
            cJSON *outgoing_interface = cJSON_GetObjectItem(json_item, "outgoing_interface");
            cJSON *metric = cJSON_GetObjectItem(json_item, "metric");
            cJSON *route_type = cJSON_GetObjectItem(json_item, "route_type");
  
            uint32_t dest_ip = ip_to_uint32(destination->valuestring);  
            uint32_t mask_ip = ip_to_uint32(subnet_mask->valuestring);  
            uint32_t next_hop_ip = ip_to_uint32(next_hop->valuestring);

            add_route(ipv4RouteTable, dest_ip, mask_ip, next_hop_ip,
                        outgoing_interface->valuestring, 1, route_type->valuestring);
        }  
    }  
    show_ipv4_route_table(ipv4RouteTable);
    
    // 释放JSON对象  
    cJSON_Delete(json);  
    return ;  
}

// int main(int argc, char **argv) {

//     IPv4RoutingTable *IPv4RoutingTable = create_ipv4_routing_table();
    
//     for (int i = 0; i < argc; ++i) {
//         if (!strcmp(argv[i], "-crt")) {
//             config_ipv4_table(IPv4RoutingTable, argv[i + 1]);
//             break;
//         }
//     }

//     return 0;
// }

// #endif // ROUTE_INIT_H