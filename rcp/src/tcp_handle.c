#include "tcp_handle.h"


Tcp_handler *create_tcp_handler() {
    Tcp_handler *tcp_handler = (Tcp_handler *)malloc(sizeof(Tcp_handler));
    memset(tcp_handler, 0, sizeof(Tcp_handler));
    tcp_handler->count = 0;

    return tcp_handler;
}

static void remove_nitems_buffer(Buffer *buffer, size_t item_cnt) {
    if (item_cnt == 0) {
        return ;
    }
    int slow = 0, fast = item_cnt;
    while (fast < buffer->count) {
        buffer->buffer[slow] = buffer->buffer[fast];
        buffer->seq_nums[slow] = buffer->seq_nums[fast];
        buffer->data_lens[slow] = buffer->data_lens[fast];
        slow += 1;
        fast += 1;
    }
    buffer->count -= item_cnt;
    return ;
}

static void remove_session(Tcp_handler *tcp_handler, size_t session_idx) {
    for (size_t idx = session_idx; idx < tcp_handler->count - 1; ++idx) {
        memcpy(&tcp_handler->triple_ids[idx], &tcp_handler->triple_ids[idx + 1],
                        sizeof(Triple_id));
        memcpy(&tcp_handler->tcb[idx], &tcp_handler->tcb[idx + 1],
                        sizeof(TCB));
        memcpy(&tcp_handler->recv_buffer[idx], &tcp_handler->recv_buffer[idx + 1],
                        sizeof(Buffer));
        memcpy(&tcp_handler->sent_buffer[idx], &tcp_handler->sent_buffer[idx + 1],
                        sizeof(Buffer));
    }
    tcp_handler->count -= 1;
    return ;
}

static void add_item_buffer(Buffer *buffer, unsigned char *data, size_t data_len, uint32_t seq_num) {    
    size_t idx = buffer->count;
    if (idx == 1000) {
        fprintf(stdout, "[ERROR]: TCP BUFFER EXCEEDS!\n");
        exit(1);
    }
    buffer->count += 1;
    buffer->buffer[idx] = (unsigned char *)malloc(data_len);
    memcpy(buffer->buffer[idx], data, data_len);
    buffer->seq_nums[idx] = seq_num;
    buffer->data_lens[idx] = data_len;
}

static int find_triple_idx(Tcp_handler *tcp_handler, Triple_id *triple_id){
    fprintf(stdout, "[TCP FINDIDX]: START FINDING in %ld\n", tcp_handler->count);
    for (int i = 0; i < tcp_handler->count; ++i) {
        if (tcp_handler->triple_ids[i].dest_port == triple_id->dest_port &&
            tcp_handler->triple_ids[i].src_port == triple_id->src_port &&
            tcp_handler->triple_ids[i].src_ip_addr == triple_id->src_ip_addr)
        {
            return i;
        }
    }
    return -1;
};

static int assign_resource(Tcp_handler *tcp_handler, Triple_id *triple_id, Tcp_packet *tcp_packet) {
    fprintf(stdout, "[TCP ASSGN]: START ASSIGNING RESOUCES\n");
    if (tcp_handler->count == MAX_SESSION) {
        fprintf(stdout, "[ERROR]: EXCEED MAX SESSON\n");
        exit(1);
    }
    int idx = tcp_handler->count;
    tcp_handler->count += 1;
    // 拷贝三元组标识符
    memcpy(&tcp_handler->triple_ids[idx], triple_id, sizeof(Triple_id));
    // 初始化缓冲区
    tcp_handler->recv_buffer->count = 0;
    // 初始化控制块TCP
    tcp_handler->tcb[idx].status_code = SYN_SENT; // 稍后回复SYN，这里直接置
    tcp_handler->tcb[idx].ack_number = tcp_packet->sequence_number + 1;
    tcp_handler->tcb[idx].window_size = 1000;
    srand(time(NULL));
    tcp_handler->tcb[idx].seq_number = (rand() % 1000) + 1; // 随机初始化序列号
    return idx;
}

static uint16_t compute_ipv4_checksum(ipv4_header *ipv4_hdr) {
    // 初始化和
    uint32_t sum = 0;

    // 逐16位加和，IPv4 头部大小为20字节
    uint16_t *buffer = (uint16_t *)ipv4_hdr;
    for (size_t i = 0; i < sizeof(ipv4_header) / 2; i++) {
        sum += *buffer++;
    }

    // 处理进位
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    // 返回反转后的校验和
    return (uint16_t)(~sum);
}

static void constuct_tcp_ipv4_header(ipv4_header *ipv4_hdr, ipv4_header *reply_ipv4_hdr, size_t length) {
    reply_ipv4_hdr->version = ipv4_hdr->version;
    reply_ipv4_hdr->ihl = ipv4_hdr->ihl;
    reply_ipv4_hdr->tos = ipv4_hdr->tos;
    reply_ipv4_hdr->total_length = htons(length);
    reply_ipv4_hdr->identification = ipv4_hdr->identification;
    reply_ipv4_hdr->flags_offset = ipv4_hdr->flags_offset;
    reply_ipv4_hdr->ttl = 64;
    reply_ipv4_hdr->protocol = IPPROTO_TCP;
    reply_ipv4_hdr->src_addr = ipv4_hdr->dest_addr; // 源地址变为原来的目的地址
    reply_ipv4_hdr->dest_addr = ipv4_hdr->src_addr; // 目的地址变为原来的源地址

    reply_ipv4_hdr->checksum = 0;
    reply_ipv4_hdr->checksum = compute_ipv4_checksum(reply_ipv4_hdr);
}

static uint16_t swap_endian(uint16_t d) {
    return (d >> 8) | ((d & 0xFF) << 8);
}
static uint32_t swap32_endian(uint32_t d32) {
    return (d32 >> 24) | ((d32 & 0x00FF0000) >> 8) |
            ((d32 & 0xFF00) << 8) | ((d32 & 0xFF) << 24);
}

// static void pcep(unsigned char *data, size_t data_length) {
//     fprintf(stdout, "[PCEP]: ");
//     for (int i = 0; i < data_length; ++i) {
//         fprintf(stdout, "%c", data[i]);
//     }
//     fprintf(stdout, "\n");
//     return ;
// }

void process_tcp_packet(Tcp_handler *tcp_handler, IPv4RoutingTable *ipv4RoutingTable, Ipv4_arp_table *ipv4_arp_table,
                Pkg_sender *pkg_sender, ipv4_header *ipv4_hdr, Tcp_packet *tcp_packet) {
    Triple_id triple_id = {
        tcp_packet->source_port,
        ipv4_hdr->src_addr,
        tcp_packet->destination_port,
    };

    // 静态配置端口侦听函数
    void (*upload_to_app)(unsigned char *data, size_t data_length) = NULL;
    switch (tcp_packet->destination_port) {
    case 4189:
        upload_to_app = pcep;
        break;
    default:
        break;
    }

    // 首先检查是不是SYN
    if (tcp_packet->flags & FLAG_SYN) {
        int session_idx = find_triple_idx(tcp_handler, &triple_id);
        // 判断是否已分配资源，即是否重传的SYN
        if (-1 == session_idx) {
            // 第一次收到
            session_idx = assign_resource(tcp_handler, &triple_id, tcp_packet);
            // 回复SYN
        }
        fprintf(stdout, "[RCP TCP]: Session ID is %d\n", session_idx);
        // SYN_ACK报文不检查发送缓存，但每次放入第一个。

        ipv4_header reply_ipv4_hdr;
        constuct_tcp_ipv4_header(ipv4_hdr, &reply_ipv4_hdr, 20 + 20);
        fprintf(stdout, "[RCP TCP]: Finished construct IPv4\n");

        Tcp_packet reply_tcp_packet;
        reply_tcp_packet.source_port = tcp_packet->destination_port;
        reply_tcp_packet.destination_port = tcp_packet->source_port;
        reply_tcp_packet.sequence_number = tcp_handler->tcb[session_idx].seq_number;
        reply_tcp_packet.ack_number = tcp_handler->tcb[session_idx].ack_number;
        reply_tcp_packet.data_offset = 20 / 4;
        reply_tcp_packet.flags = FLAG_SYN | FLAG_ACK;
        reply_tcp_packet.window_size = tcp_handler->tcb[session_idx].window_size;
        // 跳过校验位checksum

        reply_tcp_packet.urgent_pointer = 0;
        reply_tcp_packet.options = NULL;
        // SYN_ACK无数据
        reply_tcp_packet.data = NULL;

        int sum_len = 20 + 20;
        unsigned char sent_packet[sum_len];
        memset(sent_packet, 0, sum_len * sizeof(unsigned char));
        memcpy(sent_packet, &reply_ipv4_hdr, sizeof(ipv4_header));
        unsigned char *pointer = sent_packet + sizeof(ipv4_header);
        *(uint16_t *)pointer = swap_endian(reply_tcp_packet.source_port);
        pointer += 2;
        *(uint16_t *)pointer = swap_endian(reply_tcp_packet.destination_port);
        pointer += 2;
        *(uint32_t *)pointer = swap32_endian(reply_tcp_packet.sequence_number);
        pointer += 4;
        *(uint32_t *)pointer = swap32_endian(reply_tcp_packet.ack_number);
        pointer += 4;
        *(uint8_t *)pointer = reply_tcp_packet.data_offset << 4;
        pointer += 1;
        *(uint8_t *)pointer = reply_tcp_packet.flags;
        pointer += 1;
        *(uint16_t *)pointer = swap_endian(reply_tcp_packet.window_size);
        pointer += 2;
        // TODO: checksum 和 urgent_pointer

        IPv4RouteEntry *ipv4RouteEntry = lookup_route(ipv4RoutingTable, reply_ipv4_hdr.dest_addr);
        fprintf(stdout, "[RCP TCP]: Sent From %s to %d.%d.%d.%d\n", ipv4RouteEntry->outgoing_interface,
                (ipv4RouteEntry->next_hop & 0xFF000000) >> 24, 
                (ipv4RouteEntry->next_hop & 0x00FF0000) >> 16, 
                (ipv4RouteEntry->next_hop & 0x0000FF00) >> 8,
                (ipv4RouteEntry->next_hop & 0x000000FF));

        uint32_t next_hop_addr = swap32_endian(ipv4RouteEntry->next_hop);
        unsigned char * next_mac_addr = find_ipv4_mac_byarp(ipv4_arp_table, next_hop_addr);
        fprintf(stdout, "[RCP TCP]: Next addr is %2X:%2X:%2X:%2X:%2X:%2X\n", 
                next_mac_addr[0], next_mac_addr[1], next_mac_addr[2], next_mac_addr[3], next_mac_addr[4], next_mac_addr[5]);
        pkg_send(pkg_sender, sent_packet, sum_len, 0x0800, ipv4RouteEntry->outgoing_interface, next_mac_addr);

        return ;
    }
    size_t data_length = 0;
    if (tcp_packet->flags & FLAG_ACK)  {
        int session_idx = find_triple_idx(tcp_handler, &triple_id);
        fprintf(stdout, "[RCP TCP]: Session Idx is %d\n", session_idx);
        fprintf(stdout, "[RCP TCP]: Session status is %d\n", tcp_handler->tcb[session_idx].status_code);
        switch (tcp_handler->tcb[session_idx].status_code) {
        case SYN_SENT:
            // 建立连接
            tcp_handler->tcb[session_idx].status_code = ESTABLISHED;
            // drop to established
        case ESTABLISHED:
            tcp_handler->tcb[session_idx].seq_number = tcp_packet->ack_number;

            // 检查该报文的序列号是否是期望的ACK号
            fprintf(stdout, "[RCP TCP]: Client Ack %d, Seq is %d, We Expect: %d\n", 
                tcp_packet->ack_number, tcp_packet->sequence_number, tcp_handler->tcb[session_idx].ack_number);
            
            if (tcp_packet->sequence_number == tcp_handler->tcb[session_idx].ack_number) {
                // 先上交本报文的数据
                data_length = swap_endian(ipv4_hdr->total_length) - ipv4_hdr->ihl * 4 - tcp_packet->data_offset * 4;
                fprintf(stdout, "[RCP TCP]: Total Length: %d, IP Header Length: %d, TCP Header Length %d\n",
                        swap_endian(ipv4_hdr->total_length), ipv4_hdr->ihl * 4, tcp_packet->data_offset * 4);
                upload_to_app(tcp_packet->data, data_length);
                tcp_handler->tcb[session_idx].ack_number += data_length;
                
                // 上交存放的连续数据
                for (int recv_buf_idx = 0; recv_buf_idx < tcp_handler->recv_buffer[session_idx].count; ++recv_buf_idx) {
                    if (tcp_handler->recv_buffer[session_idx].seq_nums[recv_buf_idx] != tcp_handler->tcb[session_idx].ack_number) {
                        remove_nitems_buffer(&tcp_handler->recv_buffer[session_idx], recv_buf_idx);
                        break;
                    }
                    upload_to_app(tcp_handler->recv_buffer[session_idx].buffer[recv_buf_idx],
                                    tcp_handler->recv_buffer[session_idx].data_lens[recv_buf_idx]);
                    tcp_handler->tcb[session_idx].ack_number += tcp_handler->recv_buffer[session_idx].data_lens[recv_buf_idx];
                }
                fprintf(stdout, "[RCP TCP]: Ack number update to %d\n", tcp_handler->tcb[session_idx].ack_number);
                // TODO 确认
            } else if (tcp_packet->sequence_number > tcp_handler->tcb[session_idx].ack_number){
                // 如果序列号大于我们的期待，存放数据
                data_length = swap_endian(ipv4_hdr->total_length) - ipv4_hdr->ihl * 4 - tcp_packet->data_offset * 4;
                add_item_buffer(&tcp_handler->recv_buffer[session_idx], tcp_packet->data, data_length, tcp_packet->sequence_number);
                fprintf(stdout, "[RCP TCP]: Save Seq: %d\n", tcp_packet->sequence_number);
            }
            break;
        case TIME_WAIT:
            fprintf(stdout, "[RCP TCP]: TMWAIT ACK number is %d, OUR SEQ is %d\n", tcp_packet->ack_number,
                                                                            tcp_handler->tcb[session_idx].seq_number);
            if (tcp_handler->tcb[session_idx].seq_number == tcp_packet->ack_number) {
                remove_session(tcp_handler, session_idx);
            }
            break;
        default: break;
        }
    }
    // 断开连接
    if (tcp_packet->flags & FLAG_FIN) {
        fprintf(stdout, "[RCP TCP]: END CONNECTION!\n");
        int session_idx = find_triple_idx(tcp_handler, &triple_id);
        ipv4_header reply_ipv4_hdr;
        constuct_tcp_ipv4_header(ipv4_hdr, &reply_ipv4_hdr, 20 + 20);
        fprintf(stdout, "[RCP TCP]: Finished construct IPv4\n");

        Tcp_packet reply_tcp_packet;
        reply_tcp_packet.source_port = tcp_packet->destination_port;
        reply_tcp_packet.destination_port = tcp_packet->source_port;
        reply_tcp_packet.sequence_number = tcp_handler->tcb[session_idx].seq_number;
        reply_tcp_packet.ack_number = tcp_handler->tcb[session_idx].ack_number;
        reply_tcp_packet.data_offset = 20 / 4;
        reply_tcp_packet.flags = FLAG_FIN | FLAG_ACK;
        reply_tcp_packet.window_size = tcp_handler->tcb[session_idx].window_size;
        // 跳过校验位checksum

        reply_tcp_packet.urgent_pointer = 0;
        reply_tcp_packet.options = NULL;
        // SYN_ACK无数据
        reply_tcp_packet.data = NULL;

        int sum_len = 20 + 20;
        unsigned char sent_packet[sum_len];
        memset(sent_packet, 0, sum_len * sizeof(unsigned char));
        memcpy(sent_packet, &reply_ipv4_hdr, sizeof(ipv4_header));
        unsigned char *pointer = sent_packet + sizeof(ipv4_header);
        *(uint16_t *)pointer = swap_endian(reply_tcp_packet.source_port);
        pointer += 2;
        *(uint16_t *)pointer = swap_endian(reply_tcp_packet.destination_port);
        pointer += 2;
        *(uint32_t *)pointer = swap32_endian(reply_tcp_packet.sequence_number);
        pointer += 4;
        *(uint32_t *)pointer = swap32_endian(reply_tcp_packet.ack_number);
        pointer += 4;
        *(uint8_t *)pointer = reply_tcp_packet.data_offset << 4;
        pointer += 1;
        *(uint8_t *)pointer = reply_tcp_packet.flags;
        pointer += 1;
        *(uint16_t *)pointer = swap_endian(reply_tcp_packet.window_size);
        pointer += 2;
        // TODO: checksum 和 urgent_pointer
        tcp_handler->tcb[session_idx].seq_number += 1;
        tcp_handler->tcb[session_idx].status_code = TIME_WAIT;

        IPv4RouteEntry *ipv4RouteEntry = lookup_route(ipv4RoutingTable, reply_ipv4_hdr.dest_addr);
        fprintf(stdout, "[RCP TCP]: Sent From %s to %d.%d.%d.%d\n", ipv4RouteEntry->outgoing_interface,
                (ipv4RouteEntry->next_hop & 0xFF000000) >> 24, 
                (ipv4RouteEntry->next_hop & 0x00FF0000) >> 16, 
                (ipv4RouteEntry->next_hop & 0x0000FF00) >> 8,
                (ipv4RouteEntry->next_hop & 0x000000FF));
        uint32_t next_hop_addr = swap32_endian(ipv4RouteEntry->next_hop);
        unsigned char * next_mac_addr = find_ipv4_mac_byarp(ipv4_arp_table, next_hop_addr);
        fprintf(stdout, "[RCP TCP]: Next addr is %2X:%2X:%2X:%2X:%2X:%2X\n", 
                next_mac_addr[0], next_mac_addr[1], next_mac_addr[2], next_mac_addr[3], next_mac_addr[4], next_mac_addr[5]);
        pkg_send(pkg_sender, sent_packet, sum_len, 0x0800, ipv4RouteEntry->outgoing_interface, next_mac_addr);
    }
}
