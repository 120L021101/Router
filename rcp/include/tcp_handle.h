// tcp_handle.h
#ifndef TCP_HANDLE_H
#define TCP_HANDLE_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <ifaddrs.h>
#include "ethernet.h"
#include "pkg_sender.h"
#include "pkg_rcver.h"
#include "send.h"
#include "ipv4.h"
#include "tcp.h"
#include "ipv4_table.h"
#include "pcep_handle.h"

#define MAX_SESSION 100
#define MAX_BUFFER 10000

#define FLAG_ACK 0x10
#define FLAG_PSH 0x08
#define FLAG_PST 0x04
#define FLAG_SYN 0x02
#define FLAG_FIN 0x01 


typedef enum {
    CLOSED,        // 初始状态，表示没有连接
    LISTEN,        // 服务器监听来自客户端的连接请求
    SYN_SENT,      // 客户端已发送 SYN 报文，等待服务器确认
    SYN_RECEIVED,  // 服务器接收到 SYN 报文，发送 SYN+ACK，并等待客户端确认
    ESTABLISHED,   // 连接已建立，双方可以开始数据传输
    FIN_WAIT_1,    // 主动关闭连接的一方发送 FIN 报文，等待对方确认
    FIN_WAIT_2,    // 主动关闭连接的一方已收到 ACK，等待对方发送 FIN
    CLOSE_WAIT,    // 被动关闭连接的一方已接收到 FIN，等待关闭
    CLOSING,       // 双方同时发送 FIN 请求关闭连接
    LAST_ACK,      // 被动关闭连接的一方已发送 FIN，等待对方确认
    TIME_WAIT      // 主动关闭连接的一方等待一段时间，确保对方收到 ACK
} Tcp_state;


typedef struct _Triple_id {
    uint16_t src_port;
    uint32_t src_ip_addr;
    uint16_t dest_port;
} Triple_id;

typedef struct _TCB {
    uint32_t seq_number;
    uint32_t ack_number;
    uint16_t window_size;
    Tcp_state status_code;
    // timer_t timer; // 之后实现
} TCB;

typedef struct _Buffer {
    unsigned char *buffer[1000];
    uint32_t seq_nums[1000];
    size_t data_lens[1000];
    size_t count;
} Buffer;

typedef struct {
    Triple_id triple_ids[MAX_SESSION];
    TCB tcb[MAX_SESSION];
    Buffer recv_buffer[MAX_SESSION];
    Buffer sent_buffer[MAX_SESSION];
    size_t count;
} Tcp_handler;

Tcp_handler *create_tcp_handler();

void process_tcp_packet(Tcp_handler *tcp_handler, IPv4RoutingTable *ipv4RoutingTable, Ipv4_arp_table *ipv4_arp_table,
                Pkg_sender *pkg_sender, ipv4_header *ipv4_hdr, Tcp_packet *tcp_packet);

#endif // TCP_HANDLE_H