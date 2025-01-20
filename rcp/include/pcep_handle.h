// pcep_handle.h
#ifndef PCEP_HANDLE_H
#define PCEP_HANDLE_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "pkg_sender.h"
#include "icmpv4.h"
#include "send.h"
#include "ipv4.h"

// PCEP Message-Type
#define PCEP_OPEN 1
#define PCEP_KEEPALIVE 2
#define PCEP_PCERR 3
#define PCEP_PCREQ 4
#define PCEP_PCREP 5
#define PCEP_NOTIFICATION 6
#define PCEP_PCINIT 7
#define PCEP_PCRPT 8
#define PCEP_PCUPD 9
#define PCEP_PCNTF 10
#define PCEP_ENDMESSAGE 11

// PCEP OBJECT CLASS
#define PCEP_OPEN_OBJECT_CLASS 1
#define PCEP_RequestParameters_OBJECT_CLASS 2
#define PCEP_NOPATH_OBJECT_CLASS 3
#define PCEP_ENDPOINTS_OBJECT_CLASS 4
#define PCEP_BANDWIDTH_OBJECT_CLASS 5


typedef struct {
    uint8_t version;
    uint8_t flags;
    uint8_t message_type;
    uint16_t message_length;
} PCEP_Header;

typedef struct {
    uint8_t object_class;
    uint8_t object_type;
    uint8_t flags;
    uint16_t object_length;
} Object_Comm_Header;

typedef struct {
    uint8_t version;
    uint8_t flags;
    uint8_t keepalive;
    uint8_t deadTimer;
    uint8_t sid;
} OPEN_Object_Body;


PCEP_Header *parse_pcep_header(unsigned char *data, size_t data_length);
Object_Comm_Header *parse_object_comm_header(unsigned char *data, size_t data_length);
OPEN_Object_Body *parse_open_object_body(unsigned char *data, size_t data_length);

void pcep(unsigned char *data, size_t data_length);
// 初始化中央处理器的pcep功能
void init_rcp_pcep();

#endif