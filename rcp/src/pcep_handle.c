#include "pcep_handle.h"

#define MAX_PCEP_SESSIONS 100

static int pcep_sessions[MAX_PCEP_SESSIONS];

void init_rcp_pcep() {
    for (size_t i = 0; i < MAX_PCEP_SESSIONS; ++i) {
        pcep_sessions[i] = -1;
    }
}

static int create_pcep_session(uint8_t sid) {
    for (size_t i = 0; i < MAX_PCEP_SESSIONS; ++i) {
        if (pcep_sessions[i] == -1) {
            pcep_sessions[i] = sid;
            return 0;
        }
    }
    return -1; // exceed maximum limitation
}

static uint16_t swap_endian(uint16_t d) {
    return (d >> 8) | ((d & 0xFF) << 8);
}

Object_Comm_Header *parse_object_comm_header(unsigned char *data, size_t data_length) {
    unsigned char *object_ptr = data + 4;
    Object_Comm_Header *object_comm_header = (Object_Comm_Header *)malloc(sizeof(Object_Comm_Header));
    memset(object_comm_header, 0, sizeof(Object_Comm_Header));
    object_comm_header->object_class = object_ptr[0];
    object_comm_header->object_type = (object_ptr[1] & 0xF0) >> 4;
    object_comm_header->flags = object_ptr[1] & 0x0F;
    object_comm_header->object_length = swap_endian(*(uint16_t *)(object_ptr + 2));
    return object_comm_header;
}
OPEN_Object_Body *parse_open_object_body(unsigned char *data, size_t data_length) {
    unsigned char *object_ptr = data + 8;
    OPEN_Object_Body *open_object_body = (OPEN_Object_Body *)malloc(sizeof(OPEN_Object_Body));
    memset(open_object_body, 0, sizeof(OPEN_Object_Body));

    open_object_body->version = (object_ptr[0] & 0xE0) >> 5;
    open_object_body->flags = 0;
    open_object_body->keepalive = object_ptr[1];
    open_object_body->deadTimer = object_ptr[2];
    open_object_body->sid = object_ptr[3];

    return open_object_body;
}


PCEP_Header *parse_pcep_header(unsigned char *data, size_t data_length) {
    PCEP_Header *pcep_header = (PCEP_Header *)malloc(sizeof(PCEP_Header));
    memset(pcep_header, 0, sizeof(PCEP_Header));
    pcep_header->version = (data[0] & 0xE0) >> 5;
    pcep_header->flags = (data[0] & 0x1F);
    pcep_header->message_type = data[1];
    pcep_header->message_length = swap_endian(*(uint16_t *)(data + 2));

    return pcep_header;
}



void pcep(unsigned char *data, size_t data_length) {
    PCEP_Header *pcep_header = parse_pcep_header(data, data_length);

    fprintf(stdout, "[PCEP]: PCEP VERSION: %d\n[PCEP]: PCEP FLAGS: %d\n[PCEP]: PCEP MSG TYPE: %d\n[PCEP]: PCEP MSG LEN: %d\n",
                pcep_header->version, pcep_header->flags, pcep_header->message_type, pcep_header->message_length);

    Object_Comm_Header *object_comm_header = parse_object_comm_header(data, data_length);

    fprintf(stdout, "[PCEP]: OBJ CLASS: %d\n[PCEP]: OBJ TYPE: %d\n[PCEP]: OBJ LEN: %d\n",
                object_comm_header->object_class, object_comm_header->object_type, object_comm_header->object_length);

    OPEN_Object_Body *open_object_body = NULL;
    switch (object_comm_header->object_class) {
    case PCEP_OPEN_OBJECT_CLASS:
        open_object_body = parse_open_object_body(data, data_length);
        fprintf(stdout, "[PCEP]: OBJ VER: %d\n[PCEP]: OBJ KEEPALIVE: %d\n[PCEP]: OBJ DEADTIMER: %d\n[PCEP]: OBJ SID:%d\n",
                open_object_body->version, open_object_body->keepalive, open_object_body->deadTimer, open_object_body->sid);
        create_pcep_session(open_object_body->sid);
        break;
    default: break;
    }   

    // fprintf(stdout, "[PCEP]: OBJ CLASS: %d\n[PCEP]: OBJ TYPE: %d\n[PCEP]: OBJ LEN: %d\n",
    //             object_comm_header->object_class, object_comm_header->object_type, object_comm_header->object_length);

    free(pcep_header);
    free(object_comm_header);
    if (open_object_body != NULL) 
        free(open_object_body);
}