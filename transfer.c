#include "transfer.h"


uint32_t get_random_src_address(uint32_t random_num){
    uint32_t res = 0xc0 ;
    res = (res << 24) | (random_num >> 8);
    return res;
}

byte *serialize_ip_header(IP_Header_t *ip_header){
    size_t offset = 0;
    byte *stream = (byte *) malloc(sizeof(IP_Header_t));
    // version_n_IHL
    memmove(stream, &ip_header->version_n_IHL, sizeof(ip_header->version_n_IHL));
    offset += sizeof(ip_header->version_n_IHL);
    // type_of_service
    memmove(stream + offset, &ip_header->type_of_service, sizeof(ip_header->type_of_service));
    offset += sizeof(ip_header->type_of_service);
    // total_length
    uint16_t _total_length = htons(ip_header->total_length);
    memmove(stream + offset, &_total_length, sizeof(ip_header->total_length));
    offset += sizeof(ip_header->total_length);
    // id
    uint16_t _id = htons(ip_header->id);
    memmove(stream + offset, &_id, sizeof(ip_header->id));
    offset += sizeof(ip_header->id);
    // flags_n_offset
    uint16_t _flags_n_offset = htons(ip_header->flags_n_offset);
    memmove(stream + offset, &_flags_n_offset, sizeof(ip_header->flags_n_offset));
    offset += sizeof(ip_header->flags_n_offset);
    // time_to_live
    memmove(stream + offset, &ip_header->time_to_live, sizeof(ip_header->time_to_live));
    offset += sizeof(ip_header->time_to_live);
    // protocol
    memmove(stream + offset, &ip_header->protocol, sizeof(ip_header->protocol));
    offset += sizeof(ip_header->protocol);
    // checksum
    uint16_t _checksum = htons(ip_header->checksum);
    memmove(stream + offset, &_checksum, sizeof(ip_header->checksum));
    offset += sizeof(ip_header->checksum);
    // src_address
    uint32_t _src_address = htonl(ip_header->src_address);
    memmove(stream + offset, &_src_address, sizeof(ip_header->src_address));
    offset += sizeof(ip_header->src_address);
    // dst_address
    uint32_t _dst_address = htonl(ip_header->dst_address);
    memmove(stream + offset, &_dst_address, sizeof(ip_header->dst_address));
    offset += sizeof(ip_header->dst_address);

    return stream;
}

byte *serialize_tcp_header(TCP_Header_t *tcp_header){
    size_t offset = 0;
    byte *stream = (byte *) malloc(sizeof(TCP_Header_t));
    // src_port 
    uint16_t _src_port = htons(tcp_header->src_port);
    memmove(stream, &_src_port, sizeof(tcp_header->src_port));
    offset += sizeof(tcp_header->src_port);
    // dst_port
    uint16_t _dst_port = htons(tcp_header->dst_port);
    memmove(stream + offset, &_dst_port, sizeof(tcp_header->dst_port));
    offset += sizeof(tcp_header->dst_port);
    // sequence_num
    uint32_t _sequence_num = htons(tcp_header->sequence_num);
    memmove(stream + offset, &_sequence_num, sizeof(tcp_header->sequence_num));
    offset += sizeof(tcp_header->sequence_num);
    // ack_num
    uint32_t _ack_num = htons(tcp_header->ack_num);
    memmove(stream + offset, &_ack_num, sizeof(tcp_header->ack_num));
    offset += sizeof(tcp_header->ack_num);
    // offset_n_reserved
    memmove(stream + offset, &tcp_header->offset_n_reserved, sizeof(tcp_header->offset_n_reserved));
    offset += sizeof(tcp_header->offset_n_reserved);
    // control_bits
    memmove(stream + offset, &tcp_header->control_bits, sizeof(tcp_header->control_bits));
    offset += sizeof(tcp_header->control_bits);
    // window
    uint16_t _window = htons(tcp_header->window);
    memmove(stream + offset, &_window, sizeof(tcp_header->window));
    offset += sizeof(tcp_header->window);
    // checksum
    uint16_t _checksum = htons(tcp_header->checksum);
    memmove(stream + offset, &_checksum, sizeof(tcp_header->checksum));
    offset += sizeof(tcp_header->checksum);
    // urgent_ptr
    uint16_t _urgent_ptr = htons(tcp_header->urgent_ptr);
    memmove(stream + offset, &_urgent_ptr, sizeof(tcp_header->urgent_ptr));

    return stream;
}

/* Deprecated but may want to revisit */
void update_checksums(IP_Header_t* ip_header, TCP_Header_t* tcp_header) {
    if (ip_header == NULL) {
        perror("IP Header is NULL");
        exit(-EINVAL);
    }
    if (tcp_header == NULL) {
        perror("TCP Header is NULL");
        exit(-EINVAL);
    }
}

byte *form_packet(byte *ip_stream, byte *tcp_stream) {
    size_t len_ip = sizeof(IP_Header_t);
    size_t len_tcp = sizeof(TCP_Header_t);
    byte *result = (byte *) malloc(len_ip + len_tcp);
    memmove(result, ip_stream, len_ip);
    memmove(result + len_ip, tcp_stream, len_tcp);
    return result;
}

void fill_SYN(IP_Header_t *iphead, TCP_Header_t *tcphead, uint32_t dst_address, uint16_t dst_port){
    // IP Segment
    IP_set_version(iphead, 0x4);
    IP_set_IHL(iphead, 0x5);
    IP_set_type_of_service(iphead, 0x00);
    IP_set_total_length(iphead, 0x0028);
    IP_set_id(iphead, 0xabcd);
    IP_set_flags(iphead, 0x0);
    IP_set_offset(iphead, 0x0);
    IP_set_time_to_live(iphead, 0x40);
    IP_set_protocol(iphead, 0x06);
    IP_set_dst_address(iphead, dst_address);

    // TCP Segment
    TCP_set_src_port(tcphead, 0x1234);
    TCP_set_dst_port(tcphead, dst_port);
    TCP_set_sequence_num(tcphead, 0x0);
    TCP_set_ack_num(tcphead, 0x0);
    TCP_set_offset(tcphead, 0x5);
    TCP_set_reserved(tcphead, 0x0);
    TCP_set_control_bits(tcphead, 0x2);
    TCP_set_window(tcphead, 0x7110);
    TCP_set_ugent_ptr(tcphead, 0x0);
}

/* specify the endianess OF THE SYSTEM */
void bin_dump(byte *stream, int numbytes, int endianess){
    if(endianess == LITTLE_ENDIAN){
        for(int i = 0; i < numbytes; i ++){
            byte chunk = *(stream + i);
            for(int b = 7; b >= 0; b --){
                (chunk & (1 << b)) ? printf("1") : printf("0");
            }
            printf(" ");
        }
        printf("\n");
    }else{ //big endian
        for(int i = numbytes - 1; i >= 0; i --){
            byte chunk = *(stream + i);
            for(int b = 7; b >= 0; b --){
                (chunk & (1 << b)) ? printf("1") : printf("0");
            }
            printf(" ");
        }
        printf("\n");
    }
}

void hexDump(void *buffer, size_t length) {
    unsigned char* p = (unsigned char*) buffer;

    for (size_t i = 0; i < length; i++) {
        printf("%02X ", p[i]);

        // Print an extra space after 8 bytes
        if ((i + 1) % 8 == 0)
            printf(" ");

        // Print a new line after 16 bytes
        if ((i + 1) % 16 == 0)
            printf("\n");
    }

    // Print a final new line if the last line wasn't complete
    if (length % 16 != 0)
        printf("\n");
}