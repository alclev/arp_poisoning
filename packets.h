#ifndef PACKETS_H
#define PACKETS_H


#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>


#define IO_LIMIT 1

typedef unsigned char byte;


/* STRUCTURES */

/**
 * @brief IP Header segment of the TCP/IP packet
 * 
 */
typedef struct  IP_Header {
    uint8_t version_n_IHL;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_n_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_address;
    uint32_t dst_address;
    // leaving out options and padding for SYN packet
} __attribute__((__packed__)) IP_Header_t;

/**
 * @brief TCP Header segment of the TCP/IP packet
 * 
 */
typedef struct TCP_Header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence_num;
    uint32_t ack_num;
    uint8_t offset_n_reserved;
    uint8_t control_bits;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
    // leaving out options for SYN packet
} __attribute__((__packed__)) TCP_Header_t;


/* PROTOTYPES */


/**
 * @brief Set the version field
 * 
 * @param self Instance of the IP_Header_t struct
 * @param version The new version
 */
void IP_set_version(IP_Header_t* this, uint8_t version);

/**
 * @brief Set the IP Header Length
 * 
 * @param this Instance of the IP_Header_t struct
 * @param IHP the new IP Header Length
 */
void IP_set_IHL(IP_Header_t* this, uint8_t IHL);

void IP_set_type_of_service(IP_Header_t* this, uint8_t type_of_service);

void IP_set_total_length(IP_Header_t* this, uint16_t total_length);

void IP_set_id(IP_Header_t* this, uint16_t id);

void IP_set_flags(IP_Header_t* this, uint8_t flags);

void IP_set_offset(IP_Header_t* this, uint16_t offset);

void IP_set_time_to_live(IP_Header_t* this, uint8_t time_to_live);

void IP_set_protocol(IP_Header_t* this, uint8_t protocol);

void IP_set_checksum(IP_Header_t* this, uint16_t checksum); 

void IP_set_src_address(IP_Header_t* this, uint32_t src_address);

void IP_set_dst_address(IP_Header_t* this, uint32_t dst_address);

/**
 * @brief Updates checksum using current values in structure
 * 
 * @param this Instance of the IP_Header_t struct
 */
void IP_update_checksum(IP_Header_t* this);

void TCP_set_src_port(TCP_Header_t* this, uint16_t src_port);

void TCP_set_dst_port(TCP_Header_t* this, uint16_t dst_port);

void TCP_set_sequence_num(TCP_Header_t* this, uint32_t seq_num);

void TCP_set_ack_num(TCP_Header_t* this, uint32_t ack_num);

void TCP_set_offset(TCP_Header_t* this, uint8_t offset);

void TCP_set_reserved(TCP_Header_t* this, uint8_t reserved);

void TCP_set_control_bits(TCP_Header_t* this, uint8_t flags);

void TCP_set_window(TCP_Header_t* this, uint16_t window);

void TCP_set_checksum(TCP_Header_t* this, uint16_t checksum);

void TCP_set_ugent_ptr(TCP_Header_t* this, uint16_t urgent_ptr);

 /**
  * @brief Calculates and inserts checksum into TCP segment
  * 
  * @param this Pointer to the instance of the TCP_Header struct
  * @param IP_segment Pointer to the instance of the IP_Header struct
  */
void TCP_update_checksum(TCP_Header_t* this, IP_Header_t* IP_segment);

uint16_t ones_complement_add(uint16_t a, uint16_t b);

#endif