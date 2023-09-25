#ifndef TRANSFER_H
#define TRANSFER_H


#include "packets.h"

/* General Libraries*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h> 
#include <string.h>
#include <stdlib.h>
#include <errno.h>

/* Libraries for Sockets */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>


/**
 * @brief Sets source address of IP Segment to random address starting with 192.
 * 
 * @param random_num random number used for random address
 */
uint32_t get_random_src_address(uint32_t random_num);

/**
 * @brief Serialize the IP_Header_t struct into a buffer with network byte ordering
 * 
 * @param ip_header Pointer to the instance of the IP_Header_t struct to be serialized
 * @return byte* Pointer to the beginning of the serialized buffer
 */
byte *serialize_ip_header(IP_Header_t *ip_header);

/**
 * @brief Serialize the TCP_Header_t struct into a buffer with network byte ordering
 * 
 * @param tcp_header Pointer to the instance of the TCP_Header_t struct to be serialized
 * @return byte* Pointer to the beginning of the buffer with serialized TCP_Header_t
 */
byte *serialize_tcp_header(TCP_Header_t *tcp_header);

/**
 * @brief Updates the checksums of a serialized TCP/IP packet
 * 
 * @param packet_stream Pointer to the beginning of the serialized packet
 */
void update_checksums(IP_Header_t* ip_header, TCP_Header_t* tcp_header);

/**
 * @brief combines the serialized streams of the IP Header and TCP Header
 * 
 * @param ip_stream Pointer to the beginning of the serialized IP_Header_t
 * @param tcp_stream Pointer to the beginning of the serialized TCP_Header_t
 * @return byte* Pointer to the beginning of the serialized packet
 */
byte *form_packet(byte *ip_stream, byte *tcp_stream);

/**
 * @brief Populates IP and TCP headers with SYN fields
 * 
 * @param iphead Pointer to the instance of the IP_Header_t struct to be populated
 * @param tcphead Pointer to the instance of the TCP_Header_t struct to be populated
 * @param dst_address The destination ip address of the packet
 * @param dst_port The destination port of the packet
 */
void fill_SYN(IP_Header_t *iphead, TCP_Header_t *tcphead, uint32_t dst_address, uint16_t dst_port);

/**
 * @brief Dumps the binary of the specified stream/buffer
 * 
 * @param stream The stream/buffer to be read
 * @param numbytes The number of bytes to be read
 * @param endianess The endianness of the architecture
 */
void bin_dump(byte *stream, int numbytes, int endianess);

/**
 * @brief Dumps the hex of the specified stream/buffer
 * 
 * @param buffer The stream/buffer to be read
 * @param length The number of bytes to be read
 */
void hexDump(void *buffer, size_t length);


#endif