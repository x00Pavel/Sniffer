/**
 * \author Pavel Yadlouski (xyadlo00)
 * \date April, 2020
 * \brief Projet for subject IPK
 * \file functions.c  'Backend' functionality of sniffer
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Default values
char *interface = "any";
int num_of_pkts = 1;
int port = -1;
int tcp_flag = 0, udp_flag = 0;
int tcp_f = -1, udp_f = -1;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total_cnt = 0, i, j;

struct sockaddr_in source, dest;
struct bpf_program fp;

/**
 * \brief Printing of log information to standart error output
 */
void print_log(char *msg, int type) {
    switch (type) {
        case 1:
            fprintf(stderr, "\033[1;31mERROR\033[0m: %s\n", msg);
            break;
        case 2:
            fprintf(stderr, "\033[1;34mLOG\033[0m: %s\n", msg);
            break;
        default:
            break;
    }
}

/**
 * \brief Formated print of given packet
 */
void print_data(const u_int8_t *packet, u_int32_t size) {
    u_int32_t j;
    for (u_int32_t i = 0; i < size; i = i + 16 ) {
        char str[17];

        u_int32_t len = 16;
        if (i + 16 >= size) {
            len = size - i;
        } //else {
            // printf("0x%04x ", i);
        // }
            printf("0x%04x ", i );

        for (j = 0; j < len; j++) {
            printf("%02x ", packet[i + j]);

            if (packet[i + j] > 32 && packet[i + j] < 127) {
                sprintf(str + j, "%c", packet[i + j]);
            } else {
                sprintf(str + j, ".");
            }
        }

        if (len != 16) {
            for (u_int32_t a = len; a < 16; a++) {
                printf("   ");
            }
        }
        if (i != 0 && (i + 16) % 64 == 0) {
            printf("%s\n\n", str);
        } else {
            printf("%s\n", str);
        }
    }
    printf("\n");
}

// void process_tcp(){
//     struct tcphdr *tcp_h = (struct tcphdr *)(packet + ip_hdr_len + sizeof(struct ethhdr));
//     source.sin_port = tcp_h->source;
//     dest.sin_port = tcp_h->dest;
// }

void process_packet(const struct pcap_pkthdr *header, const u_int8_t *packet) {
    struct timeval timestamp = header->ts;
    char str[80];
    struct tm *info;
    char src[NI_MAXHOST];  // Buffer for source address
    char dst[NI_MAXHOST];  // Buffer for destination address
    struct iphdr *iph;
    int ip_hdr_len;

    // Prepare data for processing
    iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
    ip_hdr_len = iph->ihl * 4;
    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));
    source.sin_family = AF_INET;
    dest.sin_family = AF_INET;
    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;

    // Ger source host name or IP addres on failed
    if (getnameinfo((struct sockaddr *)&source, sizeof(source), src,
                    sizeof(src), NULL, 0, 0) != 0) {
        print_log("Error in getting source address", 1);
        exit(1);
    }

    // Ger destination host name or IP addres on failed
    if (getnameinfo((struct sockaddr *)&dest, sizeof(dest), dst, sizeof(dst),
                    NULL, 0, 0) != 0) {
        print_log("Error in getting destination address", 1);
        exit(1);
    }

    // Getting header of current protocol
    struct tcphdr *tcp_h;
    struct udphdr *udp_h;
    
    switch (iph->protocol) {
        case 6:  // TCP

            print_log("TCP packet", 2);
            tcp_h =
                (struct tcphdr *)(packet + ip_hdr_len + sizeof(struct ethhdr));
            source.sin_port = tcp_h->source;
            dest.sin_port = tcp_h->dest;
            break;
        case 17:  // UDP
            print_log("UDP packet", 2);
            udp_h =
                (struct udphdr *)(packet + ip_hdr_len + sizeof(struct ethhdr));
            source.sin_port = udp_h->uh_sport;
            dest.sin_port = udp_h->uh_dport;
            break;
        default:  // Other protocol
            print_log("Other protocol", 2);
            return;
    }

    // Getting time from timestamp
    info = localtime(&timestamp.tv_sec);
    strftime(str, 80, "%X", info);
    fprintf(stdout, "%s.%ld ", str, timestamp.tv_usec);
    fprintf(stdout, "%s: %u-> %s: %u\n\n", src, ntohs(source.sin_port), dst,
            ntohs(dest.sin_port));
    print_data(packet, header->len);
}

/**
 * \brief Function for creating filter string
 *
 * \param[out] filter Returning string with genreated filter string
 */
void create_filter(char *filter) {
    if (udp_f == tcp_f) {
        if (port != -1) {
            sprintf(filter, "tcp port %d or udp port %d", port, port);
        } else {
            sprintf(filter, "tcp or udp ");
        }
    } else if (udp_f == 1) {
        if (port != -1) {
            sprintf(filter, "udp port %d", port);
        }
        else{
            sprintf(filter, "udp");
        }
    } else if (tcp_f == 1) {
        if (port != -1) {
            sprintf(filter, "tcp port %d", port);
        }
        else{
            sprintf(filter, "tcp");
        }
    }
}

/**
 * \brief Function that prepare given interface for sniffing
 */
void start_loop() {
    char err_buf[PCAP_ERRBUF_SIZE];
    char filter[128];
    pcap_t *handler;
    struct pcap_pkthdr header;
    const uint8_t *packet;

    // Opening interfacer for sniffing
    print_log("Opening interface for sniffing ", 2);
    print_log(interface, 2);
    handler = pcap_open_live(interface, 65536, 1, 0, err_buf);
    if (handler == NULL) {
        print_log("Couldn't open device", 1);
        print_log(err_buf, 1);
        exit(1);
    }

    // Setup filter
    create_filter(filter);
    print_log(filter, 2);
    if (pcap_compile(handler, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        print_log("Creating of filters is failed...", 1);
        pcap_geterr(handler);
        exit(1);
    }

    if (pcap_setfilter(handler, &fp) == -1) {
        print_log("Setting filter is failed", 1);
        print_log(err_buf, 1);
        exit(1);
    }

    // Processing of packets
    print_log("Start sniffing given device", 2);

    for (int i = 0; i < num_of_pkts; i++) {
        packet = pcap_next(handler, &header);
        if (packet == NULL) {
            print_log("Didn't grab packet", 1);
            exit(1);
        }

        process_packet(&header, packet);
    }
}
