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
#include <sys/socket.h>
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
    unsigned j;
    for (size_t i = 0; i < size; i += 16) {
        char str[32];

        unsigned len = 16;
        if (i + 16 >= size) {
            len = 15 - i % 16;
            printf("0x%04lx ", i + len);
        } else {
            printf("0x%04lx ", i);
        }

        for (j = 0; j < len; j++) {
            // u_int8_t c = packet[i + j];
            printf("%x ", packet[i + j]);
            sprintf(str + j, "%x ", packet[i + j]);
        }

        for (j = 0; j < len; j++) {
            if (packet[i + j] > 32 && packet[i + j] < 127) {
                printf("%c", packet[i + j]);
            } else {
                printf(".");
            }
        }

        if (i != 0 && (i + 16) % 64 == 0) {
            printf("\n\n");
        } else {
            printf("\n");
        }
    }
    printf("\n");
}

void process_packet(u_int8_t *args, const struct pcap_pkthdr *header,
                    const u_int8_t *packet) {
    (void)args;
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
            source.sin_port = udp_h->source;
            dest.sin_port = udp_h->dest;
            break;
        default:  // Other protocol
            print_log("Other protocol", 2);
            return;
    }

    // Getting time from timestamp
    info = localtime(&timestamp.tv_sec);
    strftime(str, 80, "%X", info);
    fprintf(stdout, "%s.%ld ", str, timestamp.tv_usec);
    fprintf(stdout, "%s: %u-> %s: %u\n\n", src, source.sin_port, dst,
            dest.sin_port);
    print_data(packet, header->len);
}



/**
 * \brief Function for creating filter string
 *
 * \param[out] filter Returning string with genreated filter string
 */
void create_filter(char *filter) {
    size_t offset = 0;
    if (udp_f == tcp_f) {
        sprintf(filter, "%s", "tcp and udp ");
        offset = sizeof("tcp nad udp ");
    } else if (udp_f == 1) {
        sprintf(filter, "%s", "udp ");
        offset = sizeof("proto udp ");
    } else if (tcp_f == 1) {
        sprintf(filter, "%s", "tcp ");
        offset = sizeof("proto tcp ");
    }

    if (port != -1) {
        sprintf(filter + offset, "and port %d", port);
    }
}

/**
 * \brief Function that prepare given interface for sniffing
 */
void start_loop() {
    char err_buf[PCAP_ERRBUF_SIZE];
    char filter[64];
    pcap_if_t *alldevsp;
    pcap_t *handler;
    struct pcap_pkthdr header;
    const uint8_t *packet;

    // First get the list of available devices
    print_log("Finding available devices ... ", 2);
    if (pcap_findalldevs(&alldevsp, err_buf) == -1) {
        print_log("Error scanning devices", 1);
        print_log(err_buf, 1);
        exit(1);
    }

    // Check if given interface is valid on current device
    bool valid = false;
    for (pcap_if_t *device = alldevsp; device != NULL; device = device->next) {
        if (device->name != NULL) {
            if (strcmp(device->name, interface) == 0) {
                valid = true;
                print_log("Interface is valid", 2);
                break;
            }
        }
    }

    if (!valid) {
        print_log("Interface is not avaliable on this device.", 1);
        exit(1);
    }

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

        process_packet(NULL, &header, packet);
    }
}
