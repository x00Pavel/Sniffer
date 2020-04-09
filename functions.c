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

FILE *logfile;
struct sockaddr_in src, dst;

char *interface = "any";
int num_of_pkts = -1;
int port = -1;
int tcp = 0;
int udp = 0;
int total = 0;

void print_log(char *msg, int type) {
    switch (type) {
        case 1:
            printf("\033[0;31mERROR\033[0m: %s\n", msg);
            break;
        case 2:
            printf("\033[0;34mLOG\033[0m: %s\n", msg);
            break;
        default:
            break;
    }
}
void process_packet(u_int8_t *args, const struct pcap_pkthdr *header,
                    const u_int8_t *buffer) {
    print_log("HER", 2);
    u_int32_t size = header->len;
    

    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) {
        case 6:  // TCP
            printf("total len in tcp %d", iph->tot_len);
            break;
        case 17:  // UDP
            printf("total len in udp %d", iph->tot_len);
            break;
        default:  // Other protocol
            break;
            // print_log("Protocol not supported");
            // exit(1);
    }
}

void start_loop() {
    pcap_if_t *alldevsp;
    char err_buff[PCAP_ERRBUF_SIZE];
    char *device;

    if (pcap_findalldevs(&alldevsp, err_buff) == -1) {
        printf("Error finding devices : %s", err_buff);
        exit(1);
    }

    pcap_if_t *tmp;
    int i = 0;
    for (tmp = alldevsp; tmp; tmp = tmp->next) {
        printf("#%d: %s %s \n", ++i, tmp->name, tmp->description);
    }

    pcap_t *handler;
    device = alldevsp[0].name;
    handler = pcap_open_live(device, 65536, 1, 0, err_buff);
    if (handler != NULL) {
        fprintf(stderr, "Can't open %s: %s\n", device, err_buff);
        exit(1);
    }

    print_log("Open live is done", 2);

    logfile = fopen("log.txt", "w");
    if (logfile == NULL) {
        printf("Unable to create file.");
    }

    // Put the device in sniff loop
    pcap_loop(handler, num_of_pkts, process_packet, NULL);
}
