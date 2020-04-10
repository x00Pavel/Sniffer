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


char *interface = "any";
int num_of_pkts = 1;
int port = -1;
int tcp_flag = 0;
int udp_flag = 0;

FILE *logfile;
struct sockaddr_in source, dest;
int tcp_f = -1, udp_f = -1;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total_cnt = 0, i, j;
struct bpf_program fp;

size_t def_size = 20 * sizeof(char);

typedef struct string_s {
     char * str;
     size_t size;
     size_t len;
} string_t;

string_t string = {NULL, 0, 0};

void delete_string(){
    if (string.str){
        free(string.str);
    } 
}

void concat_str(char *src){
    if ((sizeof(src)/sizeof(char)) + string.len + 4 >= string.size) {
        string.str = (char *) realloc(string.str, def_size);
        string.size += def_size;
    }
    string.str = strcat(string.str, src);
    string.str = strcat(string.str, " ");
}

void create_string() {
    if (string.str){
        free(string.str);
        string.str = NULL;
    } 
    string.str = (char *)malloc(def_size);
    string.size = def_size;
    string.len = 0;
}

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

void process_tcp(const u_int8_t *buffer, u_int32_t size) {}

void process_udp(const u_int8_t *buffer, u_int32_t size) {}

void process_packet(u_int8_t *args, const struct pcap_pkthdr *header,
                    const u_int8_t *buffer) {
    u_int32_t size = header->len;

    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ++total_cnt;

    switch (iph->protocol) {
        case 6:  // TCP
            process_tcp(buffer, size);
            printf("total len in tcp %d\n", iph->tot_len);
            break;
        case 17:  // UDP
            process_udp(buffer, size);
            printf("total len in udp %d\n", iph->tot_len);
            break;
        default:  // Other protocol
            break;
            // print_log("Protocol not supported");
            // exit(1);
    }
}

char *create_filter(){
    create_string();
    if (udp_f == tcp_f){
        concat_str("tcp or udp");
    } else if (udp_f == 1){
        concat_str("udp");
    } else if (tcp_f == 1){
        concat_str("tcp");
    }

    if (port != -1){
        char str[sizeof(port) + 1];
        sprintf(str, "%d", port);
        concat_str("port");
        concat_str(str);
    }

    return string.str;
}

void start_loop() {
    pcap_if_t *alldevsp; //, *device;
    pcap_t *handler;  // Handle of the device that shall be sniffed
    char *filter;

    char err_buf[PCAP_ERRBUF_SIZE];
    int count = 0;

    // First get the list of available devices
    print_log("Finding available devices ... ", 2);
    if (pcap_findalldevs(&alldevsp, err_buf)) {
        print_log("Error scanning devices", 1);
        print_log(err_buf, 1);
        exit(1);
    }

    // Print the available devices
    // printf("\nAvailable Devices are :\n");
    // for (device = alldevsp; device != NULL; device = device->next) {
    //     printf("%d. %s - %s\n", count, device->name, device->description);
    //     if (device->name != NULL) {
    //         strcpy(devs[count], device->name);
    //     count++;

    //     }
    // }

    count = sizeof(&alldevsp);
    bool valid = false;
    for (int i = 0; i <= count; i = i + 1) {
        char *name = alldevsp[i].name;
        if (name != NULL) {
            if (strcmp(name, interface) == 0) {
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

    print_log("Opening interface for sniffing ", 2);
    print_log(interface, 2);
    handler = pcap_open_live(interface, 65536, 1, 0, err_buf);
    if (handler == NULL) {
        print_log("Couldn't open device", 1);
        print_log(err_buf, 1);
        exit(1);
    }

    // Setup filter 
    filter = create_filter();
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


    print_log("Start sniffing given device", 2);

    // Put the device in sniff loop
    pcap_loop(handler, num_of_pkts, process_packet, NULL);
}