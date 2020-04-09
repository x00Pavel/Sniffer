#include <pcap/pcap.h>
#include <stdint.h>

extern char *interface;
extern int num_of_pkts;
extern int port;
extern int tcp;
extern int udp;

void print_log(char *msg, int type);

void start_loop();

void process_packet(u_int8_t *args, const struct pcap_pkthdr *header,
                    const u_int8_t *buffer);
