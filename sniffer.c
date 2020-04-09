#include <getopt.h>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "functions.h"

int main(int argc, char **argv) {
    int c;

    if (argc == 1) {
        print_log("No parameters are specified", 1);
        exit(1);
    }

    static struct option long_opts[] = {{"tcp", no_argument, &tcp, 1},
                                        {"udp", no_argument, &udp, 1}};

    while ((c = getopt_long(argc, argv, "i:p:n:tu", long_opts, NULL)) != -1) {
        switch (c) {
            case 0:
                break;
            case 'i':
                if (optarg != NULL) {
                    interface = optarg;
                } else {
                    printf("Flag -i is set, but no interface given. Out..\n");
                    return 1;
                }
                break;
            case 'n':
                num_of_pkts = (int) strtol(optarg, NULL, 10);
                break;
            case 'p':
                port = (int) strtol(optarg, NULL, 10);
                break;
            case 't':
                tcp = true;
                break;
            case 'u':
                udp = true;
                break;
            case '?':
            default:
                print_log("Error while processing arguments. Unknown argument", 1);
                return 1;
        }
    }

    start_loop();
    print_log("All alright.End..", 2);
    return 0;
}
