#include <getopt.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "functions.h"

void print_help() {
    printf(
        "\033[1mHow to use\033[0m:\n"
        "\tsudo ./ipk-sniffer -i <interface_name> [-n <num>] [-u] [-t] [-p "
        "<port>]\n"
        "\n\033[1mDescripton\033[0m:\n"
        "This program is a packet sniffer. It supports printing out \n"
        "whole paket of TCP and UDP protocols.\n\n"
        "\033[1mParameters\033[0m:\n"
        "\t-i <inteffaces_name> interface to be sniffed\n"
        "\t-n <num>             maximum count of packtees to be sniffed\n"
        "\t-u --udp             filter UDP packets\n"
        "\t-t --tcp             filter TCP packets\n"
        "\t-p <port>            number of port to be sniffed\n");
}
int main(int argc, char **argv) {
    int c;

    if (argc == 1) {
        print_help();
        return 0;
    }
    // Long arguments
    static struct option long_opts[] = {{"tcp", no_argument, &tcp_f, 1},
                                        {"udp", no_argument, &udp_f, 1},
                                        {"help", no_argument, NULL, 0}};
    // Parse input arguments
    int option_index = 0;
    while ((c = getopt_long(argc, argv, "hi:p:n:tu", long_opts,
                            &option_index)) != -1) {
        switch (c) {
            case 0:
                if (strcmp(long_opts[option_index].name, "help") == 0) {
                    if (argc != 2) {
                        print_log(
                            "Parameter '--help' can not be combined with "
                            "other parameters.",
                            1);
                        exit(1);
                    } else {
                        print_help();
                    }
                    return 0;
                }
                break;
            case 'h':
                print_help();
                return 0;
            case 'i':
                if (optarg != NULL) {
                    interface = optarg;
                } else {
                    printf("Flag -i is set, but no interface given. Out..\n");
                    return 1;
                }
                break;
            case 'n':
                num_of_pkts = (int)strtol(optarg, NULL, 10);
                break;
            case 'p':
                // Check if argument is set
                port = (int)strtol(optarg, NULL, 10);
                break;
            case 't':
                tcp_f = 1;
                break;
            case 'u':
                udp_f = 1;
                break;
            case '?':
            default:
                print_log("Error while processing arguments. Unknown argument",
                          1);
                return 1;
        }
    }

    start_loop();
    print_log("All alright.End..", 2);
    return 0;
}
