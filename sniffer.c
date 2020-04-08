#include <stdio.h>
#include <pcap.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>

//typedef enum interfaces {
//    all = 0,
//    eth0 = 1,
//    wlan0 = 2
//} Interfaces;


FILE *logofile;
struct sockaddr_in src, dst;

char* interface = "all";
int num_of_pkts = -1;
int port = -1;
bool tcp = false;
bool udp = false;

int main(int argc, char** argv) {
    int c;

    pcap_if_t *alldevsp, *device;
    pcap_t *host;
    char err_buff[100];
    char *device_name;
    char devs[100][100];

    if (pcap_findalldevs(&alldevsp, err_buff)){
        printf("Error finding devices : %s" , err_buff);
        exit(1);
    }

    pcap_if_t *tmp;
    int i = 0;
    for (tmp = alldevsp; tmp; tmp = tmp->next){
        printf("#%d: %s %s %s\n",++i,tmp->name,tmp->description,tmp->description);
    }

    while ((c = getopt(argc, argv, "i:p:n:tcpudp")) != -1){
        switch (c){
            case 'i':
                if (optarg != NULL){
                    interface = optarg;
                }
                else{
                    printf("Flag -i is set, but no interface given. Out...\n");
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
            default:
                return 1;
        }
        printf("arg is %c\nvalue is %s\n",c, optarg);
    }



    return 0;
}
