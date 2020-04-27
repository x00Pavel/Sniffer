/**
 * \author Pavel Yadlouski (xyadlo00)
 * \date April, 2020
 * \brief Projet for subject IPK
 * \file functions.h  Header file for functions.c
 */

#include <pcap/pcap.h>
#include <stdint.h>
#include <stdbool.h>

extern char *interface;
extern int num_of_pkts;
extern int port;
extern int tcp_f, udp_f;

void print_log(char *msg, int type);

void start_loop();
