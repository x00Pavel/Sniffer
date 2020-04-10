CFLAGS= -Wconversion -Wunreachable-code -Wextra -Wall -O -g
FNC=functions.c
SNIFFER=sniffer.c

make:
	gcc ${CFLAGS} -o ipk-sniffer ${SNIFFER} ${FNC} -lpcap

run:
	./ipk-sniffer -i wlp2s0 -t -u -n 10

val:
	valgrind --leak-check=full --track-origins=yes ./ipk-sniffer  -i wlp2s0 --tcp  -p 8888 -n 10
