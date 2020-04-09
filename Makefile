CFLAGS= -Wconversion -Wunreachable-code -Wextra -Wall -O -g
FNC=functions.c
SNIFFER=sniffer.c

make:
	gcc ${CFLAGS} -o ipk-sniffer ${SNIFFER} ${FNC} -lpcap

val:
	valgrind  --leak-check=full --track-origins=yes ./ipk-sniffer