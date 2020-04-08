CFLAGS= -Wconversion -Wunreachable-code -Wextra -Wall -O -g
SNIFFER=sniffer.c

make:
	gcc ${CFLAGS} -o ipk-sniffer ${SNIFFER} -lpcap

val:
	valgrind  --leak-check=full --track-origins=yes ./ipk-sniffer