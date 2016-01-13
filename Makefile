
#CFLAGS=-O2
CFLAGS=-g -Wall
LDFLAGS=-lcrypto

all: main

main: 2cca

2cca: 2cca.c
	$(CC) $(CFLAGS) -o $@ $+ $(LDFLAGS)

clean:
	rm -f 2cca

