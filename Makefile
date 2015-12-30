
CFLAGS=-O2
#CFLAGS=-g
LDFLAGS=-lcrypto

all: main

main: 2cca

2cca: 2cca.c
	$(CC) $(CFLAGS) -o $@ $+ $(LDFLAGS)

clean:
	rm 2cca

