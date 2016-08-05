# Example makefile for 2cca
# Should work on Linux, BSD, and OSX
# OSX requires installing libressl with brew

#CFLAGS=-O2
CFLAGS=-g -Wall
LDFLAGS=-lcrypto

# For OSX only
OS:=$(shell uname)
ifeq ($(OS),Darwin)
    LIBRESSL=/usr/local/opt/libressl
    CFLAGS+=-I$(LIBRESSL)/include
    LDFLAGS+=-L$(LIBRESSL)/lib
endif
    

all: main

main: 2cca

2cca: 2cca.c
	$(CC) $(CFLAGS) -o $@ $+ $(LDFLAGS)

clean:
	rm -f 2cca

