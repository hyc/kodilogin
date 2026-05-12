CFLAGS=-g

all: kodilogin ltunnel

kodilogin: main.o tpool.o utils.o
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto -pthread

ltunnel: ltunnel.c
	$(CC) $(CFLAGS) -o $@ $^

main.o: main.c tpool.h utils.h
tpool.o: tpool.c tpool.h
utils.o: utils.c utils.h

