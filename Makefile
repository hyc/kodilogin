CFLAGS=-g

prog: main.o tpool.o
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto

main.o: main.c tpool.h
tpool.o: tpool.c tpool.h

