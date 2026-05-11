CFLAGS=-g

kodilogin: main.o tpool.o utils.o
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto -pthread

main.o: main.c tpool.h utils.h
tpool.o: tpool.c tpool.h
utils.o: utils.c utils.h

