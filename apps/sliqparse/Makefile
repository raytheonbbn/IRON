CC=g++
CFLAGS=-Wall -Werror -DDEBUG_LOGGING -O2

sliqparse: sliqparse.o
	$(CC) -o sliqparse sliqparse.o -lpcap

sliqparse.o: sliqparse.c
	$(CC) -c $(CFLAGS) sliqparse.c

clean:
	rm *.o sliqparse
