CC=g++
CFLAGS=-Wall -DDEBUG_LOGGING

all: vreplay vrcvr addvif delvif

vreplay: vreplay.o
	$(CC) -o vreplay vreplay.o -lpcap -lpthread

vreplay.o: vreplay.c
	$(CC) -c $(CFLAGS) vreplay.c

vrcvr: vrcvr.o
	$(CC) -o vrcvr vrcvr.o -lpthread

vrcvr.o: vrcvr.c
	$(CC) -c $(CFLAGS) vrcvr.c

addvif: addvif.o
	$(CC) -o addvif addvif.o

addvif.o: addvif.c
	$(CC) -c $(CFLAGS) addvif.c

delvif: delvif.o
	$(CC) -o delvif delvif.o

delvif.o: delvif.c
	$(CC) -c $(CFLAGS) delvif.c

clean:
	rm *.o vreplay vrcvr addvif delvif

