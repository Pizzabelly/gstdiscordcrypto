all: CC=gcc

CFLAGS  = -O3 -Wall -std=c99 $(shell pkg-config --cflags --libs gstreamer-1.0 gstreamer-plugins-base-1.0)

all: obj lib

debug: CFLAGS += -DDEBUG -g
debug: executable

all: LDFLAGS  = -lgstbase-1.0 -lgstrtp-1.0 -lsodium

obj: gstdiscordcrypto.c
	$(CC) $(CFLAGS) -c -fpic gstdiscordcrypto.c

lib: gstdiscordcrypto.o
	$(CC) -shared -o discordcrypto.so gstdiscordcrypto.o $(LDFLAGS)

clean:
	$(RM) discordcrypto.so gstdiscordcrypto.o
