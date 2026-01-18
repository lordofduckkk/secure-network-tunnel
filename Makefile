CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2
LDLIBS = -lssl -lcrypto

all: tunnel-server tunnel-client

tunnel-server: src/tls-server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

tunnel-client: src/tls-client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f tunnel-server tunnel-client

.PHONY: all clean

