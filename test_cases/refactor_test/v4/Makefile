CC = gcc
CFLAGS = -O0 -g -finstrument-functions -no-pie
LDFLAGS = -no-pie
all: processor
processor: main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
clean:
	rm -f processor
.PHONY: all clean
