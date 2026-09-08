CC = gcc
CFLAGS = -O0 -g -finstrument-functions -no-pie
LDFLAGS = -no-pie

all: processor

processor: main.o data.o io.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

main.o: main.c data.h io.h
	$(CC) $(CFLAGS) -c -o $@ $<

data.o: data.c data.h
	$(CC) $(CFLAGS) -c -o $@ $<

io.o: io.c io.h data.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o processor

.PHONY: all clean
