CC = gcc
CFLAGS = -Wall -g -c
LDFLAGS = -lpfring

PROJECT = sniff

compile: $(PROJECT).o
	$(CC) $^ -o $(PROJECT) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $^

clean:
	rm -f *.o $(PROJECT)
