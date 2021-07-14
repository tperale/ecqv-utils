CFLAGS=-c -g -O0 -Wextra -Wall -pedantic -std=gnu99 `pkg-config --cflags openssl`
LDFLAGS=`pkg-config --libs openssl` -ldl
SOURCES=$(wildcard src/*.c)
OBJECTS=$(SOURCES:.c=.o)
EXEC=ecqv-utils
CC=gcc

all: $(SOURCES) $(EXEC)

$(EXEC): $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f src/*.o $(EXEC)
