CC=gcc
CFLAGS=-Wall -Wextra -Wwrite-strings -g
SRC= $(wildcard *.c)
TARGET=flood
LIBS=-lpthread

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(LIBS) -o $(TARGET)

clean: 
	rm -rf $(TARGET)