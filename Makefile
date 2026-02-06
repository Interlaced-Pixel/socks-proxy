CC = clang
CFLAGS = -Wall -Wextra -O2 -I.
LDFLAGS = -lpthread

SRCS = socks5.c
TARGET = socks5

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
