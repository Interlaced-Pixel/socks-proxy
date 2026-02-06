# Prefer clang if available, otherwise fall back to gcc
ifneq ($(shell command -v clang 2>/dev/null),)
CC := clang
else ifneq ($(shell command -v gcc 2>/dev/null),)
CC := gcc
else
CC := clang
endif

CFLAGS = -Wall -Wextra -O2 -I.

# Detect Windows (MSYS2/MinGW) and link Winsock instead of pthreads
ifeq ($(OS),Windows_NT)
LDFLAGS = -lws2_32
else
LDFLAGS = -lpthread
endif

SRCS = socks5.c
TARGET = socks5

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

TESTS = tests
TEST_SRCS = tests.c

tests: $(TEST_SRCS)
	$(CC) $(CFLAGS) $(TEST_SRCS) -o $(TESTS) $(LDFLAGS)

check: all tests
	./$(TESTS)

clean:
	rm -f $(TARGET) $(TESTS)

.PHONY: all clean tests check
