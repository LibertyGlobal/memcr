MAKEFLAGS += -rR

ifeq ("$(origin CC)", "default")
    undefine CC
endif

CC ?= $(CROSS_COMPILE)gcc

CFLAGS = -Wall -Werror -g -O2

SRC = $(wildcard *.c)
BIN = $(SRC:%.c=%)

MEMCR ?= ../memcr

all: $(BIN)
	@./run.sh $(MEMCR)

$(BIN): %: %.c Makefile
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: all clean
