CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lcrypto
TARGET = merkletree
SRC = merkletree.c
BINDIR = bin

all: $(BINDIR)/$(TARGET)

$(BINDIR)/$(TARGET): $(SRC) | $(BINDIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BINDIR):
	mkdir -p $(BINDIR)

clean:
	rm -rf $(BINDIR)

.PHONY: all clean

