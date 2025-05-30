CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lcrypto
TARGET = merkletree
SRC = merkletree.c
BINDIR = bin
OUTBIN = $(BINDIR)/$(TARGET)

all: $(OUTBIN)

$(OUTBIN): $(SRC) | $(BINDIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BINDIR):
	mkdir -p $(BINDIR)

run: $(OUTBIN)
	./$(OUTBIN)

clean:
	rm -rf $(BINDIR)

.PHONY: all clean run

