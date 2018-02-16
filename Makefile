TARGETS += flashtool
TARGETS += poke
TARGETS += peek

CFLAGS += \
	-std=c99 \
	-g \
	-O3 \
	-W \
	-Wall \
	-MMD \
	-MF .$(notdir $@).d \
	-I . \

all: $(TARGETS)

flashtool: flashtool.o spiflash.o util.o
peek: peek.o util.o
poke: poke.o util.o

$(TARGETS):
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	$(RM) *.o .*.d $(TARGETS)

-include .*.d
