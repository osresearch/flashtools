TARGETS += flashtool
TARGETS += poke
TARGETS += peek
TARGETS += cbfs
TARGETS += uefi

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
cbfs: cbfs.o util.o
uefi: uefi.o util.o

$(TARGETS):
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	$(RM) *.o .*.d $(TARGETS)

-include .*.d
