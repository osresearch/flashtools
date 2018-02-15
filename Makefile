TARGETS += flashwrite
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

flashwrite: flashwrite.o spiflash.o DirectHW.o
peek: peek.o DirectHW.o util.o
poke: poke.o DirectHW.o util.o

$(TARGETS):
	$(CC) $(LDFLAGS) -o $@ $^

ifeq ($(KERNEL),Darwin)
CFLAGS += -D__darwin__
LDFLAGS += -framework IOKit
endif


clean:
	$(RM) *.o .*.d $(TARGETS)

-include .*.d
