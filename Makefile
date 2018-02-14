TARGETS += flashwrite

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

flashwrite: main.o spiflash.o DirectHW.o
	$(CC) $(LDFLAGS) -o $@ $^

ifeq ($(KERNEL),Darwin)
CFLAGS += -D__darwin__
LDFLAGS += -framework IOKit
endif


clean:
	$(RM) *.o .*.d $(TARGETS)

-include .*.d
