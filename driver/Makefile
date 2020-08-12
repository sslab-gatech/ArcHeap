CC ?= gcc
AFL_DIR := ../tool/afl-2.52b
CFLAGS += -std=gnu99 -g

APP := driver
FUZZ_APP := driver-fuzz
OUTPUT ?= output

all: $(APP) $(FUZZ_APP)

$(APP): driver.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

$(FUZZ_APP): driver.c
	$(AFL_DIR)/afl-gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean:
	rm -rf $(APP) $(FUZZ_APP)

.PHONY: all clean
