PTMALLOC := $(addprefix ptmalloc2-glibc2.23/, house-of-unsorted-einherjar unaligned-double-free fast-bin-to-other-bin overlapping-chunks-smallbin)
DLMALLOC := dlmalloc-2.8.6/house-of-lily
TARGET := $(PTMALLOC) $(DLMALLOC)

CFLAGS := -I.

all: $(TARGET)

clean:
	rm -rf $(TARGET)

.PHONY: all clean
