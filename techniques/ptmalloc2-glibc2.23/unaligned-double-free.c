#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>

#include "malloc-lib.h"

int main() {
  const int a = 3;
  const int b = 4;

  int sz1 = 0x400 - 8;
  int sz2 = 0x300 - 8;

  void *p1[a], *p2[b];

  // [PRE-CONDITION]
  //    sz1: non-fast-bin size
  //    sz2: non-fast-bin size
  //    sz1 and sz2 have the following relationship;
  //    assert(chunk_size(sz1) * a == chunk_size(sz2) * b);
  // [BUG] double free
  // [POST-CONDITION]
  //    two chunks overlap

  for (int i = 0; i < a; i++)
    p1[i] = malloc(sz1);

  // allocate a chunk to prevent merging with the top chunk
  void* p = malloc(0);

  // free from backward not to modify size of p1[a - 1]
  for (int i = a - 1; i >= 0; i--)
    free(p1[i]);

  // allocate chunks to fill empty space
  for (int i = 0; i < b; i++)
    p2[i] = malloc(sz2);

  // now a next free chunk of p1[a-1] is p whose P=1,
  // and p1[a-1] contains valid metadata
  // since malloc does not clean up the memory

  // [BUG] double free
  free(p1[a-1]);

  // now new allocation returns p1[a-1]
  // that overlaps with p2[b-1]
  assert(malloc(sz1) == p1[a-1]);
}
