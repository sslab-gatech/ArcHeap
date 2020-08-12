#include <stddef.h>
#include <stdio.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))

typedef size_t INTERNAL_SIZE_T;

struct malloc_chunk {
    INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
    INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

    struct malloc_chunk* fd;         /* double links -- used only if free. */
    struct malloc_chunk* bk;

    /* Only used for large blocks: pointer to next larger size.  */
    struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
    struct malloc_chunk* bk_nextsize;
};

struct malloc_chunk* raw_to_chunk(void* p) {
  return p - offsetof(struct malloc_chunk, fd);
}

int round_up(int num, int multiple) {
    assert(multiple);
    return ((num + multiple - 1) / multiple) * multiple;
}

int chunk_size(int sz) {
  return MAX(
      round_up(sz + sizeof(INTERNAL_SIZE_T), sizeof(INTERNAL_SIZE_T) * 2),
      offsetof(struct malloc_chunk, fd_nextsize));
}
