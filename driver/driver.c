#include <signal.h>
#include <time.h>
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>

#define FIRST_ARG(N, ...) N

#define DEBUG(...) do{ \
  assert(!strchr(FIRST_ARG(__VA_ARGS__), '\n')); \
  STMT("  // "); \
  STMT(__VA_ARGS__ ); \
  STMT("\n"); \
} while( false );


// API for printing statements
#define BEGIN_STMT \
  add_stmt("  ");

#define STMT(...) do { \
  add_stmt(__VA_ARGS__); \
} while (false);

#define END_STMT \
  flush_stmt();

#define CLEAR_STMT \
  clear_stmt();

#define DBG_VALUE "[VALUE] "
#define DBG_INFO "[INFO] "
#define FATAL(...) do { DEBUG(__VA_ARGS__); done(); } while(false)

#define MIN(a,b) \
  ({ __typeof__ (a) _a = (a); \
   __typeof__ (b) _b = (b); \
   _a < _b ? _a : _b; })

#define MAX(a,b) \
  ({ __typeof__ (a) _a = (a); \
   __typeof__ (b) _b = (b); \
   _a > _b ? _a : _b; })

typedef enum {
  VULN_OVERFLOW,
  VULN_OFF_BY_ONE_NULL,
  VULN_OFF_BY_ONE,
  VULN_WRITE_AFTER_FREE,
  VULN_DOUBLE_FREE,
  VULN_ARBITRARY_FREE,
  VULN_LAST
} VulnType;

typedef enum {
  EVENT_OVERLAP,
  EVENT_RESTRICTED_WRITE_IN_CONTAINER,
  EVENT_RESTRICTED_WRITE_IN_BUFFER,
  EVENT_ARBITRARY_WRITE_IN_CONTAINER,
  EVENT_ARBITRARY_WRITE_IN_BUFFER,
  EVENT_ALLOC_IN_CONTAINER,
  EVENT_ALLOC_IN_BUFFER,
  EVENT_LAST
} EventType;

typedef enum {
  CAP_HEAP_ADDR,
  CAP_CONTAINER_ADDR,
  CAP_BUFFER_ADDR,
  CAP_DEALLOC,
  CAP_HEAP_WRITE,
  CAP_BUFFER_WRITE,
  CAP_LAST,
} CapabilityType;

typedef struct {
  uintptr_t orig;
  uintptr_t orig_real;
  uintptr_t shadow;
  uintptr_t shadow_real;
  int front;
  int limit;
  int memory_size;
  int memory_size_real;
  int nmemb;
} ShadowMemory;

typedef struct {
  size_t limit;
  size_t size;
  char* buf;
  int index;
} Command;

typedef struct {
  ShadowMemory smem;
  bool* freed;
  bool* valid;
  size_t* usable_size;
  int limit;
  int* size;
} HeapManager;

typedef struct {
  char* name;
  int type;
  bool enable;
} Option;

typedef struct __attribute__((packed)) {
  int header;
  int footer;
  int round;
  int minsz;
} AllocatorInfo;

const uintptr_t kBadPtr = 0xcccccccc;

// Global variables
EventType       g_event_type = EVENT_LAST;
Command         g_cmd;
HeapManager     g_hmgr;
ShadowMemory    g_buffer;
uintptr_t       g_lower_bound = 0;
uintptr_t       g_upper_bound = 0;
char            g_stmt_buf[0x1000];
int             g_stmt_size = 0;
Command         g_actions;
int             g_skipped = 0;
// Info: header, footer, round, minsz
AllocatorInfo  g_allocator_info = {-1, -1, -1, -1};

// NOTE: MAX_NUM_SIZES should be <= 65535
#define MAX_NUM_SIZES 0x1000
uintptr_t       g_sizes[MAX_NUM_SIZES];
uintptr_t       g_num_sizes;

#define MAX_NUM_TXN 0x1000
uintptr_t       g_txns[MAX_NUM_TXN];
uintptr_t       g_num_txn;
uintptr_t       g_idx_txn;

#define TXN_ID_ALLOCATE 0
#define TXN_ID_DEALLOCATE 1
#define TXN_ID_VULN 2

Option  g_capabilities[] = {
  {"HEAP_ADDR", CAP_HEAP_ADDR, true},
  {"CONTAINER_ADDR", CAP_CONTAINER_ADDR, true},
  {"BUFFER_ADDR", CAP_BUFFER_ADDR, true},
  {"DEALLOC", CAP_DEALLOC, true},
  {"HEAP_WRITE", CAP_HEAP_WRITE, true},
  {"BUFFER_WRITE", CAP_BUFFER_WRITE, true},
};

Option g_vulns[] = {
  {"OVERFLOW", VULN_OVERFLOW, true},
  {"OFF_BY_ONE_NULL", VULN_OFF_BY_ONE_NULL, true},
  {"OFF_BY_ONE", VULN_OFF_BY_ONE, true},
  {"WRITE_AFTER_FREE", VULN_WRITE_AFTER_FREE, true},
  {"DOUBLE_FREE", VULN_DOUBLE_FREE, true},
  {"ARBITRARY_FREE", VULN_ARBITRARY_FREE, true}
};

Option g_events[] = {
  {"OVERLAP", EVENT_OVERLAP, true},
  {"RESTRICTED_WRITE_IN_CONTAINER", EVENT_RESTRICTED_WRITE_IN_CONTAINER, true},
  {"RESTRICTED_WRITE_IN_BUFFER", EVENT_RESTRICTED_WRITE_IN_BUFFER, true},
  {"ARBITRARY_WRITE_IN_CONTAINER", EVENT_ARBITRARY_WRITE_IN_CONTAINER, true},
  {"ARBITRARY_WRITE_IN_BUFFER", EVENT_ARBITRARY_WRITE_IN_BUFFER, true},
  {"ALLOC_IN_CONTAINER", EVENT_ALLOC_IN_CONTAINER, true},
  {"ALLOC_IN_BUFFER", EVENT_ALLOC_IN_BUFFER, true},
};

uintptr_t interesting_values[] = {
  -1,
  -sizeof(void*),
  0,
  sizeof(void*),
};

void add_stmt(char* fmt, ...) {
  va_list ap;
  int i, sum;

  va_start (ap, fmt);
  int size = vsnprintf(g_stmt_buf + g_stmt_size,
      sizeof(g_stmt_buf) - g_stmt_size,
      fmt, ap);

  if (size < 0) {
    DEBUG("Error occurred when copying a statement");
    exit(-1);
  }
  g_stmt_size += size;
  va_end(ap);
}

void clear_stmt() {
  g_stmt_size = 0;
  g_stmt_buf[0] = 0;
}

void flush_stmt() {
  if (g_stmt_size != 0) {
    g_stmt_buf[g_stmt_size] = 0;
    if (g_stmt_buf[g_stmt_size - 1] == '\n')
      fprintf(stderr, "%s", g_stmt_buf);
    else
      fprintf(stderr, "%s;\n", g_stmt_buf);
    clear_stmt();
  }
}

void done() {
  fprintf(stderr,
      "}\n");

  fprintf(stderr, "// The number of actions: %d\n", g_actions.index - g_skipped);
  if (g_event_type != EVENT_LAST) {
    fprintf(stderr, "// " DBG_INFO "EVENT_%s is detected\n",
        g_events[g_event_type].name);
    kill(getpid(), SIGUSR2);
  }
  else
    exit(-1);
}

void set_event_type(EventType ety) {
  // EVENT_* is ascending ordered by interesting
  // e.g., ALLOC_IN_BUFFER is more interesting than OVERLAP or RESTRICTED_WRITE_IN_BUFFER
  if (ety != EVENT_LAST
       && g_events[ety].enable) {
    if (g_event_type == EVENT_LAST)
      g_event_type = ety; // At first time
    else
      g_event_type = MAX(g_event_type, ety);
  }
}

uintptr_t round_up(uintptr_t value, int multiple) {
  uintptr_t remainder = value % multiple;
  if (remainder == 0)
    return value;
  else
    return value + multiple - remainder;
}

uintptr_t round_up_page_size(uintptr_t size) {
  return round_up(size, getpagesize());
}

void* random_mmap(size_t size) {
  // Randomly allocate maps to prevent interactions between them
  while (true) {
    uintptr_t base = rand() & (~0xfff);
    void* addr = mmap((void*)base, size,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0);

    if (addr != MAP_FAILED)
      return addr;
  }
}

void shadow_mem_init(ShadowMemory* smem, int limit, int nmemb) {
  smem->limit = limit;
  smem->front = 0;
  smem->nmemb = nmemb;
  smem->memory_size = round_up_page_size(limit * nmemb);
  // Shadow memory looks like [UNUSED_AREA | USED_AREA | UNUSED_AREA]
  // This helps to detect out of bounds modification
  smem->memory_size_real = smem->memory_size * 3;
  smem->orig_real = (uintptr_t)random_mmap(smem->memory_size_real);
  smem->orig = (uintptr_t)smem->orig_real + smem->memory_size;
  smem->shadow_real = (uintptr_t)random_mmap(smem->memory_size_real);
  smem->shadow = (uintptr_t)smem->shadow_real + smem->memory_size;
}

uintptr_t shadow_mem_get(ShadowMemory* smem, int index) {
  uintptr_t value = 0;
  memcpy(&value, (void*)(smem->orig + index * smem->nmemb), smem->nmemb);
  return value;
}

void shadow_mem_set(ShadowMemory* smem, int index, uintptr_t elem) {
  assert(index < smem->limit);

  int off = index * smem->nmemb;
  memcpy((void*)(smem->orig + off), &elem, smem->nmemb);
  memcpy((void*)(smem->shadow + off), &elem, smem->nmemb);
}

void shadow_mem_push(ShadowMemory* smem, uintptr_t elem) {
  if (smem->front == smem->limit)
    FATAL(DBG_INFO "Reach the maximum in ShadowMemory");

  shadow_mem_set(smem, smem->front, elem);
  smem->front++;
}

bool shadow_mem_verify(ShadowMemory* smem) {
  return memcmp((void*)smem->orig, (void*)smem->shadow,
      smem->limit * smem->nmemb);
}

int shadow_mem_diff(ShadowMemory* smem, intptr_t* orig, intptr_t* shadow) {
  void* ptr_orig = (void*)smem->orig;
  void* ptr_shadow = (void*)smem->shadow;

  for (int i = 0; i < smem->limit; i ++) {
    if (memcmp(ptr_orig, ptr_shadow, smem->nmemb)) {
      *orig = *(intptr_t*)ptr_orig;
      *shadow = *(intptr_t*)ptr_shadow;
      return i;
    }

    ptr_orig += smem->nmemb;
    ptr_shadow += smem->nmemb;
  }

  return -1;
}

void shadow_mem_make_same(ShadowMemory* smem) {
  memcpy((void*)smem->shadow, (void*)smem->orig,
      smem->limit * smem->nmemb);
}

void command_init(Command* cmd, const char* filename, int limit) {
  cmd->limit = limit;
  cmd->buf = (char*)random_mmap(limit);
  cmd->index = 0;

  if (filename != NULL) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
      FATAL("Cannot open a file: %s", filename);
    }
    cmd->size = read(fd, cmd->buf, limit);
    close(fd);
  }
  else
    cmd->size = limit;

  assert(cmd->size != -1);
}

void command_check_index(Command* cmd, int req) {
  if (cmd->index + req > cmd->size)
    FATAL(DBG_INFO "Reach the end of input");
}

void command_next(Command* cmd, void* buf, size_t size) {
  command_check_index(cmd, size);
  memcpy(buf, cmd->buf + cmd->index, size);
  cmd->index += size;
}

const char* command_name(Command* cmd, const char* prefix) {
  static char name[256];
  snprintf(name, sizeof(name), "%s:%d", prefix, cmd->index);
  return name;
}

#define DEFINE_COMMAND_NEXT(sz) \
  uint##sz##_t command_next_##sz(Command* cmd) { \
  uint##sz##_t ch; \
  command_next(cmd, &ch, sizeof(ch)); \
  return ch; \
}

DEFINE_COMMAND_NEXT(8);
DEFINE_COMMAND_NEXT(16);
DEFINE_COMMAND_NEXT(32);
DEFINE_COMMAND_NEXT(64);
DEFINE_COMMAND_NEXT(ptr);

intptr_t command_next_offset(Command* cmd) {
  return command_next_8(cmd) % 9 - 4;
}

uintptr_t command_next_range(Command* cmd, int beg, int end) {
  return command_next_32(cmd) % (end - beg) + beg;
}

void heap_mgr_init(HeapManager* hmgr, int limit) {
  hmgr->limit = limit;
  shadow_mem_init(&hmgr->smem, limit, sizeof(void*));
  hmgr->freed = (bool*)random_mmap(round_up_page_size(limit));
  hmgr->valid = (bool*)random_mmap(round_up_page_size(limit));
  hmgr->usable_size = (size_t*)random_mmap(round_up_page_size(limit * sizeof(size_t)));
  hmgr->size = (int*)random_mmap(round_up_page_size(limit * sizeof(int)));
}

void* heap_mgr_get_heap(HeapManager* hmgr, int* index) {
  if (hmgr->smem.front == 0)
    return NULL;
  *index %= hmgr->smem.front;
  if (hmgr->valid[*index])
    return (void*)shadow_mem_get(&hmgr->smem, *index);
  else
    return (void*)kBadPtr;
}

void* heap_mgr_get_valid_heap(HeapManager* hmgr, int* index) {
  if (hmgr->smem.front == 0)
    return NULL;

  *index %= hmgr->smem.front;
  if (hmgr->freed[*index])
    return NULL;

  return (void*)heap_mgr_get_heap(hmgr, index);
}

void* heap_mgr_get_freed_heap(HeapManager* hmgr, int* index) {
  if (hmgr->smem.front == 0)
    return NULL;

  *index %= hmgr->smem.front;
  if (!hmgr->freed[*index])
    return NULL;

  return heap_mgr_get_heap(hmgr, index);
}

// XXX: Don't like name..
bool do_action() {
  if (command_next_8(&g_actions) == 0) {
    return true;
  }
  else {
    g_skipped++;
    // Remove the statement for this operation
    CLEAR_STMT;
    return false;
  }
}

bool do_action_heap(void* h) {
  if (do_action() && (uintptr_t)h != kBadPtr)
    return true;
  else {
    CLEAR_STMT;
    return false;
  }
}

void check_overlap(HeapManager* hmgr, ShadowMemory* buffer, int i) {
  uintptr_t h1 = (uintptr_t)heap_mgr_get_valid_heap(hmgr, &i);

  for (int j = 0; j < hmgr->smem.front; j++) {
    if (i == j)
      continue;
    uintptr_t h2 = (uintptr_t)heap_mgr_get_valid_heap(hmgr, &j);

    if (h1 == 0 || h2 == 0 || h1 == kBadPtr || h2 == kBadPtr)
      continue;

    if ((h1 <= h2 && h2 < h1 + hmgr->usable_size[i])
        || (h2 <= h1 && h1 < h2 + hmgr->usable_size[j])) {
      DEBUG("[BUG] Found overlap");
      DEBUG("p[%d]=%p (size=%ld), "
          "p[%d]=%p (size=%ld)", i, (void*)h1, hmgr->usable_size[i],
          j, (void*)h2, hmgr->usable_size[j]);
      BEGIN_STMT;
      STMT("assert((p[%d] <= p[%d] && p[%d] < p[%d] + %ld)"
              " || (p[%d] <= p[%d] && p[%d] < p[%d] + %ld))",
              i, j, j, i, hmgr->usable_size[i],
              j, i, i, j, hmgr->usable_size[j]);
      END_STMT;
      set_event_type(EVENT_OVERLAP);
    }
  }

  if (h1 >= buffer->orig
      && h1 < buffer->orig + buffer->memory_size) {
    DEBUG("[BUG] Found allocation in buffer");
    DEBUG("p[%d]=%p (size=%ld), "
        "buf=%p (size=%d)",
        i,
        (void*)h1, hmgr->usable_size[i],
        (void*)buffer->orig, buffer->memory_size);
    BEGIN_STMT;
    STMT("assert((void*)buf <= p[%d] "
          "&& p[%d] <= (void*)buf + sizeof(buf))", i, i);
    END_STMT;
    set_event_type(EVENT_ALLOC_IN_BUFFER);
  }

  if (h1 >= hmgr->smem.orig
      && h1 < hmgr->smem.orig + hmgr->smem.memory_size) {
    DEBUG("[BUG] Found allocation in a container");
    DEBUG("p[%d]=%p (size=%ld), "
        "container=%p (size=%d)",
        i,
        (void*)h1, hmgr->usable_size[i],
        (void*)hmgr->smem.orig, hmgr->smem.memory_size);
    BEGIN_STMT;
    STMT("assert((void*)p <= p[%d] "
          "&& p[%d] <= (void*)p + sizeof(p))", i, i);
    END_STMT;
    set_event_type(EVENT_ALLOC_IN_CONTAINER);
  }
}

void check_buffer_modify(ShadowMemory *buffer, bool write) {
  if (shadow_mem_verify(buffer)) {
    intptr_t orig = 0, shadow = 0;
    int index = shadow_mem_diff(buffer, &orig, &shadow);

    DEBUG("[BUG] Found modification in buffer at index %d - %p -> %p",
        index, shadow, orig);
    shadow_mem_make_same(buffer);
    if (write)
      set_event_type(EVENT_ARBITRARY_WRITE_IN_BUFFER);
    else
      set_event_type(EVENT_RESTRICTED_WRITE_IN_BUFFER);
    END_STMT
  }
}

void check_container_modify(HeapManager* hmgr, bool write) {
  if (shadow_mem_verify(&hmgr->smem)) {
    intptr_t orig = 0, shadow = 0;
    int index = shadow_mem_diff(&hmgr->smem, &orig, &shadow);

    DEBUG("[BUG] Found modification in container at index %d - %p -> %p",
        index, shadow, orig);
    shadow_mem_make_same(&hmgr->smem);
    if (write)
      set_event_type(EVENT_ARBITRARY_WRITE_IN_CONTAINER);
    else
      set_event_type(EVENT_RESTRICTED_WRITE_IN_CONTAINER);
    END_STMT
  }
}

uintptr_t fuzz_unaligned_size(Command* cmd) {
  // Return aligned size
  int beg = 0, end = 0;

  if (g_num_sizes != 0) {
    // If -s option is given, then use size from the input
    return g_sizes[command_next_16(cmd) % g_num_sizes];
  }

  switch (command_next_8(cmd) % 6)  {
    case 0 ... 1:
      beg = (1 << 0);
      end = 1 << 5;
      break;

    case 2 ... 3:
      beg = (1 << 5);
      end = (1 << 10);
      break;

    case 4:
      beg = (1 << 10);
      end = (1 << 15);
      break;

    case 5:
      beg = (1 << 15);
      end = 1 << 20;
      break;

    default:
      assert(false);
  }
  return command_next_range(cmd, beg, end);
}

uintptr_t fuzz_aligned_size(Command* cmd) {
  return round_up(fuzz_unaligned_size(cmd), 8);
}

uintptr_t fuzz_size(HeapManager* hmgr, Command* cmd) {
  int index = command_next_16(cmd);
  if (heap_mgr_get_heap(hmgr, &index) == NULL) {
    // If there is no size.. return random size
    return fuzz_aligned_size(cmd);
  }
  else {
    if (command_next_8(cmd) & 1) {
      // Return usable size
      return hmgr->usable_size[index];
    }
    else {
      // Chunk size would be the usable_size + overhead
      int overhead = 0;
      if (g_allocator_info.header != -1)
        overhead = g_allocator_info.header + g_allocator_info.footer;
      else {
        // We don't have information about overhead.
        // Let's use random value (but we believe it is address-aligned).
        overhead = (command_next_8(cmd) % 4) * sizeof(void*);
      }
      return hmgr->usable_size[index] + overhead;
    }
  }
}

uintptr_t get_txn(uintptr_t orig) {
  // No transaction has been specified
  if (g_num_txn == 0)
    return orig;

  // Consumed all transactions
  if (g_num_txn == g_idx_txn)
    done();

  return g_txns[g_idx_txn++];
}

uintptr_t fuzz_transform_linear(Command* cmd, uintptr_t size) {
  int a = 1, b = 0;
  switch (command_next_8(cmd) % 5) {
    case 0 ... 1:
      a = 1;
      b = command_next_offset(cmd) * sizeof(void*);
      break;

    case 2 ... 3:
      a = command_next_8(cmd) % 3 + 1;
      b = 0;
      break;

    case 4:
      a = command_next_8(cmd) % 3 + 1;
      b = command_next_offset(cmd) * sizeof(void*);
      break;

    default:
      assert(false);
  }

  return a * size + b + (command_next_8(cmd) & 7);
}

uintptr_t fuzz_int(HeapManager* hmgr, ShadowMemory* buffer, Command* cmd) {
  uintptr_t value = 0;
  int op;

retry:
  op = command_next_8(cmd);

  switch (op % 13) {
    case 0: {
      // Interesting values
      value = interesting_values[command_next_8(cmd)
        % (sizeof(interesting_values) / sizeof(intptr_t))];
      break;
    }

    case 1: {
      // Offset of the buffer and a chunk
      if (!g_capabilities[CAP_HEAP_ADDR].enable
          || !g_capabilities[CAP_BUFFER_ADDR].enable)
        goto retry;
      int index_h = command_next_16(cmd);
      void* h = heap_mgr_get_heap(hmgr, &index_h);
      if (h == NULL)
        goto retry;

      int index_b = command_next_16(cmd) % buffer->limit;
      if (h == NULL)
        goto retry;
      uintptr_t buffer_heap_off
          = buffer->orig + index_b * sizeof(void*)
          - (uintptr_t)h;
      int sign = command_next_8(cmd) & 1 ? -1 : 1;
      int off = command_next_offset(cmd) * sizeof(void*);
      if (sign == 1) {
        STMT("(uintptr_t)&buf[%d] - (uintptr_t)p[%d] + %d",
          index_b, index_h, off);
      }
      else {
        STMT("(uintptr_t)p[%d] - (uintptr_t)&buf[%d] + %d",
          index_h, index_b, off);
      }
      return sign * buffer_heap_off + off;
    }

    case 2: {
      // Offset of the container and a chunk
      if (!g_capabilities[CAP_HEAP_ADDR].enable
          || !g_capabilities[CAP_CONTAINER_ADDR].enable)
        goto retry;
      int index_h = command_next_16(cmd);
      void* h = heap_mgr_get_heap(hmgr, &index_h);
      if (h == NULL)
        goto retry;

      int size = hmgr->smem.front == 0 ? hmgr->limit : hmgr->smem.front;
      int index_c = command_next_16(cmd) % size;

      uintptr_t container_heap_off
        = hmgr->smem.orig + index_c * sizeof(void*)
        - (uintptr_t)h;
      int sign = command_next_8(cmd) & 1 ? -1 : 1;
      int off = command_next_offset(cmd) * sizeof(void*);
      if (sign == 1) {
        STMT("(uintptr_t)&p[%d] - (uintptr_t)p[%d] + %d",
            index_c, index_h, off);
      }
      else {
        STMT("(uintptr_t)p[%d] - (uintptr_t)&p[%d] + %d",
            index_h, index_c, off);
      }
      return sign * container_heap_off + off;
    }

    case 3: {
      // Aligned random size
      value = fuzz_aligned_size(cmd);
      break;
    }

    case 4: {
      // Unaligned random size
      value = fuzz_unaligned_size(cmd);
      break;
    }

    case 5 ... 8: {
      // Fuzzy size
      value = fuzz_size(hmgr, cmd);
      break;
    }

    case 9 ... 12: {
      // Fuzzy size + Linear transformation
      value = fuzz_transform_linear(cmd, fuzz_size(hmgr, cmd));
      break;
    }

    default:
      assert(false);
  }

  STMT("%ld", value);
  return value;
}

uintptr_t fuzz_ptr(HeapManager* hmgr, ShadowMemory* buffer, Command* cmd) {
  uintptr_t value = 0;
  int op;

retry:
  op = command_next_8(cmd);

  switch (op % 4) {
    case 0: {
      break;
    }

    case 1: {
      // Heap address
      if (!g_capabilities[CAP_HEAP_ADDR].enable)
        goto retry;
      int index = command_next_16(cmd);
      void* h = heap_mgr_get_heap(hmgr, &index);
      if (h == NULL)
        break;
      int off = command_next_offset(cmd) * sizeof(void*);
      STMT("(uintptr_t)p[%d] + %d", index, off);
      return (uintptr_t)h + off;
    }

    case 2: {
      // Buffer address
      if (!g_capabilities[CAP_BUFFER_ADDR].enable)
        goto retry;
      int index = command_next_16(cmd) % buffer->limit;
      STMT("(uintptr_t)&buf[%d]", index);
      return (uintptr_t)buffer->orig + index * sizeof(uintptr_t);
    }

    case 3: {
      // Container address
      if (!g_capabilities[CAP_CONTAINER_ADDR].enable)
        goto retry;
      int size = hmgr->smem.front == 0 ? hmgr->limit : hmgr->smem.front;
      int index = command_next_16(cmd) % size;
      uintptr_t h = hmgr->smem.orig;
      int off = command_next_offset(cmd) * sizeof(void*);
      STMT("(uintptr_t)&p[%d] + %d", index, off);
      return h + index * sizeof(uintptr_t) + off;
    }

    default:
      assert(false);
  }

  // NULL
  STMT("%ld", value);
  return value;
}


// XXX: bad naming
uintptr_t fuzz_aligned_to_unaligned_lower(Command* cmd, uintptr_t size) {
  switch (command_next_8(cmd) % 3) {
    case 0:
      return size;
    case 1:
      return size | 1;
    case 2:
      return size | (command_next_8(cmd) & 7);
    default:
      assert(false);
  }
}

int heap_mgr_allocate(HeapManager* hmgr, ShadowMemory* buffer, size_t size) {
  // Returns -1 if it does not actually allocate

  void* ptr = NULL;
  bool valid;

  if (do_action()) {
    ptr = malloc(size);
    valid = true;
  }
  else {
    ptr = (void*)kBadPtr;
    valid = false;
  }

  shadow_mem_push(&hmgr->smem, (uintptr_t)ptr);
  int index = hmgr->smem.front - 1;
  hmgr->valid[index] = valid;

  if (g_allocator_info.header != -1) {
    int overhead = g_allocator_info.header + g_allocator_info.footer;
    hmgr->usable_size[index] = MAX(g_allocator_info.minsz,
        round_up(size + overhead, g_allocator_info.round)) - overhead;
  }
  else if (valid) {
    hmgr->usable_size[index] = size;

    // Since malloc_usable_size() can be failed due to an invalid chunk,
    // e.g., tcmalloc, we check techniques before calling malloc_usable_size()
    check_overlap(hmgr, buffer, index);
    check_buffer_modify(buffer, false);
    check_container_modify(hmgr, false);

    hmgr->usable_size[index] = malloc_usable_size(ptr);
  }
  // TODO: Remove hmgr->size
  hmgr->size[index] = size;
  return (ptr == (void*)kBadPtr) ? -1 : index;
}

bool heap_mgr_force_deallocate(HeapManager* hmgr, int* index) {
  if (hmgr->smem.front < 2)
    return false;

  *index %= hmgr->smem.front;
  void* ptr = (void*)shadow_mem_get(&hmgr->smem, *index);
  hmgr->freed[*index] = true;

  if (do_action_heap(ptr)) {
    free(ptr);
    return true;
  }
  else
    return false;
}

bool heap_mgr_deallocate(HeapManager* hmgr, int* index) {
  if (hmgr->smem.front < 2)
    return false;

  *index %= hmgr->smem.front;
  if (hmgr->freed[*index])
    return false;

  return heap_mgr_force_deallocate(hmgr, index);
}

uintptr_t fuzz_value(HeapManager* hmgr, ShadowMemory* buffer, Command* cmd) {
  int op = command_next_8(cmd);

  switch (op % 2) {
    case 0:
      return fuzz_int(hmgr, buffer, cmd);
    case 1:
      return fuzz_ptr(hmgr, buffer, cmd);
    default:
      assert(false);
  }
}

void fuzz_allocate(HeapManager* hmgr, ShadowMemory* buffer, Command* cmd) {
retry:
  BEGIN_STMT;
  STMT("p[%d] = malloc(", hmgr->smem.front);

  uintptr_t size = 0;
  if (g_num_sizes != 0) {
    // If -s option is given, then use size from the input
    size = g_sizes[command_next_16(cmd) % g_num_sizes];
    STMT("%ld", size);
  }
  else
    size = fuzz_int(hmgr, buffer, cmd);

  if ((g_lower_bound != 0 && g_lower_bound > size) ||
      (g_upper_bound != 0 && size > g_upper_bound)) {
    CLEAR_STMT;
    goto retry;
  }
  STMT(")");
  END_STMT;
  int index = heap_mgr_allocate(hmgr, buffer, size);

  if (index != -1) {
    check_overlap(hmgr, buffer, index);
    check_buffer_modify(buffer, false);
    check_container_modify(hmgr, false);
  }
}

void fuzz_deallocate(HeapManager* hmgr, ShadowMemory* buffer, Command* cmd) {
  // Do nothing if less than one memory is allocated
  int index = command_next_16(cmd);

  if (heap_mgr_deallocate(hmgr, &index)) {
    BEGIN_STMT;
    STMT("free(p[%d])", index);
    END_STMT;
    check_buffer_modify(buffer, false);
    check_container_modify(hmgr, false);
  }
}

void fuzz_fill_heap(HeapManager* hmgr, ShadowMemory* buffer, Command* cmd) {
  int index = command_next_16(cmd);
  void* h = heap_mgr_get_valid_heap(hmgr, &index);
  // Not a valid heap
  if (h == NULL)
    return;

  int num_slots = hmgr->usable_size[index] / sizeof(uintptr_t);
  if (num_slots == 0)
    return;

  bool higher = command_next_8(cmd) & 1;
  int beg = 0, end = 0;

  if (higher) {
    beg = 0;
    end = command_next_8(cmd) % MIN(num_slots, 8) + 1;
  }
  else {
    beg = num_slots - (command_next_8(cmd) % MIN(num_slots, 8) + 1);
    end = num_slots;
  }

  assert(beg >= 0 && end <= num_slots);

  for (int i = beg; i < end; i++) {
    BEGIN_STMT;
    STMT("((uintptr_t*)p[%d])[%d] = ", index, i);
    uintptr_t value = fuzz_value(hmgr, buffer, cmd);

    if (do_action_heap(h))
      *((uintptr_t*)h + i) = value;
    END_STMT;
  }

  check_buffer_modify(buffer, true);
  check_container_modify(hmgr, true);
}

void fuzz_fill_buffer(HeapManager *hmgr,
    ShadowMemory* buffer, Command* cmd) {
  int index = command_next_16(cmd) % buffer->limit;
  int remainder = buffer->limit - index;
  int num = command_next_8(cmd) % MIN(8, remainder) + 1;

  for (int i = 0; i < num; i++) {
    BEGIN_STMT;
    STMT("buf[%d] = ", index + i);
    uintptr_t value = fuzz_value(hmgr, buffer, cmd);
    if (do_action())
      shadow_mem_set(buffer, index + i, value);
    END_STMT;
  }

  check_buffer_modify(buffer, true);
  check_container_modify(hmgr, true);
}

VulnType get_random_vuln_type(Command* cmd) {
  while (true) {
    VulnType vuln = command_next_8(cmd) % VULN_LAST;
    if (g_vulns[vuln].enable)
      return vuln;
  }
}

void fuzz_vuln(HeapManager* hmgr,
    ShadowMemory* buffer, Command* cmd) {
  static VulnType prev_vuln = VULN_LAST;
  VulnType vuln = get_random_vuln_type(cmd);
  vuln = get_txn(vuln);

  // Do not allow two types of vulnerability
  if (prev_vuln != VULN_LAST
      && vuln != prev_vuln)
    return;

  switch (vuln) {
    case VULN_OVERFLOW: {
      int index = command_next_16(cmd);
      void* h = heap_mgr_get_valid_heap(hmgr, &index);
      if (h == NULL)
        return;

      int num = command_next_8(cmd) % 8 + 1;

      bool first = true;
      for (int i = 0; i < num; i ++) {
        if (first) DEBUG("[VULN] Overflow");
        BEGIN_STMT;
        // NOTE: We overflow from usable_size[index] - sizeof(void*).
        // This is sensitive to ptmalloc that contains metadata at the last
        int off = hmgr->usable_size[index] + (i - 1) * sizeof(void*);
        STMT("*(uintptr_t*)(p[%d] + %d) = ", index, off);
        uintptr_t value = fuzz_value(hmgr, buffer, cmd);
        if (do_action_heap(h)) {
          if (first) first = false;
          *(uintptr_t*)((uintptr_t)h + off) = value;
        }
        END_STMT;
      }
    }
    break;

    case VULN_OFF_BY_ONE: {
      int index = command_next_16(cmd);
      void* h = heap_mgr_get_valid_heap(hmgr, &index);
      if (h == NULL)
        return;

      if (do_action_heap(h)) {
        uint8_t value = command_next_8(cmd);
        uint8_t old = *(uint8_t*)((uintptr_t)h + hmgr->usable_size[index]);

        DEBUG("[VULN] Off-by-one");
        DEBUG("old = %d, new=%d", old, value);

        BEGIN_STMT;
        STMT("*(char*)(p[%d] + %ld) = %d", index, hmgr->usable_size[index], value);
        *(uint8_t*)((uintptr_t)h + hmgr->usable_size[index]) = value;
        END_STMT;
      }
    }
    break;

    case VULN_OFF_BY_ONE_NULL: {
      int index = command_next_16(cmd);
      void* h = heap_mgr_get_valid_heap(hmgr, &index);
      if (h == NULL)
        return;

      if (do_action_heap(h)) {
        uint8_t old = *(uint8_t*)((uintptr_t)h + hmgr->usable_size[index]);
        DEBUG("[VULN] Off-by-one NULL");
        DEBUG("old = %d", old);

        BEGIN_STMT;
        STMT("*(char*)(p[%d] + %ld) = 0", index, hmgr->usable_size[index]);

        *(uint8_t*)((uintptr_t)h + hmgr->usable_size[index]) = 0;

        END_STMT;
      }
    }
    break;

    case VULN_WRITE_AFTER_FREE: {
      // XXX: Merge with fill heap
      int index = command_next_16(cmd);
      void* h = heap_mgr_get_freed_heap(hmgr, &index);
      // Not a valid heap
      if (h == NULL)
        return;

      int num_slots = hmgr->usable_size[index] / sizeof(uintptr_t);
      if (num_slots == 0)
        return;

      bool higher = command_next_8(cmd) & 1;
      int beg = 0, end = 0;

      if (higher) {
        beg = 0;
        end = command_next_8(cmd) % MIN(num_slots, 8) + 1;
      }
      else {
        beg = num_slots - (command_next_8(cmd) % MIN(num_slots, 8) + 1);
        end = num_slots;
      }

      assert(beg >= 0 && end <= num_slots);

      bool first = true;
      for (int i = beg; i < end; i++) {
        if (first) DEBUG("[VULN] Write-after-free");
        BEGIN_STMT;
        STMT("((uintptr_t*)p[%d])[%d] = ", index, i);
        uintptr_t value = fuzz_value(hmgr, buffer, cmd);
        if (do_action_heap(h)) {
          if (first) first = false;
          *((uintptr_t*)h + i) = value;
        }
        END_STMT;
      }
    }
    break;

    case VULN_DOUBLE_FREE: {
      int index = command_next_16(cmd);
      void* h = heap_mgr_get_freed_heap(hmgr, &index);
      if (h == NULL)
        return;

      for (int i = 0 ; i < hmgr->limit; i++) {
        int other_index = i;
        void* other_h = heap_mgr_get_valid_heap(hmgr, &other_index);
        if (other_h == h && (uintptr_t)h != kBadPtr) {
          DEBUG(DBG_INFO "This is not really freed memory");
          return;
        }
      }

      if (do_action()) {
        DEBUG("[VULN] Double free");
        if (heap_mgr_force_deallocate(hmgr, &index)) {
          BEGIN_STMT;
          STMT("free(p[%d])", index);
          END_STMT;

          check_buffer_modify(buffer, false);
          check_container_modify(hmgr, false);
        }
      }
    }
    break;

    case VULN_ARBITRARY_FREE: {
      int index = command_next_16(cmd) % buffer->limit;

      if (do_action()) {
        DEBUG("[VULN] Arbitrary free");

        BEGIN_STMT;
        STMT("free(&buf[%d])", index);
        END_STMT;

        free((void*)(buffer->orig + index * sizeof(uintptr_t)));
        check_buffer_modify(buffer, false);
        check_container_modify(hmgr, false);
      }
    }
    break;

    default:
      assert(false);
  }

  prev_vuln = vuln;
}

void print_options(char* name, Option* options, int num_elem) {
  bool first = true;
  fprintf(stderr, "     <%s>:= ", name);
  for (int i = 0; i < num_elem; i++) {
    if (first)
      first = false;
    else
      fprintf(stderr, " | ");
    fprintf(stderr, "%s", options[i].name);
  }
  fprintf(stderr, "\n");
}

void set_option(char* name, Option* options, int num_elem) {
  for (int i = 0; i < num_elem; i++) {
    if (!strcmp(optarg, options[i].name)) {
      options[i].enable = false;
      return;
    }
  }

  fprintf(stderr, "// [ERROR] No such %s: %s\n", name, optarg);
  exit(-1);
}

void set_allocator_information() {
  char* saveptr = optarg;
  // TODO: Better way to parse AllocatorInfo
  assert(sizeof(AllocatorInfo) == 4 * sizeof(int));
  int* ptr = (int*)&g_allocator_info;
  for (int i = 0; i < 4; i++) {
    char* p = strtok_r(saveptr, ":", &saveptr);
    if (p == NULL) {
      fprintf(stderr, "// [ERROR] Invalid format for allocator information\n");
      exit(-1);
    }
    ptr[i] = atoi(p);
  }

  if (g_allocator_info.round == 0) {
    // Round cannot be zero
    fprintf(stderr, "// [ERROR] Round cannot be zero\n");
    exit(-1);
  }

  fprintf(stderr,
      "// [INFO] Allocator information: header=%d, footer=%d, round=%d, minsz=%d\n",
      g_allocator_info.header,
      g_allocator_info.footer,
      g_allocator_info.round,
      g_allocator_info.minsz);
}

void usage(char* filename) {
  fprintf(stderr,
  "Usage: %s [OPTION]... FILE [MAPFILE]\n"
  "  -c <cap>: Disable a capability\n", filename);
  print_options("cap", g_capabilities, CAP_LAST);

  fprintf(stderr,
  "  -v <vuln>: Disable a vulnerbility\n");
  print_options("vuln", g_vulns, VULN_LAST);

  fprintf(stderr,
  "  -e <event>: Disable an event\n");
  print_options("event", g_events, EVENT_LAST);

  fprintf(stderr,
  "  -u <ub>: Set upper bound of allocation\n"
  "  -l <lb>: Set lower bound of allocation\n"
  "  -s <list-of-sizes>: Set allocations sizes (e.g., 1,2,3)\n"
  "  -a <header>:<footer>:<round>:<minsz>: Set information for allocator\n"
#if 0
  // Make this option hidden, which is only used for evaluation
  "  -A <list-of-transactions>: Set a sequence of transactions\n"
  "     Possible Transactions - "
  "        M: alloc, F: free\n"
  "        OV: overflow, O1: off-by-one, O1N: off-by-one NULL\n"
  "        FF: double free, AF: arbitrary free, WF: write-after-free\n"
  "        (e.g., M-M-OV-F-M)\n"
#endif
  "    e.g. For ptmalloc in 64-bit, -a 8:0:16:32\n"
  "  -h: Display this help and exit\n");
}

int main(int argc, char** argv) {
  int c;
  while ((c = getopt(argc, argv, "A:s:c:v:e:u:l:a:h")) != -1) {
    switch (c) {
      case 'c':
        set_option("capability", g_capabilities, CAP_LAST);
        break;
      case 'v':
        set_option("vuln", g_vulns, VULN_LAST);
        break;
      case 'e':
        set_option("event", g_events, EVENT_LAST);
        break;
      case 'u':
        g_upper_bound = strtoul(optarg, NULL, 10);
        if (g_upper_bound)
          fprintf(stderr, "// [INFO] Set upper bound: %ld\n", g_upper_bound);
        break;
      case 'l':
        g_lower_bound = strtoul(optarg, NULL, 10);
        if (g_lower_bound)
          fprintf(stderr, "// [INFO] Set lower bound: %ld\n", g_lower_bound);
        break;
      case 's': {
        char *ptr = strtok(optarg, ",");
        while (ptr != NULL) {
          int size = atoi(ptr);
          if (size <= 0) {
            fprintf(stderr, "[FATAL] Invalid size in -s option\n");
            exit(-1);
          }

          if (g_num_sizes >= MAX_NUM_SIZES) {
            fprintf(stderr, "[FATAL] Too many sizes in -s option\n");
            exit(-1);
          }

          g_sizes[g_num_sizes++] = size;
          ptr = strtok(NULL, ",");

        }

        fprintf(stderr, "[INFO] Sizes: {");
        bool first = true;

        for (uintptr_t i = 0; i < g_num_sizes; i++) {
          if (!first)
            fprintf(stderr, ", ");
          if (first)
            first = false;

          fprintf(stderr, "%ld", g_sizes[i]);
        }
        fprintf(stderr, "}\n");

        break;
      }

      case 'A': {
        // TODO: 'A' option should be mutually exclusive with 'c' and 'v'
        char * ptr = strtok(optarg, "-");
        while (ptr != NULL) {
          if (!strcmp(ptr, "M")) {
            g_txns[g_num_txn++] = TXN_ID_ALLOCATE;
          }
          else if (!strcmp(ptr, "F")) {
            g_txns[g_num_txn++] = TXN_ID_DEALLOCATE;
          }
          else if (!strcmp(ptr, "OV")) {
            g_txns[g_num_txn++] = TXN_ID_VULN;
            g_txns[g_num_txn++] = VULN_OVERFLOW;
          }
          else if (!strcmp(ptr, "O1")) {
            g_txns[g_num_txn++] = TXN_ID_VULN;
            g_txns[g_num_txn++] = VULN_OFF_BY_ONE;
          }
          else if (!strcmp(ptr, "O1N")) {
            g_txns[g_num_txn++] = TXN_ID_VULN;
            g_txns[g_num_txn++] = VULN_OFF_BY_ONE_NULL;
          }
          else if (!strcmp(ptr, "AF")) {
            g_txns[g_num_txn++] = TXN_ID_VULN;
            g_txns[g_num_txn++] = VULN_ARBITRARY_FREE;
          }
          else if (!strcmp(ptr, "FF")) {
            g_txns[g_num_txn++] = TXN_ID_VULN;
            g_txns[g_num_txn++] = VULN_DOUBLE_FREE;
          }
          else if (!strcmp(ptr, "WF")) {
            g_txns[g_num_txn++] = TXN_ID_VULN;
            g_txns[g_num_txn++] = VULN_WRITE_AFTER_FREE;
          }
          else {
            fprintf(stderr, "[FATAL] Unknown transaction: %s", ptr);
            exit(-1);
          }
          ptr = strtok(NULL, "-");
        }

        // TODO: Make more pretty printing
        fprintf(stderr, "// [INFO] List of transactions: ");
        bool first = true;
        for (uintptr_t i = 0; i < g_num_txn; i++) {
          if (!first)
            fprintf(stderr, ", ");
          if (first)
            first = false;

          fprintf(stderr, "%ld", g_txns[i]);
        }
        fprintf(stderr, "\n");
        break;
      }

      case 'a':
        set_allocator_information();
        break;
      case 'h':
      default:
        usage(argv[0]);
        exit(-1);
    }
  }

  if (argc == optind || argc > optind + 2) {
    usage(argv[0]);
    exit(-1);
  }

  char* input_file = argv[optind];
  char* bitmap_file = NULL;

  const int heap_limit = 0x100;
  const int buffer_limit = 0x100;

  fprintf(stderr,
      "#include <assert.h>\n"
      "#include <stdio.h>\n"
      "#include <stdlib.h>\n"
      "#include <stdint.h>\n"
      "#include <malloc.h>\n\n"
      "void* p[%d];\n"
      "uintptr_t buf[%d];\n\n"
      "int main() {\n", heap_limit, buffer_limit);

  srand(time(NULL));

  struct sigaction sa;
  sa.sa_handler = NULL;
  memset(&sa, 0, sizeof(struct sigaction));
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = done;
  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGSEGV, &sa, NULL);

  // Use global variables to avoid using heap
  if (argc == optind + 1)
    command_init(&g_actions, NULL, 0x1000);
  else
    command_init(&g_actions, argv[optind + 1], 0x1000);

  command_init(&g_cmd, argv[optind], 0x1000);
  DEBUG(DBG_INFO "Command buffer: %p", g_cmd.buf);
  DEBUG(DBG_INFO "Input size: %lu", g_cmd.size);

  heap_mgr_init(&g_hmgr, heap_limit);
  shadow_mem_init(&g_buffer, buffer_limit, sizeof(uintptr_t));

  while (true) {
    uint8_t op;
    bool is_txn;

retry:
    op = command_next_8(&g_cmd);

    // Transactions: allocate, deallocate, vuln
    // Non-transactions: heap writes, buffer writes
    switch (op % 5) {
      case 0:
      case 1:
      case 2:
        is_txn = true;
        break;
      case 3:
      case 4:
        is_txn = false;
        break;
    }

    if (is_txn) {
      op = get_txn(op);
      switch (op % 3) {
        case TXN_ID_ALLOCATE:
          fuzz_allocate(&g_hmgr, &g_buffer, &g_cmd);
          break;
        case TXN_ID_DEALLOCATE:
          if (!g_capabilities[CAP_DEALLOC].enable)
            goto retry;
          fuzz_deallocate(&g_hmgr, &g_buffer, &g_cmd);
          break;
        case TXN_ID_VULN:
          fuzz_vuln(&g_hmgr, &g_buffer, &g_cmd);
          break;
        default:
          assert(false);
      }
    }
    else {
      switch (op % 2) {
        case 0:
          if (!g_capabilities[CAP_HEAP_WRITE].enable)
            goto retry;
          fuzz_fill_heap(&g_hmgr, &g_buffer, &g_cmd);
          break;
        case 1:
          if (!g_capabilities[CAP_BUFFER_WRITE].enable)
            goto retry;
          fuzz_fill_buffer(&g_hmgr, &g_buffer, &g_cmd);
          break;
        default:
          assert(false);
      }
    }
  }
}
