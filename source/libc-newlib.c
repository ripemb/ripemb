#include <stdlib.h>
#include <stdint.h>
#include <reent.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include "heap.h"
#include "ripe_attack_generator.h"

void exit(int status) {
    while (1)
      ;
}

/* For saving and restoring the heap, we need to take care of static variables from newlib's mallocr.c too. */
#include <malloc.h>

/* data section */
#define NAV             128   /* number of bins */
struct malloc_chunk
{
  size_t prev_size; /* Size of previous chunk (if free). */
  size_t size;      /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;   /* double links -- used only if free. */
  struct malloc_chunk* bk;
};
typedef struct malloc_chunk* mbinptr;
extern mbinptr __malloc_av_[NAV * 2 + 2];
extern char* __malloc_sbrk_base;
extern unsigned long __malloc_trim_threshold;

/* bss (not initialized but possibly used/set before save_heap is called) */
extern unsigned long __malloc_top_pad;
extern struct mallinfo __malloc_current_mallinfo;
extern unsigned long __malloc_max_sbrked_mem;
extern unsigned long __malloc_max_total_mem;

/* Make sure the actual heap is small enough to allow the safe heap to store additional static implementation variables. */
static ATTR_HEAP_SECTION uint8_t heap[RIPE_MAX_HEAP_SIZE-sizeof(uint8_t *) \
  -sizeof(__malloc_av_)-sizeof(__malloc_sbrk_base)-sizeof(__malloc_trim_threshold) \
  -sizeof(__malloc_top_pad)-sizeof(__malloc_current_mallinfo)-sizeof(__malloc_max_sbrked_mem)-sizeof(__malloc_max_total_mem)];
static ATTR_HEAP_SECTION uint8_t *cur_brk = heap;

void *_sbrk_r(struct _reent *reent, ptrdiff_t diff) {
  uint8_t *_old_brk = cur_brk;
  if (cur_brk + diff > (heap + RIPE_MAX_HEAP_SIZE)) {
    reent->_errno = ENOMEM;
    return (void *)-1;
  }
  cur_brk += diff;
  return _old_brk;
}

#ifdef RIPE_SAFE_HEAP
void save_heap(uint8_t *heap_safe) {
  uint8_t *ptr = heap_safe;
  APPEND_SAVE_HEAP(ptr, cur_brk);
  APPEND_SAVE_HEAP(ptr, __malloc_av_);
  APPEND_SAVE_HEAP(ptr, __malloc_sbrk_base);
  APPEND_SAVE_HEAP(ptr, __malloc_trim_threshold);
  APPEND_SAVE_HEAP(ptr, __malloc_top_pad);
  APPEND_SAVE_HEAP(ptr, __malloc_current_mallinfo);
  APPEND_SAVE_HEAP(ptr, __malloc_max_sbrked_mem);
  APPEND_SAVE_HEAP(ptr, __malloc_max_total_mem);
  APPEND_SAVE_HEAP(ptr, heap);
}

void restore_heap(uint8_t *heap_safe) {
  uint8_t *src = heap_safe;
  RESTORE_SAVE_HEAP(src, cur_brk);
  RESTORE_SAVE_HEAP(src, __malloc_av_);
  RESTORE_SAVE_HEAP(src, __malloc_sbrk_base);
  RESTORE_SAVE_HEAP(src, __malloc_trim_threshold);
  RESTORE_SAVE_HEAP(src, __malloc_top_pad);
  RESTORE_SAVE_HEAP(src, __malloc_current_mallinfo);
  RESTORE_SAVE_HEAP(src, __malloc_max_sbrked_mem);
  RESTORE_SAVE_HEAP(src, __malloc_max_total_mem);
  RESTORE_SAVE_HEAP(src, heap);
}
#endif
