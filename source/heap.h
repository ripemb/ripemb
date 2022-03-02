#ifndef HEAP_H
#define HEAP_H

#include <string.h>

#define str(x) #x
#define sstr(x) str(x)
#ifdef RIPE_HEAP_SECTION
  #define ATTR_HEAP_SECTION __attribute__((section(sstr(.RIPE_HEAP_SECTION))))
#else
  #define ATTR_HEAP_SECTION
#endif

#define APPEND_SAVE_HEAP(safe, src) \
  memcpy(safe, &src, sizeof(src)); \
  safe += sizeof(src);

#define RESTORE_SAVE_HEAP(safe, dst) \
  memcpy(&dst, safe, sizeof(dst)); \
  safe += sizeof(dst);

#endif
