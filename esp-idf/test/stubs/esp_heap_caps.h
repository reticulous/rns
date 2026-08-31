/* Host stand-in for ESP-IDF's capability allocator. Reached only because
 * MsgPack.h includes Bytes.h, which includes microreticulum's Memory.h — the
 * record path allocates through gp_alloc, not through this. Plain malloc is
 * the right answer off-device: there is one heap and no PSRAM to ask for. */
#pragma once
#include <cstdlib>

#define MALLOC_CAP_SPIRAM   (1 << 10)
#define MALLOC_CAP_INTERNAL (1 << 11)
#define MALLOC_CAP_8BIT     (1 << 2)
#define MALLOC_CAP_DEFAULT  (1 << 3)

inline void* heap_caps_malloc(size_t n, uint32_t)  { return std::malloc(n); }
inline void* heap_caps_calloc(size_t c, size_t n, uint32_t) { return std::calloc(c, n); }
inline void  heap_caps_free(void* p)               { std::free(p); }
inline size_t heap_caps_get_free_size(uint32_t)    { return 0; }
