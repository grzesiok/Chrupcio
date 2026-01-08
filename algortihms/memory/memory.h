#ifndef _LIBALGORITHMS_MEMORY_H
#define _LIBALGORITHMS_MEMORY_H
#include <stdint.h>
#define memoryPtrMove(ptr, diff) (void*)((uint64_t)ptr+(uint64_t)diff)
#define memoryAlign(val, alignment) ((val%alignment == 0) ? val : (val-(val%alignment)+alignment))
#endif