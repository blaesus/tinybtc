#include "config.h"

#if TRACE_MEMORY_USE
void *malloc_audited(size_t size, char* label);
void *calloc_audited(size_t count, size_t size, char* label);
void free_audited(void *ptr, char* label);
#define CALLOC(count, size, label) (calloc_audited(count, size, label))
#define MALLOC(size, label) (malloc_audited(size, label))
#define FREE(ptr, label) (free_audited(ptr, label))
#else
#define CALLOC(count, size, label) (calloc(count, size))
#define MALLOC(size, label) (malloc(size))
#define FREE(ptr, label) (free(ptr))
#endif

