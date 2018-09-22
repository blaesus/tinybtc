#include <stdio.h>
#include <stdlib.h>
#include "utils/memory.h"

void *malloc_audited(size_t size, char* label) {
    printf("alloc: %li for [%s]\n", size, label);
    return malloc(size);
}

void *calloc_audited(size_t count, size_t size, char* label) {
    printf("alloc: %li for [%s]\n", count * size, label);
    return calloc(count ,size);
}

void free_audited(void *ptr, char* label) {
    printf("free: [%s]\n", label);
    free(ptr);
}
