#pragma once

#include <stdint.h>
#include "datatypes.h"

#define MAX_HASHMAP_BUCKET_COUNT (1UL << 24)

#define MAX_HASHMAP_KEY_WIDTH 64

struct HashmapNode {
    Byte key[MAX_HASHMAP_KEY_WIDTH];
    void *ptrValue;
    uint32_t valueLength;
    struct HashmapNode *next;
};

typedef struct HashmapNode HashmapNode;

struct Hashmap {
    uint64_t bucketCount;
    uint32_t keyWidth;
    HashmapNode *data[MAX_HASHMAP_BUCKET_COUNT];
};

typedef struct Hashmap Hashmap;

void init_hashmap(Hashmap *ptrHashmap, uint64_t size, uint32_t keywidth);
int8_t hashmap_set(Hashmap *ptrHashmap, Byte *key, void *ptrValue, uint32_t valueLength);
void *hashmap_get(Hashmap *ptrHashmap, Byte *key, uint32_t *ptrValueLength);
void free_hashmap(Hashmap *ptrHashmap);
void print_hashmap(Hashmap *ptrHashmap);
