#include <stdlib.h>
#include "hashmap.h"
#include "hash.h"
#include "util.h"

static uint64_t calculate_index(Byte *key, uint32_t keyWidth, uint64_t bucketCount);

void hashmap_init(Hashmap *ptrHashmap, uint64_t bucketCount, uint32_t keywidth) {
    if (keywidth > MAX_HASHMAP_KEY_WIDTH) {
        printf("hash map keywidth %u too big, falling back to %u\n", keywidth, MAX_HASHMAP_KEY_WIDTH);
        keywidth = MAX_HASHMAP_KEY_WIDTH;
    }
    if (bucketCount > MAX_HASHMAP_BUCKET_COUNT) {
        printf("bucket count %llu too big, falling back to %lu\n", bucketCount, MAX_HASHMAP_BUCKET_COUNT);
        bucketCount = MAX_HASHMAP_BUCKET_COUNT;
    }
    memset(ptrHashmap, 0, sizeof(Hashmap));
    ptrHashmap->keyWidth = keywidth;
    ptrHashmap->bucketCount = bucketCount;
}

uint64_t calculate_index(Byte *key, uint32_t keyWidth, uint64_t bucketCount) {
    Byte hash[SHA256_LENGTH] = {0};
    sha256(key, keyWidth, hash);
    uint64_t hashIndex = combine_uint32(hash) % bucketCount;
    return hashIndex;
}

int8_t hashmap_set(Hashmap *ptrHashmap, Byte *key, void *ptrValue, uint32_t valueLength) {
    HashmapNode *ptrNewNode = calloc(1, sizeof(*ptrNewNode));
    if (ptrNewNode == NULL) {
        printf("FAILRE!\n");
        return -1;
    }
    memcpy(ptrNewNode->key, key, ptrHashmap->keyWidth);
    ptrNewNode->valueLength = valueLength;
    ptrNewNode->ptrValue = calloc(1, valueLength);
    if (ptrNewNode->ptrValue == NULL) {
        printf("FAILRE!\n");
        return -2;
    }
    memcpy(ptrNewNode->ptrValue, ptrValue, valueLength);
    ptrNewNode->next = NULL;

    uint64_t bucketIndex = calculate_index(key, ptrHashmap->keyWidth, ptrHashmap->bucketCount);
    if (ptrHashmap->data[bucketIndex] == NULL) {
        ptrHashmap->data[bucketIndex] = ptrNewNode;
    }
    else {
        // Collision
        HashmapNode *ptrSearch = ptrHashmap->data[bucketIndex];
        if (memcmp(ptrSearch->key, key, ptrHashmap->keyWidth) == 0) {
            free(ptrHashmap->data[bucketIndex]->ptrValue);
            ptrHashmap->data[bucketIndex] = ptrNewNode;
            return 0;
        }
        while (ptrSearch->next) {
            if (memcmp(ptrSearch->key, key, ptrHashmap->keyWidth) == 0) {
                free(ptrHashmap->data[bucketIndex]->ptrValue);
                ptrHashmap->data[bucketIndex] = ptrNewNode;
                return 0;
            }
            ptrSearch = ptrSearch->next;
        }
        ptrSearch->next = ptrNewNode;
    }
    return 0;
}


void *hashmap_get(Hashmap *ptrHashmap, Byte *key, uint32_t *ptrValueLength) {
    uint64_t bucketIndex = calculate_index(key, ptrHashmap->keyWidth, ptrHashmap->bucketCount);
    HashmapNode *ptrNode = ptrHashmap->data[bucketIndex];
    if (ptrNode == NULL) {
        return NULL;
    }
    while (memcmp(ptrNode->key, key, ptrHashmap->keyWidth) != 0) {
        if (ptrNode->next) {
            ptrNode = ptrNode->next;
        }
        else {
            return NULL;
        }
    }
    if (ptrValueLength) {
        *ptrValueLength = ptrNode->valueLength;
    }
    return ptrNode->ptrValue;
}

uint64_t hashmap_getkeys(Hashmap *ptrHashmap, Byte *keys) {
    uint64_t outputIndex = 0;
    for (uint32_t bucket = 0; bucket < ptrHashmap->bucketCount; bucket++) {
        HashmapNode *ptrNode = ptrHashmap->data[bucket];
        if (ptrNode) {
            memcpy(keys + outputIndex * SHA256_LENGTH, ptrNode->key, SHA256_LENGTH);
            outputIndex++;
        }
    }
    return outputIndex;
}

void print_hashmap(Hashmap *ptrHashmap) {
    printf("%llu buckets, keywidth=%u\n", ptrHashmap->bucketCount, ptrHashmap->keyWidth);
    for (uint32_t i = 0; i < ptrHashmap->bucketCount; i++) {
        HashmapNode *ptrNode = ptrHashmap->data[i];
        if (ptrNode) {
            printf("Node %u: %p\n", i, ptrNode);
        }
    }
}
