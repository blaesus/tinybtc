#pragma once
#include <stdint.h>
#include "datatypes.h"

#define GET_BLOCK_INDEX(hash) (hashmap_get(&global.blockIndices, hash, NULL))
#define SET_BLOCK_INDEX(hash, index) (hashmap_set(&global.blockIndices, hash, &index, sizeof(index)))

#define CALLOC(count, size, label) (calloc_audited(count, size, label))
#define MALLOC(size, label) (malloc_audited(size, label))
#define FREE(ptr, label) (free_audited(ptr, label))

int segment_uint32(uint32_t number, uint8_t *chars);
uint16_t combine_uint16(const uint8_t *chars);
uint32_t combine_uint32(const uint8_t *chars);
uint64_t combine_uint64(const uint8_t *chars);
int32_t uint_to_str(uint32_t data, char *output);
void random_bytes(uint32_t count, uint8_t *data);
void printUint64(uint64_t input);
void print_object(void *ptrData, uint64_t length);
void random_bytes(uint32_t count, uint8_t *data);
uint64_t random_uint64(void);
uint32_t random_range(uint32_t lower, uint32_t upper);
double random_betwen_0_1(void);
uint32_t min(uint32_t a, uint32_t b);
bool ips_equal(IP ipA, IP ipB);
int64_t getFileSize(FILE *file);
void reverse_endian(Byte *data, uint32_t width);
int8_t bytescmp(const Byte *bytesA, const Byte *bytesB, uint32_t width);
char *date_string(time_t time);
bool is_byte_array_empty(const Byte *hash, uint64_t length);
double timeval_to_double_ms(struct timeval time);
double getNow();
void *malloc_audited(size_t size, char* label);
void *calloc_audited(size_t count, size_t size, char* label);
void free_audited(void *ptr, char* label);
