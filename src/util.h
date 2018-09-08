#pragma once
#include <stdint.h>
#include "datatypes.h"

#define GET_BLOCK_INDEX(hash) (hashmap_get(&global.blockIndices, hash, NULL))
#define SET_BLOCK_INDEX(hash, index) (hashmap_set(&global.blockIndices, hash, &index, sizeof(index)))

int segment_uint32(uint32_t number, uint8_t *chars);
uint16_t combine_uint16(const uint8_t *chars);
uint32_t combine_uint32(const uint8_t *chars);
uint64_t combine_uint64(const uint8_t *chars);
int32_t uint_to_str(uint32_t data, char *output);
void random_bytes(uint32_t count, uint8_t *data);
void printUint64(uint64_t input);
void print_object(uint8_t *ptrData, uint64_t length);
void random_bytes(uint32_t count, uint8_t *data);
uint64_t random_uint64(void);
uint32_t random_range(uint32_t lower, uint32_t upper);
double random_betwen_0_1(void);
uint32_t min(uint32_t a, uint32_t b);
bool ips_equal(IP ipA, IP ipB);
int64_t getFileSize(FILE *file);
void reverse_endian(Byte *data, uint32_t width);
int8_t bytescmp(const Byte *bytesA, const Byte *bytesB, uint32_t width);
