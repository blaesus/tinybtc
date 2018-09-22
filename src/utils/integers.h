#pragma once
#include <stdint.h>
void segment_uint32(uint32_t number, uint8_t *chars);
uint16_t combine_uint16(const uint8_t *chars);
uint32_t combine_uint32(const uint8_t *chars);
uint64_t combine_uint64(const uint8_t *chars);
uint32_t min(uint32_t a, uint32_t b);
