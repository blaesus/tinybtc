#pragma once
#include <stdint.h>

#define BYTE 8

int segment_int32(uint32_t number, uint8_t chars[4]);
uint32_t combine_int32(uint8_t chars[4]);
int32_t uint_to_str(uint32_t data, char *output);
