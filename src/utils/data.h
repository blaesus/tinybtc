#pragma once
#include <stdint.h>
#include "datatypes.h"
void reverse_bytes(Byte *data, uint32_t width);
void print_object(void *ptrData, uint64_t length);
int8_t bytescmp(const Byte *bytesA, const Byte *bytesB, uint32_t width);
bool is_byte_array_empty(const Byte *hash, uint64_t length);
