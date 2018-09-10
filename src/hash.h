#pragma once

#include <stdint.h>
#include "datatypes.h"

#define SHA256_LENGTH 32

typedef Byte SHA256_HASH[SHA256_LENGTH];

void sha256(void *data, uint32_t length, SHA256_HASH result);
void dsha256(void *data, uint32_t length, SHA256_HASH result);
void print_sha256(Byte *hash);
void print_sha256_reverse(Byte *hash);
void print_sha256_short(Byte *hash);
void print_hash_with_description(char *description, Byte *hash);
