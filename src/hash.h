#pragma once

#include <stdint.h>
#include "datatypes.h"

#define SHA256_LENGTH 32
#define RIPEMD_LENGTH 20

typedef Byte SHA256_HASH[SHA256_LENGTH];
typedef Byte RIPEMD_HASH[RIPEMD_LENGTH];

void sha256(void *data, uint32_t length, SHA256_HASH result);
void dsha256(void *data, uint32_t length, SHA256_HASH result);
void sharipe(void *data, uint32_t length, SHA256_HASH result);
void print_sha256(Byte *hash);
void print_sha256_reverse(Byte *hash);
void print_sha256_short(Byte *hash);
void print_hash_with_description(char *description, Byte *hash);
bool is_hash_empty(Byte *hash);
void sha256_string_to_array(char *str, Byte *hash);
