#pragma once

#include <stdint.h>
#include "sha256/sha256.h"

#define SHA256_LENGTH 32

typedef uint8_t SHA256_HASH[SHA256_LENGTH];

void sha256(void *data, uint32_t length, SHA256_HASH result);
void dsha256(void *data, uint32_t length, SHA256_HASH result);
