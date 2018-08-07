#pragma once

#include <stdint.h>
#include "sha256.h"

#define SHA256_LENGTH 32

typedef uint8_t SHA256_HASH[SHA256_LENGTH];

typedef void HashFunction(void *data, uint32_t length, SHA256_HASH result);

HashFunction sha256;
HashFunction dsha256;

