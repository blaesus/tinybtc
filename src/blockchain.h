#pragma once
#include <stdint.h>
#include "gmp.h"
#include "hash.h"
#include "datatypes.h"
#include "messages/block.h"

void target_4to32(TargetQuodBytes targetBytes, Byte *bytes);
long double targetQuodToRoughDouble(Byte *targetBytes);
void targetQuodToMpz(Byte *targetBytes, mpz_t targetMpz);
void targetMpzToQuod(mpz_t targetMpz, Byte *targetBytes);

bool hash_satisfies_target(const Byte *hash, const Byte *target);
bool validate_blockchain(BlockPayloadHeader ptrFirstHeader, uint32_t chainLength);
void relocate_main_chain(void);
bool is_block_header_legal_as_tip(BlockPayloadHeader *ptrHeader);
void target_mul(Byte *targetBytes, long double ratio, Byte *result);

