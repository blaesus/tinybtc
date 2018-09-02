#pragma once
#include <stdint.h>
#include <messages/block.h>

int32_t save_peer_addresses(void);
int32_t load_peer_addresses(void);
int32_t save_headers(void);
int32_t load_headers(void);
int32_t init_db(void);
void init_genesis(void);
int8_t save_block(BlockPayload *ptrBlock, Byte *hash);
int8_t load_block(Byte *hash, BlockPayload *ptrBlock);
bool check_block_existence(Byte *hash);
