#pragma once
#include <stdint.h>
#include <messages/block.h>

#define ERROR_BAD_DATA -99;

int32_t save_peer_candidates(void);
int32_t load_peer_candidates(void);
int32_t save_block_indices(void);
int32_t load_block_indices(void);
int8_t init_db();
int8_t save_block(BlockPayload *ptrBlock);
int8_t load_block(Byte *hash, BlockPayload *ptrBlock);
void save_chain_data();
int8_t save_tx(TxPayload *ptrTx);
int8_t load_tx(Byte *hash, TxPayload *ptrPayload);
void load_genesis();
uint64_t get_hash_keys_of_blocks(SHA256_HASH hashes[]);
void migrate();
void cleanup_db();
