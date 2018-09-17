#pragma once
#include <stdint.h>
#include <messages/block.h>

int32_t save_peer_candidates(void);
int32_t load_peer_candidates(void);
int32_t save_block_indices(void);
int32_t load_block_indices(void);
int8_t init_db();
void init_genesis(void);
int8_t save_block(BlockPayload *ptrBlock);
int8_t load_block(Byte *hash, BlockPayload *ptrBlock);
bool check_block_existence(Byte *hash);
void save_chain_data();
int8_t save_tx(TxPayload *ptrTx);
int8_t load_tx(Byte *hash, TxPayload *ptrPayload);
void load_genesis();
