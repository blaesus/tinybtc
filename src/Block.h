#pragma once
//
// Created by Andy Shu on 29/7/2018.
//

#include <stdint.h>

struct BlockHeader {
    uint32_t version;
    uint32_t previous_block_hash;
    uint32_t merkle_root;
    uint32_t timestamp;
    uint32_t difficulty_target;
};

typedef struct BlockHeader BlockHeader;

struct Block {
    uint32_t magic_number;
    uint32_t block_size;
    BlockHeader header;
};

typedef struct Block Block;

