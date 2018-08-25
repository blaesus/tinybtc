#pragma once

#include "messages/block.h"

uint32_t mine_block_header(
    BlockPayloadHeader header,
    uint32_t initialNonce,
    char *processLabel
);
