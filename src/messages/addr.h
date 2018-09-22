#pragma once

#include <stdint.h>
#include "datatypes.h"
#include "messages/shared.h"

#define MAX_RECORDS_IN_ADDR 4096

struct AddrPayload {
    uint64_t count;
    struct AddrRecord addr_list[MAX_RECORDS_IN_ADDR];
};

typedef struct AddrPayload AddrPayload;

int32_t parse_into_addr_message(
    Byte *ptrBuffer,
    Message *ptrMessage
);

void print_addr_message(Message *ptrMessage);
