#pragma once

#include <stdint.h>
#include <datatypes.h>
#include "messages/shared.h"

#define MAX_ADDR_LIST 1024

struct AddrRecord {
    uint32_t timestamp;
    struct NetworkAddressWithTime net_addr;
};

typedef struct AddrRecord AddrRecord;

struct AddrPayload {
    uint64_t count;
    struct AddrRecord addr_list[MAX_ADDR_LIST];
};

typedef struct AddrPayload AddrPayload;

int32_t parse_into_addr_message(
    Byte *ptrBuffer,
    Message *ptrMessage
);

void print_addr_message(Message *ptrMessage);
