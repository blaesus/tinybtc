#pragma once
#include <stdint.h>
#include "datatypes.h"
#include "hash.h"
#include "parameters.h"
#include "header.h"

#define CMD_VERSION "version"
#define CMD_VERACK "verack"
#define CMD_INV "inv"

#define VAR_INT_CHECKPOINT_8  0xFD
#define VAR_INT_PREFIX_16  0xFD
#define VAR_INT_CHECKPOINT_16  0xFFFF
#define VAR_INT_PREFIX_32  0xFE
#define VAR_INT_CHECKPIONT_32  0xFFFFFFFF
#define VAR_INT_PREFIX_64  0xFF

uint8_t calc_number_varint_width(uint64_t number);

uint8_t serialize_to_varint(uint64_t data, uint8_t *ptrBuffer);

uint8_t parse_varint(
    uint8_t *ptrBuffer,
    uint64_t *result
);

uint64_t serialize_varstr(
    struct VariableLengthString *ptrVarStr,
    uint8_t *ptrBuffer
);

struct InventoryVector {
    uint32_t type : 4 * BITS_IN_BYTE;
    SHA256_HASH hash;
};

typedef struct InventoryVector InventoryVector;

struct GenericDataPayload {
    uint64_t count;
    struct InventoryVector inventory[MAX_INV_SIZE];
};

typedef struct GenericDataPayload GenericDataPayload;

#define Payload void

// @see https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure

struct Message {
    Header header;
    Payload *payload;
};

typedef struct Message Message;

bool begins_with_header(void *p);

uint64_t serialize_network_address(
    struct NetworkAddress *ptrAddress,
    uint8_t *ptrBuffer,
    uint32_t bufferSize
);

Message get_empty_message(void);

uint64_t parse_network_address(
    uint8_t *ptrBuffer,
    struct NetworkAddress *ptrAddress
);

uint64_t parse_as_varstr(
    uint8_t *ptrBuffer,
    struct VariableLengthString *ptrResult
);

