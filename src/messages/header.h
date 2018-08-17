#pragma once

#include <stdint.h>
#include "datatypes.h"

#define CHECKSUM_SIZE 4
typedef uint8_t PayloadChecksum[CHECKSUM_SIZE];

struct Header {
    uint32_t magic : BYTES(4);
    uint8_t command[12];
    uint32_t length : BYTES(4);
    PayloadChecksum checksum;
};

typedef struct Header Header;

void calculate_data_checksum(void *ptrBuffer, uint32_t count, uint8_t *ptrResult);

uint64_t parse_message_header(
    uint8_t *buffer,
    Header *ptrHeader
);

Header get_empty_header(void);

void print_message_header(Header header);
