#include <stdint.h>
#include <string.h>

#include "header.h"
#include "hash.h"
#include "messages/shared.h"

uint64_t parse_message_header(
    uint8_t *buffer,
    Header *ptrHeader
) {
    memcpy(ptrHeader, buffer, sizeof(Header));
    return sizeof(Header);
}

Header get_empty_header() {
    Header header = {
        .magic = parameters.magic,
        .command = {0},
        .checksum = {0},
        .length = 0
    };
    return header;
}

void calculate_data_checksum(void *ptrBuffer, uint32_t count, uint8_t *ptrResult) {
    SHA256_HASH hash = {0};
    dsha256(ptrBuffer, count, hash);
    memcpy(ptrResult, hash, CHECKSUM_SIZE);
}

void print_message_header(Header header) {
    printf("\nheader: MAGIC=%x, COMMAND=%s, LENGTH=%u\n",
           header.magic,
           header.command,
           header.length
    );
}

