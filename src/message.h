#pragma once

#include <stdint.h>

struct Message {
    uint32_t magic;
    char command[12];
    uint32_t length;
    uint32_t checksum;
    uint8_t *payload;
};

typedef struct Message Message;
