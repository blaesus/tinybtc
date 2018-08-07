#pragma once

#include <stdint.h>
#include "inet.h"

struct Parameters {
    uint32_t magic;
    uint64_t services;
    int32_t protocolVersion;
    DomainName dnsSeeds[6];
    uint16_t port;
    uint8_t backlog;
};

extern const struct Parameters parameters;
