#pragma once

#include <stdint.h>
#include "inet.h"

struct Parameters {
    int32_t protocolVersion;
    DomainName dnsSeeds[6];
    uint16_t remotePort;
};

const struct Parameters parameters;
