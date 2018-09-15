#pragma once

#include <stdint.h>
#include "datatypes.h"

#define SERVICE_NODE_NETWORK (1 << 0)
#define SERVICE_NODE_GETUTXO (1 << 1)
#define SERVICE_NODE_BLOOM (1 << 2)
#define SERVICE_NODE_WITNESS (1 << 3)
#define SERVICE_NODE_XTHIN (1 << 4)
#define SERVICE_NODE_NETWORK_LIMITED (1 << 10)

struct Periods {
    uint32_t mainTimer;
    int32_t autoexit;
    int32_t autosave;
    int32_t ping;
    uint16_t resetIBDMode;
    uint16_t peerDataExchange;
};

struct Config {
    struct Periods periods;
    int32_t maxPingLatency;
    int32_t protocolVersion;
    uint8_t userAgent[128];
    ServiceBits services;
    uint32_t maxIncoming;
    uint32_t maxOutgoing;
    uint32_t maxOutgoingIBD;
    uint32_t addrLife;
    uint8_t backlog;
    uint16_t getaddrThreshold;
    const char redisHost[64];
    uint16_t redisPort;
    double ibdModeAvailabilityThreshold;
    uint16_t ibdPeerMaxBlockDifference;
};

extern const struct Config config;
