#pragma once

#include <stdint.h>
#include "datatypes.h"

#define MAIN_NET_MAGIC 0xD9B4BEF9
#define TEST_NET_MAGIC 0xDAB5BFFA
#define TEST_NET_3_MAGIC 0x0709110B
#define DIY_NET_MAGIC 0x20180427

#define MAIN_NET_PORT 8333
#define TEST_NET_PORT 18333

#define SERVICE_NODE_NETWORK (1 << 0)
#define SERVICE_NODE_GETUTXO (1 << 1)
#define SERVICE_NODE_BLOOM (1 << 2)
#define SERVICE_NODE_WITNESS (1 << 3)
#define SERVICE_NODE_XTHIN (1 << 4)
#define SERVICE_NODE_NETWORK_LIMITED (1 << 10)

#define MAX_MESSAGE_LENGTH 65536

#define MAX_INV_SIZE 50000

struct Parameters {
    uint32_t magic;
    ServiceBits services;
    int32_t protocolVersion;
    int32_t minimalPeerVersion;
    DomainName dnsSeeds[6];
    uint16_t port;
    uint8_t backlog;
    uint32_t maxIncoming;
    uint32_t maxOutgoing;
    uint8_t userAgent[128];
    uint32_t addrLife;
    uint16_t getaddrThreshold;
};

extern const struct Parameters parameters;
