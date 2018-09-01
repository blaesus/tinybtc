#pragma once

#include <stdint.h>
#include "datatypes.h"

#define MAIN_NET_MAGIC 0xD9B4BEF9
#define TEST_NET_MAGIC 0xDAB5BFFA
#define TEST_NET_3_MAGIC 0x0709110B
#define DIY_NET_MAGIC 0x20180427

#define MAIN_NET_PORT 8333
#define TEST_NET_PORT 18333

#define MESSAGE_BUFFER_LENGTH 2 * 1024 * 1024

#define MAX_INV_SIZE 50000

#define CLEAR_OLD_ADDR_THRESHOLD 1000

struct ChainParameters {
    uint32_t magic;
    int32_t minimalPeerVersion;
    DomainName dnsSeeds[6];
    uint16_t port;
    uint16_t getaddrThreshold;
    uint8_t genesisHeight;
    uint16_t retargetPeriod;
    uint16_t retargetLookBackPeriod;
    uint32_t desiredRetargetPeriod;
    int64_t blockMaxForwardTimestamp;
};

extern const struct ChainParameters mainnet;
