#pragma once

#include <stdint.h>
#include "datatypes.h"

#define SERVICE_NODE_NETWORK (1 << 0)
#define SERVICE_NODE_GETUTXO (1 << 1)
#define SERVICE_NODE_BLOOM (1 << 2)
#define SERVICE_NODE_WITNESS (1 << 3)
#define SERVICE_NODE_XTHIN (1 << 4)
#define SERVICE_NODE_NETWORK_LIMITED (1 << 10)

#define INSTRUCTION_KILL "kill"

#define LOG_MESSAGE_LOADING false
#define LOG_MESSAGE_SENDING false
#define LOG_MESSAGE_SENT false
#define LOG_PEER_REPLACE false
#define LOG_SCRIPT_STACKS false
#define LOG_BLOCK_LOAD false
#define LOG_VALIDATION_PROCEDURES false
#define LOG_SIGNATURE_FIXING false
#define LOG_BLOCK_REGISTRATION_DETAILS false
#define LOG_DB_ERROR false

#define TRACE_MEMORY_USE false

struct Periods {
    uint64_t autoexit;
    uint64_t saveIndices;
    uint64_t resetIBDMode;
    uint64_t peerDataExchange;
    uint64_t timeoutPeers;
    uint64_t printNodeStatus;
    uint64_t ping;
    uint64_t validateNewBlocks;
};

struct Tolerances {
    uint64_t handshake;
    uint64_t latency;
    uint64_t peerLife;
    uint64_t blockValidation;
};

struct Config {
    struct Periods periods;
    struct Tolerances tolerances;
    int32_t protocolVersion;
    uint8_t userAgent[128];
    ServiceBits services;
    uint32_t maxIncoming;
    uint32_t maxOutgoing;
    uint32_t maxOutgoingIBD;
    uint32_t peerCandidateLife;
    uint8_t backlog;
    uint16_t getaddrThreshold;
    char *txLocationDBName;
    char *utxoDBName;
    uint16_t catchupThreshold;
    uint16_t apiPort;
    char *silentIncomingMessageCommands;
    bool verifyBlocks;
};

extern const struct Config config;
