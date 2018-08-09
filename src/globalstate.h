#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "uv.h"
#include "parameters.h"
#include "datatypes.h"

#define MAX_PEERS 1000

struct GlobalState {
    uv_tcp_t listenSocket;
    uv_idle_t idler;
    struct Peer peers[MAX_PEERS];
    uint32_t peerCount;
    uint64_t eventCounter;
    struct NetworkAddress myAddress;
    uint32_t blockchainHeight;
};

typedef struct GlobalState GlobalState;

extern GlobalState global;

void add_peer(IP ip, bool myClient);