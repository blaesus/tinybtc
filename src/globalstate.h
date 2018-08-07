#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "uv.h"
#include "parameters.h"

#define MAX_PEERS 10000

struct Peer {
    bool valid;
    IP ip;
    uv_tcp_t *socket;
};

struct GlobalState {
    uv_tcp_t listenSocket;
    uv_idle_t idler;
    struct Peer peers[MAX_PEERS];
    uint32_t peerCount;
    uint64_t eventCounter;
};

typedef struct GlobalState GlobalState;

extern GlobalState global;

void add_peer(IP ip);
