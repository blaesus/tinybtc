#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "uv/uv.h"
#include "redis/hiredis.h"
#include "parameters.h"
#include "datatypes.h"
#include "peer.h"

#define MAX_PEERS 256
#define MAX_ADDR_CACHE 65536

struct GlobalState {
    uv_tcp_t listenSocket;
    uv_idle_t idler;

    IP peerAddresses[MAX_ADDR_CACHE];
    uint32_t peerAddressCount;

    struct Peer peers[MAX_PEERS];
    uint32_t peerCount;

    uint64_t eventCounter;
    struct NetworkAddress myAddress;
    uint32_t blockchainHeight;
};

typedef struct GlobalState GlobalState;

extern GlobalState global;

void add_peer_address(IP ip);
