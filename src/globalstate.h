#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include "parameters.h"

#define MAX_PEERS 10000

struct Peer {
    bool active;
    IP ip;
    int socket;
};

struct GlobalState {
    struct Peer peers[MAX_PEERS];
    uint32_t peerCount;
};

typedef struct GlobalState GlobalState;

GlobalState globalState;

void add_peer(IP ip);
