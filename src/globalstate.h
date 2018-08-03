#pragma once
#include <stdint.h>
#include "parameters.h"

struct GlobalState {
    IPAddressString peerIps[10000];
    uint32_t peerIpIndex;
};

typedef struct GlobalState GlobalState;

GlobalState globalState;
