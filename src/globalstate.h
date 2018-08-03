#pragma once
#include <stdint.h>
#include "parameters.h"

struct GlobalState {
    IP peerIps[10000];
    uint32_t peerIpCount;
};

typedef struct GlobalState GlobalState;

GlobalState globalState;
