#include "config.h"
#include "units.h"
#include "parameters.h"

const struct Config config = {
    .autoExitPeriod = 120,
    .mainTimerInterval = 1000,
    .protocolVersion = 70015,
    .services = SERVICE_NODE_NETWORK,
    .maxIncoming = 125,
    .maxOutgoing = 8,
    .addrLife = DAY(14),
    .userAgent = "/Satoshi:0.16.2/tinybtc:0.0.1/",
    .backlog = 32,
    .getaddrThreshold = 1000,
    .peerDataRequestPeriod = 10,
    .redisHost = "127.0.0.1",
    .redisPort = 6379,
};
