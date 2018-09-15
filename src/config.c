#include "config.h"
#include "units.h"
#include "parameters.h"

const struct Config config = {
    .periods = {
        .mainTimer = 1000,
        .autoexit = MINUTE(60),
        .autosave = 60,
        .ping = 59,
        .peerDataExchange = 1,
        .resetIBDMode = 60,
    },
    .maxPingLatency = 2,
    .protocolVersion = 70015,
    .services = SERVICE_NODE_NETWORK,
    .maxIncoming = 125,
    .maxOutgoing = 8,
    .maxOutgoingIBD = 32,
    .addrLife = DAY(14),
    .userAgent = "/Satoshi:0.16.2/tinybtc:0.0.1/",
    .backlog = 32,
    .getaddrThreshold = 1000,
    .redisHost = "127.0.0.1",
    .redisPort = 6379,
    .ibdModeAvailabilityThreshold = 0.95,
    .ibdPeerMaxBlockDifference = 100,
};
