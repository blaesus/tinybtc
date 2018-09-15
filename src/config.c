#include "config.h"
#include "units.h"
#include "parameters.h"

const struct Config config = {
    .periods = {
        .autoexit = MINUTE_TO_MILLISECOND(60),
        .saveIndices = SECOND_TO_MILLISECOND(60),
        .ping = SECOND_TO_MILLISECOND(60),
        .peerDataExchange = SECOND_TO_MILLISECOND(1),
        .resetIBDMode = SECOND_TO_MILLISECOND(60),
        .timeoutPeers = SECOND_TO_MILLISECOND(10),
        .printNodeStatus = SECOND_TO_MILLISECOND(5),
    },
    .maxPingLatency = 2,
    .protocolVersion = 70015,
    .services = SERVICE_NODE_NETWORK,
    .maxIncoming = 125,
    .maxOutgoing = 8,
    .maxOutgoingIBD = 32,
    .addrLife = DAY_TO_SECOND(14),
    .userAgent = "/Satoshi:0.16.2/tinybtc:0.0.1/",
    .backlog = 32,
    .getaddrThreshold = 1000,
    .redisHost = "127.0.0.1",
    .redisPort = 6379,
    .ibdModeAvailabilityThreshold = 0.95,
    .ibdPeerMaxBlockDifference = 100,
};
