#include "config.h"
#include "units.h"
#include "parameters.h"

const struct Config config = {
    .periods = {
        .autoexit = MINUTE_TO_MILLISECOND(30),
        .saveIndices = SECOND_TO_MILLISECOND(120),
        .peerDataExchange = SECOND_TO_MILLISECOND(1),
        .resetIBDMode = SECOND_TO_MILLISECOND(60),
        .timeoutPeers = SECOND_TO_MILLISECOND(10),
        .printNodeStatus = SECOND_TO_MILLISECOND(5),
    },
    .tolerances = {
        .handshake = SECOND_TO_MILLISECOND(8),
        .latency = SECOND_TO_MILLISECOND(8),
        .peerLife = SECOND_TO_MILLISECOND(120),
    },
    .protocolVersion = 70015,
    .services = SERVICE_NODE_NETWORK,
    .maxIncoming = 125,
    .maxOutgoing = 8,
    .maxOutgoingIBD = 64,
    .addrLife = DAY_TO_SECOND(14),
    .userAgent = "/Satoshi:0.16.2/tinybtc:0.0.1/",
    .backlog = 32,
    .getaddrThreshold = 1000,
    .dbName = "chaindb",
    .ibdModeAvailabilityThreshold = 0.95,
    .ibdPeerMaxBlockDifference = 100,
    .apiPort = 9494,
    .silentIncomingMessageCommands = "inv,pong,ping",
    .deepReindexBlocks = false,
};
