#include "config.h"
#include "units.h"
#include "parameters.h"

const struct Config config = {
    .periods = {
        .autoexit = 0,
        .saveIndices = MINUTE_TO_MILLISECOND(5),
        .peerDataExchange = SECOND_TO_MILLISECOND(1),
        .resetIBDMode = SECOND_TO_MILLISECOND(120),
        .timeoutPeers = SECOND_TO_MILLISECOND(10),
        .printNodeStatus = SECOND_TO_MILLISECOND(5),
        .ping = SECOND_TO_MILLISECOND(13),
        .validateNewBlocks = MINUTE_TO_MILLISECOND(1),
    },
    .tolerances = {
        .handshake = SECOND_TO_MILLISECOND(10),
        .latency = SECOND_TO_MILLISECOND(10),
        .peerLife = MINUTE_TO_MILLISECOND(10),
    },
    .protocolVersion = 70015,
    .services = SERVICE_NODE_NETWORK,
    .maxIncoming = 125,
    .maxOutgoing = 8,
    .maxOutgoingIBD = 64,
    .peerCandidateLife = DAY_TO_SECOND(30),
    .userAgent = "/Satoshi:0.16.2/tinybtc:0.0.1/",
    .backlog = 32,
    .getaddrThreshold = 1000,
    .dbName = "chaindb",
    .ibdModeAvailabilityThreshold = 0.95,
    .ibdPeerMaxBlockDifference = 100,
    .apiPort = 9494,
    .silentIncomingMessageCommands = "inv,pong,ping,addr",
    .deepReindexBlocks = false,
};
