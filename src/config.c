#include "config.h"
#include "units.h"
#include "parameters.h"

const struct Config config = {
    .autoExitPeriod = 60,
    .mainTimerInterval = 1000,
    .protocolVersion = 70015,
    .services = SERVICE_NODE_NETWORK,
    .maxIncoming = 125,
    .maxOutgoing = 8,
    .addrLife = DAY(14),
    .userAgent = "/Satoshi:0.16.2/tinybtc:0.0.1/",
    .backlog = 32,
};
