#include "config.h"
#include "units.h"
#include "parameters.h"

const struct Config config = {
    .autoExitPeriod = 60,
    .mainTimerInterval = 2000,
    .protocolVersion = 70015,
    .services = SERVICE_NODE_NETWORK,
    .maxIncoming = 125,
    .maxOutgoing = 16,
    .addrLife = DAY(14),
    .userAgent = "/Satoshi:0.16.2/diy-bitcoin:0.0.1/",
    .backlog = 32,
};
