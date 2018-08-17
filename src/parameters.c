#include <stdint.h>
#include "parameters.h"
#include "units.h"

const struct Parameters parameters = {

    .magic = MAIN_NET_MAGIC,

    // see Satoshi's version.h
    .protocolVersion = 70015,

    .minimalPeerVersion = 31800,

    .port = MAIN_NET_PORT,

    .services = SERVICE_NODE_NETWORK & SERVICE_NODE_WITNESS,

    // For node Discovery
    // See https://en.bitcoin.it/wiki/Satoshi_Client_Node_Discovery
    .dnsSeeds = {
        "seed.bitcoin.sipa.be",
        "dnsseed.bluematt.me",
        "dnsseed.bitcoin.dashjr.org",
        "seed.bitcoinstats.com",
        "seed.bitcoin.jonasschnelli.ch",
        "seed.btc.petertodd.org",
    },

    .userAgent = "/Satoshi:0.16.2/",

    .maxIncoming = 125,

    .maxOutgoing = 16,

    .backlog = 32,

    .addrLife = DAY(14),

    .getaddrThreshold = 1000,
};
