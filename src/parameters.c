#include <stdint.h>
#include "parameters.h"

#define MAIN_NET_MAGIC 0xD9B4BEF9
#define DIY_NET_MAGIC 0x20180427

#define SERVICE_NODE_NETWORK 1
#define SERVICE_NODE_GETUTXO 2
#define SERVICE_NODE_BLOOM 4
#define SERVICE_NODE_WITNESS 8
#define SERVICE_NODE_NETWORK_LIMITED 1024

const struct Parameters parameters = {

    .magic = MAIN_NET_MAGIC,

    // see Satoshi's version.h
    .protocolVersion = 70015,

    .port = 8333,

    .services = SERVICE_NODE_NETWORK,

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

    .backlog = 32
};
