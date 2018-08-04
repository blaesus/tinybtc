#include <stdint.h>
#include "parameters.h"

#define MAIN_NET_MAGIC 0xD9B4BEF9
#define DIY_NET_MAGIC 0x20180427

const struct Parameters parameters = {

    .magic = MAIN_NET_MAGIC,

    // see Satoshi's version.h
    .protocolVersion = 70015,

    .port = 8333,

    // For node Discovery
    // See https://en.bitcoin.it/wiki/Satoshi_Client_Node_Discovery

    .dnsSeeds = {
        "seed.bitcoin.sipa.be",
        "dnsseed.bluematt.me",
        "dnsseed.bitcoin.dashjr.org",
        "seed.bitcoinstats.com",
        "seed.bitcoin.jonasschnelli.ch",
        "seed.btc.petertodd.org",
    }
};
