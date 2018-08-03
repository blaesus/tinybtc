#include <stdint.h>
#include "parameters.h"

const uint32_t MAGIC_NUMBER = 0x20180427;

const struct Parameters parameters = {

    // For node Discovery
    // See https://en.bitcoin.it/wiki/Satoshi_Client_Node_Discovery

    .dns_seeds = {
        "seed.bitcoin.sipa.be",
        "dnsseed.bluematt.me",
        "dnsseed.bitcoin.dashjr.org",
        "seed.bitcoinstats.com",
        "seed.bitcoin.jonasschnelli.ch",
        "seed.btc.petertodd.org",
    }
};
