//
// Created by Andy Shu on 30/7/2018.
//

#include <stdint.h>

const uint32_t MAGIC_NUMBER = 0x20180427;

// Node Discovery
// See https://en.bitcoin.it/wiki/Satoshi_Client_Node_Discovery

const char *dns_seeds[] = {
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.org",
};
