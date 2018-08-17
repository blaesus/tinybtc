#pragma once

#include <stdint.h>
#include "datatypes.h"
#include "hash.h"

#define MAX_TX_COUNT 4096
#define MAX_SCRIPT_LENGTH 65536
#define MAX_WITNESS_COMPONENT_DATA_LENGTH 4096
#define MAX_WITNESS_COMPONENT_COUNT 1024

#define TX int

// @see https://en.bitcoin.it/wiki/Protocol_documentation#tx

struct Outpoint {
    SHA256_HASH hash;
    uint32_t index;
};

typedef struct Outpoint Outpoint;

struct TxIn {
    Outpoint previous_output;
    uint64_t script_length;
    Byte signature_script[MAX_SCRIPT_LENGTH];
    uint32_t sequence;
};

typedef struct TxIn TxIn;

struct TxOut {
    int64_t value;
    uint64_t pk_script_length;
    Byte pk_script[MAX_SCRIPT_LENGTH];
};

typedef struct TxOut TxOut;

// @see https://bitcoin.stackexchange.com/questions/68924/

struct WitnessComponent {
    uint64_t length;
    Byte data[MAX_WITNESS_COMPONENT_DATA_LENGTH];
};

typedef struct WitnessComponent WitnessComponent;

struct TxWitness {
    uint64_t count;
    WitnessComponent components[MAX_WITNESS_COMPONENT_COUNT];
};

typedef struct TxWitness TxWitness;

struct TxPayload {
    int32_t version;
    Byte flag;
    VarIntMem tx_in_count;
    TxIn tx_in[MAX_TX_COUNT];
    VarIntMem tx_out_count;
    TxOut tx_out[MAX_TX_COUNT];
    TxWitness tx_witness[MAX_TX_COUNT];
    uint32_t lock_time;
};
