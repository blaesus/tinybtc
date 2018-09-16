#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "hiredis/hiredis.h"
#include "parameters.h"
#include "datatypes.h"
#include "peer.h"
#include "hashmap.h"
#include "messages/block.h"
#include "blockchain.h"

#define MAX_PEERS 256
#define MAX_ADDR_CACHE 65536
#define PEER_ADDRESS_COUNT_WIDTH 4
#define MAX_ORPHAN_COUNT 4096

struct GlobalState {
    bool ibdMode;
    void *timerTable;

    uv_tcp_t listenSocket;
    redisContext *ptrRedisContext;

    AddrRecord peerAddresses[MAX_ADDR_CACHE];
    uint32_t peerAddressCount;

    Peer peers[MAX_PEERS];
    uint32_t peerCount;

    time_t start_time;
    NetworkAddress myAddress;

    Hashmap blockIndices;
    SHA256_HASH orphans[MAX_ORPHAN_COUNT];
    uint16_t orphanCount;

    BlockPayload genesisBlock;
    SHA256_HASH genesisHash;

    BlockIndex mainTip;
    uint32_t maxFullBlockHeight;
};

typedef struct GlobalState GlobalState;

extern GlobalState global;

void add_peer_address(NetworkAddress addr, uint32_t timestamp);

void dedupe_global_addr_cache(void);

void clear_old_addr(void);

int32_t set_addr_timestamp(IP ip, uint32_t timestamp);
int32_t set_addr_services(IP ip, ServiceBits bits);
int32_t disable_ip(IP ip);

bool is_peer(IP ip);
int8_t get_next_missing_block(Byte *hash);
bool is_block_being_requested(Byte *hash);
uint32_t get_handshaken_peer_count();
bool peer_hand_shaken(Peer *ptrPeer);
