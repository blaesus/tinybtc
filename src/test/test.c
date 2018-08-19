#include <stdint.h>
#include <stdlib.h>

#include "datatypes.h"
#include "networking.h"
#include "peer.h"
#include "globalstate.h"
#include "messages/shared.h"
#include "messages/version.h"
#include "messages/block.h"
#include "test/test.h"

static int32_t test_version_messages() {
    Message message = get_empty_message();

    struct sockaddr_in fixtureAddr;
    IP fixtureMyIp = {0};
    IP fixturePeerIp = {0};

    uv_ip4_addr("", parameters.port, &fixtureAddr);
    convert_ipv4_address_to_ip_array(
        fixtureAddr.sin_addr.s_addr,
        fixtureMyIp
    );
    struct NetworkAddress myAddress = {
        .services = 0x40d,
        .ip = {0},
        .port = htons(0)
    };
    memcpy(myAddress.ip, fixtureMyIp, sizeof(IP));
    global.myAddress = myAddress;

    uv_ip4_addr("138.68.93.0", parameters.port, &fixtureAddr);
    convert_ipv4_address_to_ip_array(
        fixtureAddr.sin_addr.s_addr,
        fixturePeerIp
    );
    struct Peer fixturePeer = {
        .handshake = {
            .acceptThem = false,
            .acceptUs = false,
        },
        .socket = NULL,
        .relationship = REL_MY_SERVER,
        .address = {
            .services = 0x9,
            .ip = {0},
            .port = htons(8333)
        }
    };
    memcpy(fixturePeer.address.ip, fixturePeerIp, sizeof(IP));

    uint8_t messageBuffer[MAX_MESSAGE_LENGTH] = {0};

    make_version_message(&message, &fixturePeer);
    uint64_t dataSize = serialize_version_message(&message, messageBuffer);
    print_object(messageBuffer, dataSize);

    return 0;
}

static void test_genesis() {
    Message message = get_empty_message();
    load_block_message("genesis.dat", &message);
    Byte buffer[10000] = {0};
    BlockPayload *ptrGenesisBlock = message.ptrPayload;
    uint64_t width = serialize_block_payload_header(&ptrGenesisBlock->header, buffer);
    SHA256_HASH hash = {0};
    dsha256(buffer, (uint32_t)width, hash);

    print_object(buffer, width);
    /* expected output:
    0000 - 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0010 - 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0020 - 00 00 00 00 3b a3 ed fd 7a 7b 12 b2 7a c7 2c 3e
    0030 - 67 76 8f 61 7f c8 1b c3 88 8a 51 32 3a 9f b8 aa
    0040 - 4b 1e 5e 4a 29 ab 5f 49 ff ff 00 1d 1d ac 2b 7c END
    */

    print_object(hash, sizeof(hash));
    /* expected output:
    0000 - 6f e2 8c 0a b6 f1 b3 72 c1 a6 a2 46 ae 63 f7 4f
    0010 - 93 1e 83 65 e1 5a 08 9c 68 d6 19 00 00 00 00 00 END
     */
}

void print_block_payload(
    BlockPayload *ptrBlock
) {
    printf("version: %u\n", ptrBlock->header.version);
    printf("merkle root:");
    print_object(ptrBlock->header.merkle_root, SHA256_LENGTH);
    TxNode *ptrTxNode = ptrBlock->ptrFirstTxNode;
    for (uint32_t i = 0; i < ptrBlock->txCount; i++) {
        printf("\nTransaction %u\n", i+1);
        TxPayload tx = ptrTxNode->tx;
        printf(
            "  version = %u, tx_in_count = %llu, tx_out_count = %llu\n",
            tx.version,
            tx.txInputCount,
            tx.txOutputCount
        );
        ptrTxNode = ptrTxNode->next;
    }
}

static void test_block() {
    Message message = get_empty_message();
    load_block_message("fixtures/block_7323.dat", &message);
    BlockPayload *ptrBlock = message.ptrPayload;

    print_object(ptrBlock->header.merkle_root, SHA256_LENGTH);
    /*
     * Expected:
     * 0000 - 2c 6e 39 bf 15 34 6c 13 1e 35 b6 7b 59 24 08 ef
     * 0010 - 80 92 e1 fd 92 84 19 d8 b5 2f 0b 6e f2 a6 b8 a7 END
     */

    print_block_payload(ptrBlock);
}

static void test_block_parsing_and_serialization() {
    Message message = get_empty_message();
    load_block_message("fixtures/block_7323.dat", &message);

    Byte messageBuffer[4096] = {0};
    serialize_block_message(&message, messageBuffer);
    print_object(messageBuffer, message.header.length + sizeof(message.header));

    Byte checksum[4] = {0};
    Byte payloadBuffer[4096] = {0};
    serialize_block_payload(message.ptrPayload, payloadBuffer);
    calculate_data_checksum(payloadBuffer, message.header.length, checksum);
    printf("Correct checksum:");
    print_object(message.header.checksum, 4);
    printf("Calculated checksum from parsed-and-serialized:");
    print_object(checksum, 4);
    printf("Difference = %u (expecting 0)", memcmp(message.header.checksum, checksum, 4));

    /**
     * Expect checksum to be
     * 0000 - a1 30 12 ed END
     */

}

static void test_merkle_on_path(char *path) {
    Message message = get_empty_message();
    load_block_message(path, &message);
    SHA256_HASH merkleRoot = {0};
    BlockPayload *ptrPayload = message.ptrPayload;
    compute_merkle_root(ptrPayload->ptrFirstTxNode, merkleRoot);
    print_object(merkleRoot, SHA256_LENGTH);
}

static void test_merkles() {
    test_merkle_on_path("genesis.dat");
    /**
     * Expect:
     * 0000 - 3b a3 ed fd 7a 7b 12 b2 7a c7 2c 3e 67 76 8f 61
     * 0010 - 7f c8 1b c3 88 8a 51 32 3a 9f b8 aa 4b 1e 5e 4a END
     */

    test_merkle_on_path("fixtures/block_7323.dat");
    /**
     * Expected:
     * 0000 - 2c 6e 39 bf 15 34 6c 13 1e 35 b6 7b 59 24 08 ef
     * 0010 - 80 92 e1 fd 92 84 19 d8 b5 2f 0b 6e f2 a6 b8 a7 END
     */
}


void test() {
    // test_version_messages()
    // test_genesis();
    // test_block();
    // test_block_parsing_and_serialization();
    test_merkles();

}
