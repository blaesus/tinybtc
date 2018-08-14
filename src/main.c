#include <stdlib.h>

#include "uv/uv.h"
#include "redis/hiredis.h"

#include "comm.h"
#include "data.h"
#include "globalstate.h"
#include "message.h"
#include "inet.h"
#include "hash.h"

void cleanup() {
    printf("Cleaning up\n");
    free_networking_resources();
    save_peer_addresses();
}

int32_t run_main_loop() {
    return uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}

int32_t test_version_messages() {
    struct Message message = {0};
    struct VersionPayload payload = {0};

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
            .handshake = 0,
            .socket = NULL,
            .myClient = false,
            .address = {
                .services = 0x9,
                .ip = {0},
                .port = htons(8333)
            }
    };
    memcpy(fixturePeer.address.ip, fixturePeerIp, sizeof(IP));

    uint8_t messageBuffer[MESSAGE_BUFFER_SIZE] = {0};

    uint32_t payloadLength = make_version_payload_to_peer(&fixturePeer, &payload);
    make_version_message(&message, &payload, payloadLength);

    uint64_t dataSize = serialize_version_message(
            &message,
            messageBuffer,
            MESSAGE_BUFFER_SIZE
    );

    print_object(messageBuffer, dataSize);

    return 0;
}

int32_t init_db() {
    printf("Connecting to redis database...\n");
    redisContext *c;
    const char *hostname = "127.0.0.1";
    int port = 6379;

    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    c = redisConnectWithTimeout(hostname, port, timeout);
    if (c == NULL || c->err) {
        if (c) {
            printf("Connection error: %s\n", c->errstr);
            redisFree(c);
        } else {
            printf("Connection error: can't allocate redis context\n");
        }
        exit(1);
    }
    printf("Redis connected");
    return 0;
}

void init() {
    srand((unsigned int)time(NULL));
    setup_main_event_loop(true);
    init_db();
}

void testHash() {
    uint8_t buffer[SHA256_LENGTH] = {0};
    char *data = "hello";
    dsha256(data, 5, buffer);
    print_object(buffer, SHA256_LENGTH);
    //Should be 95 95 c9 df ...
}

int32_t network() {
    load_peer_addresses();
    if (global.peerAddressCount == 0) {
        dns_bootstrap();
        save_peer_addresses();
    }
    setup_listen_socket();
    connect_to_peers();
    return 0;
}

int32_t main(int32_t argc, char **argv) {
    init();
//    testHash();
//    test_version_messages();
//    network();
    run_main_loop();
    atexit(&cleanup);
    return 0;
}

