#include <stdlib.h>

#include "uv.h"

#include "comm.h"
#include "data.h"
#include "globalstate.h"
#include "message.h"
#include "inet.h"
#include "hash.h"

void cleanup() {
    printf("Cleaning up\n");
    free_networking_resources();
    save_peers();
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
            .valid = true,
            .socket = NULL,
            .myClient = false,
            .address = {
                .services = 0x9,
                .ip = {0},
                .port = htons(8333)
            }
    };
    memcpy(fixturePeer.address.ip, fixturePeerIp, sizeof(IP));

    uint8_t messageBuffer[MESSAGE_BUFFER_SIZE] = {};
    memset(messageBuffer, 0xFF, sizeof(messageBuffer));

    uint64_t userAgentLength = make_version_payload_to_peer(&fixturePeer, &payload);
    uint64_t payloadLength = userAgentLength + 1 /* Length itself */ + 85; // TODO: calculate;
    make_version_message(&message, &payload, payloadLength);

    uint64_t dataSize = serialize_version_message(
            &message,
            messageBuffer,
            MESSAGE_BUFFER_SIZE
    );

    printObjectWithLength(&messageBuffer, dataSize);

    return 0;
}

void init() {
    srand((unsigned int)time(NULL));
}

void testHash() {
    uint8_t buffer[SHA256_LENGTH] = {0};
    char *data = "hello";
    dsha256(data, 5, buffer);
    printObjectWithLength(buffer, SHA256_LENGTH);
    //Should be 95 95 c9 df ...
}

int32_t main() {
    init();
//    testHash();
    test_version_messages();
}

int32_t mainX() {
    init();
    load_peers();
    if (!global.peerCount) {
        dns_bootstrap();
    }
    setup_main_event_loop(false);
    setup_listen_socket();
    setup_peer_connections();
    run_main_loop();
    atexit(&cleanup);
    return 0;
}
