#include <stdlib.h>

#include "uv/uv.h"
#include "redis/hiredis.h"

#include "communication.h"
#include "networking.h"
#include "hash.h"
#include "persistent.h"
#include "globalstate.h"
#include "messages/shared.h"
#include "messages/version.h"

void cleanup() {
    printf("Cleaning up\n");
    free_networking_resources();
    save_peer_addresses();
    printf("\nGood byte!\n");
}

int32_t run_main_loop() {
    return uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}

int32_t test_version_messages() {
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
        .myClient = false,
        .address = {
            .services = 0x9,
            .ip = {0},
            .port = htons(8333)
        }
    };
    memcpy(fixturePeer.address.ip, fixturePeerIp, sizeof(IP));

    uint8_t messageBuffer[MESSAGE_BUFFER_SIZE] = {0};

    make_version_message(&message, &fixturePeer);
    uint64_t dataSize = serialize_version_message(&message, messageBuffer);
    print_object(messageBuffer, dataSize);

    return 0;
}

void init() {
    srand((unsigned int)time(NULL));
    setup_main_event_loop(true);
    init_db();
}

int32_t setup_peers() {
    load_peer_addresses();
    if (global.peerAddressCount == 0) {
        dns_bootstrap();
        save_peer_addresses();
    }
    setup_listen_socket();
    connect_to_peers();
    return 0;
}

int32_t main(/* int32_t argc, char **argv */) {
    init();
//    testHash();
//    test_version_messages();
    setup_peers();
    run_main_loop();
    atexit(&cleanup);
    return 0;
}

