#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <math.h>

#include "libuv/include/uv.h"

#include "communication.h"
#include "globalstate.h"
#include "units.h"
#include "blockchain.h"
#include "config.h"
#include "peer.h"
#include "persistent.h"

#include "messages/common.h"
#include "messages/shared.h"
#include "messages/version.h"
#include "messages/verack.h"
#include "messages/inv.h"
#include "messages/addr.h"
#include "messages/getaddr.h"
#include "messages/blockreq.h"
#include "messages/sendheaders.h"
#include "messages/reject.h"
#include "messages/pingpong.h"
#include "messages/headers.h"
#include "messages/print.h"

#include "utils/networking.h"
#include "utils/datetime.h"
#include "utils/random.h"
#include "utils/memory.h"
#include "utils/data.h"
#include "utils/integers.h"

void send_getheaders(uv_tcp_t *socket);
void send_getdata_for_block(uv_tcp_t *socket, Byte *hash);
int32_t setup_api_socket(void);
void termination_check();

bool disable_candidate(PeerCandidate *ptrCandidate) {
    if (ptrCandidate) {
        ptrCandidate->status = PEER_CANDIDATE_STATUS_DISABLED;
        return true;
    }
    return false;
}

void replace_peer(Peer *ptrPeer) {
    #if LOG_PEER_REPLACE
    double now = get_now();
    double life = (now - ptrPeer->connectionStart) / SECOND_TO_MILLISECOND(1);
    printf("Replacing peer %u (life %.1fs)\n", ptrPeer->slot, life);
    #endif
    connect_to_best_candidate_as_peer(ptrPeer->slot);
}

void ping_peer(Peer *ptrPeer) {
    if (ptrPeer->networking.ping.pingSent && !ptrPeer->networking.ping.pongReceived) {
        double now = get_now();
        fprintf(stderr, "ping: unfinished ping before...\n");
        record_latency(ptrPeer, now - ptrPeer->networking.ping.pingSent);
    }
    ptrPeer->networking.ping.nonce = random_uint64();
    ptrPeer->networking.ping.pongReceived = 0;
    // networking.ping.pingSent is recorded in on_message_attempted
    PingpongPayload ptrPayload = {
        .nonce = ptrPeer->networking.ping.nonce
    };
    send_message(&ptrPeer->socket, CMD_PING, &ptrPayload);
}

bool check_peer(Peer *ptrPeer) {
    double now = get_now();

    // Check handshake
    double timeSinceConnection = now - ptrPeer->handshake.handshakeStart;
    bool timeoutForLateHandshake =
        !peer_hand_shaken(ptrPeer) && (timeSinceConnection > config.tolerances.handshake);
    if (timeoutForLateHandshake) {
        disable_candidate(ptrPeer->candidacy);
        printf("Timeout peer %02u: no handshake after %.1fms\n", ptrPeer->slot, timeSinceConnection);
        replace_peer(ptrPeer);
        return true;
    }

    // Check ping
    bool latencyFullyTested = is_latency_fully_tested(ptrPeer);
    double averageLatency = average_peer_latency(ptrPeer);

    bool timeoutForLatePong = latencyFullyTested && (averageLatency > config.tolerances.latency);
    if (timeoutForLatePong) {
        printf("Timeout peer %02u: average latency=%.1fms\n", ptrPeer->slot, averageLatency);
        replace_peer(ptrPeer);
    }
    return false;
}

void check_peer_life(Peer *ptrPeer) {
    double now = get_now();
    double life = now - ptrPeer->connectionStart;
    if (life > config.tolerances.peerLife) {
        printf(
            "Timeout peer %u as life exhausted (%.1f > %llu) \n",
            ptrPeer->slot,
            life,
            config.tolerances.peerLife
        );
        replace_peer(ptrPeer);
    }
}

void ping_peers() {
    for (uint32_t i = 0; i < global.peerCount; i++) {
        Peer *ptrPeer = global.peers[i];
        if (peer_hand_shaken(ptrPeer)) {
            ping_peer(ptrPeer);
        }
    }
}

void check_peers_connectivity() {
    for (uint32_t i = 0; i < global.peerCount; i++) {
        Peer *ptrPeer = global.peers[i];
        check_peer(ptrPeer);
        if (config.tolerances.peerLife) {
            check_peer_life(ptrPeer);
        }
    }
}

static bool is_peer_idle(Peer *ptrPeer) {
    return peer_hand_shaken(ptrPeer) && is_hash_empty(ptrPeer->networking.requesting);
}

static uint32_t count_idle_peers() {
    uint32_t count = 0;
    for (uint32_t i = 0; i < global.peerCount; i++) {
        Peer *ptrPeer = global.peers[i];
        if (is_peer_idle(ptrPeer)) {
            count++;
        }
    }
    return count;
}

void exchange_data_with_peers() {
    printf("Exchanging data with peers...\n");
    uint32_t idlePeers = count_idle_peers();
    SHA256_HASH *blocksDesired = CALLOC(idlePeers, SHA256_LENGTH, "exchange_data_with_peers:hashes");
    uint32_t blocksFound = find_missing_blocks(blocksDesired, idlePeers);
    uint32_t blockIndex = 0;
    for (uint32_t i = 0; i < global.peerCount; i++) {
        Peer *ptrPeer = global.peers[i];
        if (!ptrPeer) {
            continue;
        }
        else if (!peer_hand_shaken(ptrPeer)) {
            continue;
        }
        if (ptrPeer->chain_height > global.mainHeaderTip.context.height) {
            send_getheaders(&ptrPeer->socket);
        }
        Byte *blockToRequest = NULL;
        if (is_peer_idle(ptrPeer) && (blockIndex < blocksFound)) {
            blockToRequest = blocksDesired[blockIndex];
            blockIndex++;
            send_getdata_for_block(&ptrPeer->socket, blockToRequest);
        }
    }
    FREE(blocksDesired, "exchange_data_with_peers:hashes");
}

void print_node_status() {
    printf("\n==== Node status ====\n");

    printf("Peers: \n");
    uint16_t validPeers = 0;
    for (uint32_t i = 0; i < global.peerCount; i++) {
        Peer *ptrPeer = global.peers[i];
        if (peer_hand_shaken(ptrPeer)) {
            validPeers++;
            if (is_latency_fully_tested(ptrPeer)) {
                double averageLatency = average_peer_latency(ptrPeer);
                printf(
                    "Peer %02u: %7.1fms (%llu KB)\n",
                    ptrPeer->slot,
                    averageLatency,
                    ptrPeer->networking.incomingBytes / 1024
                );
            }
            else {
                printf("Peer %02u:     ?ms (%llu KB)\n", ptrPeer->slot, ptrPeer->networking.incomingBytes / 1024);
            }
        }
        else {
            printf("Peer %02u:     <>\n", ptrPeer->slot);
        }
    }
    printf("%u/%u valid peers, out of %u candidates\n", validPeers, global.peerCount, global.peerCandidateCount);

    printf("Header tip at height %u", global.mainHeaderTip.context.height);
    print_sha256_reverse(global.mainHeaderTip.meta.hash);
    printf("\n");
    printf("Validated tip at height %u", global.mainValidatedTip.context.height);
    print_sha256_reverse(global.mainValidatedTip.meta.hash);
    printf("\n");
    printf("=====================\n");
}

bool should_catchup() {
    uint32_t maxFullBlockHeight = max_full_block_height_from_genesis();
    uint32_t missingBlocks = global.mainHeaderTip.context.height - maxFullBlockHeight;
    return missingBlocks > config.catchupThreshold;
}

void reset_ibd_mode() {
    bool shouldIBD = should_catchup();
    if (shouldIBD && global.mode == MODE_NORMAL) {
        printf("\nSwitching on catchup mode\n");
        global.mode = MODE_CATCHUP;
    }
    if (!shouldIBD && global.mode == MODE_CATCHUP) {
        printf("\nSwitching off catchup mode\n");
        global.mode = MODE_NORMAL;
    }
}

void validate_blocks_timer_callback() {
    validate_blocks(config.tolerances.blockValidation);
}

typedef void TimerCallback(uv_timer_t *);

struct TimerTableRow {
    uint64_t interval;
    TimerCallback *callback;
    bool onlyOnce;
};

typedef struct TimerTableRow TimerTableRow;

void setup_timers() {
    TimerTableRow timerTableAutomatic[] = {
        {
            .interval = config.periods.peerDataExchange,
            .callback = &exchange_data_with_peers,
        },
        {
            .interval = config.periods.saveIndices,
            .callback = &save_chain_data,
        },
        {
            .interval = config.periods.autoexit,
            .callback = &initiate_termination,
            .onlyOnce = true,
        },
        {
            .interval = config.periods.terminationCheck,
            .callback = &termination_check,
        },
        {
            .interval = config.periods.resetIBDMode,
            .callback = &reset_ibd_mode,
        },
        {
            .interval = config.periods.timeoutPeers,
            .callback = &check_peers_connectivity,
        },
        {
            .interval = config.periods.ping,
            .callback = &ping_peers,
        },
        {
            .interval = config.periods.printNodeStatus,
            .callback = &print_node_status,
        },
        {
            .interval = config.periods.validateNewBlocks,
            .callback = &validate_blocks_timer_callback,
        }
    };
    uint32_t rowCount = sizeof(timerTableAutomatic) / sizeof(timerTableAutomatic[0]);

    TimerTableRow *timerTable = CALLOC(rowCount, sizeof(TimerTableRow), "setup_timers:timerTable");
    memcpy(timerTable, timerTableAutomatic, sizeof(timerTableAutomatic));
    for (uint32_t i = 0; i < rowCount; i++) {
        TimerTableRow *row = &timerTable[i];
        if (row->interval > 0 && row->callback) {
            uv_timer_t *timer = CALLOC(1, sizeof(*timer), "setup_timers:timer");
            global.timers[global.timerCount++] = timer;
            uv_timer_init(uv_default_loop(), timer);
            if (row->onlyOnce) {
                uv_timer_start(timer, row->callback, row->interval, 0);
            }
            else {
                uv_timer_start(timer, row->callback, 0, row->interval);
            }
        }
    }
    global.timerTable = timerTable;
}

void stop_timers() {
    printf("Stopping timers...\n");
    for (uint32_t i = 0; i < global.timerCount; i++) {
        uv_timer_t *timer = global.timers[i];
        if (!timer) {
            continue;
        }
        uv_timer_stop(global.timers[i]);
        // FREE(timer, "setup_timers:timer"); // TODO: release safely
    }
    // FREE(global.timerTable, "setup_timers:timerTable"); // TODO: release safely
}

uint32_t setup_main_event_loop() {
    printf("Setting up main event loop...");
    uv_loop_init(uv_default_loop());
    setup_timers();
    setup_api_socket();
    printf("Done.\n");
    return 0;
}

void send_getheaders(uv_tcp_t *socket) {
    uint32_t hashCount = 1;

    BlockRequestPayload payload = {
        .version = config.protocolVersion,
        .hashCount = hashCount,
        .hashStop = {0}
    };
    memcpy(&payload.blockLocatorHash[0], global.mainHeaderTip.meta.hash, SHA256_LENGTH);

    send_message(socket, CMD_GETHEADERS, &payload);
}

void send_getdata_for_block(uv_tcp_t *socket, Byte *hash) {
    GenericIVPayload payload = {
        .count = 1,
    };
    InventoryVector iv = {
        .type = IV_TYPE_MSG_BLOCK,
    };
    memcpy(iv.hash, hash, SHA256_LENGTH);
    payload.inventory[0] = iv;
    send_message(socket, CMD_GETDATA, &payload);
}

char *get_ip_from_context(void *data) {
    return convert_ipv4_readable(((SocketContext *)data)->peer->address.ip);
}

int32_t parse_buffer_into_message(uint8_t *ptrBuffer, Message *ptrMessage) {
    Header header = get_empty_header();
    parse_message_header(ptrBuffer, &header);
    char *command = (char *)header.command;
    if (strcmp(command, CMD_VERSION) == 0) {
        return parse_into_version_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_VERACK) == 0) {
        return parse_into_verack_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_INV) == 0) {
        return parse_into_inv_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_ADDR) == 0) {
        return parse_into_addr_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_REJECT) == 0) {
        return parse_into_reject_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_PING) == 0) {
        return parse_into_pingpong_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_PONG) == 0) {
        return parse_into_pingpong_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_HEADERS) == 0) {
        return parse_into_headers_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_BLOCK) == 0) {
        return parse_into_block_message(ptrBuffer, ptrMessage);
    }
    else if (strcmp(command, CMD_GETDATA) == 0) {
        return parse_into_blockreq_message(ptrBuffer, ptrMessage);
    }
    else {
        fprintf(stderr, "Cannot parse message with unknown command '%s'\n", command);
        return 1;
    }
}

void free_write_request(uv_write_t *writeRequest) {
    struct WriteContext *ptrContext = writeRequest->data;
    FREE(ptrContext->buf.base, "send_message:buffer");
    FREE(ptrContext, "write_buffer_to_socket:WriteContext");
    FREE(writeRequest, "write_buffer_to_socket:WriteRequest");
}

void on_message_attempted(uv_write_t *writeRequest, int status) {
    struct WriteContext *ptrContext = writeRequest->data;

    char *ipString = get_ip_from_context(ptrContext);
    if (status) {
        fprintf(stderr, "failed to send message to %s: %s \n", ipString, uv_strerror(status));
        goto cleanup;
    }
    else {
        Message msg = get_empty_message();
        int32_t error = parse_buffer_into_message((Byte *)ptrContext->buf.base, &msg);
        if (error) {
            #if LOG_MESSAGE_SENT
            printf("unknown message sent to %s\n", msg.header.command);
            #endif
        }
        else {
            #if LOG_MESSAGE_SENT
            printf("%s message sent to %s\n", msg.header.command, ipString);
            #endif
            if (strcmp((char *)msg.header.command, CMD_PING) == 0) {
                double now = get_now();
                ptrContext->peer->networking.ping.pingSent = now;
            }
            else if (strcmp((char *)msg.header.command, CMD_VERSION) == 0) {
                double now = get_now();
                ptrContext->peer->handshake.handshakeStart = now;
            }
        }
        if (msg.ptrPayload) {
            free_message_payload(&msg);
            msg.ptrPayload = NULL;
        }
    }
    cleanup:
    free_write_request(writeRequest);
}

void write_buffer_to_socket(
    uv_buf_t *ptrUvBuffer,
    uv_tcp_t *socket
) {
    SocketContext *ptrSocketContext = socket->data;
    struct WriteContext *ptrWriteContext = CALLOC(1, sizeof(*ptrWriteContext), "write_buffer_to_socket:WriteContext");
    ptrWriteContext->peer = ptrSocketContext->peer;
    ptrWriteContext->buf = *ptrUvBuffer;
    uv_write_t *ptrWriteReq = CALLOC(1, sizeof(uv_write_t), "write_buffer_to_socket:WriteRequest");
    uint8_t bufferCount = 1;
    ptrWriteReq->data = ptrWriteContext;
    int32_t writeError = uv_write(ptrWriteReq, (uv_stream_t *)socket, ptrUvBuffer, bufferCount, &on_message_attempted);
    if (writeError) {
        fprintf(stderr, "uv_write failed with %s(%i)\n", uv_strerror(writeError), writeError);
        free_write_request(ptrWriteReq);
    }
}

void send_message(uv_tcp_t *socket, char *command, void *ptrData) {
    Message message = get_empty_message();
    SocketContext *ptrContext = (SocketContext *)socket->data;
    Byte *buffer = MALLOC(MESSAGE_BUFFER_LENGTH, "send_message:buffer");
    uv_buf_t uvBuffer = uv_buf_init((char *)buffer, sizeof(buffer));
    uvBuffer.base = (char *)buffer;

    uint64_t dataSize = 0;

    if (strcmp(command, CMD_VERSION) == 0) {
        make_version_message(&message, ptrContext->peer);
        dataSize = serialize_version_message(&message, buffer);
    }
    else if (strcmp(command, CMD_VERACK) == 0) {
        make_verack_message(&message);
        dataSize = serialize_verack_message(&message, buffer);
    }
    else if (strcmp(command, CMD_GETADDR) == 0) {
        make_getaddr_message(&message);
        dataSize = serialize_getaddr_message(&message, buffer);
    }
    else if (strcmp(command, CMD_GETDATA) == 0) {
        GenericIVPayload *ptrPayload = ptrData;
        make_iv_message(
            &message,
            ptrPayload,
            (Byte *)CMD_GETDATA,
            sizeof(CMD_GETDATA)
        );
        dataSize = serialize_iv_message(&message, buffer);
    }
    else if (strcmp(command, CMD_GETHEADERS) == 0) {
        BlockRequestPayload *ptrPayload = ptrData;
        make_blockreq_message(&message, ptrPayload, CMD_GETHEADERS, sizeof(CMD_GETHEADERS));
        dataSize = serialize_blockreq_message(&message, buffer);
    }
    else if (strcmp(command, CMD_GETBLOCKS) == 0) {
        BlockRequestPayload *ptrPayload = ptrData;
        make_blockreq_message(&message, ptrPayload, CMD_GETBLOCKS, sizeof(CMD_GETBLOCKS));
        dataSize = serialize_blockreq_message(&message, buffer);
    }
    else if (strcmp(command, CMD_SENDHEADERS) == 0) {
        make_sendheaders_message(&message);
        dataSize = serialize_sendheaders_message(&message, buffer);
    }
    else if (strcmp(command, CMD_PING) == 0) {
        PingpongPayload *ptrPayload = ptrData;
        make_ping_message(&message, ptrPayload);
        dataSize = serialize_pingpong_message(&message, buffer);
    }
    else if (strcmp(command, CMD_PONG) == 0) {
        PingpongPayload *ptrPayload = ptrData;
        make_pong_message(&message, ptrPayload);
        dataSize = serialize_pingpong_message(&message, buffer);
    }
    else if (strcmp(command, XCMD_BINARY) == 0) {
        struct VariableLengthString *ptrPayload = ptrData;
        dataSize = ptrPayload->length;
        memcpy(buffer, ptrPayload->string, dataSize);
    }
    else {
        fprintf(stderr, "send_message: Cannot recognize command %s", command);
        goto release_resources;
    }
    uvBuffer.len = dataSize;

    char *ipString = get_ip_from_context(socket->data);
    if (strcmp(command, XCMD_BINARY) == 0) {
        printf("Sending binary to peer %s\n", ipString);
        print_object((Byte *)uvBuffer.base, uvBuffer.len);
    }
    else {
        #if LOG_MESSAGE_SENDING
        printf(
            "Sending message %s to peer %s\n",
            message.header.command,
            ipString
        );
        #endif
    }
    write_buffer_to_socket(&uvBuffer, socket);
    release_resources:
    free_message_payload(&message);
}

void on_handshake_success(Peer *ptrPeer) {
    if (global.mode == MODE_CATCHUP) {
        uint32_t maxFullBlockHeight = max_full_block_height_from_genesis();
        if (ptrPeer->chain_height < maxFullBlockHeight) {
            printf("Switching peer for lack of blocks\n");
            replace_peer(ptrPeer);
            return;
        }
    }
    bool shouldSendGetaddr = global.peerCandidateCount < config.getaddrThreshold;
    if (shouldSendGetaddr) {
        send_message(&ptrPeer->socket, CMD_GETADDR, NULL);
    }
    ping_peer(ptrPeer);
}

bool should_skip_print(char *command) {
    return strstr(config.silentIncomingMessageCommands, command) != NULL;
}

void handle_incoming_message(Peer *ptrPeer, Message message) {
    if (!should_skip_print((char *)message.header.command)) {
        print_message(&message);
    }
    double now = get_now();
    uint32_t timestamp = (uint32_t) round(now / SECOND_TO_MILLISECOND(1));
    ptrPeer->candidacy->addr.timestamp = timestamp;

    char *command = (char *)message.header.command;

    if (strcmp(command, CMD_VERSION) == 0) {
        VersionPayload *ptrPayloadTyped = message.ptrPayload;
        if (ptrPayloadTyped->version >= mainnet.minimalPeerVersion) {
            ptrPeer->handshake.acceptThem = true;
        }
        ptrPeer->chain_height = ptrPayloadTyped->start_height;
        ptrPeer->candidacy->addr.net_addr.services = ptrPayloadTyped->services;
        if (peer_hand_shaken(ptrPeer)) {
            on_handshake_success(ptrPeer);
        }
    }
    else if (strcmp(command, CMD_VERACK) == 0) {
        ptrPeer->handshake.acceptUs = true;
        send_message(&ptrPeer->socket, CMD_VERACK, NULL);
        if (peer_hand_shaken(ptrPeer)) {
            on_handshake_success(ptrPeer);
        }
    }
    else if (strcmp(command, CMD_ADDR) == 0) {
        AddrPayload *ptrPayload = message.ptrPayload;
        uint64_t skipped = 0;
        for (uint64_t i = 0; i < ptrPayload->count; i++) {
            struct AddrRecord *record = &ptrPayload->addr_list[i];
            if (is_ipv4(record->net_addr.ip)) {
                uint32_t timestampForRecord = record->timestamp - HOUR_TO_SECOND(2);
                add_address_as_candidate(record->net_addr, timestampForRecord);
            }
            else {
                skipped++;
            }
        }
    }
    else if (strcmp(command, CMD_PING) == 0) {
        send_message(&ptrPeer->socket, CMD_PONG, message.ptrPayload);
    }
    else if (strcmp(command, CMD_PONG) == 0) {
        PingpongPayload *ptrPayload = message.ptrPayload;
        if (ptrPayload->nonce == ptrPeer->networking.ping.nonce) {
            ptrPeer->networking.ping.pongReceived = now;
            double ping = ptrPeer->networking.ping.pingSent;
            double latency = now - ping;
            record_latency(ptrPeer, latency);
            bool latencyFullyTested = is_latency_fully_tested(ptrPeer);
            if (latencyFullyTested) {
                double averageLatency = average_peer_latency(ptrPeer);
                ptrPeer->candidacy->averageLatency = averageLatency;
            }
        }
        else {
            printf(
                "Unexpected pong nonce: received %llu, expecting %llu\n",
                ptrPayload->nonce, ptrPeer->networking.ping.nonce
            );
        }
    }
    else if (strcmp(command, CMD_HEADERS) == 0) {
        HeadersPayload *ptrPayload = message.ptrPayload;
        for (uint64_t i = 0; i < ptrPayload->count; i++) {
            BlockPayloadHeader *ptrHeader = &ptrPayload->headers[i].header;
            int8_t status = process_incoming_block_header(ptrHeader);
            if (status && status != HEADER_EXISTED) {
                printf("new header status %i\n", status);
            }
        }
    }
    else if (strcmp(command, CMD_BLOCK) == 0) {
        BlockPayload *ptrBlock = message.ptrPayload;
        process_incoming_block(ptrBlock, false);
        memset(ptrPeer->networking.requesting, 0, SHA256_LENGTH);
    }
    else if (strcmp(command, CMD_INV) == 0) {
        // send_message(ptrPeer->connection, CMD_GETDATA, message.ptrPayload);
    }
    free_message_payload(&message);
}

bool checksum_match(Byte *ptrBuffer) {
    Header messageHeader;
    parse_message_header(ptrBuffer, &messageHeader);
    PayloadChecksum checksum = {0};
    calculate_data_checksum(ptrBuffer + sizeof(messageHeader), messageHeader.length, checksum);
    return memcmp(checksum, messageHeader.checksum, CHECKSUM_SIZE) == 0;
}

int64_t find_first_magic(Byte *data, uint64_t maxLength) {
    Byte *p = data;
    while ((p - data + sizeof(mainnet.magic)) < maxLength) {
        if (starts_with_magic(p)) {
            return (int64_t)(p - data);
        }
        p++;
    }
    return -1;
}

void extract_message_from_stream_buffer(MessageCache *ptrCache, Peer *ptrPeer) {
    int64_t magicOffset = find_first_magic(ptrCache->buffer, ptrCache->bufferIndex);
    while (magicOffset >= 0) {
        if (magicOffset != 0) {
            memcpy(ptrCache->buffer, ptrCache->buffer + magicOffset, ptrCache->bufferIndex - magicOffset);
            ptrCache->bufferIndex -= magicOffset;
            printf("Trimmed preceding %llu non-magic bytes", magicOffset);
        }
        Header header = get_empty_header();
        parse_message_header(ptrCache->buffer, &header);
        uint64_t messageSize = sizeof(Header) + header.length;
        #if LOG_MESSAGE_LOADING
        printf("Message loading from %s: (%llu/%llu)\n",
                   convert_ipv4_readable(ptrPeer->address.ip),
                   ptrCache->bufferIndex,
                   messageSize
            );
        #endif
        if (ptrCache->bufferIndex >= messageSize) {
            Message message = get_empty_message();
            if (!checksum_match(ptrCache->buffer)) {
                printf("Payload checksum mismatch");
                print_message_header(header);
            }
            else {
                int32_t error = parse_buffer_into_message(ptrCache->buffer, &message);
                if (error) {
                    free_message_payload(&message);
                }
                else {
                    handle_incoming_message(ptrPeer, message);
                }
            }
            memcpy(ptrCache->buffer, ptrCache->buffer + messageSize, ptrCache->bufferIndex - messageSize);
            ptrCache->bufferIndex -= messageSize;
            magicOffset = find_first_magic(ptrCache->buffer, ptrCache->bufferIndex);
        }
        else {
            break;
        }
    }
}

void on_incoming_segment(uv_stream_t *socket, ssize_t nread, const uv_buf_t *buf) {
    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error %s\n", uv_err_name((int)nread));
            uv_close((uv_handle_t*) socket, NULL);
        }
        else {
            // file ended; noop
        }
        goto cleanup;
    }
    SocketContext *ptrContext = (SocketContext *)socket->data;
    ptrContext->peer->networking.lastHeard = get_now();
    MessageCache *ptrCache = &(ptrContext->streamCache);
    memcpy(ptrCache->buffer + ptrCache->bufferIndex, buf->base, buf->len);
    ptrCache->bufferIndex += nread;
    ptrContext->peer->networking.incomingBytes += nread;
    extract_message_from_stream_buffer(ptrCache, ptrContext->peer);
    cleanup:
    FREE(buf->base, "allocate_read_buffer:bufBase");
}

void allocate_read_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    if (!handle) {
        // Make it used
    }
    buf->base = MALLOC(suggested_size, "allocate_read_buffer:bufBase");
    buf->len = suggested_size;
}

uv_connect_t *create_connect_request(Peer *ptrPeer) {
    ConnectContext *ptrContext = CALLOC(1, sizeof(*ptrContext), "create_connect_request:ConnectContext");
    ptrContext->peer = ptrPeer;
    uv_connect_t *ptrConnectRequest = CALLOC(1, sizeof(uv_connect_t), "create_connect_request:ConnectRequest");
    ptrConnectRequest->data = ptrContext;
    return ptrConnectRequest;
}

void free_connect_request(uv_connect_t *connectRequest) {
    if (!connectRequest) {
        return;
    }
    FREE(connectRequest, "create_connect_request:ConnectRequest");
    FREE(connectRequest->data, "create_connect_request:ConnectContext");
}

void on_peer_connect(uv_connect_t* connectionRequest, int32_t error) {
    ConnectContext *ptrContext = (ConnectContext *)connectionRequest->data;
    char *ipString = convert_ipv4_readable(ptrContext->peer->address.ip);
    if (error) {
        fprintf(
            stderr,
            "connection failed with peer %s: %s(%i) \n",
            ipString,
            uv_strerror(error),
            error
        );
        if (ptrContext->peer->relationship == PEER_RELATIONSHIP_OUR_SERVER) {
            disable_candidate(ptrContext->peer->candidacy);
            replace_peer(ptrContext->peer);
        }
    }
    else {
        printf("connected with peer %s \n", ipString);
        send_message((uv_tcp_t *)connectionRequest->handle, CMD_VERSION, NULL);
        int32_t readError = uv_read_start(connectionRequest->handle, allocate_read_buffer, on_incoming_segment);
        if (readError) {
            fprintf(stderr, "uv_read failed %s(%i)", uv_strerror(readError), readError);
        }
    }
    free_connect_request(connectionRequest);
}

void release_socket_context(uv_handle_t *socket) {
    SocketContext *data = (SocketContext *)socket->data;
    if (data) {
        if (data->peer) {
            FREE(data->peer, "Peer");
            data->peer = NULL;
        }
        FREE(data, "SocketContext");
    }
}

void on_socket_closed(uv_handle_t *socket) {
    release_socket_context(socket);
}

void release_peer(Peer *ptrPeer) {
    if (!ptrPeer) {
        return;
    }
    uv_handle_t *socket = (uv_handle_t *) &ptrPeer->socket;
    if (uv_is_closing(socket)) {
        fprintf(stderr, "release_peer: Socket is already closing...\n");
        uv_tcp_t *backupSocket = MALLOC(sizeof(*backupSocket), "release_peer:zombieSocket");
        memcpy(backupSocket, socket, sizeof(*socket));
        global.zombieSockets[global.zombineSocketCount] = backupSocket;
        global.zombineSocketCount = (global.zombineSocketCount + 1) % MAX_ZOMBIE_SOCKETS;
        // release_socket_context(socket); // TODO: Release safely
    }
    else {
        uv_close(socket, on_socket_closed);
    }
}

Peer *create_peer(PeerCandidate* ptrCandidate) {
    Peer *ptrPeer = CALLOC(1, sizeof(Peer), "Peer");
    double now = get_now();
    ptrPeer->connectionStart = now;
    ptrPeer->handshake.handshakeStart = now; // to be updated in on_message_attempted
    memcpy(ptrPeer->address.ip, ptrCandidate->addr.net_addr.ip, sizeof(IP));
    ptrPeer->candidacy = ptrCandidate;

    SocketContext *socketContext = CALLOC(1, sizeof(SocketContext), "SocketContext");
    socketContext->peer = ptrPeer;

    ptrPeer->socket.data = socketContext;

    uv_tcp_init(uv_default_loop(), &ptrPeer->socket);
    return ptrPeer;
}

Peer *swap_slot_with_candidate(uint32_t slot, PeerCandidate *ptrCandidate) {
    Peer *ptrOldPeer = global.peers[slot];
    Peer *ptrNewPeer = create_peer(ptrCandidate);
    ptrNewPeer->slot = slot;
    global.peers[ptrNewPeer->slot] = ptrNewPeer;
    release_peer(ptrOldPeer);
    return ptrNewPeer;
}

int32_t connect_peer_candidate(PeerCandidate *ptrCandidate, uint32_t peerSlot)  {
    NetworkAddress *netAddr = &ptrCandidate->addr.net_addr;
    printf("Initializing peer %u with IP %s \n", peerSlot, convert_ipv4_readable(netAddr->ip));

    Peer *ptrPeer = swap_slot_with_candidate(peerSlot, ptrCandidate);

    uv_connect_t *ptrConnectRequest = create_connect_request(ptrPeer);

    // Connection request
    struct sockaddr_in remoteAddress;
    uv_ip4_addr(convert_ipv4_readable(netAddr->ip), htons(netAddr->port), &remoteAddress);
    int32_t connectError = uv_tcp_connect(
        ptrConnectRequest,
        &ptrPeer->socket,
        (const struct sockaddr*)&remoteAddress,
        &on_peer_connect
    );
    if (connectError) {
        fprintf(stderr, "uv_tcp_connect: failed with %s(%i)\n", uv_strerror(connectError), connectError);
        free_connect_request(ptrConnectRequest);
        return connectError;
    }
    return 0;
}

void on_incoming_segment_to_api(uv_stream_t *socket, ssize_t nread, const uv_buf_t *buf) {
    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error %s\n", uv_err_name((int)nread));
            uv_close((uv_handle_t*) socket, NULL);
        }
        else {
            // file ended; noop
        }
        return;
    }
    printf("\nIncoming segment to API socket\n");
    if (memcmp(buf->base, INSTRUCTION_KILL, strlen(INSTRUCTION_KILL)) == 0) {
        initiate_termination();
    }
    FREE(buf->base, "allocate_read_buffer:bufBase");
}


void on_incoming_api_connection(uv_stream_t *server, int status) {
    printf("Incoming api connection...\n");
    if (status < 0) {
        fprintf(stderr, "New connection error %s\n", uv_strerror(status));
        return;
    }

    uv_tcp_t *client = MALLOC(sizeof(uv_tcp_t), "on_incoming_api_connection: client");
    uv_tcp_init(uv_default_loop(), client);
    if (uv_accept(server, (uv_stream_t*) client) == 0) {
        printf("Accepted\n");
        uv_read_start((uv_stream_t *) client, allocate_read_buffer, on_incoming_segment_to_api);
    } else {
        printf("Cannot accept\n");
        uv_close((uv_handle_t*) client, NULL);
    }
}

int32_t setup_api_socket() {
    printf("Setting up api socket...\n");
    struct sockaddr_in localAddress;
    uv_ip4_addr("0.0.0.0", config.apiPort, &localAddress);
    uv_tcp_init(uv_default_loop(), &global.apiSocket);
    uv_tcp_bind(&global.apiSocket, (const struct sockaddr*) &localAddress, 0);
    int32_t listenError = uv_listen(
        (uv_stream_t *) &global.apiSocket,
        config.backlog,
        on_incoming_api_connection
    );
    if (listenError) {
        fprintf(stderr, "Listen error %s\n", uv_strerror(listenError));
        return 1;
    }
    printf("Done\n");
    return 0;
}

static PeerCandidate *pick_random_addr() {
    uint32_t index = random_range(0, global.peerCandidateCount - 1);
    return &global.peerCandidates[index];
}

static PeerCandidate *pick_random_nonpeer_candidate() {
    PeerCandidate *ptrCandidate;
    do {
        ptrCandidate = pick_random_addr();
    } while (is_peer(ptrCandidate));
    return ptrCandidate;
}

static double rate_candidate(PeerCandidate *ptrCandidate) {
    double now = get_now();

    double statusScore;
    if (ptrCandidate->status == PEER_CANDIDATE_STATUS_DISABLED) {
        statusScore = -10;
    }
    else {
        statusScore = 0;
    }
    double timestampScore = 0;
    double deltaT = now - SECOND_TO_MILLISECOND(ptrCandidate->addr.timestamp * 1.0);
    // Prefer recent candidates, but not those connected in last 24 hours
    if (deltaT > DAY_TO_MILLISECOND(7)) {
        timestampScore = 0.8;
    }
    else if (deltaT > DAY_TO_MILLISECOND(1)) {
        timestampScore = 1.0;
    }
    else {
        timestampScore = 0.5;
    }

    double latencyScore = 0;
    if (ptrCandidate->averageLatency) {
        latencyScore = config.tolerances.latency / ptrCandidate->averageLatency;
    }
    else {
        latencyScore = 1;
    }
    double shuffleScore = random_betwen_0_1() * 2;
    double score = statusScore + timestampScore + latencyScore + shuffleScore;
    return score;
}

static PeerCandidate *pick_best_nonpeer_candidate(double *finalScore) {
    PeerCandidate *ptrBestCandidate = &global.peerCandidates[0];
    double bestScore = rate_candidate(ptrBestCandidate);
    for (uint32_t i = 0; i < global.peerCandidateCount; i++) {
        PeerCandidate *ptrCandidate = &global.peerCandidates[i];
        if (is_peer(ptrCandidate)) {
            continue;
        }
        double score = rate_candidate(ptrCandidate);
        if (score > bestScore) {
            ptrBestCandidate = ptrCandidate;
            bestScore = score;
        }
    }
    if (finalScore) {
        *finalScore = bestScore;
    }
    return ptrBestCandidate;
}

void connect_to_best_candidate_as_peer(uint32_t peerIndex) {
    double score = 0;
    PeerCandidate *ptrCandidate = pick_best_nonpeer_candidate(&score);
    connect_peer_candidate(ptrCandidate, peerIndex);
}

int32_t connect_to_initial_peers() {
    uint32_t outgoingConfig = global.mode == MODE_CATCHUP ? config.maxOutgoingIBD : config.maxOutgoing;
    uint32_t outgoing = min(outgoingConfig, global.peerCandidateCount);
    for (uint32_t i = 0; i < outgoing; i++) {
        connect_to_best_candidate_as_peer(i);
        global.peerCount += 1;
    }
    return 0;
}

void terminate_peers() {
    printf("Terminating peers...\n");
    for (uint32_t slot = 0; slot < global.peerCount; slot++) {
        struct Peer *peer = global.peers[slot];
        global.peers[slot] = NULL;
        release_peer(peer);
    }
    printf("Done.\n");
}

bool are_all_peers_terminated() {
    bool result = true;
    for (uint64_t i = 0; i < global.peerCount; i++) {
        if (global.peers[i]) {
            result = false;
        }
    }
    return result;
}

void check_to_cleanup() {
    if (are_all_peers_terminated()) {
        printf("\nCleaning up\n");
        uv_stop(uv_default_loop());
        uv_loop_close(uv_default_loop());
        printf("\nGood byte!\n");
    }
    else {
        printf("\nStill terminating peers...\n");
        terminate_peers();
    }
}

void terminate_execution() {
    if (global.terminating) {
        return;
    }
    global.terminating = true;
    save_chain_data();
    if (global.mode == MODE_NORMAL || global.mode == MODE_CATCHUP) {
        stop_timers();
        terminate_peers();
    }
    cleanup_db();
    if (global.mode == MODE_NORMAL || global.mode == MODE_CATCHUP) {
        uv_timer_t *timer = CALLOC(1, sizeof(*timer), "terminate_execution:timer");
        uv_timer_init(uv_default_loop(), timer);
        uv_timer_start(timer, check_to_cleanup, 0, 500);
    }
}

void initiate_termination() {
    printf("Issued termination command\n");
    global.shouldTerminate = true;
}

void termination_check() {
    if (global.shouldTerminate) {
        terminate_execution();
    }
}
