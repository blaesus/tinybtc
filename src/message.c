#include <string.h>
#include <time.h>
#include "message.h"

int serializeVersionPayload(struct VersionPayload payload, uint8_t *data) {
    uint32_t length = 0;
    return 0;
}

int serialize_version_message(struct Message *message, uint8_t *data) {
    uint8_t *p;
    p = data;
    memcpy(p, &message->magic, sizeof(message->magic));
    p += sizeof(message->magic);
    memcpy(p, &message->command, sizeof(message->command));
    p += sizeof(message->command);
    memcpy(p, &message->payload, sizeof(message->payload));
    p += sizeof(message->payload);
    return sizeof(message->payload);
}
