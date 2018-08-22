#include <stdint.h>
#include "string.h"
#include "stdio.h"

#include "messages/shared.h"
#include "messages/version.h"
#include "messages/verack.h"
#include "messages/inv.h"
#include "messages/addr.h"
#include "messages/reject.h"
#include "messages/pingpong.h"
#include "messages/headers.h"

void print_message(
    Message *ptrMessage
) {
    char *command = (char *)ptrMessage->header.command;
    printf("\n>=========  Incoming %s ===========", command);
    if (strcmp(command, CMD_VERSION) == 0) {
        print_version_message(ptrMessage);
    }
    else if (strcmp(command, CMD_VERACK) == 0) {
        print_verack_message(ptrMessage);
    }
    else if (strcmp(command, CMD_INV) == 0) {
        print_inv_message(ptrMessage);
    }
    else if (strcmp(command, CMD_ADDR) == 0) {
        print_addr_message(ptrMessage);
    }
    else if (strcmp(command, CMD_REJECT) == 0) {
        print_reject_message(ptrMessage);
    }
    else if (strcmp(command, CMD_PING) == 0) {
        print_pingpong_message(ptrMessage);
    }
    else if (strcmp(command, CMD_PONG) == 0) {
        print_pingpong_message(ptrMessage);
    }
    else if (strcmp(command, CMD_HEADERS) == 0) {
        print_headers_message(ptrMessage);
    }
    else {
        fprintf(stderr, "Cannot print payload of unspecified COMMAND %s\n", command);
    }
    printf("=======================================<\n");
}
