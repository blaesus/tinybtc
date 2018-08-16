#include <stdint.h>
#include "string.h"
#include "stdio.h"

#include "messages/shared.h"
#include "messages/version.h"
#include "messages/verack.h"
#include "messages/inv.h"

void print_message(
    Message *ptrMessage
) {
    printf("\n>=========  Incoming  ===========");
    char *command = (char *)ptrMessage->header.command;
    if (strcmp(command, CMD_VERSION) == 0) {
        print_version_message(ptrMessage);
    }
    else if (strcmp(command, CMD_VERACK) == 0) {
        print_verack_message(ptrMessage);
    }
    else if (strcmp(command, CMD_INV) == 0) {
        print_inv_message(ptrMessage);
    }
    else {
        fprintf(stderr, "Cannot print payload for COMMAND %s\n", command);
    }
    printf("================================<\n");
}
