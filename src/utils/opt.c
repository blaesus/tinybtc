#include <getopt.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "opt.h"
#include "globalstate.h"
#include "utils/memory.h"
#include "utils/data.h"

void handle_options(int32_t argc, char **argv) {
    int32_t optionIndex = 0;
    struct option options[] = {
        {"revalidate", required_argument, 0, 'r'},
        {"test", no_argument, 0, 't'},
        {NULL, 0, NULL, 0}
    };
    int32_t optionChar;
    while (true) {
        optionChar = getopt_long_only(argc, argv, "o:r:t", options, &optionIndex);
        if (optionChar == -1) {
            break;
        }
        switch (optionChar) {
            case 'r': {
                int32_t *count = CALLOC(1, sizeof(*count), "handle_options:modeData");
                *count = atoi(optarg);
                global.mode = MODE_VALIDATE;
                global.modeData = count;
                break;
            }
            case 'o': {
                Byte *hash = CALLOC(1, SHA256_LENGTH, "handle_options:modeData");
                sha256_hex_to_binary(optarg, hash);
                reverse_endian(hash, SHA256_LENGTH);
                global.mode = MODE_VALIDATE_ONE;
                global.modeData = hash;
                break;
            }
            case 't': {
                global.mode = MODE_TEST;
                break;
            }
            default: {
            }
        }
    }
}

