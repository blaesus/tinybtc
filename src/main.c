//
// Created by Andy Shu on 30/7/2018.
//

#include "Block.h"
#include "constants.h"

int main() {
    BlockHeader header = { 0 };

    Block block = {
            .magic_number = MAGIC_NUMBER,
            .block_size = 1,
            .header = header,
    };
    return 0;
}
