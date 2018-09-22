#include <stdint.h>
#include <stdlib.h>
#include "utils/random.h"
#include "utils/integers.h"

void random_bytes(uint32_t count, uint8_t *data) {
    for (uint32_t i = 0; i < count; i++) {
        data[i] = (uint8_t)(rand() & 0xFF);
    }
}

uint64_t random_uint64() {
    uint8_t nonceBytes[8] = {0};
    random_bytes(8, nonceBytes);
    return combine_uint64(nonceBytes);
}

// borders inclusive
uint32_t random_range(uint32_t lower, uint32_t upper) {
    return lower + (rand() % (upper - lower + 1));
}

double random_betwen_0_1() {
    return (double)rand() / (double)RAND_MAX ;
}

