#include <stdint.h>
#include "datatypes.h"
#include "utils/integers.h"

void segment_uint32(uint32_t number, uint8_t *chars) {
    chars[0] = (uint8_t)(number & 0xFF);
    chars[1] = (uint8_t)((number >> 1 * BITS_IN_BYTE) & 0xFF);
    chars[2] = (uint8_t)((number >> 2 * BITS_IN_BYTE) & 0xFF);
    chars[3] = (uint8_t)((number >> 3 * BITS_IN_BYTE) & 0xFF);
}

uint16_t combine_uint16(const uint8_t *chars) {
    uint16_t number = + (chars[1] << 1 * BITS_IN_BYTE)
                      + (chars[0]);
    return number;
}

uint32_t combine_uint32(const uint8_t *chars) {
    uint32_t number = (chars[3] << 3 * BITS_IN_BYTE)
                      + (chars[2] << 2 * BITS_IN_BYTE)
                      + (chars[1] << 1 * BITS_IN_BYTE)
                      + (chars[0]);
    return number;
}

uint64_t combine_uint64(const uint8_t *chars) {
    uint64_t number =
        + (chars[7] * 1ULL << 7 * BITS_IN_BYTE) // Enforce width
        + (chars[6] * 1ULL << 6 * BITS_IN_BYTE)
        + (chars[5] * 1ULL << 5 * BITS_IN_BYTE)
        + (chars[4] * 1ULL << 4 * BITS_IN_BYTE)
        + (chars[3] << 3 * BITS_IN_BYTE)
        + (chars[2] << 2 * BITS_IN_BYTE)
        + (chars[1] << 1 * BITS_IN_BYTE)
        + (chars[0]);
    return number;
}

uint32_t min(uint32_t a, uint32_t b) {
    if (a <= b) {
        return a;
    }
    return b;
}

