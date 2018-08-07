#include <stdlib.h>
#include <stdio.h>

#include "util.h"
#include "datatypes.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

int segment_int32(uint32_t number, uint8_t chars[4]) {
    chars[0] = (uint8_t)(number & 0xFF);
    chars[1] = (uint8_t)((number >> 1 * BITS_IN_BYTE) & 0xFF);
    chars[2] = (uint8_t)((number >> 2 * BITS_IN_BYTE) & 0xFF);
    chars[3] = (uint8_t)((number >> 3 * BITS_IN_BYTE) & 0xFF);
    return 0;
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

uint32_t count_string_length(char *s) {
    uint32_t i;
    for (i = 0; s[i] != '\0'; i++);
    return i+1;
}

void swap(char *a, char *b) {
    char temp = *b;
    *b = *a;
    *a = temp;
}

void reverse_string(char *s) {
    uint32_t length = count_string_length(s);
    for (uint32_t i = 0; i < length / 2; i++) {
        swap(&s[i], &s[length - i - 2]);
    }
}

int32_t uint_to_str(uint32_t data, char *output) {
    uint32_t i;
    for (i = 0; data > 0; i++) {
        uint32_t digit = data % 10;
        output[i] = (char)(digit + '0');
        data /= 10;
    }
    output[i] = '\0';
    reverse_string(output);
    return 0;
}

void randomBytes(uint32_t count, uint8_t *data) {
    for (uint32_t i = 0; i < count; i++) {
        data[i] = (uint8_t)(rand() & 0xFF);
    }
}

void printUint64(uint64_t input) {
    printf("%"PRIu64"\n", input);
}

void printObjectWithLength(uint8_t *ptrData, uint64_t length) {
    uint32_t index;
    uint8_t character = 0;
    for (index = 0; index < length; index++) {
        character = (uint8_t)(*ptrData & 0xFF);
        if (index % 16 == 0) {
            printf("\n%03x0 - ", index / 16);
        }
        printf("%02x ", character);
        ptrData++;
    }
}
