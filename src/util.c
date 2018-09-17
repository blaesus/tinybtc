#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/time.h>

#include "util.h"
#include "datatypes.h"
#include "globalstate.h"

int segment_uint32(uint32_t number, uint8_t *chars) {
    chars[0] = (uint8_t)(number & 0xFF);
    chars[1] = (uint8_t)((number >> 1 * BITS_IN_BYTE) & 0xFF);
    chars[2] = (uint8_t)((number >> 2 * BITS_IN_BYTE) & 0xFF);
    chars[3] = (uint8_t)((number >> 3 * BITS_IN_BYTE) & 0xFF);
    return 0;
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

uint32_t count_string_length(const char *s) {
    uint32_t i;
    for (i = 0; s[i] != '\0'; i++);
    return i+1;
}

void swap_char(char *a, char *b) {
    char temp = *b;
    *b = *a;
    *a = temp;
}

void reverse_string(char *s) {
    uint32_t length = count_string_length(s);
    for (uint32_t i = 0; i < length / 2; i++) {
        swap_char(&s[i], &s[length - i - 2]);
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
uint32_t random_range(
    uint32_t lower,
    uint32_t upper
) {
    return lower + (rand() % (upper - lower + 1));
}

double random_betwen_0_1() {
    return (double)rand() / (double)RAND_MAX ;
}

void printUint64(uint64_t input) {
    printf("%"PRIu64"\n", input);
}

void print_object(void *ptrData, uint64_t length) {
    uint64_t index;
    uint8_t character = 0;
    Byte *p = ptrData;
    for (index = 0; index < length; index++) {
        character = (uint8_t)(*p & 0xFF);
        if (index % 16 == 0) {
            printf("\n%03llx0 - ", index / 16);
        }
        printf("%02x ", character);
        p++;
    }
    printf("END \n");
}

uint32_t min(uint32_t a, uint32_t b) {
    if (a <= b) {
        return a;
    }
    return b;
}

bool ips_equal(IP ipA, IP ipB) {
    return memcmp(ipA, ipB, sizeof(IP)) == 0;
}

int64_t getFileSize(FILE *file) {
    fseek(file, 0L, SEEK_END);
    int64_t filesize = ftell(file);
    fseek(file, 0L, SEEK_SET);
    return filesize;
}

void reverse_endian(Byte *data, uint32_t width) {
    for (uint32_t i = 0; i < width / 2; i++) {
        Byte temp = data[i];
        data[i] = data[width - i - 1];
        data[width - i - 1] = temp;
    }
}

int8_t bytescmp(
    const Byte *bytesA,
    const Byte *bytesB,
    uint32_t width
) {
    for (uint32_t i = width - 1; i > 0; i--) {
        if (bytesA[i] < bytesB[i]) {
            return -1;
        }
        if (bytesA[i] > bytesB[i]) {
            return 1;
        }
    }
    return 0;
}

char *date_string(time_t time) {
    static char text[100];
    struct tm *timeInfo = localtime(&time);
    strftime(text, sizeof(text)-1, "%Y-%m-%d %H:%M:%S", timeInfo);
    return text;
}

bool is_byte_array_empty(const Byte *hash, uint64_t length) {
    for (uint64_t i = 0; i < length; i++) {
        if (hash[i]) {
            return false;
        }
    }
    return true;
}

double timeval_to_double_ms(struct timeval time) {
    return 1.0 * time.tv_sec * 1000 + 1.0 * time.tv_usec / 1000;
}

double get_now() {
    struct timeval nowTimeval;
    gettimeofday(&nowTimeval, NULL);
    return timeval_to_double_ms(nowTimeval);
}

void *malloc_audited(size_t size, char* label) {
    printf("alloc: %li for [%s]\n", size, label);
    return malloc(size);
}

void *calloc_audited(size_t count, size_t size, char* label) {
    printf("alloc: %li for [%s]\n", count * size, label);
    return calloc(count ,size);
}

void free_audited(void *ptr, char* label) {
    printf("free: [%s]\n", label);
    free(ptr);
}
