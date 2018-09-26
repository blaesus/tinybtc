#include <stdio.h>
#include <stdbool.h>
#include <sys/stat.h>
#include "utils/file.h"

int64_t get_file_size(FILE *file) {
    fseek(file, 0L, SEEK_END);
    int64_t filesize = ftell(file);
    fseek(file, 0L, SEEK_SET);
    return filesize;
}

bool file_exist(char *filename) {
    struct stat buffer;
    return stat(filename, &buffer) == 0;
}

