#include "stdio.h"
#include "utils/file.h"

int64_t get_file_size(FILE *file) {
    fseek(file, 0L, SEEK_END);
    int64_t filesize = ftell(file);
    fseek(file, 0L, SEEK_SET);
    return filesize;
}
