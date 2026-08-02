#include "cli.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_MAX_ARGS 32
#define FUZZ_MAX_INPUT 4096

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *copy;
    char *argv[FUZZ_MAX_ARGS + 1];
    int argc = 1;
    size_t i;
    wcat_config cfg;

    if (size == 0 || size > FUZZ_MAX_INPUT) {
        return 0;
    }
    copy = malloc(size + 1);
    if (copy == NULL) {
        return 0;
    }
    memcpy(copy, data, size);
    copy[size] = '\0';

    argv[0] = (char *)"wcat";
    for (i = 0; i < size && argc < FUZZ_MAX_ARGS; i++) {
        if (copy[i] == '\0' || copy[i] == '\n' || copy[i] == '\r' ||
            copy[i] == '\t' || copy[i] == ' ') {
            copy[i] = '\0';
            continue;
        }
        if (i == 0 || copy[i - 1] == '\0') {
            argv[argc++] = &copy[i];
        }
    }
    argv[argc] = NULL;
    (void)wcat_parse_args(argc, argv, &cfg);
    free(copy);
    return 0;
}
