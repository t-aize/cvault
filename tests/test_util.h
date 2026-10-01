#ifndef CVAULT_TEST_UTIL_H
#define CVAULT_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>

/* Unlike assert(), these checks remain active in Release builds. */
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #condition); \
        return EXIT_FAILURE; \
    } \
} while (0)

#endif
