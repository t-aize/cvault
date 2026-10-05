/**
 * @file test_util.h
 * @brief Minimal assertion helper shared by the C test programs.
 */

#ifndef CVAULT_TEST_UTIL_H
#define CVAULT_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Fail the calling function with a diagnostic when @p condition is false.
 *
 * Unlike assert(), these checks stay active in Release builds. The macro
 * returns EXIT_FAILURE, so it can only be used in functions returning int.
 */
#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #condition);          \
            return EXIT_FAILURE;                                                                   \
        }                                                                                          \
    } while (0)

#endif /* CVAULT_TEST_UTIL_H */
