/**
 * @file parser_stdin.c
 * @brief Standard-input harness for fuzzing cv_parse_line() (AFL++ compatible).
 *
 * The program reads one input from stdin and feeds it to the parser. The result
 * is intentionally ignored: the goal is to let sanitizers and the fuzzer detect
 * crashes, out-of-bounds reads and undefined behaviour, never to judge validity.
 */

#include "cvault/config.h"
#include "cvault/parser.h"

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    /* One byte more than the protocol maximum, so oversized inputs are exercised. */
    unsigned char input[CV_MAX_LINE_BYTES + 1];
    const size_t length = fread(input, 1, sizeof(input), stdin);

    if (ferror(stdin)) {
        return EXIT_FAILURE;
    }

    cv_command command;

    (void)cv_parse_line(input, length, &command);

    return EXIT_SUCCESS;
}
