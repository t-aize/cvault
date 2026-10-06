/**
 * @file parser_reference.h
 * @brief Independent reference implementation of the request grammar.
 *
 * The production parser (src/parser.c) is optimised for being allocation free and
 * bounded. This module re-implements the same grammar in the most direct way
 * possible, straight from the written specification in docs/security.md, with
 * different code. Tests run both on the same input and require identical
 * results, so a bug has to exist in both implementations to go unnoticed.
 */

#ifndef CVAULT_PARSER_REFERENCE_H
#define CVAULT_PARSER_REFERENCE_H

#include "cvault/parser.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Result of the reference parser; slices are offsets into the input line. */
typedef struct {
    cv_command_type type;
    bool has_arguments;
    bool has_value;
    size_t arguments_offset, arguments_length;
    size_t key_offset, key_length;
    size_t value_offset, value_length;
    int64_t seconds;
} reference_command;

/**
 * @brief Parse a request line according to the specification.
 *
 * @param line   Input bytes (must not be NULL when @p length is non-zero).
 * @param length Number of bytes.
 * @param out    Receives the parsed command; zeroed on every error.
 * @return The status the production parser must return for the same input.
 */
cv_status reference_parse(const unsigned char *line, size_t length, reference_command *out);

/**
 * @brief Compare the production parser with the reference on one input.
 *
 * Runs cv_parse_line() and reference_parse() and checks the status, every field
 * and the pointer ranges of the borrowed slices.
 *
 * @param why     Receives a short explanation when the results differ.
 * @param why_size Size of @p why.
 * @return true when both implementations agree completely.
 */
bool reference_agrees(const unsigned char *line, size_t length, char *why, size_t why_size);

#endif /* CVAULT_PARSER_REFERENCE_H */
