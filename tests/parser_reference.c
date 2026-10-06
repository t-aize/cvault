/**
 * @file parser_reference.c
 * @brief Reference implementation of the request grammar (see parser_reference.h).
 *
 * The grammar, in the words of docs/security.md:
 *  - A request is one line ending in LF, optionally preceded by a CR. The line
 *    contains no NUL and no other CR or LF, and is at most CV_MAX_LINE_BYTES long.
 *  - The first word runs to the first space. PING and QUIT take no arguments.
 *    Every other known command needs a key: a run of printable ASCII characters
 *    (33..126) of 1..256 bytes (1..64 for the AUTH user name).
 *  - AUTH, SET and EXPIRE carry a payload: everything after exactly one space that
 *    follows the key. GET, DEL, TTL and PURGE take only the key. EXPORT takes a
 *    prefix and optionally one more token (1..256 printable characters) after
 *    which the next page starts.
 *  - AUTH passwords have 1..1024 bytes, SET values 0..65536 bytes (more is a limit
 *    error) and EXPIRE takes a decimal signed 64-bit integer.
 *  - Unknown command words are "not implemented".
 */

#include "parser_reference.h"

#include "cvault/auth.h"
#include "cvault/config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** @brief Look up a command word; returns CV_CMD_UNKNOWN when it is not known. */
static cv_command_type lookup(const unsigned char *word, size_t length) {
    static const struct {
        const char *name;
        cv_command_type type;
    } table[] = {{"AUTH", CV_CMD_AUTH},
                 {"SET", CV_CMD_SET},
                 {"GET", CV_CMD_GET},
                 {"DEL", CV_CMD_DEL},
                 {"EXPIRE", CV_CMD_EXPIRE},
                 {"TTL", CV_CMD_TTL},
                 {"EXPORT", CV_CMD_EXPORT},
                 {"PURGE", CV_CMD_PURGE},
                 {"PING", CV_CMD_PING},
                 {"QUIT", CV_CMD_QUIT}};

    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); ++i) {
        if (strlen(table[i].name) == length && memcmp(table[i].name, word, length) == 0) {
            return table[i].type;
        }
    }

    return CV_CMD_UNKNOWN;
}

/**
 * @brief Parse a decimal signed 64-bit integer using strtoll() on a checked copy.
 *
 * Only an optional leading '-' followed by at least one digit is accepted. Redundant
 * leading zeros are dropped first so that every valid number fits the copy buffer.
 */
static bool reference_integer(const unsigned char *text, size_t length, int64_t *out) {
    char copy[32];
    bool negative = length > 0 && text[0] == '-';
    size_t first = negative ? 1 : 0;

    if (first >= length) {
        return false;
    }

    for (size_t i = first; i < length; ++i) {
        if (text[i] < '0' || text[i] > '9') {
            return false;
        }
    }

    while (first + 1 < length && text[first] == '0') {
        ++first;
    }

    size_t digits = length - first;

    if (digits + 1 >= sizeof(copy)) {
        return false; /* Too many significant digits for an int64_t. */
    }

    size_t used = 0;

    if (negative) {
        copy[used++] = '-';
    }

    memcpy(copy + used, text + first, digits);

    copy[used + digits] = 0;
    errno = 0;

    char *end = NULL;
    long long value = strtoll(copy, &end, 10);

    if (errno == ERANGE || *end != 0) {
        return false;
    }

    *out = (int64_t)value;

    return true;
}

cv_status reference_parse(const unsigned char *line, size_t length, reference_command *out) {
    memset(out, 0, sizeof(*out));

    if (length == 0) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    if (length > CV_MAX_LINE_BYTES) {
        return CV_ERR_LIMIT;
    }

    for (size_t i = 0; i < length; ++i) {
        if (line[i] == '\0') {
            return CV_ERR_INVALID_ARGUMENT;
        }
    }

    if (line[length - 1] != '\n') {
        return CV_ERR_INVALID_ARGUMENT;
    }

    /* The content is everything before the terminator (LF or CRLF). */
    size_t end = length - 1;

    if (end > 0 && line[end - 1] == '\r') {
        --end;
    }

    if (end == 0) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    for (size_t i = 0; i < end; ++i) {
        if (line[i] == '\n' || line[i] == '\r') {
            return CV_ERR_INVALID_ARGUMENT;
        }
    }

    size_t word_end = 0;

    while (word_end < end && line[word_end] != ' ') {
        ++word_end;
    }

    cv_command_type type = lookup(line, word_end);

    if (type == CV_CMD_UNKNOWN) {
        return CV_ERR_NOT_IMPLEMENTED;
    }

    if (type == CV_CMD_PING || type == CV_CMD_QUIT) {
        if (word_end != end) {
            return CV_ERR_INVALID_ARGUMENT;
        }

        out->type = type;

        return CV_OK;
    }

    if (word_end == end) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    size_t arguments = word_end + 1;
    size_t arguments_length = end - arguments;
    size_t key_length = 0;

    while (key_length < arguments_length && line[arguments + key_length] != ' ') {
        unsigned char c = line[arguments + key_length];

        if (c < 33 || c > 126) {
            return CV_ERR_INVALID_ARGUMENT;
        }

        ++key_length;
    }

    size_t maximum = type == CV_CMD_AUTH ? CV_AUTH_USER_BYTES : CV_MAX_KEY_BYTES;

    if (key_length == 0 || key_length > maximum) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    bool has_payload = type == CV_CMD_AUTH || type == CV_CMD_SET || type == CV_CMD_EXPIRE;
    bool has_extra = key_length != arguments_length;
    bool continuation = type == CV_CMD_EXPORT && has_extra;

    if (!has_payload && !continuation && has_extra) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    if (has_payload && key_length == arguments_length) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    out->type = type;
    out->has_arguments = true;
    out->arguments_offset = arguments;
    out->arguments_length = arguments_length;
    out->key_offset = arguments;
    out->key_length = key_length;

    if (has_payload || continuation) {
        out->has_value = true;
        out->value_offset = arguments + key_length + 1;
        out->value_length = arguments_length - key_length - 1;
    }

    cv_status status = CV_OK;

    if (type == CV_CMD_AUTH &&
        (out->value_length == 0 || out->value_length > CV_AUTH_PASSWORD_BYTES)) {
        status = CV_ERR_INVALID_ARGUMENT;
    } else if (type == CV_CMD_SET && out->value_length > CV_MAX_VALUE_BYTES) {
        status = CV_ERR_LIMIT;
    } else if (type == CV_CMD_EXPIRE &&
               !reference_integer(line + out->value_offset, out->value_length, &out->seconds)) {
        status = CV_ERR_INVALID_ARGUMENT;
    } else if (continuation) {
        if (out->value_length == 0 || out->value_length > CV_MAX_KEY_BYTES) {
            status = CV_ERR_INVALID_ARGUMENT;
        }

        for (size_t i = 0; i < out->value_length && status == CV_OK; ++i) {
            unsigned char c = line[out->value_offset + i];

            if (c < 33 || c > 126) {
                status = CV_ERR_INVALID_ARGUMENT;
            }
        }
    }

    if (status != CV_OK) {
        memset(out, 0, sizeof(*out));
    }

    return status;
}

/** @brief Write a formatted explanation into the caller's buffer. */
static bool
differ(char *why, size_t why_size, const char *message, long long actual, long long expected) {
    if (why && why_size) {
        (void)snprintf(
            why, why_size, "%s: production=%lld reference=%lld", message, actual, expected);
    }

    return false;
}

bool reference_agrees(const unsigned char *line, size_t length, char *why, size_t why_size) {
    static const unsigned char empty[1] = {0};
    const unsigned char *input = line ? line : empty;
    reference_command expected;
    cv_command actual;
    cv_status expected_status = reference_parse(input, length, &expected);
    cv_status actual_status = cv_parse_line(length ? line : NULL, length, &actual);

    if (actual_status != expected_status) {
        return differ(why, why_size, "status", actual_status, expected_status);
    }

    if (actual.type != expected.type) {
        return differ(why, why_size, "type", actual.type, expected.type);
    }

    /* Every borrowed slice must be a window of the input, at the expected place. */
    const unsigned char *arguments =
        expected.has_arguments ? input + expected.arguments_offset : NULL;
    const unsigned char *key = expected.has_arguments ? input + expected.key_offset : NULL;
    const unsigned char *value = expected.has_value ? input + expected.value_offset : NULL;

    if (actual.arguments != arguments || actual.arguments_length != expected.arguments_length) {
        return differ(why,
                      why_size,
                      "arguments",
                      (long long)actual.arguments_length,
                      (long long)expected.arguments_length);
    }

    if (actual.key != key || actual.key_length != expected.key_length) {
        return differ(
            why, why_size, "key", (long long)actual.key_length, (long long)expected.key_length);
    }

    if (actual.value != value || actual.value_length != expected.value_length) {
        return differ(why,
                      why_size,
                      "value",
                      (long long)actual.value_length,
                      (long long)expected.value_length);
    }

    if (actual.seconds != expected.seconds) {
        return differ(why, why_size, "seconds", actual.seconds, expected.seconds);
    }

    return true;
}
