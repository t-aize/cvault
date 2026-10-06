/**
 * @file parser.c
 * @brief Implementation of the cvault request-line parser.
 *
 * The parser works in three stages: frame validation (terminator, NUL, size),
 * command-word lookup, then per-command argument splitting. It never allocates
 * and never writes to its input.
 */

#include "cvault/parser.h"

#include "cvault/auth.h"
#include "cvault/config.h"

#include <stdbool.h>
#include <string.h>

/**
 * @brief Parse a strict signed decimal integer.
 *
 * Accepts an optional leading '-' followed by one or more ASCII digits and
 * nothing else (no '+', spaces or underscores). The magnitude is accumulated as
 * unsigned so INT64_MIN parses without signed overflow, and overflow is
 * rejected before every multiply-add rather than detected afterwards.
 *
 * @param digits      Candidate text (not NUL-terminated).
 * @param digit_count Length of @p digits.
 * @param out         Receives the value on success; untouched on failure.
 * @return true when the whole slice is a valid int64_t.
 */
static bool decimal(const unsigned char *digits, size_t digit_count, int64_t *out) {
    bool negative = digit_count && *digits == '-';

    if (negative) {
        ++digits;
        --digit_count;
    }

    if (!digit_count) {
        return false;
    }

    uint64_t maximum = negative ? (uint64_t)INT64_MAX + 1 : (uint64_t)INT64_MAX, value = 0;

    for (size_t i = 0; i < digit_count; ++i) {
        if (digits[i] < '0' || digits[i] > '9') {
            return false;
        }

        unsigned int digit = digits[i] - '0';

        if (value > (maximum - digit) / 10) {
            return false;
        }

        value = value * 10 + digit;
    }

    /* Apply the sign exactly once; INT64_MIN has no positive counterpart. */
    *out = negative ? (value == (uint64_t)INT64_MAX + 1 ? INT64_MIN : -(int64_t)value)
                    : (int64_t)value;

    return true;
}

cv_status cv_parse_line(const unsigned char *line, size_t length, cv_command *out) {
    if (!out) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    *out = (cv_command){0};

    if (!line || !length) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    if (length > CV_MAX_LINE_BYTES) {
        return CV_ERR_LIMIT;
    }

    /* Stage 1: framing. Exactly one LF-terminated line, no NUL bytes. */
    if (line[length - 1] != '\n' || memchr(line, 0, length)) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    size_t content_length = length - 1;

    if (content_length && line[content_length - 1] == '\r') {
        --content_length;
    }

    if (!content_length || memchr(line, '\n', content_length) ||
        memchr(line, '\r', content_length)) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    /* Stage 2: command word, terminated by the first space or end of line. */
    size_t command_length = 0;

    while (command_length < content_length && line[command_length] != ' ') {
        ++command_length;
    }

    const char *names[] = {
        "", "AUTH", "SET", "GET", "DEL", "EXPIRE", "TTL", "EXPORT", "PURGE", "PING", "QUIT"};
    cv_command command = {0};

    for (size_t i = 1; i < sizeof(names) / sizeof(names[0]); ++i) {
        if (command_length == strlen(names[i]) && memcmp(line, names[i], command_length) == 0) {
            command.type = (cv_command_type)i;
        }
    }

    if (command.type == CV_CMD_UNKNOWN) {
        return CV_ERR_NOT_IMPLEMENTED;
    }

    /* PING and QUIT take no arguments at all. */
    if (command.type == CV_CMD_PING || command.type == CV_CMD_QUIT) {
        if (command_length != content_length) {
            return CV_ERR_INVALID_ARGUMENT;
        }

        *out = command;

        return CV_OK;
    }

    /* Every other command needs at least a key after the command word. */
    if (command_length == content_length) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    /* Stage 3: split "<key>[ <payload>]" and validate each part. */
    command.arguments = line + command_length + 1;
    command.arguments_length = content_length - command_length - 1;
    command.key = command.arguments;

    while (command.key_length < command.arguments_length &&
           command.key[command.key_length] != ' ') {
        unsigned char c = command.key[command.key_length];

        if (c < 33 || c > 126) {
            return CV_ERR_INVALID_ARGUMENT;
        }

        ++command.key_length;
    }

    size_t maximum = command.type == CV_CMD_AUTH ? CV_AUTH_USER_BYTES : CV_MAX_KEY_BYTES;

    if (!command.key_length || command.key_length > maximum) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    bool payload =
        command.type == CV_CMD_AUTH || command.type == CV_CMD_SET || command.type == CV_CMD_EXPIRE;
    bool has_payload_bytes = command.key_length != command.arguments_length;

    if (command.type == CV_CMD_EXPORT && has_payload_bytes) {
        /* EXPORT <prefix> <after>: the continuation is one more key-like token. */
        command.value = command.key + command.key_length + 1;
        command.value_length = command.arguments_length - command.key_length - 1;

        if (!command.value_length || command.value_length > CV_MAX_KEY_BYTES) {
            return CV_ERR_INVALID_ARGUMENT;
        }

        for (size_t i = 0; i < command.value_length; ++i) {
            if (command.value[i] < 33 || command.value[i] > 126) {
                return CV_ERR_INVALID_ARGUMENT;
            }
        }
    } else if (!payload) {
        /* GET / DEL / TTL / PURGE / bare EXPORT: the key must be the only argument. */
        if (has_payload_bytes) {
            return CV_ERR_INVALID_ARGUMENT;
        }
    } else {
        /* AUTH / SET / EXPIRE: a payload must follow the single separator. */
        if (command.key_length == command.arguments_length) {
            return CV_ERR_INVALID_ARGUMENT;
        }

        command.value = command.key + command.key_length + 1;
        command.value_length = command.arguments_length - command.key_length - 1;

        if (command.type == CV_CMD_AUTH &&
            (!command.value_length || command.value_length > CV_AUTH_PASSWORD_BYTES)) {
            return CV_ERR_INVALID_ARGUMENT;
        }

        if (command.type == CV_CMD_SET && command.value_length > CV_MAX_VALUE_BYTES) {
            return CV_ERR_LIMIT;
        }

        if (command.type == CV_CMD_EXPIRE &&
            !decimal(command.value, command.value_length, &command.seconds)) {
            return CV_ERR_INVALID_ARGUMENT;
        }
    }

    *out = command;

    return CV_OK;
}
