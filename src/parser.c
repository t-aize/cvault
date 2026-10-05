#include "cvault/parser.h"
#include "cvault/auth.h"
#include "cvault/config.h"
#include <stdbool.h>
#include <string.h>

static bool decimal(const unsigned char *digits, size_t digit_count, int64_t *out) {
    /* Accumulate unsigned magnitude to handle INT64_MIN without signed overflow.
     * Reject overflow before multiply/add, then apply the sign exactly once. */
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
    if (command.type == CV_CMD_UNKNOWN || command.type == CV_CMD_EXPORT ||
        command.type == CV_CMD_PURGE) {
        return CV_ERR_NOT_IMPLEMENTED;
    }
    if (command.type == CV_CMD_PING || command.type == CV_CMD_QUIT) {
        if (command_length != content_length) {
            return CV_ERR_INVALID_ARGUMENT;
        }
        *out = command;
        return CV_OK;
    }
    if (command_length == content_length) {
        return CV_ERR_INVALID_ARGUMENT;
    }
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
    if (!payload) {
        if (command.key_length != command.arguments_length) {
            return CV_ERR_INVALID_ARGUMENT;
        }
    } else {
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
