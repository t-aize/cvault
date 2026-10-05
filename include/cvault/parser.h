#ifndef CVAULT_PARSER_H
#define CVAULT_PARSER_H

#include "cvault/common.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    CV_CMD_UNKNOWN = 0,
    CV_CMD_AUTH,
    CV_CMD_SET,
    CV_CMD_GET,
    CV_CMD_DEL,
    CV_CMD_EXPIRE,
    CV_CMD_TTL,
    CV_CMD_EXPORT,
    CV_CMD_PURGE,
    CV_CMD_PING,
    CV_CMD_QUIT
} cv_command_type;

typedef struct {
    cv_command_type type;
    /** Complete argument span, excluding the line terminator (compatibility view). */
    const unsigned char *arguments;
    size_t arguments_length;
    /** Non-NUL-terminated slices; key is the username for AUTH. Never retain them
     * after the transport consumes/wipes its input buffer. */
    const unsigned char *key, *value;
    size_t key_length, value_length;
    /** Validated signed seconds for EXPIRE; zero for other commands. */
    int64_t seconds;
} cv_command;

/** Parse one complete LF/CRLF line without allocation or modification.
 * Slices borrow input. Strict arity, printable ASCII keys, bounded AUTH/SET
 * payloads and signed EXPIRE seconds. Grammar documented in docs/security.md.
 * Output resets on all errors; unknown/reserved commands return NOT_IMPLEMENTED.
 */
cv_status cv_parse_line(const unsigned char *line, size_t length, cv_command *out);

#endif
