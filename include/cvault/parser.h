#ifndef CVAULT_PARSER_H
#define CVAULT_PARSER_H

#include <stddef.h>
#include "cvault/common.h"

typedef enum {
    CV_CMD_UNKNOWN = 0,
    CV_CMD_AUTH, CV_CMD_SET, CV_CMD_GET, CV_CMD_DEL,
    CV_CMD_EXPIRE, CV_CMD_TTL, CV_CMD_EXPORT, CV_CMD_PURGE
} cv_command_type;

typedef struct {
    cv_command_type type;
    const unsigned char *arguments;
    size_t arguments_length;
} cv_command;

/* Planned: parse one complete LF-terminated line without modifying it.
 * Argument slices borrow the caller's input buffer. No allocation.
 * Grammar parsing is not implemented; basic input limits are enforced. */
cv_status cv_parse_line(const unsigned char *line, size_t length, cv_command *out);

#endif
