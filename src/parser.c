#include <string.h>
#include "cvault/config.h"
#include "cvault/parser.h"

cv_status cv_parse_line(const unsigned char *line, size_t length, cv_command *out) {
    if (out == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    *out = (cv_command){CV_CMD_UNKNOWN, NULL, 0};
    if (line == NULL || length == 0) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    if (length > CV_MAX_LINE_BYTES) {
        return CV_ERR_LIMIT;
    }
    if (line[length - 1] != '\n' || memchr(line, '\0', length) != NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    /* TODO: tokenize commands, validate arity/keys/numbers and value bounds. */
    return CV_ERR_NOT_IMPLEMENTED;
}
