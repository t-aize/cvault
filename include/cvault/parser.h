/**
 * @file parser.h
 * @brief Allocation-free parser for the cvault text protocol.
 *
 * One request is one line terminated by LF or CRLF. Words are separated by a
 * single ASCII space. The grammar, per command:
 *
 * | Line                            | Meaning                                     |
 * |---------------------------------|---------------------------------------------|
 * | `AUTH <user> <password>`        | Log in; the password runs to end of line.   |
 * | `SET <key> <value>`             | Store a value; it runs to end of line.      |
 * | `GET <key>`                     | Read a value.                               |
 * | `DEL <key>`                     | Delete a key.                               |
 * | `EXPIRE <key> <seconds>`        | Set a relative time to live (signed int64). |
 * | `TTL <key>`                     | Read the remaining time to live.            |
 * | `EXPORT <prefix> [<after>]`     | Export a page of the readable keys under a  |
 * |                                 | prefix; `<after>` continues a previous page.|
 * | `PURGE <prefix>`                | Erase the writable keys under a prefix.     |
 * | `PING` / `QUIT`                 | Liveness check / close the connection.      |
 *
 * Unknown command words answer #CV_ERR_NOT_IMPLEMENTED. The full security
 * grammar is documented in docs/security.md.
 */

#ifndef CVAULT_PARSER_H
#define CVAULT_PARSER_H

#include "cvault/common.h"

#include <stddef.h>
#include <stdint.h>

/** Command word recognised at the start of a request line. */
typedef enum {
    CV_CMD_UNKNOWN = 0, /**< Not a known command (never returned on success). */
    CV_CMD_AUTH,        /**< Authenticate the connection. */
    CV_CMD_SET,         /**< Store or replace a value. */
    CV_CMD_GET,         /**< Read a value. */
    CV_CMD_DEL,         /**< Delete a value. */
    CV_CMD_EXPIRE,      /**< Attach a relative expiration. */
    CV_CMD_TTL,         /**< Query the remaining lifetime. */
    CV_CMD_EXPORT,      /**< Export the readable keys under a prefix, one page at a time. */
    CV_CMD_PURGE,       /**< Erase the writable keys under a prefix. */
    CV_CMD_PING,        /**< Liveness probe, allowed before authentication. */
    CV_CMD_QUIT         /**< Ask the server to close the connection. */
} cv_command_type;

/**
 * @brief A validated request, expressed as slices of the input line.
 *
 * Nothing is copied: every pointer borrows the buffer handed to
 * cv_parse_line(). Slices are not NUL-terminated and must not be retained after
 * the transport consumes or wipes its input buffer.
 */
typedef struct {
    /** Which command was parsed. */
    cv_command_type type;

    /** Complete argument span, excluding the line terminator (compatibility view). */
    const unsigned char *arguments;
    size_t arguments_length;

    /** Key slice (the user name for AUTH, the prefix for EXPORT and PURGE) and the
     * payload slice that follows it: the password for AUTH, the value for SET, the
     * decimal text for EXPIRE, the optional continuation key for EXPORT. */
    const unsigned char *key, *value;
    size_t key_length, value_length;

    /** Validated signed seconds for EXPIRE; zero for every other command. */
    int64_t seconds;
} cv_command;

/**
 * @brief Parse one complete request line without allocating or modifying it.
 *
 * Enforces strict arity, printable ASCII keys (33..126), bounded AUTH and SET
 * payloads and a well-formed signed 64-bit EXPIRE count.
 *
 * @param line   Input bytes including the trailing LF; embedded NUL, CR (other
 *               than the CRLF terminator) and LF are rejected.
 * @param length Number of bytes in @p line, at most #CV_MAX_LINE_BYTES.
 * @param out    Receives the command; reset to all-zero on every error.
 * @return #CV_OK on success; #CV_ERR_INVALID_ARGUMENT for malformed input;
 *         #CV_ERR_LIMIT when a size bound is exceeded; #CV_ERR_NOT_IMPLEMENTED
 *         for unknown command words.
 */
cv_status cv_parse_line(const unsigned char *line, size_t length, cv_command *out);

#endif /* CVAULT_PARSER_H */
