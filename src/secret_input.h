/**
 * @file secret_input.h
 * @brief Private helper that reads one secret line from standard input.
 *
 * Shared by `cvault-server --hash-password` and `cvault-cli`, so that both read
 * passwords the same way: never from the command line, with terminal echo
 * disabled when stdin is a terminal.
 */

#ifndef CVAULT_SECRET_INPUT_H
#define CVAULT_SECRET_INPUT_H

#include "cvault/common.h"

#include <signal.h>
#include <stddef.h>

/**
 * @brief Read one line from stdin without echoing it.
 *
 * On a terminal the prompt is written to stderr, echo is turned off while the
 * line is typed and restored on every path. Otherwise (a pipe or a file) the
 * line is read silently. A trailing CR is removed and the line terminator is
 * not part of the secret.
 *
 * @param prompt      Text shown on a terminal, or NULL for none.
 * @param buffer      Receives the secret bytes (no terminator); wiped on error.
 * @param capacity    Size of @p buffer. A longer line, or one containing a NUL
 *                    byte, is rejected.
 * @param length      Receives the number of secret bytes; reset to 0 on error.
 * @param interrupted Optional flag set by a signal handler; when it becomes
 *                    non-zero the read stops with an error. May be NULL.
 * @return #CV_OK, #CV_ERR_INVALID_ARGUMENT for bad arguments, #CV_ERR_LIMIT for
 *         an oversized or NUL-containing line, or #CV_ERR_IO when reading fails,
 *         the terminal cannot be configured or @p interrupted was raised.
 */
cv_status cv_secret_read(const char *prompt,
                         unsigned char *buffer,
                         size_t capacity,
                         size_t *length,
                         const volatile sig_atomic_t *interrupted);

#endif /* CVAULT_SECRET_INPUT_H */
