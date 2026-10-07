/**
 * @file secret_input.c
 * @brief Echo-free reading of one secret line from stdin on POSIX and Windows.
 */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "secret_input.h"

#include "cvault/crypto.h"

#include <stdbool.h>
#include <stdio.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

cv_status cv_secret_read(const char *prompt,
                         unsigned char *buffer,
                         size_t capacity,
                         size_t *length,
                         const volatile sig_atomic_t *interrupted) {
    if (length) {
        *length = 0;
    }

    if (!buffer || !capacity || !length) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    bool terminal = false;

    /* Turn terminal echo off so the secret is not displayed while typed. */
#ifdef _WIN32
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;

    terminal = GetConsoleMode(input, &mode) != 0;

    if (terminal && !SetConsoleMode(input, mode & ~ENABLE_ECHO_INPUT)) {
        return CV_ERR_IO;
    }
#else
    struct termios previous;

    terminal = isatty(STDIN_FILENO) != 0;

    if (terminal) {
        if (tcgetattr(STDIN_FILENO, &previous) != 0) {
            return CV_ERR_IO;
        }

        struct termios hidden = previous;

        hidden.c_lflag &= (tcflag_t)~ECHO;

        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
            return CV_ERR_IO;
        }
    }
#endif

    if (terminal && prompt) {
        fputs(prompt, stderr);
        fflush(stderr);
    }

    /* Read one line; NUL bytes and over-long input make the secret invalid. */
    size_t count = 0;
    int c;
    cv_status status = CV_OK;

    while (!(interrupted && *interrupted) && (c = fgetc(stdin)) != EOF && c != '\n') {
        if (c == 0 || count == capacity) {
            status = CV_ERR_LIMIT;
            break;
        }

        buffer[count++] = (unsigned char)c;
    }

    if (ferror(stdin) || (interrupted && *interrupted)) {
        status = CV_ERR_IO;
    }

    if (count && buffer[count - 1] == '\r') {
        --count;
    }

    /* Restore the terminal before doing anything else. */
#ifdef _WIN32
    if (terminal && !SetConsoleMode(input, mode)) {
        status = CV_ERR_IO;
    }
#else
    if (terminal && tcsetattr(STDIN_FILENO, TCSAFLUSH, &previous) != 0) {
        status = CV_ERR_IO;
    }
#endif

    if (terminal) {
        fputc('\n', stderr);
    }

    if (status != CV_OK) {
        cv_crypto_wipe(buffer, capacity);

        return status;
    }

    *length = count;

    return CV_OK;
}
