/**
 * @file console_signals.h
 * @brief Private adapter that installs and restores console signal handlers.
 *
 * Embedders keep control of process-wide signal state: only the convenience
 * loop cv_server_run() uses this header, and it always restores the previous
 * handlers when it exits.
 */

#ifndef CVAULT_CONSOLE_SIGNALS_H
#define CVAULT_CONSOLE_SIGNALS_H

#include <signal.h>
#include <stdbool.h>

/** Previously installed handlers, kept so they can be restored. */
typedef struct {
#ifdef _WIN32
    void (*interrupt_handler)(int);
    void (*terminate_handler)(int);
    void (*break_handler)(int);
#else
    struct sigaction interrupt_action;
    struct sigaction terminate_action;
#endif
} cv_console_signals;

/**
 * @brief Install @p handler for the termination signals.
 *
 * All-or-nothing: if any installation fails, the handlers already replaced are
 * put back and false is returned.
 *
 * @param previous Receives the handlers being replaced.
 * @param handler  Async-signal-safe handler to install.
 * @return true on success.
 */
static bool cv_console_install(cv_console_signals *previous, void (*handler)(int)) {
#ifdef _WIN32
    previous->interrupt_handler = signal(SIGINT, handler);

    if (previous->interrupt_handler == SIG_ERR) {
        return false;
    }

    previous->terminate_handler = signal(SIGTERM, handler);

    if (previous->terminate_handler == SIG_ERR) {
        (void)signal(SIGINT, previous->interrupt_handler);

        return false;
    }

    /* Windows process groups receive CTRL_BREAK_EVENT as SIGBREAK. Handling it
     * lets services and integration tests drain connections and synchronize
     * checkpoints/audit records instead of terminating abruptly. */
    previous->break_handler = signal(SIGBREAK, handler);

    if (previous->break_handler == SIG_ERR) {
        (void)signal(SIGINT, previous->interrupt_handler);
        (void)signal(SIGTERM, previous->terminate_handler);

        return false;
    }
#else
    struct sigaction action = {0};

    action.sa_handler = handler;

    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGINT, &action, &previous->interrupt_action) != 0) {
        return false;
    }

    if (sigaction(SIGTERM, &action, &previous->terminate_action) != 0) {
        (void)sigaction(SIGINT, &previous->interrupt_action, NULL);

        return false;
    }
#endif

    return true;
}

/** @brief Put back the handlers saved by cv_console_install(). */
static void cv_console_restore(const cv_console_signals *previous) {
#ifdef _WIN32
    (void)signal(SIGINT, previous->interrupt_handler);
    (void)signal(SIGTERM, previous->terminate_handler);
    (void)signal(SIGBREAK, previous->break_handler);
#else
    (void)sigaction(SIGINT, &previous->interrupt_action, NULL);
    (void)sigaction(SIGTERM, &previous->terminate_action, NULL);
#endif
}

#endif /* CVAULT_CONSOLE_SIGNALS_H */
