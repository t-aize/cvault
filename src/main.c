/**
 * @file main.c
 * @brief Command-line entry point of `cvault-server`.
 *
 * Besides starting the server, the executable offers a few one-shot
 * maintenance modes that exit immediately: `--help`, `--version`,
 * `--generate-key`, `--hash-password` and `--dump-audit`.
 *
 * Start-up order when serving:
 *  1. Parse and validate every option.
 *  2. Recover encrypted persistent state (if `--data` is given).
 *  3. Load the security policy and authenticate the audit log (if `--security`
 *     is given). Any failure here prevents the listener from ever opening.
 *  4. Bind the listening socket and run the event loop until a signal arrives.
 *  5. Shut down in dependency order: transport, final snapshot, security
 *     service, persistence.
 */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "console_signals.h"
#include "cvault/audit.h"
#include "cvault/crypto.h"
#include "cvault/persist.h"
#include "cvault/server.h"
#include "cvault/version.h"
#include "security_service.h"

#ifndef _WIN32
#include <termios.h>
#include <unistd.h>
#endif

/** Set by the signal handler; polled by the main loop and by password input. */
static volatile sig_atomic_t stop_requested = 0;

/** @brief Signal handler: only sets a flag, which is async-signal-safe. */
static void handle_signal(int number) {
    (void)number;

    stop_requested = 1;
}

/** @brief Monotonic milliseconds used only to schedule snapshots. */
static uint64_t scheduling_ms(void) {
    /* Scheduling only; stored expirations use the persistence clock. */
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) {
        return 0;
    }

    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
#endif
}

/**
 * @brief Parse an unsigned decimal option value.
 *
 * Strict parsing rejects signs, whitespace, trailing junk and overflow.
 *
 * @param text    Option text.
 * @param maximum Largest accepted value.
 * @param out     Receives the value on success.
 * @return true when @p text is a valid number not above @p maximum.
 */
static bool parse_number(const char *text, unsigned long maximum, unsigned long *out) {
    if (text[0] == '\0') {
        return false;
    }

    for (const char *cursor = text; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
    }

    errno = 0;

    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);

    if (errno == ERANGE || *end != '\0' || value > maximum) {
        return false;
    }

    *out = value;

    return true;
}

/**
 * @brief Implement `--hash-password`.
 *
 * Passwords are read from stdin, never from argv, so they cannot leak through
 * the process list or shell history. Echo is disabled on an attached terminal
 * and restored on every normal error path. The bounded buffer is wiped before
 * returning.
 *
 * @return EXIT_SUCCESS after printing one Argon2id PHC string, otherwise
 *         EXIT_FAILURE.
 */
static int hash_password(void) {
    unsigned char password[CV_AUTH_PASSWORD_BYTES + 2] = {0};
    bool terminal = false;

    /* Turn terminal echo off so the password is not displayed while typed. */
#ifdef _WIN32
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;

    terminal = GetConsoleMode(input, &mode) != 0;

    if (terminal && !SetConsoleMode(input, mode & ~ENABLE_ECHO_INPUT)) {
        return EXIT_FAILURE;
    }
#else
    struct termios previous;

    terminal = isatty(STDIN_FILENO) != 0;

    if (terminal) {
        if (tcgetattr(STDIN_FILENO, &previous) != 0) {
            return EXIT_FAILURE;
        }

        struct termios hidden = previous;

        hidden.c_lflag &= (tcflag_t)~ECHO;

        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
            return EXIT_FAILURE;
        }
    }
#endif

    if (terminal) {
        fputs("Password: ", stderr);
        fflush(stderr);
    }

    /* Read one line; NUL bytes and over-long input make the password invalid. */
    size_t length = 0;
    int c;
    bool valid = true;

    while (!stop_requested && (c = fgetc(stdin)) != EOF && c != '\n') {
        if (c == 0 || length == sizeof(password)) {
            valid = false;
            break;
        }

        password[length++] = (unsigned char)c;
    }

    if (ferror(stdin) || stop_requested) {
        valid = false;
    }

    if (length && password[length - 1] == '\r') {
        --length;
    }

    /* Restore the terminal before doing anything else. */
#ifdef _WIN32
    if (terminal && !SetConsoleMode(input, mode)) {
        valid = false;
    }
#else
    if (terminal && tcsetattr(STDIN_FILENO, TCSAFLUSH, &previous) != 0) {
        valid = false;
    }
#endif

    if (terminal) {
        fputc('\n', stderr);
    }

    char hash[CV_AUTH_HASH_BYTES];
    cv_status status =
        valid ? cv_auth_hash_password(password, length, hash) : CV_ERR_INVALID_ARGUMENT;

    cv_crypto_wipe(password, sizeof(password));

    if (status == CV_OK && (puts(hash) == EOF || fflush(stdout) != 0)) {
        status = CV_ERR_IO;
    }

    cv_crypto_wipe(hash, sizeof(hash));

    if (status != CV_OK) {
        fprintf(stderr, "cvault-server: password hashing failed: %s\n", cv_status_string(status));
    }

    return status == CV_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * @brief Implement `--dump-audit`: verify and export the audit log as JSON Lines.
 *
 * The server must be stopped, because the audit file is exclusively locked while
 * the server runs.
 *
 * @param audit_path Path of the audit log.
 * @param key_path   Path of the audit master key file.
 * @return EXIT_SUCCESS or EXIT_FAILURE.
 */
static int dump_audit(const char *audit_path, const char *key_path) {
    unsigned char key[CV_PERSIST_KEY_BYTES] = {0};
    cv_audit *audit = NULL;
    cv_status result = cv_persist_key_load(key_path, key);

    if (result == CV_OK) {
        result = cv_audit_open(audit_path, key, false, &audit);
    }

    cv_crypto_wipe(key, sizeof(key));

    if (result == CV_OK) {
        result = cv_audit_export(audit, stdout);
    }

    cv_status closed = cv_audit_close(audit);

    if (result == CV_OK) {
        result = closed;
    }

    if (result != CV_OK) {
        fprintf(stderr, "cvault-server: audit export failed: %s\n", cv_status_string(result));
    }

    return result == CV_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}

/** @brief Print the `--help` text. */
static void print_usage(void) {
    puts("Usage: cvault-server [options]\n"
         "  --bind ADDRESS          Numeric IPv4/IPv6 address (default 127.0.0.1)\n"
         "  --port PORT             TCP port, 0 for ephemeral (default 6380)\n"
         "  --max-clients COUNT     Connection limit, 1..1024 (default 128)\n"
         "  --backend auto|poll|epoll\n"
         "  --idle-timeout-ms MS    Idle connection deadline (default 30000)\n"
         "  --frame-timeout-ms MS   Incomplete frame deadline (default 5000)\n"
         "  --shutdown-timeout-ms MS  Response drain deadline (default 2000)\n"
         "  --data DIRECTORY        Enable encrypted persistence (with --key-file)\n"
         "  --key-file FILE         Existing private 32-byte encryption key\n"
         "  --snapshot-interval-ms MS  Background checkpoint interval (default 60000)\n"
         "  --generate-key FILE     Create a new key and exit; never overwrite\n"
         "  --security FILE         Private credential/prefix policy\n"
         "  --audit FILE            Encrypted audit stream (required with --security)\n"
         "  --audit-key-file FILE   Separate private 32-byte audit master key\n"
         "  --hash-password         Read password from stdin; print Argon2id hash\n"
         "  --dump-audit FILE --audit-key-file FILE  Verify/export JSON Lines; server stopped\n"
         "  --help | --version\n"
         "TCP transport: AUTH and prefix-controlled storage with --security; otherwise "
         "PING/QUIT probes only.");
}

int main(int argc, char **argv) {
    /* One-shot modes that exit immediately. */
    if (argc == 2 && strcmp(argv[1], "--hash-password") == 0) {
        /* Catch interruption while terminal echo is disabled. The normal read
         * error path restores terminal state and wipes the password buffer. */
        cv_console_signals previous;

        if (!cv_console_install(&previous, handle_signal)) {
            return EXIT_FAILURE;
        }

        int result = hash_password();

        cv_console_restore(&previous);

        return result;
    }

    if (argc == 5 && strcmp(argv[1], "--dump-audit") == 0 &&
        strcmp(argv[3], "--audit-key-file") == 0) {
        return dump_audit(argv[2], argv[4]);
    }

    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        print_usage();

        return EXIT_SUCCESS;
    }

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("cvault-server " CVAULT_VERSION);

        return EXIT_SUCCESS;
    }

    cv_server_config config = cv_server_config_default();
    const char *directory = NULL, *key_path = NULL;
    const char *policy_path = NULL, *audit_path = NULL, *audit_key = NULL;
    uint32_t snapshot_interval = 60000;
    bool interval_given = false;

    if (argc == 3 && strcmp(argv[1], "--generate-key") == 0) {
        cv_status result = cv_persist_key_generate(argv[2]);

        if (result != CV_OK) {
            fprintf(stderr, "cvault-server: %s\n", cv_status_string(result));
        }

        return result == CV_OK ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    /* Options are strict `--name value` pairs. */
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 >= argc) {
            fputs("Missing option value. See --help.\n", stderr);

            return EXIT_FAILURE;
        }

        const char *option = argv[i];
        const char *value = argv[i + 1];

        if (strcmp(option, "--bind") == 0) {
            config.bind_address = value;
        } else if (strcmp(option, "--data") == 0) {
            directory = value;
        } else if (strcmp(option, "--key-file") == 0) {
            key_path = value;
        } else if (strcmp(option, "--security") == 0) {
            policy_path = value;
        } else if (strcmp(option, "--audit") == 0) {
            audit_path = value;
        } else if (strcmp(option, "--audit-key-file") == 0) {
            audit_key = value;
        } else if (strcmp(option, "--backend") == 0) {
            if (strcmp(value, "auto") == 0) {
                config.backend = CV_NETWORK_AUTO;
            } else if (strcmp(value, "poll") == 0) {
                config.backend = CV_NETWORK_POLL;
            } else if (strcmp(value, "epoll") == 0) {
                config.backend = CV_NETWORK_EPOLL;
            } else {
                fputs("Invalid network backend. See --help.\n", stderr);

                return EXIT_FAILURE;
            }
        } else {
            /* Numeric options: pick the upper bound, then validate the value. */
            unsigned long maximum = INT_MAX;

            if (strcmp(option, "--port") == 0) {
                maximum = UINT16_MAX;
            } else if (strcmp(option, "--max-clients") == 0) {
                maximum = (unsigned long)CV_HARD_MAX_CLIENTS;
            } else if (strcmp(option, "--idle-timeout-ms") != 0 &&
                       strcmp(option, "--frame-timeout-ms") != 0 &&
                       strcmp(option, "--snapshot-interval-ms") != 0 &&
                       strcmp(option, "--shutdown-timeout-ms") != 0) {
                fputs("Unknown option. See --help.\n", stderr);

                return EXIT_FAILURE;
            }

            unsigned long number = 0;

            if (!parse_number(value, maximum, &number) ||
                (number == 0 && strcmp(option, "--port") != 0)) {
                fputs("Invalid numeric option. See --help.\n", stderr);

                return EXIT_FAILURE;
            }

            if (strcmp(option, "--port") == 0) {
                config.port = (uint16_t)number;
            } else if (strcmp(option, "--max-clients") == 0) {
                config.max_clients = (size_t)number;
            } else if (strcmp(option, "--idle-timeout-ms") == 0) {
                config.idle_timeout_ms = (uint32_t)number;
            } else if (strcmp(option, "--frame-timeout-ms") == 0) {
                config.frame_timeout_ms = (uint32_t)number;
            } else if (strcmp(option, "--snapshot-interval-ms") == 0) {
                snapshot_interval = (uint32_t)number;
                interval_given = true;
            } else {
                config.shutdown_timeout_ms = (uint32_t)number;
            }
        }
    }

    /* Option groups must be complete: persistence and security each need all parts. */
    if ((directory == NULL) != (key_path == NULL) || (interval_given && !directory)) {
        fputs("Persistence requires --data and --key-file together. See --help.\n", stderr);

        return EXIT_FAILURE;
    }

    if ((policy_path || audit_path || audit_key) && !(policy_path && audit_path && audit_key)) {
        fputs("Security requires --security, --audit and --audit-key-file together. See --help.\n",
              stderr);

        return EXIT_FAILURE;
    }

    /* Recover durable state and validate security before exposing a listener.
     * An invalid policy, key or authenticated file must prevent readiness. */
    cv_persist *store = NULL;
    cv_status status = CV_OK;

    if (directory) {
        unsigned char key[CV_PERSIST_KEY_BYTES];

        status = cv_persist_key_load(key_path, key);

        cv_persist_options options = {directory, key, sizeof(key), NULL, NULL};

        if (status == CV_OK) {
            status = cv_persist_open(&options, &store);
        }

        cv_crypto_wipe(key, sizeof(key));

        if (status != CV_OK) {
            fprintf(stderr, "cvault-server: recovery failed: %s\n", cv_status_string(status));

            return EXIT_FAILURE;
        }
    }

    cv_security *security = NULL;

    if (policy_path) {
        status = cv_security_open(
            policy_path, audit_path, audit_key, store, config.max_clients, &security);
    }

    /* Callback context outlives the transport. Destroy sockets first so every
     * disconnect can reclaim its session while the policy/audit still exist. */
    cv_server *server = NULL;

    if (status == CV_OK) {
        status =
            cv_server_create(&config, security ? cv_security_handler : NULL, security, &server);
    }

    if (status == CV_OK && security) {
        status = cv_server_set_disconnect_handler(server, cv_security_disconnect);
    }

    if (status != CV_OK) {
        fprintf(stderr, "cvault-server: %s\n", cv_status_string(status));

        (void)cv_security_close(security);
        (void)cv_persist_close(store);

        return EXIT_FAILURE;
    }

    cv_console_signals previous;

    if (!cv_console_install(&previous, handle_signal)) {
        fputs("cvault-server: cannot install shutdown handlers\n", stderr);

        cv_server_destroy(server);
        (void)cv_security_close(security);
        (void)cv_persist_close(store);

        return EXIT_FAILURE;
    }

    printf("Listening on %s:%u (%s)\n",
           config.bind_address,
           (unsigned int)cv_server_port(server),
           cv_server_backend_name(server));
    fflush(stdout);

    /* Main loop: step the transport, watch service health, schedule snapshots. */
    uint64_t last_snapshot = scheduling_ms();

    while (status == CV_OK && !cv_server_is_stopped(server)) {
        if (stop_requested) {
            status = cv_server_request_stop(server);
        }

        if (status == CV_OK) {
            status = cv_server_step(server, 100);
        }

        if (status == CV_OK) {
            status = cv_security_status(security);
        }

        if (status == CV_OK && store) {
            bool done = false;

            status = cv_persist_snapshot_poll(store, &done);

            uint64_t now = scheduling_ms();

            if (status == CV_OK && done && !stop_requested && now >= last_snapshot &&
                now - last_snapshot >= snapshot_interval) {
                status = cv_persist_snapshot_start(store);
                last_snapshot = now;
            }
        }
    }

    /* Finish the owner-thread lifecycle in dependency order. A poisoned audit
     * service never acknowledges further work; persistence still closes/joins
     * outstanding snapshot jobs even when graceful checkpointing is skipped. */
    cv_console_restore(&previous);
    cv_server_destroy(server);

    if (store && status == CV_OK) {
        status = cv_persist_snapshot_wait(store);

        if (status == CV_OK) {
            status = cv_persist_snapshot(store);
        }
    }

    cv_status security_status = cv_security_close(security);

    if (status == CV_OK) {
        status = security_status;
    }

    cv_status close_status = cv_persist_close(store);

    if (status == CV_OK) {
        status = close_status;
    }

    if (status != CV_OK) {
        fprintf(stderr, "cvault-server: %s\n", cv_status_string(status));
    }

    return status == CV_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
