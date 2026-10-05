/**
 * @file main.c
 * @brief Command-line entry point of `cvault-server`.
 *
 * Besides starting the server, the executable offers a few one-shot
 * maintenance modes that exit immediately: `--help`, `--version`,
 * `--generate-key`, `--hash-password` and `--dump-audit`. Options are parsed by
 * the vendored argparse library (see third_party/README.md); numeric values are
 * validated here with a strict decimal parser.
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

#include "argparse.h"
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
 * @brief Raw command-line values.
 *
 * Text options are NULL when they were not given, which lets the program tell
 * "absent" from "present with a default-looking value". Numbers stay text until
 * validated by parse_number().
 */
typedef struct {
    int version;                      /* --version */
    int hash_password;                /* --hash-password */
    const char *generate_key;         /* --generate-key FILE */
    const char *dump_audit;           /* --dump-audit FILE */
    const char *bind;                 /* --bind ADDRESS */
    const char *port;                 /* --port PORT */
    const char *max_clients;          /* --max-clients COUNT */
    const char *backend;              /* --backend auto|poll|epoll */
    const char *idle_timeout_ms;      /* --idle-timeout-ms MS */
    const char *frame_timeout_ms;     /* --frame-timeout-ms MS */
    const char *shutdown_timeout_ms;  /* --shutdown-timeout-ms MS */
    const char *data;                 /* --data DIRECTORY */
    const char *key_file;             /* --key-file FILE */
    const char *snapshot_interval_ms; /* --snapshot-interval-ms MS */
    const char *security;             /* --security FILE */
    const char *audit;                /* --audit FILE */
    const char *audit_key_file;       /* --audit-key-file FILE */
} cli_options;

/**
 * @brief Parse the command line into @p options.
 *
 * argparse prints the help text itself for `--help`, and reports unknown options
 * and missing values on stderr before exiting with status 1. Positional
 * arguments are never valid for this program.
 *
 * @return true when the command line is well formed.
 */
static bool parse_arguments(int argc, char **argv, cli_options *options) {
    static const char *const usages[] = {"cvault-server [options]", NULL};
    struct argparse_option definitions[] = {
        OPT_HELP(),
        OPT_BOOLEAN(
            0, "version", &options->version, "print the version and exit", NULL, 0, OPT_NONEG),

        OPT_GROUP("Network"),
        OPT_STRING(
            0, "bind", &options->bind, "numeric IPv4/IPv6 address (default 127.0.0.1)", NULL, 0, 0),
        OPT_STRING(
            0, "port", &options->port, "TCP port, 0 for ephemeral (default 6380)", NULL, 0, 0),
        OPT_STRING(0,
                   "max-clients",
                   &options->max_clients,
                   "connection limit, 1..1024 (default 128)",
                   NULL,
                   0,
                   0),
        OPT_STRING(
            0, "backend", &options->backend, "auto, poll or epoll (default auto)", NULL, 0, 0),
        OPT_STRING(0,
                   "idle-timeout-ms",
                   &options->idle_timeout_ms,
                   "idle connection deadline (default 30000)",
                   NULL,
                   0,
                   0),
        OPT_STRING(0,
                   "frame-timeout-ms",
                   &options->frame_timeout_ms,
                   "incomplete frame deadline (default 5000)",
                   NULL,
                   0,
                   0),
        OPT_STRING(0,
                   "shutdown-timeout-ms",
                   &options->shutdown_timeout_ms,
                   "response drain deadline (default 2000)",
                   NULL,
                   0,
                   0),

        OPT_GROUP("Persistence"),
        OPT_STRING(0,
                   "data",
                   &options->data,
                   "enable encrypted persistence in this directory (needs --key-file)",
                   NULL,
                   0,
                   0),
        OPT_STRING(0,
                   "key-file",
                   &options->key_file,
                   "existing private 32-byte encryption key",
                   NULL,
                   0,
                   0),
        OPT_STRING(0,
                   "snapshot-interval-ms",
                   &options->snapshot_interval_ms,
                   "background checkpoint interval (default 60000)",
                   NULL,
                   0,
                   0),

        OPT_GROUP("Security"),
        OPT_STRING(0,
                   "security",
                   &options->security,
                   "private credential and prefix policy file",
                   NULL,
                   0,
                   0),
        OPT_STRING(0,
                   "audit",
                   &options->audit,
                   "encrypted audit stream (required with --security)",
                   NULL,
                   0,
                   0),
        OPT_STRING(0,
                   "audit-key-file",
                   &options->audit_key_file,
                   "separate private 32-byte audit master key",
                   NULL,
                   0,
                   0),

        OPT_GROUP("Maintenance commands (run once, then exit)"),
        OPT_STRING(0,
                   "generate-key",
                   &options->generate_key,
                   "create a new key file and exit; never overwrites",
                   NULL,
                   0,
                   0),
        OPT_BOOLEAN(0,
                    "hash-password",
                    &options->hash_password,
                    "read a password from stdin and print its Argon2id hash",
                    NULL,
                    0,
                    OPT_NONEG),
        OPT_STRING(0,
                   "dump-audit",
                   &options->dump_audit,
                   "verify and export this audit file as JSON Lines (needs --audit-key-file, "
                   "server stopped)",
                   NULL,
                   0,
                   0),
        OPT_END(),
    };
    struct argparse parser;

    argparse_init(&parser, definitions, usages, 0);
    argparse_describe(&parser,
                      "\nA small encrypted key-value store served over TCP.",
                      "\nTCP transport: AUTH and prefix-controlled storage with --security; "
                      "otherwise PING/QUIT probes only.");

    /* argparse returns the number of leftover positional arguments. */
    if (argparse_parse(&parser, argc, (const char **)argv) != 0) {
        fputs("cvault-server: unexpected argument. See --help.\n", stderr);

        return false;
    }

    return true;
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
 * @brief Read a numeric option, keeping @p value unchanged when it is absent.
 *
 * @param name       Option name for the error message (without dashes).
 * @param text       Option text, or NULL when the option was not given.
 * @param maximum    Largest accepted value.
 * @param allow_zero Whether zero is acceptable (only the port allows it).
 * @param value      Receives the number when the option is present.
 * @return false (after printing a message) when the text is invalid.
 */
static bool read_number(const char *name,
                        const char *text,
                        unsigned long maximum,
                        bool allow_zero,
                        unsigned long *value) {
    if (!text) {
        return true;
    }

    unsigned long number = 0;

    if (!parse_number(text, maximum, &number) || (number == 0 && !allow_zero)) {
        fprintf(stderr, "cvault-server: invalid value for --%s. See --help.\n", name);

        return false;
    }

    *value = number;

    return true;
}

/**
 * @brief Build the server configuration from the parsed options.
 *
 * @param options           Parsed command line.
 * @param config            Starts at the defaults and receives the overrides.
 * @param snapshot_interval Receives the snapshot interval in milliseconds.
 * @return false (after printing a message) when any value is invalid.
 */
static bool
build_config(const cli_options *options, cv_server_config *config, uint32_t *snapshot_interval) {
    unsigned long port = config->port, clients = config->max_clients;
    unsigned long idle = config->idle_timeout_ms, frame = config->frame_timeout_ms;
    unsigned long shutdown = config->shutdown_timeout_ms, interval = *snapshot_interval;

    if (!read_number("port", options->port, UINT16_MAX, true, &port) ||
        !read_number("max-clients",
                     options->max_clients,
                     (unsigned long)CV_HARD_MAX_CLIENTS,
                     false,
                     &clients) ||
        !read_number("idle-timeout-ms", options->idle_timeout_ms, INT_MAX, false, &idle) ||
        !read_number("frame-timeout-ms", options->frame_timeout_ms, INT_MAX, false, &frame) ||
        !read_number(
            "shutdown-timeout-ms", options->shutdown_timeout_ms, INT_MAX, false, &shutdown) ||
        !read_number(
            "snapshot-interval-ms", options->snapshot_interval_ms, INT_MAX, false, &interval)) {
        return false;
    }

    config->port = (uint16_t)port;
    config->max_clients = (size_t)clients;
    config->idle_timeout_ms = (uint32_t)idle;
    config->frame_timeout_ms = (uint32_t)frame;
    config->shutdown_timeout_ms = (uint32_t)shutdown;
    *snapshot_interval = (uint32_t)interval;

    if (options->bind) {
        config->bind_address = options->bind;
    }

    if (options->backend) {
        if (strcmp(options->backend, "auto") == 0) {
            config->backend = CV_NETWORK_AUTO;
        } else if (strcmp(options->backend, "poll") == 0) {
            config->backend = CV_NETWORK_POLL;
        } else if (strcmp(options->backend, "epoll") == 0) {
            config->backend = CV_NETWORK_EPOLL;
        } else {
            fputs("cvault-server: invalid network backend. See --help.\n", stderr);

            return false;
        }
    }

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

/** @brief True when any option that only makes sense for a running server was given. */
static bool has_serving_options(const cli_options *options) {
    return options->bind || options->port || options->max_clients || options->backend ||
           options->idle_timeout_ms || options->frame_timeout_ms || options->shutdown_timeout_ms ||
           options->data || options->key_file || options->snapshot_interval_ms ||
           options->security || options->audit;
}

/**
 * @brief Check the combination of options.
 *
 * Persistence and security each need all of their options. A maintenance
 * command stands alone: it cannot be combined with another command or with
 * server options.
 *
 * @param maintenance Set to true when a maintenance command was requested.
 * @return false (after printing a message) for an invalid combination.
 */
static bool check_combinations(const cli_options *options, bool *maintenance) {
    int commands = (options->version != 0) + (options->hash_password != 0) +
                   (options->generate_key != NULL) + (options->dump_audit != NULL);

    *maintenance = commands != 0;

    if (commands > 1 || (commands == 1 && has_serving_options(options)) ||
        (commands == 1 && options->audit_key_file && !options->dump_audit)) {
        fputs("cvault-server: a maintenance command cannot be combined with other options. "
              "See --help.\n",
              stderr);

        return false;
    }

    if (options->dump_audit && !options->audit_key_file) {
        fputs("cvault-server: --dump-audit requires --audit-key-file. See --help.\n", stderr);

        return false;
    }

    if (commands != 0) {
        return true;
    }

    if ((options->data == NULL) != (options->key_file == NULL) ||
        (options->snapshot_interval_ms && !options->data)) {
        fputs("Persistence requires --data and --key-file together. See --help.\n", stderr);

        return false;
    }

    if ((options->security || options->audit || options->audit_key_file) &&
        !(options->security && options->audit && options->audit_key_file)) {
        fputs("Security requires --security, --audit and --audit-key-file together. See --help.\n",
              stderr);

        return false;
    }

    return true;
}

/** @brief Run one of the maintenance commands and return the process exit code. */
static int run_maintenance(const cli_options *options) {
    if (options->version) {
        puts("cvault-server " CVAULT_VERSION);

        return EXIT_SUCCESS;
    }

    if (options->generate_key) {
        cv_status result = cv_persist_key_generate(options->generate_key);

        if (result != CV_OK) {
            fprintf(stderr, "cvault-server: %s\n", cv_status_string(result));
        }

        return result == CV_OK ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (options->dump_audit) {
        return dump_audit(options->dump_audit, options->audit_key_file);
    }

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

/** @brief Recover state, serve until a signal arrives, shut down in order. */
static int run_server(const cli_options *options) {
    cv_server_config config = cv_server_config_default();
    uint32_t snapshot_interval = 60000;

    if (!build_config(options, &config, &snapshot_interval)) {
        return EXIT_FAILURE;
    }

    /* Recover durable state and validate security before exposing a listener.
     * An invalid policy, key or authenticated file must prevent readiness. */
    cv_persist *store = NULL;
    cv_status status = CV_OK;

    if (options->data) {
        unsigned char key[CV_PERSIST_KEY_BYTES];

        status = cv_persist_key_load(options->key_file, key);

        cv_persist_options persist_options = {options->data, key, sizeof(key), NULL, NULL};

        if (status == CV_OK) {
            status = cv_persist_open(&persist_options, &store);
        }

        cv_crypto_wipe(key, sizeof(key));

        if (status != CV_OK) {
            fprintf(stderr, "cvault-server: recovery failed: %s\n", cv_status_string(status));

            return EXIT_FAILURE;
        }
    }

    cv_security *security = NULL;

    if (options->security) {
        status = cv_security_open(options->security,
                                  options->audit,
                                  options->audit_key_file,
                                  store,
                                  config.max_clients,
                                  &security);
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

int main(int argc, char **argv) {
    cli_options options = {0};
    bool maintenance = false;

    if (!parse_arguments(argc, argv, &options) || !check_combinations(&options, &maintenance)) {
        return EXIT_FAILURE;
    }

    return maintenance ? run_maintenance(&options) : run_server(&options);
}
