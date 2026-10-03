#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cvault/server.h"
#include "cvault/version.h"
#include "console_signals.h"

static volatile sig_atomic_t stop_requested = 0;
static void handle_signal(int number) {
    (void)number;
    stop_requested = 1;
}

/* Strict decimal parsing rejects signs, whitespace, trailing junk and overflow. */
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

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        puts("Usage: cvault-server [options]\n"
             "  --bind ADDRESS          Numeric IPv4/IPv6 address (default 127.0.0.1)\n"
             "  --port PORT             TCP port, 0 for ephemeral (default 6380)\n"
             "  --max-clients COUNT     Connection limit, 1..1024 (default 128)\n"
             "  --backend auto|poll|epoll\n"
             "  --idle-timeout-ms MS    Idle connection deadline (default 30000)\n"
             "  --frame-timeout-ms MS   Incomplete frame deadline (default 5000)\n"
             "  --shutdown-timeout-ms MS  Response drain deadline (default 2000)\n"
             "  --help | --version\n"
             "TCP transport: PING and QUIT probes available; storage command dispatch is pending.");
        return EXIT_SUCCESS;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("cvault-server " CVAULT_VERSION);
        return EXIT_SUCCESS;
    }
    cv_server_config config = cv_server_config_default();
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 >= argc) {
            fputs("Missing option value. See --help.\n", stderr);
            return EXIT_FAILURE;
        }
        const char *option = argv[i];
        const char *value = argv[i + 1];
        if (strcmp(option, "--bind") == 0) {
            config.bind_address = value;
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
            unsigned long maximum = INT_MAX;
            if (strcmp(option, "--port") == 0) {
                maximum = UINT16_MAX;
            } else if (strcmp(option, "--max-clients") == 0) {
                maximum = (unsigned long)CV_HARD_MAX_CLIENTS;
            } else if (strcmp(option, "--idle-timeout-ms") != 0 &&
                       strcmp(option, "--frame-timeout-ms") != 0 &&
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
            } else {
                config.shutdown_timeout_ms = (uint32_t)number;
            }
        }
    }
    cv_server *server = NULL;
    cv_status status = cv_server_create(&config, NULL, NULL, &server);
    if (status != CV_OK) {
        fprintf(stderr, "cvault-server: %s\n", cv_status_string(status));
        return EXIT_FAILURE;
    }
    cv_console_signals previous;
    if (!cv_console_install(&previous, handle_signal)) {
        fputs("cvault-server: cannot install shutdown handlers\n", stderr);
        cv_server_destroy(server);
        return EXIT_FAILURE;
    }
    printf("Listening on %s:%u (%s)\n", config.bind_address,
           (unsigned int)cv_server_port(server), cv_server_backend_name(server));
    fflush(stdout);
    while (status == CV_OK && !cv_server_is_stopped(server)) {
        if (stop_requested) {
            status = cv_server_request_stop(server);
        }
        if (status == CV_OK) {
            status = cv_server_step(server, 100);
        }
    }
    cv_console_restore(&previous);
    cv_server_destroy(server);
    if (status != CV_OK) {
        fprintf(stderr, "cvault-server: %s\n", cv_status_string(status));
    }
    return status == CV_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
