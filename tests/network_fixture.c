/**
 * @file network_fixture.c
 * @brief Test server for the TCP transport, driven by tests/test_network.py.
 *
 * Run without arguments (or with `poll` / `epoll`) it starts a server on an
 * ephemeral loopback port and serves a small set of test commands. Run with
 * `--api-tests` it exercises the C API directly and exits.
 *
 * Test commands understood by the handler:
 *
 *     BIG       reply of the maximum size
 *     ID        reply with the client ID
 *     ECHO x    reply with x
 *     ZERO      empty reply
 *     BAD       handler failure (the transport must close the client)
 *     OVERSIZE  reply length beyond the buffer (the transport must reject it)
 *     STOP      reply +OK and shut the server down
 *     CLOSE     reply +OK and close the connection
 *     PING      reply +PONG
 */

#include "cvault/server.h"
#include "test_util.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** Handler that implements the test commands; `context` points to a stop flag. */
static cv_status handler(void *context,
                         uint64_t id,
                         const unsigned char *line,
                         size_t length,
                         unsigned char *response,
                         size_t capacity,
                         size_t *written,
                         bool *close_after) {
    bool *stop = context;
    const char *reply = "-ERR unknown\n";

    if (length == 4 && memcmp(line, "BIG\n", 4) == 0) {
        memset(response, 'B', capacity);

        response[capacity - 1] = '\n';
        *written = capacity;

        return CV_OK;
    }

    if (length == 3 && memcmp(line, "ID\n", 3) == 0) {
        int result = snprintf((char *)response, capacity, "%llu\n", (unsigned long long)id);

        if (result < 0 || (size_t)result >= capacity) {
            return CV_ERR_LIMIT;
        }

        *written = (size_t)result;

        return CV_OK;
    }

    if (length >= 5 && memcmp(line, "ECHO ", 5) == 0) {
        if (length - 5 > capacity) {
            return CV_ERR_LIMIT;
        }

        *written = length - 5;

        memcpy(response, line + 5, *written);

        return CV_OK;
    }

    if (length == 5 && memcmp(line, "ZERO\n", 5) == 0) {
        *written = 0;

        return CV_OK;
    }

    if (length == 4 && memcmp(line, "BAD\n", 4) == 0) {
        return CV_ERR_IO;
    }

    if (length == 9 && memcmp(line, "OVERSIZE\n", 9) == 0) {
        *written = capacity + 1;

        return CV_OK;
    }

    if (length == 5 && memcmp(line, "STOP\n", 5) == 0) {
        *stop = true;
        reply = "+OK\n";
    } else if (length == 6 && memcmp(line, "CLOSE\n", 6) == 0) {
        *close_after = true;
        reply = "+OK\n";
    } else if (length == 5 && memcmp(line, "PING\n", 5) == 0) {
        reply = "+PONG\n";
    }

    *written = strlen(reply);

    memcpy(response, reply, *written);

    return CV_OK;
}

/** @brief Direct tests of the public server API: argument validation and lifecycle. */
static int api_checks(void) {
    cv_server *server = NULL;
    cv_server_config config = cv_server_config_default();

    /* NULL arguments. */
    CHECK(cv_server_create(&config, NULL, NULL, NULL) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_server_create(NULL, NULL, NULL, &server) == CV_ERR_INVALID_ARGUMENT && server == NULL);
    CHECK(cv_server_step(NULL, 0) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_server_request_stop(NULL) == CV_ERR_INVALID_ARGUMENT);
    CHECK(!cv_server_is_stopped(NULL) && cv_server_port(NULL) == 0);
    CHECK(strcmp(cv_server_backend_name(NULL), "none") == 0);

    cv_server_stats stats = {1, 1, 1};

    CHECK(cv_server_get_stats(NULL, &stats) == CV_ERR_INVALID_ARGUMENT &&
          stats.active_clients == 0);
    CHECK(cv_server_get_stats(NULL, NULL) == CV_ERR_INVALID_ARGUMENT);

    /* Invalid configuration values, one at a time. */
    config.max_clients = CV_HARD_MAX_CLIENTS + 1;

    CHECK(cv_server_create(&config, NULL, NULL, &server) == CV_ERR_INVALID_ARGUMENT);

    config = cv_server_config_default();
    config.bind_address = "not-a-numeric-address";

    CHECK(cv_server_create(&config, NULL, NULL, &server) == CV_ERR_INVALID_ARGUMENT);

    config.bind_address = NULL;

    CHECK(cv_server_create(&config, NULL, NULL, &server) == CV_ERR_INVALID_ARGUMENT);

    config = cv_server_config_default();
    config.idle_timeout_ms = 0;

    CHECK(cv_server_create(&config, NULL, NULL, &server) == CV_ERR_INVALID_ARGUMENT);

    config = cv_server_config_default();
    config.frame_timeout_ms = 0;

    CHECK(cv_server_create(&config, NULL, NULL, &server) == CV_ERR_INVALID_ARGUMENT);

    config = cv_server_config_default();
    config.shutdown_timeout_ms = 0;

    CHECK(cv_server_create(&config, NULL, NULL, &server) == CV_ERR_INVALID_ARGUMENT);

    config = cv_server_config_default();
    config.backend = (cv_network_backend)99;

    CHECK(cv_server_create(&config, NULL, NULL, &server) == CV_ERR_INVALID_ARGUMENT);

#ifndef __linux__
    config.backend = CV_NETWORK_EPOLL;

    CHECK(cv_server_create(&config, NULL, NULL, &server) == CV_ERR_NOT_IMPLEMENTED);
#endif

    /* A valid server on an ephemeral port. */
    config = cv_server_config_default();
    config.port = 0;

    CHECK(cv_server_create(&config, NULL, NULL, &server) == CV_OK);

#ifdef __linux__
    CHECK(strcmp(cv_server_backend_name(server), "epoll") == 0);
#elif defined(_WIN32)
    CHECK(strcmp(cv_server_backend_name(server), "WSAPoll") == 0);
#else
    CHECK(strcmp(cv_server_backend_name(server), "poll") == 0);
#endif

    CHECK(cv_server_port(server) != 0);
    CHECK(cv_server_step(server, -1) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_server_step(server, 0) == CV_OK);
    CHECK(cv_server_get_stats(server, &stats) == CV_OK && stats.active_clients == 0);

    /* Binding the same port twice must fail cleanly. */
    config.port = cv_server_port(server);

    cv_server *duplicate = NULL;

    CHECK(cv_server_create(&config, NULL, NULL, &duplicate) == CV_ERR_IO && duplicate == NULL);

    /* Stopping is idempotent and leaves the server stopped. */
    CHECK(cv_server_request_stop(server) == CV_OK);
    CHECK(cv_server_request_stop(server) == CV_OK && cv_server_is_stopped(server));
    CHECK(cv_server_step(server, 0) == CV_OK);

    cv_server_destroy(server);
    cv_server_destroy(NULL);

    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--api-tests") == 0) {
        return api_checks();
    }

    /* Short timeouts keep the Python integration tests fast. */
    cv_server_config config = cv_server_config_default();

    config.port = 0;
    config.max_clients = 4;
    config.idle_timeout_ms = 1200;
    config.frame_timeout_ms = 500;
    config.shutdown_timeout_ms = 400;

    if (argc == 2 && strcmp(argv[1], "poll") == 0) {
        config.backend = CV_NETWORK_POLL;
    } else if (argc == 2 && strcmp(argv[1], "epoll") == 0) {
        config.backend = CV_NETWORK_EPOLL;
    } else if (argc != 1) {
        return EXIT_FAILURE;
    }

    bool stop = false;
    cv_server *server = NULL;
    cv_status status = cv_server_create(&config, handler, &stop, &server);

    if (status != CV_OK) {
        fprintf(stderr, "fixture startup: %s\n", cv_status_string(status));

        return EXIT_FAILURE;
    }

    /* The Python tests parse this line to discover the port. */
    printf("Listening on 127.0.0.1:%u (%s)\n",
           (unsigned int)cv_server_port(server),
           cv_server_backend_name(server));
    fflush(stdout);

    while (status == CV_OK && !cv_server_is_stopped(server)) {
        if (stop) {
            status = cv_server_request_stop(server);
        }

        if (status == CV_OK) {
            status = cv_server_step(server, 100);
        }
    }

    cv_server_destroy(server);

    if (status != CV_OK) {
        fprintf(stderr, "fixture loop: %s\n", cv_status_string(status));
    }

    return status == CV_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
