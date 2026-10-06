/**
 * @file config.h
 * @brief Compile-time limits and runtime configuration of the TCP server.
 *
 * The limits below are protocol-level contracts: the parser, the storage layer,
 * the transport and the encrypted persistence formats all enforce them, so a
 * change here is a format and compatibility change.
 */

#ifndef CVAULT_CONFIG_H
#define CVAULT_CONFIG_H

#include <stddef.h>
#include <stdint.h>

/** Longest accepted key, in bytes (excluding any terminator). */
#define CV_MAX_KEY_BYTES ((size_t)256)

/** Longest accepted value, in bytes. Values are binary safe. */
#define CV_MAX_VALUE_BYTES ((size_t)65536)

/** Longest accepted request line: command word, key, value and separators. */
#define CV_MAX_LINE_BYTES (CV_MAX_KEY_BYTES + CV_MAX_VALUE_BYTES + (size_t)32)

/** Default number of simultaneously connected clients. */
#define CV_MAX_CLIENTS ((size_t)128)

/** Absolute upper bound a caller may request for the client cap. */
#define CV_HARD_MAX_CLIENTS ((size_t)1024)

/**
 * Largest reply the server will ever build for one request. It leaves room for a
 * full-size value plus the framing of GET and of an EXPORT page holding one entry
 * (key, TTL and length fields, page header and continuation line).
 */
#define CV_MAX_RESPONSE_BYTES (CV_MAX_VALUE_BYTES + (size_t)1024)

/** Socket readiness mechanism used by the event loop. */
typedef enum {
    CV_NETWORK_AUTO = 0, /**< epoll on Linux, poll()/WSAPoll() everywhere else. */
    CV_NETWORK_POLL,     /**< Portable poll()/WSAPoll() backend. */
    CV_NETWORK_EPOLL     /**< Linux epoll backend; rejected on other platforms. */
} cv_network_backend;

/**
 * @brief Options accepted by cv_server_create().
 *
 * Obtain a fully populated instance from cv_server_config_default() and adjust
 * the fields you need; the structure is copied during server creation.
 */
typedef struct {
    /** Numeric IPv4/IPv6 address, consumed during server creation. */
    const char *bind_address;

    /** TCP port; zero requests an OS-selected ephemeral port. */
    uint16_t port;

    /** Not used by the transport: persistence is configured separately (cv_persist_open()). */
    const char *data_directory;

    /** Active connection cap, between 1 and #CV_HARD_MAX_CLIENTS. */
    size_t max_clients;

    /** Readiness backend; #CV_NETWORK_AUTO picks the best one available. */
    cv_network_backend backend;

    /** Close a connection that stays silent this long (monotonic ms, 1..INT_MAX). */
    uint32_t idle_timeout_ms;

    /** Close a connection that leaves a request line unfinished this long (ms). */
    uint32_t frame_timeout_ms;

    /** Upper bound for flushing replies during a graceful shutdown (ms). */
    uint32_t shutdown_timeout_ms;
} cv_server_config;

/**
 * @brief Build the default server configuration.
 *
 * Defaults: loopback IPv4 on port 6380, #CV_MAX_CLIENTS connections, automatic
 * backend, 30 s idle timeout, 5 s frame timeout and 2 s shutdown grace period.
 *
 * @return A value-initialised configuration; no resources are allocated.
 */
cv_server_config cv_server_config_default(void);

#endif /* CVAULT_CONFIG_H */
