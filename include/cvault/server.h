/**
 * @file server.h
 * @brief Non-blocking, bounded, single-threaded TCP transport.
 *
 * The transport accepts connections, frames LF-terminated request lines and
 * hands each complete line to a handler callback; whatever the handler writes
 * is sent back to the client. It knows nothing about authentication, command
 * parsing or storage: those live in the layers above.
 *
 * ## Backends
 * `CV_NETWORK_AUTO` uses level-triggered epoll on Linux, poll() on other POSIX
 * systems and WSAPoll() on Windows.
 *
 * ## Threading
 * All calls and callbacks belong to one thread, and no callback may re-enter
 * the server.
 *
 * ## Resource bounds
 * Every connection has a fixed buffer, at most one queued reply, idle and
 * frame-completion timeouts, and per-tick I/O and accept budgets, so one slow
 * or hostile peer cannot starve the others.
 */

#ifndef CVAULT_SERVER_H
#define CVAULT_SERVER_H

#include "cvault/common.h"
#include "cvault/config.h"

#include <stdbool.h>

/** Opaque handle to a running transport. */
typedef struct cv_server cv_server;

/**
 * @brief Handle one complete request line.
 *
 * The line is LF-terminated, NUL-free and includes its terminator. Input and
 * output slices are borrowed for this call only. The handler writes at most
 * @p response_capacity bytes and reports the count through @p response_length.
 * It must be bounded: blocking work delays every client. Returning an error
 * closes only this client. When no handler is supplied the transport answers
 * PING and QUIT probes and rejects every storage command.
 *
 * @param context              Opaque pointer given to cv_server_create().
 * @param client_id            Identifier unique within this server.
 * @param line                 Request bytes.
 * @param line_length          Number of request bytes.
 * @param response             Buffer to fill with the reply.
 * @param response_capacity    Size of @p response.
 * @param response_length      Receives the reply length.
 * @param close_after_response Set to true to close the connection after the
 *                             reply has been sent.
 * @return #CV_OK, or an error that closes this connection.
 */
typedef cv_status (*cv_server_handler)(void *context,
                                       uint64_t client_id,
                                       const unsigned char *line,
                                       size_t line_length,
                                       unsigned char *response,
                                       size_t response_capacity,
                                       size_t *response_length,
                                       bool *close_after_response);

/** Connection counters. */
typedef struct {
    size_t active_clients;     /**< Currently connected clients. */
    uint64_t accepted_clients; /**< Connections accepted since start. */
    uint64_t rejected_clients; /**< Connections refused (full or out of resources). */
} cv_server_stats;

/**
 * @brief Bind, listen and create the server.
 *
 * Only numeric IPv4/IPv6 addresses are accepted; port zero selects an ephemeral
 * port. Configuration strings are consumed during creation and not borrowed
 * afterwards. The handler context is borrowed until cv_server_destroy().
 *
 * @param config  Server options, see cv_server_config_default().
 * @param handler Request handler, or NULL for the built-in probe handler.
 * @param context Opaque pointer passed to the handler.
 * @param out     Receives the server; set to NULL on failure.
 * @return #CV_OK, #CV_ERR_INVALID_ARGUMENT, #CV_ERR_NO_MEMORY, #CV_ERR_IO or
 *         #CV_ERR_NOT_IMPLEMENTED when the requested backend is unavailable.
 */
cv_status cv_server_create(const cv_server_config *config,
                           cv_server_handler handler,
                           void *context,
                           cv_server **out);

/**
 * @brief Notification that a client is gone.
 *
 * Called on the owner thread once per accepted peer, whatever the reason
 * (close, timeout, error, shutdown or destroy). It must not re-enter the
 * server. The context is the same one the command handler receives.
 *
 * @param context   Opaque pointer given to cv_server_create().
 * @param client_id Identifier of the departing client.
 */
typedef void (*cv_server_disconnect_handler)(void *context, uint64_t client_id);

/**
 * @brief Install (or clear, with NULL) the disconnect callback.
 *
 * @return #CV_OK or #CV_ERR_INVALID_ARGUMENT.
 */
cv_status cv_server_set_disconnect_handler(cv_server *server, cv_server_disconnect_handler handler);

/**
 * @brief Run one bounded event-loop iteration.
 *
 * Timer deadlines may shorten the wait. An interrupted system call counts as a
 * successful, non-fatal iteration; peer errors are isolated to that peer.
 *
 * @param server     Server to drive.
 * @param timeout_ms Longest wait for events, 0..INT_MAX milliseconds.
 * @return #CV_OK, #CV_ERR_INVALID_ARGUMENT, or #CV_ERR_IO for listener, backend
 *         or clock failures.
 */
cv_status cv_server_step(cv_server *server, int timeout_ms);

/**
 * @brief Begin a graceful shutdown.
 *
 * Stops accepting and reading, drains replies that are already queued, then
 * closes the clients. The configured shutdown deadline bounds the process, and
 * repeated requests are harmless. Call it only on the owning thread, never
 * directly from a signal handler.
 */
cv_status cv_server_request_stop(cv_server *server);

/** @brief True once a stop was requested and every client has been closed. */
bool cv_server_is_stopped(const cv_server *server);

/** @brief The bound TCP port (useful after binding port 0), or 0 for NULL. */
uint16_t cv_server_port(const cv_server *server);

/** @brief Name of the active backend: "epoll", "poll" or "WSAPoll". */
const char *cv_server_backend_name(const cv_server *server);

/**
 * @brief Copy the connection counters.
 *
 * @param out Receives the counters; zeroed on error.
 */
cv_status cv_server_get_stats(const cv_server *server, cv_server_stats *out);

/**
 * @brief Close every socket, wipe all buffers and release platform state.
 *
 * @param server Server to destroy; NULL is safe.
 */
void cv_server_destroy(cv_server *server);

/**
 * @brief Console convenience loop with the default probe handler.
 *
 * Temporarily owns the SIGINT/SIGTERM handlers (and SIGBREAK on Windows) and
 * restores them on exit. Only one cv_server_run() may execute per process.
 * Embedders should instead drive create / step / request_stop / destroy and
 * manage signals themselves.
 *
 * @return #CV_OK after an orderly stop, or the error that ended the loop.
 */
cv_status cv_server_run(const cv_server_config *config);

#endif /* CVAULT_SERVER_H */
