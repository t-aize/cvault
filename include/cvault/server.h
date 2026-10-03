#ifndef CVAULT_SERVER_H
#define CVAULT_SERVER_H

#include "cvault/common.h"
#include "cvault/config.h"
#include <stdbool.h>

/** @file Nonblocking, bounded, single-threaded TCP transport.
 * AUTO uses level-triggered epoll on Linux, poll on POSIX, WSAPoll on Windows.
 * All calls/callbacks belong to one thread. No callbacks may reenter the server.
 * The transport does not implement authentication, command parsing or storage.
 */
typedef struct cv_server cv_server;

/** Handle one complete LF-terminated, NUL-free line, including its terminator.
 * client_id is unique within this server. Input/output slices are borrowed for
 * this call only. Write at most response_capacity bytes and fill response_length.
 * close_after_response requests orderly closure after the response is sent.
 * The callback must be bounded/nonblocking; errors close only this client.
 * NULL handler selects PING/QUIT probes and rejects all storage commands.
 */
typedef cv_status (*cv_server_handler)(void *context, uint64_t client_id,
    const unsigned char *line, size_t line_length, unsigned char *response,
    size_t response_capacity, size_t *response_length, bool *close_after_response);

typedef struct {
    size_t active_clients;
    uint64_t accepted_clients;
    uint64_t rejected_clients;
} cv_server_stats;

/** Bind/listen immediately. Numeric IPv4/IPv6 only; port zero selects an ephemeral
 * port. Configuration strings are consumed during creation, not borrowed later.
 * Handler context is borrowed until destroy. Resets *out on failure.
 * Errors: INVALID_ARGUMENT, NO_MEMORY, IO, NOT_IMPLEMENTED (unavailable backend).
 */
cv_status cv_server_create(const cv_server_config *config, cv_server_handler handler,
                          void *context, cv_server **out);

/** One bounded event-loop iteration. timeout_ms is 0..INT_MAX milliseconds;
 * timer deadlines may shorten it. EINTR is a successful, nonfatal iteration.
 * Returns IO for listener/backend/clock failures; peer errors are isolated.
 */
cv_status cv_server_step(cv_server *server, int timeout_ms);

/** Stop accepting/reading, drain already queued responses, then close clients.
 * Shutdown has a configured deadline; repeated requests are harmless. Call only
 * on the owning thread, never directly from a signal handler.
 */
cv_status cv_server_request_stop(cv_server *server);
bool cv_server_is_stopped(const cv_server *server);
uint16_t cv_server_port(const cv_server *server);
const char *cv_server_backend_name(const cv_server *server);
cv_status cv_server_get_stats(const cv_server *server, cv_server_stats *out);

/** Close all sockets, wipe buffers, release platform state. NULL is safe. */
void cv_server_destroy(cv_server *server);

/** Console convenience loop: temporarily owns SIGINT/SIGTERM handlers and restores
 * them on exit. Only one run() may execute per process. Embedders should instead
 * drive create/step/request_stop/destroy and manage signals themselves.
 */
cv_status cv_server_run(const cv_server_config *config);

#endif
