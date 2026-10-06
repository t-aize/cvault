/**
 * @file security_service.h
 * @brief Application layer tying authentication, ACLs, audit and storage together.
 *
 * The service sits between the TCP transport and the storage backends. For each
 * request line it parses the command, enforces authentication and the per-prefix
 * ACL, writes an audit *intent* event, runs the storage operation, writes the
 * audit *result* event and only then formats the reply. A request whose intent
 * could not be recorded is never executed.
 *
 * ## Ownership
 * The service owns its policy, audit log, client sessions and, when no durable
 * store is supplied, a volatile in-memory table. A durable store is borrowed.
 *
 * ## Behaviour worth knowing
 *  - Single-threaded. Argon2id verification (64 MiB) intentionally blocks the
 *    loop briefly; a global gate admits at most four verifications per second.
 *  - Three failed AUTH attempts on one connection close it.
 *  - An audit failure poisons the service; the owner must stop the server loop.
 */

#ifndef CVAULT_SECURITY_SERVICE_H
#define CVAULT_SECURITY_SERVICE_H

#include "cvault/persist.h"
#include "cvault/server.h"

/** Opaque security service handle. */
typedef struct cv_security cv_security;

/**
 * @brief Load the configuration, authenticate the audit history, record START.
 *
 * Call it before binding the listening socket. The paths are only used during
 * this call.
 *
 * @param policy    Path of the policy file (users and prefix rules).
 * @param audit     Path of the encrypted audit log; created when missing.
 * @param audit_key Path of the file holding the 32-byte audit master key.
 * @param store     Durable store to use, or NULL for an owned volatile table.
 *                  A non-NULL store is borrowed and must outlive the service.
 * @param clients   Number of session slots, 1..#CV_HARD_MAX_CLIENTS.
 * @param out       Receives the service; set to NULL on failure.
 * @return #CV_OK or the error of the failing step (policy, key, audit, memory).
 */
cv_status cv_security_open(const char *policy,
                           const char *audit,
                           const char *audit_key,
                           cv_persist *store,
                           size_t clients,
                           cv_security **out);

/**
 * @brief Command callback to pass to cv_server_create().
 *
 * It inherits the transport's buffer and thread contract. Protocol errors turn
 * into error replies; fatal audit or storage errors poison the service and are
 * returned so the loop can stop.
 *
 * @param context     The #cv_security handle.
 * @param id          Unique transport ID of the client.
 * @param line        Complete request line including its terminator.
 * @param length      Length of @p line.
 * @param response    Output buffer for the reply.
 * @param capacity    Size of @p response.
 * @param written     Receives the reply length.
 * @param close_after Set to true to close the connection after the reply.
 * @return #CV_OK, or a fatal status that must stop the server.
 */
cv_status cv_security_handler(void *context,
                              uint64_t id,
                              const unsigned char *line,
                              size_t length,
                              unsigned char *response,
                              size_t capacity,
                              size_t *written,
                              bool *close_after);

/**
 * @brief Disconnect callback: wipe and recycle the session of a client.
 *
 * Register it as the transport disconnect callback so privileges can never
 * outlive a connection.
 *
 * @param context The #cv_security handle.
 * @param id      Transport ID of the departing client.
 */
void cv_security_disconnect(void *context, uint64_t id);

/**
 * @brief Erase expired entries from the storage backend in use.
 *
 * Meant to be called on a timer by the owner of the event loop. It is not an
 * audited operation: it only removes values that are already unreadable.
 *
 * @param security Service whose storage is swept.
 * @param removed  Receives the number of erased entries; reset to 0 on error.
 * @return #CV_OK, #CV_ERR_INVALID_ARGUMENT, the fatal error that poisoned the
 *         service, or a storage/clock error.
 */
cv_status cv_security_purge_expired(cv_security *security, size_t *removed);

/**
 * @brief Report whether the service is still healthy.
 *
 * The owner must check it after every network step and stop on a non-OK value.
 *
 * @param security Service to inspect; NULL reports #CV_OK.
 * @return #CV_OK, or the first fatal error that poisoned the service.
 */
cv_status cv_security_status(const cv_security *security);

/**
 * @brief Record STOP when healthy, close the audit log, wipe all state.
 *
 * Destroy the transport first. A borrowed store remains owned by the caller.
 *
 * @param security Service to close; NULL is safe.
 * @return #CV_OK, or the fatal error that poisoned the service or the audit
 *         close error.
 */
cv_status cv_security_close(cv_security *security);

#endif /* CVAULT_SECURITY_SERVICE_H */
