#ifndef CVAULT_SECURITY_SERVICE_H
#define CVAULT_SECURITY_SERVICE_H

#include "cvault/persist.h"
#include "cvault/server.h"

/** Application layer: owned policy/audit/sessions and optional memory table;
 * persistence is borrowed. Single-threaded, bounded Argon2id verification (64 MiB)
 * intentionally blocks briefly; global rate gate prevents verification floods.
 * Audit failures poison the service and must terminate the server loop. */
typedef struct cv_security cv_security;

/** Load/own configuration, authenticate audit history and record startup before
 * binding. Paths are consumed during this call. store is borrowed (NULL selects
 * owned volatile storage). *out resets on failure; clients bounds session slots. */
cv_status cv_security_open(const char *policy,
                           const char *audit,
                           const char *audit_key,
                           cv_persist *store,
                           size_t clients,
                           cv_security **out);

/** Command callback for cv_server_create; inherits its buffer/thread contract.
 * Wire errors become responses; fatal audit/store errors poison this service. */
cv_status cv_security_handler(void *context,
                              uint64_t id,
                              const unsigned char *line,
                              size_t length,
                              unsigned char *response,
                              size_t capacity,
                              size_t *written,
                              bool *close_after);

/** Register as the transport disconnect callback to wipe/reclaim session state. */
void cv_security_disconnect(void *context, uint64_t id);

/** Owner must check after every network step and stop on a non-OK result. */
cv_status cv_security_status(const cv_security *security);

/** Record STOP when healthy, close audit, wipe sessions/policy, free owned table.
 * Destroy transport first; borrowed store remains owned by caller. NULL is safe. */
cv_status cv_security_close(cv_security *security);

#endif
