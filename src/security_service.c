#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
#include "cvault/audit.h"
#include "cvault/crypto.h"
#include "cvault/parser.h"
#include "security_service.h"

/** A slot belongs to a unique transport ID, never a reusable socket descriptor.
 * Disconnect notifications wipe the complete slot, preventing privilege reuse. */
typedef struct {
    uint64_t id;
    unsigned int failures;
    cv_auth_session session;
} client;

struct cv_security {
    cv_auth_policy *policy;
    cv_audit *audit;
    cv_hashtable *memory;
    cv_persist *store;
    client *clients;
    size_t capacity;
    uint64_t request, last_auth;
    bool attempted;
    cv_status failure;
};

static cv_status monotonic(uint64_t *out) {
#ifdef _WIN32
    *out = (uint64_t)GetTickCount64();
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0 ||
        (uint64_t)now.tv_sec > (UINT64_MAX - 999) / 1000) {
        return CV_ERR_IO;
    }
    *out = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
#endif
    return CV_OK;
}

static cv_status log_event(cv_security *security,
                           client *peer,
                           cv_audit_operation operation,
                           cv_audit_phase phase,
                           cv_status result) {
    cv_audit_event event = {peer ? peer->id : 0,
                            security->request,
                            operation,
                            phase,
                            result,
                            peer ? cv_auth_identity(&peer->session) : "server"};
    cv_status status = cv_audit_record(security->audit, &event);
    if (status != CV_OK) {
        security->failure = status;
    }
    return status;
}

cv_status cv_security_open(const char *policy,
                           const char *audit,
                           const char *audit_key,
                           cv_persist *store,
                           size_t clients,
                           cv_security **out) {
    if (!out) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    if (!policy || !audit || !audit_key || !clients || clients > CV_HARD_MAX_CLIENTS) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    cv_security *security = calloc(1, sizeof(*security));
    if (!security) {
        return CV_ERR_NO_MEMORY;
    }
    security->capacity = clients;
    security->store = store;
    security->clients = calloc(clients, sizeof(client));
    cv_status status = security->clients ? CV_OK : CV_ERR_NO_MEMORY;
    if (status == CV_OK) {
        status = cv_auth_policy_load(policy, &security->policy);
    }
    unsigned char key[CV_PERSIST_KEY_BYTES] = {0};
    if (status == CV_OK) {
        status = cv_persist_key_load(audit_key, key);
    }
    if (status == CV_OK) {
        status = cv_audit_open(audit, key, true, &security->audit);
    }
    cv_crypto_wipe(key, sizeof(key));
    if (status == CV_OK && !store) {
        status = cv_hashtable_create(&security->memory);
    }
    if (status == CV_OK) {
        status = log_event(security, NULL, CV_AUDIT_START, CV_AUDIT_RESULT, CV_OK);
    }
    if (status != CV_OK) {
        cv_security_close(security);
        return status;
    }
    *out = security;
    return CV_OK;
}

void cv_security_disconnect(void *context, uint64_t id) {

    cv_security *security = context;
    if (!security) {
        return;
    }
    for (size_t i = 0; i < security->capacity; ++i) {
        if (security->clients[i].id == id) {
            cv_crypto_wipe(&security->clients[i], sizeof(client));
            return;
        }
    }
}

static client *get_client(cv_security *security, uint64_t id) {
    client *free_slot = NULL;
    for (size_t i = 0; i < security->capacity; ++i) {
        if (security->clients[i].id == id) {
            return &security->clients[i];
        }
        if (!security->clients[i].id) {
            free_slot = &security->clients[i];
        }
    }
    if (free_slot) {
        free_slot->id = id;
    }
    return free_slot;
}

static cv_status reply(const char *message, unsigned char *out, size_t capacity, size_t *written) {
    size_t n = strlen(message);
    if (n > capacity) {
        return CV_ERR_LIMIT;
    }
    memcpy(out, message, n);
    *written = n;
    return CV_OK;
}

/** Storage results borrow the table value until the next mutation. Formatting
 * happens only after the result audit event has been durably acknowledged. */
typedef struct {
    cv_status status;
    const unsigned char *value;
    size_t length;
    int64_t ttl;
} storage_result;

/* Both storage backends expose the same semantics; all calls here are preceded
 * by an ACL decision and a synchronized intent event in the command handler. */
static void execute_storage(cv_security *security,
                            const cv_command *command,
                            const char *key,
                            storage_result *result) {
    *result = (storage_result){CV_ERR_INVALID_ARGUMENT, NULL, 0, CV_TTL_MISSING};
    switch (command->type) {
    case CV_CMD_SET:
        result->status =
            security->store
                ? cv_persist_set(security->store, key, command->value, command->value_length)
                : cv_hashtable_set(security->memory, key, command->value, command->value_length);
        break;
    case CV_CMD_GET:
        result->status =
            security->store
                ? cv_persist_get(security->store, key, &result->value, &result->length)
                : cv_hashtable_get(security->memory, key, &result->value, &result->length);
        break;
    case CV_CMD_DEL:
        result->status = security->store ? cv_persist_delete(security->store, key)
                                         : cv_hashtable_delete(security->memory, key);
        break;
    case CV_CMD_EXPIRE:
        result->status = security->store
                             ? cv_persist_expire(security->store, key, command->seconds)
                             : cv_hashtable_expire(security->memory, key, command->seconds);
        break;
    case CV_CMD_TTL:
        result->status = security->store ? cv_persist_ttl(security->store, key, &result->ttl)
                                         : cv_hashtable_ttl(security->memory, key, &result->ttl);
        break;
    default:
        result->status = CV_ERR_INVALID_ARGUMENT;
        break;
    }
}

/* Keep audit schema independent of the parser enum's numerical representation. */
static cv_audit_operation audit_operation(cv_command_type command) {
    switch (command) {
    case CV_CMD_AUTH:
        return CV_AUDIT_AUTH;
    case CV_CMD_SET:
        return CV_AUDIT_SET;
    case CV_CMD_GET:
        return CV_AUDIT_GET;
    case CV_CMD_DEL:
        return CV_AUDIT_DEL;
    case CV_CMD_EXPIRE:
        return CV_AUDIT_EXPIRE;
    case CV_CMD_TTL:
        return CV_AUDIT_TTL;
    default:
        return CV_AUDIT_INVALID;
    }
}

/* Reauthentication has already cleared the session. Failed attempts (including
 * malformed/rate-limited ones) count toward a three-failure connection limit.
 * Global throttling survives disconnects and prevents reconnect-based bypass. */
static cv_status authenticate_client(cv_security *security,
                                     client *peer,
                                     const cv_command *command,
                                     const char *username,
                                     unsigned char *out,
                                     size_t capacity,
                                     size_t *written,
                                     bool *close_after) {
    const cv_audit_operation operation = CV_AUDIT_AUTH;
    uint64_t now = 0;
    cv_status status = monotonic(&now);
    if (status != CV_OK) {
        security->failure = status;
        return status;
    }
    /* At most four expensive verifications/sec globally, including new
     * connections. No sleeping and no worker thread (POSIX fork safety). */
    if (security->attempted && (now < security->last_auth || now - security->last_auth < 250)) {
        status = CV_ERR_BUSY;
    } else {
        security->attempted = true;
        security->last_auth = now;
        if (log_event(security, peer, operation, CV_AUDIT_INTENT, CV_OK) != CV_OK) {
            return security->failure;
        }
        status = cv_authenticate(
            &peer->session, security->policy, username, command->value, command->value_length);
    }
    if (status != CV_OK && ++peer->failures >= 3) {
        *close_after = true;
    }
    if (status == CV_OK) {
        peer->failures = 0;
    }
    if (log_event(security, peer, operation, CV_AUDIT_RESULT, status) != CV_OK) {
        cv_auth_session_init(&peer->session);
        return security->failure;
    }
    return reply(
        status == CV_OK ? "+OK\n" : "-ERR authentication failed\n", out, capacity, written);
}

/* Format only audited outcomes. GET framing is length-based rather than a
 * string operation, preserving binary values returned by the storage C API. */
static cv_status format_storage_response(cv_command_type type,
                                         const storage_result *result,
                                         unsigned char *out,
                                         size_t capacity,
                                         size_t *written) {
    cv_status status = result->status;
    if (type == CV_CMD_TTL && (status == CV_OK || status == CV_ERR_NOT_FOUND)) {
        int n = snprintf((char *)out, capacity, ":%" PRId64 "\n", result->ttl);
        if (n < 0 || (size_t)n >= capacity) {
            return CV_ERR_LIMIT;
        }
        *written = (size_t)n;
        return CV_OK;
    }
    if (status == CV_ERR_NOT_FOUND) {
        return reply("$-1\n", out, capacity, written);
    }
    if (status != CV_OK) {
        return reply("-ERR operation failed\n", out, capacity, written);
    }
    if (type == CV_CMD_GET) {
        int n = snprintf((char *)out, capacity, "$%zu\n", result->length);
        if (n < 0 || (size_t)n >= capacity || result->length + 1 > capacity - (size_t)n) {
            return CV_ERR_LIMIT;
        }
        if (result->length) {
            memcpy(out + n, result->value, result->length);
        }
        out[(size_t)n + result->length] = '\n';
        *written = (size_t)n + result->length + 1;
        return CV_OK;
    }
    return reply("+OK\n", out, capacity, written);
}

cv_status cv_security_handler(void *context,
                              uint64_t id,
                              const unsigned char *line,
                              size_t length,
                              unsigned char *out,
                              size_t capacity,
                              size_t *written,
                              bool *close_after) {
    if (!context || !id || !line || !out || !written || !close_after) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    *written = 0;
    *close_after = false;

    cv_security *security = context;
    if (security->failure != CV_OK) {
        return security->failure;
    }

    client *peer = get_client(security, id);
    if (!peer || security->request == UINT64_MAX) {
        security->failure = CV_ERR_LIMIT;
        return CV_ERR_LIMIT;
    }
    /* Audit sequence numbers remain unique across restarts. Request/client IDs
     * identify pairs only within the run delimited by START and STOP events. */
    ++security->request;
    /* Revoke even malformed/throttled reauthentication before parser validation. */
    bool auth_attempt =
        length >= 4 && memcmp(line, "AUTH", 4) == 0 && (length == 4 || line[4] <= ' ');
    if (auth_attempt) {
        cv_auth_session_init(&peer->session);
    }

    cv_command command;
    cv_status status = cv_parse_line(line, length, &command);
    if (status != CV_OK) {
        if (auth_attempt && ++peer->failures >= 3) {
            *close_after = true;
        }
        if (log_event(security,
                      peer,
                      auth_attempt ? CV_AUDIT_AUTH : CV_AUDIT_INVALID,
                      CV_AUDIT_RESULT,
                      auth_attempt ? CV_ERR_UNAUTHORIZED : status) != CV_OK) {
            return security->failure;
        }
        return reply(auth_attempt ? "-ERR authentication failed\n" : "-ERR invalid command\n",
                     out,
                     capacity,
                     written);
    }
    if (command.type == CV_CMD_PING) {
        return reply("+PONG\n", out, capacity, written);
    }
    if (command.type == CV_CMD_QUIT) {
        *close_after = true;
        return reply("+OK\n", out, capacity, written);
    }

    cv_audit_operation operation = audit_operation(command.type);
    char key[CV_MAX_KEY_BYTES + 1];
    memcpy(key, command.key, command.key_length);
    key[command.key_length] = 0;
    if (command.type == CV_CMD_AUTH) {
        return authenticate_client(
            security, peer, &command, key, out, capacity, written, close_after);
    }

    /* Decide access before lookup: missing and existing forbidden keys match. */
    bool write =
        command.type == CV_CMD_SET || command.type == CV_CMD_DEL || command.type == CV_CMD_EXPIRE;
    status = cv_auth_authorize(&peer->session, key, write);
    if (status != CV_OK) {
        if (log_event(security, peer, operation, CV_AUDIT_RESULT, CV_ERR_UNAUTHORIZED) != CV_OK) {
            return security->failure;
        }
        return reply("-ERR access denied\n", out, capacity, written);
    }
    if (log_event(security, peer, operation, CV_AUDIT_INTENT, CV_OK) != CV_OK) {
        return security->failure;
    }

    /* A failed intent must prevent execution. A failed result may follow a
     * committed write, so it stops the service without acknowledging success. */
    storage_result result;
    execute_storage(security, &command, key, &result);
    status = result.status;
    if (log_event(security, peer, operation, CV_AUDIT_RESULT, status) != CV_OK) {
        return security->failure;
    }
    if (status == CV_ERR_IO || status == CV_ERR_CRYPTO || status == CV_ERR_CORRUPT) {
        security->failure = status;
        return status;
    }
    return format_storage_response(command.type, &result, out, capacity, written);
}

cv_status cv_security_status(const cv_security *security) {
    return security ? security->failure : CV_OK;
}

cv_status cv_security_close(cv_security *security) {
    if (!security) {
        return CV_OK;
    }
    if (security->audit && security->failure == CV_OK) {
        (void)log_event(security, NULL, CV_AUDIT_STOP, CV_AUDIT_RESULT, CV_OK);
    }
    cv_status status = cv_audit_close(security->audit);
    if (security->failure != CV_OK) {
        status = security->failure;
    }
    cv_auth_policy_destroy(security->policy);
    cv_hashtable_destroy(security->memory);
    if (security->clients) {
        cv_crypto_wipe(security->clients, security->capacity * sizeof(client));
        free(security->clients);
    }
    cv_crypto_wipe(security, sizeof(*security));
    free(security);
    return status;
}
