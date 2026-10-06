/**
 * @file audit.c
 * @brief Chained, encrypted audit log built on the shared AEAD record codec.
 *
 * Version 1 event layout (little-endian integers, no padding, independent of
 * the host ABI), 92 bytes per event:
 *
 *     offset  size  field
 *      0       8    timestamp, Unix milliseconds
 *      8       8    client ID
 *     16       8    request ID
 *     24       1    operation
 *     25       1    phase
 *     26       1    status
 *     27       1    identity length
 *     28      64    ASCII identity, zero padded
 *
 * The codec additionally authenticates the file UUID, the sequence number and
 * the previous record tag. Domain separation of the key prevents an attacker
 * from substituting a storage journal for an audit log or vice versa.
 */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <inttypes.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "cvault/audit.h"
#include "cvault/crypto.h"
#include "persist_codec.h"
#include "persist_io.h"

/** Size in bytes of one serialised event. */
#define EVENT_BYTES 92

/** Byte offsets of the fields inside a serialised event. */
enum {
    EVENT_TIMESTAMP_OFFSET = 0,
    EVENT_CLIENT_OFFSET = 8,
    EVENT_REQUEST_OFFSET = 16,
    EVENT_OPERATION_OFFSET = 24,
    EVENT_PHASE_OFFSET = 25,
    EVENT_STATUS_OFFSET = 26,
    EVENT_IDENTITY_LENGTH_OFFSET = 27,
    EVENT_IDENTITY_OFFSET = 28
};

struct cv_audit {
    FILE *file;              /**< Log file, opened read/write. */
    cv_file_lock lock;       /**< Exclusive lock held for the handle's lifetime. */
    cv_record_stream stream; /**< Chained AEAD stream over #file. */
    unsigned char key[32];   /**< Domain-separated key derived from the master key. */
    bool failed;             /**< Poisoned after any uncertain I/O outcome. */
};

/** Operation names indexed by #cv_audit_operation, used by the JSON export. */
static const char *operations[] = {"",
                                   "AUTH",
                                   "SET",
                                   "GET",
                                   "DEL",
                                   "EXPIRE",
                                   "TTL",
                                   "INVALID",
                                   "START",
                                   "STOP",
                                   "EXPORT",
                                   "PURGE"};

/**
 * @brief Check that an identity only uses [A-Za-z0-9_.-] and fits 64 bytes.
 *
 * Restricting the alphabet lets identities be exported as JSON strings without
 * any escaping, which rules out log injection through user names.
 */
static bool valid_identity(const char *identity) {
    if (!identity || !*identity) {
        return false;
    }

    for (size_t i = 0; identity[i]; ++i) {
        unsigned char c = (unsigned char)identity[i];

        if (i == CV_AUTH_USER_BYTES ||
            !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.')) {
            return false;
        }
    }

    return true;
}

/** @brief Read the wall clock as Unix milliseconds. */
static cv_status timestamp(uint64_t *out) {
#ifdef _WIN32
    FILETIME ft;

    GetSystemTimePreciseAsFileTime(&ft);

    /* FILETIME counts 100 ns ticks since 1601; shift to the Unix epoch. */
    uint64_t ticks = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

    if (ticks < UINT64_C(116444736000000000)) {
        return CV_ERR_IO;
    }

    *out = (ticks - UINT64_C(116444736000000000)) / 10000;
#else
    struct timespec now;

    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec < 0 ||
        (uint64_t)now.tv_sec > (UINT64_MAX - 999) / 1000) {
        return CV_ERR_IO;
    }

    *out = (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
#endif

    return CV_OK;
}

/**
 * @brief Validate the application schema of an already authenticated record.
 *
 * cv_stream_next() proves authenticity first; this then checks that the
 * decrypted payload is a well-formed event. The identity alphabet is enforced
 * here so JSON export cannot be abused for injection.
 */
static cv_status validate_record(const cv_disk_record *record) {
    if (record->operation != CV_RECORD_SET || strcmp(record->key, "audit-v1") ||
        record->expiry_ms || record->value_length != EVENT_BYTES) {
        return CV_ERR_CORRUPT;
    }

    const unsigned char *payload = record->value;

    if (payload[EVENT_OPERATION_OFFSET] < CV_AUDIT_AUTH ||
        payload[EVENT_OPERATION_OFFSET] > CV_AUDIT_PURGE ||
        payload[EVENT_PHASE_OFFSET] < CV_AUDIT_INTENT ||
        payload[EVENT_PHASE_OFFSET] > CV_AUDIT_RESULT ||
        payload[EVENT_STATUS_OFFSET] > CV_ERR_BUSY || !payload[EVENT_IDENTITY_LENGTH_OFFSET] ||
        payload[EVENT_IDENTITY_LENGTH_OFFSET] > CV_AUTH_USER_BYTES) {
        return CV_ERR_CORRUPT;
    }

    char actor[CV_AUTH_USER_BYTES + 1] = {0};

    memcpy(actor, payload + EVENT_IDENTITY_OFFSET, payload[EVENT_IDENTITY_LENGTH_OFFSET]);

    if (strlen(actor) != payload[EVENT_IDENTITY_LENGTH_OFFSET] || !valid_identity(actor)) {
        return CV_ERR_CORRUPT;
    }

    /* The padding after the identity must be all zeroes. */
    for (size_t i = payload[EVENT_IDENTITY_LENGTH_OFFSET]; i < CV_AUTH_USER_BYTES; ++i) {
        if (payload[EVENT_IDENTITY_OFFSET + i]) {
            return CV_ERR_CORRUPT;
        }
    }

    return CV_OK;
}

/**
 * @brief Authenticate and validate the whole stream, optionally printing it.
 *
 * Startup and export always walk the complete stream. A partial trailing
 * record fails closed instead of silently dropping security evidence after a
 * crash. On success the file position is restored to the end so appending can
 * continue.
 *
 * @param audit  Log whose stream has just been opened at the first record.
 * @param output JSON Lines destination, or NULL to validate only.
 */
static cv_status scan(cv_audit *audit, FILE *output) {
    cv_status status = CV_OK;

    for (;;) {
        cv_disk_record record;
        bool eof, partial;

        status = cv_stream_next(&audit->stream, &record, &eof, &partial);

        if (status != CV_OK) {
            break;
        }

        if (eof) {
            if (partial) {
                status = CV_ERR_CORRUPT;
            }

            break;
        }

        status = validate_record(&record);

        if (status != CV_OK) {
            break;
        }

        if (output) {
            const unsigned char *payload = record.value;

            if (fprintf(
                    output,
                    "{\"sequence\":%" PRIu64 ",\"timestamp_ms\":%" PRIu64 ",\"client_id\":%" PRIu64
                    ",\"request_id\":%" PRIu64
                    ",\"operation\":\"%s\",\"phase\":\"%s\",\"status\":%u,\"identity\":\"%.*s\"}\n",
                    audit->stream.sequence,
                    cv_decode_u64(payload + EVENT_TIMESTAMP_OFFSET),
                    cv_decode_u64(payload + EVENT_CLIENT_OFFSET),
                    cv_decode_u64(payload + EVENT_REQUEST_OFFSET),
                    operations[payload[EVENT_OPERATION_OFFSET]],
                    payload[EVENT_PHASE_OFFSET] == CV_AUDIT_INTENT ? "intent" : "result",
                    (unsigned int)payload[EVENT_STATUS_OFFSET],
                    (int)payload[EVENT_IDENTITY_LENGTH_OFFSET],
                    (const char *)payload + EVENT_IDENTITY_OFFSET) < 0) {
                status = CV_ERR_IO;
                break;
            }
        }
    }

    /* Leave the file positioned after the last record for the next append. */
    if (status == CV_OK) {
        uint64_t end = 0;

        status = cv_io_tell(audit->file, &end);
        clearerr(audit->file);

        if (status == CV_OK) {
            status = cv_io_seek(audit->file, end);
        }
    }

    return status;
}

cv_status
cv_audit_open(const char *path, const unsigned char key[32], bool create, cv_audit **out) {
    if (!out) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    *out = NULL;

    if (!path || !*path || !key || strlen(path) > CV_PERSIST_PATH_LIMIT - 6) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    if (cv_crypto_init() != CV_OK) {
        return CV_ERR_CRYPTO;
    }

    cv_audit *audit = calloc(1, sizeof(*audit));

    if (!audit) {
        return CV_ERR_NO_MEMORY;
    }

    audit->lock.native = -1;

    /* Derive a key bound to this purpose so the same master key can safely
     * protect other files without enabling cross-file record substitution. */
    const unsigned char domain[] = "cvault-security-audit-v1";

    if (crypto_generichash(audit->key, sizeof(audit->key), domain, sizeof(domain) - 1, key, 32) !=
        0) {
        cv_audit_close(audit);

        return CV_ERR_CRYPTO;
    }

    /* Take the exclusive lock before touching the log. */
    size_t n = strlen(path);
    char *lock_path = malloc(n + 6);

    if (!lock_path) {
        cv_audit_close(audit);

        return CV_ERR_NO_MEMORY;
    }

    memcpy(lock_path, path, n);
    memcpy(lock_path + n, ".lock", 6);

    cv_status status = cv_io_lock(lock_path, &audit->lock);

    free(lock_path);

    if (status == CV_OK) {
        status = cv_io_open(path, false, false, true, &audit->file);
    }

    if (status == CV_ERR_NOT_FOUND && create) {
        /* First start: create the file with a fresh identity and a durable header. */
        status = cv_io_open(path, true, true, true, &audit->file);

        unsigned char uuid[16];

        randombytes_buf(uuid, sizeof(uuid));

        if (status == CV_OK) {
            status = cv_stream_create(audit->file, false, uuid, 0, audit->key, &audit->stream);
        }

        if (status == CV_OK) {
            status = cv_io_sync(audit->file);
        }

        if (status == CV_OK) {
            status = cv_io_sync_parent(path);
        }
    } else if (status == CV_OK) {
        /* Existing log: authenticate the entire history before trusting it. */
        status = cv_stream_open(audit->file, false, audit->key, &audit->stream);

        if (status == CV_OK && audit->stream.baseline != 0) {
            status = CV_ERR_CORRUPT;
        }

        if (status == CV_OK) {
            status = scan(audit, NULL);
        }
    }

    if (status != CV_OK) {
        cv_audit_close(audit);

        return status;
    }

    *out = audit;

    return CV_OK;
}

cv_status cv_audit_record(cv_audit *audit, const cv_audit_event *event) {
    if (!audit || !event || !valid_identity(event->identity) || event->operation < CV_AUDIT_AUTH ||
        event->operation > CV_AUDIT_PURGE || event->phase < CV_AUDIT_INTENT ||
        event->phase > CV_AUDIT_RESULT || event->result < CV_OK || event->result > CV_ERR_BUSY) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    if (audit->failed) {
        return CV_ERR_IO;
    }

    /* Serialise the event into its fixed-size little-endian layout. */
    unsigned char payload[EVENT_BYTES] = {0};
    uint64_t now = 0;
    cv_status status = timestamp(&now);

    cv_encode_u64(payload + EVENT_TIMESTAMP_OFFSET, now);
    cv_encode_u64(payload + EVENT_CLIENT_OFFSET, event->client_id);
    cv_encode_u64(payload + EVENT_REQUEST_OFFSET, event->request_id);

    payload[EVENT_OPERATION_OFFSET] = (unsigned char)event->operation;
    payload[EVENT_PHASE_OFFSET] = (unsigned char)event->phase;
    payload[EVENT_STATUS_OFFSET] = (unsigned char)event->result;
    payload[EVENT_IDENTITY_LENGTH_OFFSET] = (unsigned char)strlen(event->identity);

    memcpy(payload + EVENT_IDENTITY_OFFSET, event->identity, payload[EVENT_IDENTITY_LENGTH_OFFSET]);

    /* Encrypt, append and force the record to disk before reporting success. */
    if (status == CV_OK) {
        status = cv_stream_append(
            &audit->stream, CV_RECORD_SET, "audit-v1", payload, sizeof(payload), 0);
    }

    if (status == CV_OK) {
        status = cv_io_sync(audit->file);
    }

    cv_crypto_wipe(payload, sizeof(payload));

    /* A failed write/sync may have reached disk. Refuse all subsequent calls;
     * continuing from uncertain in-memory chain state would be unsafe. */
    if (status != CV_OK) {
        audit->failed = true;
    }

    return status;
}

cv_status cv_audit_export(cv_audit *audit, FILE *output) {
    if (!audit || !output) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    if (audit->failed) {
        return CV_ERR_IO;
    }

    /* Pass 1: authenticate everything without printing a single byte. */
    cv_stream_clear(&audit->stream);

    cv_status status = cv_io_seek(audit->file, 0);

    if (status == CV_OK) {
        status = cv_stream_open(audit->file, false, audit->key, &audit->stream);
    }

    if (status == CV_OK) {
        status = scan(audit, NULL);
    }

    /* Pass 2: only now stream the validated events to the output. */
    cv_stream_clear(&audit->stream);

    if (status == CV_OK) {
        status = cv_io_seek(audit->file, 0);
    }

    if (status == CV_OK) {
        status = cv_stream_open(audit->file, false, audit->key, &audit->stream);
    }

    if (status == CV_OK) {
        status = scan(audit, output);
    }

    if (status == CV_OK && fflush(output) != 0) {
        status = CV_ERR_IO;
    }

    if (status != CV_OK) {
        audit->failed = true;
    }

    return status;
}

cv_status cv_audit_close(cv_audit *audit) {
    if (!audit) {
        return CV_OK;
    }

    cv_status status = audit->failed ? CV_ERR_IO : CV_OK;

    cv_stream_clear(&audit->stream);

    if (audit->file && fclose(audit->file) != 0) {
        status = CV_ERR_IO;
    }

    cv_io_unlock(&audit->lock);

    cv_crypto_wipe(audit, sizeof(*audit));
    free(audit);

    return status;
}
