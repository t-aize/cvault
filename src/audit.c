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
    char *path;              /**< Copy of the log path, needed to rotate the file. */
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
                                   "PURGE",
                                   "ROTATE",
                                   "RELOAD"};

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
        payload[EVENT_OPERATION_OFFSET] > CV_AUDIT_RELOAD ||
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

/**
 * @brief Derive the per-purpose key from a master key.
 *
 * The derivation binds the key to this purpose, so the same master key can safely
 * protect other files without enabling cross-file record substitution.
 */
static cv_status derive_key(unsigned char out[32], const unsigned char master[32]) {
    const unsigned char domain[] = "cvault-security-audit-v1";

    return crypto_generichash(out, 32, domain, sizeof(domain) - 1, master, 32) == 0 ? CV_OK
                                                                                    : CV_ERR_CRYPTO;
}

/** Suffix of the staging file that holds the next log while a rotation is in progress. */
#define STAGING_SUFFIX ".next"

/** Room reserved after the path for the lock, staging and archive suffixes. */
#define SUFFIX_RESERVE ((size_t)32)

/**
 * @brief Build `<path><suffix>` in a new heap string.
 *
 * @return The string, or NULL on allocation failure.
 */
static char *with_suffix(const char *path, const char *suffix) {
    size_t base = strlen(path), extra = strlen(suffix);
    char *result = malloc(base + extra + 1);

    if (result) {
        memcpy(result, path, base);
        memcpy(result + base, suffix, extra + 1);
    }

    return result;
}

/** @brief True unless the file is certainly absent (any other outcome counts as present). */
static bool exists(const char *path) {
    FILE *file = NULL;
    cv_status status = cv_io_open(path, false, false, false, &file);

    if (file) {
        (void)fclose(file);
    }

    return status != CV_ERR_NOT_FOUND;
}

/**
 * @brief Complete or discard a rotation that a crash interrupted.
 *
 * The staging file is complete and synchronised before the old log is renamed.
 * If the log is missing, the old one was already archived, so the staging file
 * is moved into place. If both exist the crash came before the rename and the
 * staging file is only a stale preparation, which is deleted.
 */
static cv_status settle_rotation(const char *path) {
    char *staging = with_suffix(path, STAGING_SUFFIX);

    if (!staging) {
        return CV_ERR_NO_MEMORY;
    }

    cv_status status = CV_OK;

    if (exists(staging)) {
        if (exists(path)) {
            cv_io_remove(staging);
        } else {
            status = cv_io_move(staging, path);

            if (status == CV_OK) {
                status = cv_io_sync_parent(path);
            }
        }
    }

    free(staging);

    return status;
}

cv_status
cv_audit_open(const char *path, const unsigned char key[32], bool create, cv_audit **out) {
    if (!out) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    *out = NULL;

    if (!path || !*path || !key || strlen(path) > CV_PERSIST_PATH_LIMIT - SUFFIX_RESERVE) {
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

    if (derive_key(audit->key, key) != CV_OK) {
        cv_audit_close(audit);

        return CV_ERR_CRYPTO;
    }

    /* Take the exclusive lock before touching the log. */
    char *lock_path = with_suffix(path, ".lock");

    audit->path = with_suffix(path, "");

    if (!lock_path || !audit->path) {
        free(lock_path);
        cv_audit_close(audit);

        return CV_ERR_NO_MEMORY;
    }

    cv_status status = cv_io_lock(lock_path, &audit->lock);

    free(lock_path);

    /* Only the lock holder may look at a leftover from an interrupted rotation. */
    if (status == CV_OK) {
        status = settle_rotation(path);
    }

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

/**
 * @brief Serialise, encrypt, append and synchronise one event.
 *
 * Shared by normal appends and by the first record of a rotated log. The caller
 * has validated the event and decides what a failure means for its handle.
 */
static cv_status write_event(cv_record_stream *stream, FILE *file, const cv_audit_event *event) {
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
        status = cv_stream_append(stream, CV_RECORD_SET, "audit-v1", payload, sizeof(payload), 0);
    }

    if (status == CV_OK) {
        status = cv_io_sync(file);
    }

    cv_crypto_wipe(payload, sizeof(payload));

    return status;
}

/** @brief Check that an event only uses known operations, phases and results. */
static bool valid_event(const cv_audit_event *event) {
    return event && valid_identity(event->identity) && event->operation >= CV_AUDIT_AUTH &&
           event->operation <= CV_AUDIT_RELOAD && event->phase >= CV_AUDIT_INTENT &&
           event->phase <= CV_AUDIT_RESULT && event->result >= CV_OK &&
           event->result <= CV_ERR_BUSY;
}

cv_status cv_audit_record(cv_audit *audit, const cv_audit_event *event) {
    if (!audit || !valid_event(event)) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    if (audit->failed) {
        return CV_ERR_IO;
    }

    cv_status status = write_event(&audit->stream, audit->file, event);

    /* A failed write/sync may have reached disk. Refuse all subsequent calls;
     * continuing from uncertain in-memory chain state would be unsafe. */
    if (status != CV_OK) {
        audit->failed = true;
    }

    return status;
}

cv_status cv_audit_status(const cv_audit *audit) {
    return audit && audit->failed ? CV_ERR_IO : CV_OK;
}

cv_status cv_audit_size(cv_audit *audit, uint64_t *bytes) {
    if (bytes) {
        *bytes = 0;
    }

    if (!audit || !bytes) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    if (audit->failed) {
        return CV_ERR_IO;
    }

    return cv_io_tell(audit->file, bytes);
}

/**
 * @brief Write the next log (header plus its first event) to the staging file.
 *
 * @param sealed Sequence of the last record of the old log; the new header continues
 *               the numbering from it.
 * @param key    Derived key of the new log.
 */
static cv_status
prepare_next_log(const char *staging, uint64_t sealed, const unsigned char key[32]) {
    FILE *file = NULL;
    cv_record_stream stream = {0};
    unsigned char uuid[16];
    cv_status status = cv_io_open(staging, true, true, true, &file);

    if (status != CV_OK) {
        return status;
    }

    randombytes_buf(uuid, sizeof(uuid));

    status = cv_stream_create(file, false, uuid, sealed, key, &stream);

    if (status == CV_OK) {
        const cv_audit_event event = {0, 0, CV_AUDIT_ROTATE, CV_AUDIT_RESULT, CV_OK, "server"};

        status = write_event(&stream, file, &event);
    }

    cv_stream_clear(&stream);

    if (fclose(file) != 0 && status == CV_OK) {
        status = CV_ERR_IO;
    }

    if (status == CV_OK) {
        status = cv_io_sync_parent(staging);
    }

    return status;
}

/**
 * @brief Re-open the log at its path after a rotation and authenticate it.
 *
 * Rotation moves files, so the handle's file and chain state are rebuilt from disk
 * rather than patched, which also proves that the new file is readable.
 */
static cv_status reattach(cv_audit *audit) {
    cv_status status = cv_io_open(audit->path, false, false, true, &audit->file);

    if (status == CV_OK) {
        status = cv_stream_open(audit->file, false, audit->key, &audit->stream);
    }

    if (status == CV_OK) {
        status = scan(audit, NULL);
    }

    return status;
}

cv_status
cv_audit_rotate(cv_audit *audit, const unsigned char *new_key, char *archive, size_t capacity) {
    if (archive && capacity) {
        archive[0] = '\0';
    }

    if (!audit || (archive && !capacity)) {
        return CV_ERR_INVALID_ARGUMENT;
    }

    if (audit->failed) {
        return CV_ERR_IO;
    }

    /* The intent record becomes the last record of the sealed file. */
    if (audit->stream.sequence >= UINT64_MAX - 2) {
        return CV_ERR_LIMIT;
    }

    const uint64_t sealed = audit->stream.sequence + 1;
    unsigned char key[32];
    cv_status status = new_key ? derive_key(key, new_key) : CV_OK;

    if (!new_key) {
        memcpy(key, audit->key, sizeof(key));
    }

    /* Everything that can fail without side effects is checked first. */
    char suffix[32], *archive_path = NULL, *staging = NULL;

    (void)snprintf(suffix, sizeof(suffix), ".%020" PRIu64, sealed);

    if (status == CV_OK) {
        archive_path = with_suffix(audit->path, suffix);
        staging = with_suffix(audit->path, STAGING_SUFFIX);

        if (!archive_path || !staging) {
            status = CV_ERR_NO_MEMORY;
        }
    }

    if (status == CV_OK && archive && strlen(archive_path) >= capacity) {
        status = CV_ERR_LIMIT;
    }

    if (status == CV_OK && exists(archive_path)) {
        status = CV_ERR_BUSY;
    }

    if (status == CV_OK) {
        cv_io_remove(staging);

        const cv_audit_event intent = {0, 0, CV_AUDIT_ROTATE, CV_AUDIT_INTENT, CV_OK, "server"};

        status = cv_audit_record(audit, &intent);
    }

    /* Prepare the next log while the old one is still in place; failure here only
     * removes the staging file, the old log stays valid and in use. */
    if (status == CV_OK) {
        status = prepare_next_log(staging, sealed, key);

        if (status != CV_OK) {
            cv_io_remove(staging);
        }
    }

    if (status != CV_OK) {
        cv_crypto_wipe(key, sizeof(key));
        free(archive_path);
        free(staging);

        return status;
    }

    /* Past this point the handle has no valid file until the swap is complete. */
    cv_stream_clear(&audit->stream);

    if (fclose(audit->file) != 0) {
        status = CV_ERR_IO;
    }

    audit->file = NULL;

    if (status == CV_OK) {
        status = cv_io_move(audit->path, archive_path);
    }

    if (status == CV_OK) {
        status = cv_io_sync_parent(archive_path);
    }

    if (status == CV_OK) {
        status = cv_io_move(staging, audit->path);
    }

    if (status == CV_OK) {
        status = cv_io_sync_parent(audit->path);
    }

    if (status == CV_OK) {
        memcpy(audit->key, key, sizeof(audit->key));
        status = reattach(audit);
    }

    if (status == CV_OK && archive) {
        memcpy(archive, archive_path, strlen(archive_path) + 1);
    }

    if (status != CV_OK) {
        audit->failed = true;
    }

    cv_crypto_wipe(key, sizeof(key));
    free(archive_path);
    free(staging);

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
    free(audit->path);

    cv_crypto_wipe(audit, sizeof(*audit));
    free(audit);

    return status;
}
