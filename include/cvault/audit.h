/**
 * @file audit.h
 * @brief Encrypted, tamper-evident audit log of sensitive operations.
 *
 * Every security-relevant action is written as a fixed-size event to an
 * append-only file. Records are sealed with XChaCha20-Poly1305 and chained: each
 * one authenticates the file identity, its sequence number and the tag of the
 * previous record, so any modification, deletion, reordering or truncation of
 * history is detected the next time the log is opened.
 *
 * ## What is recorded
 * Client and request identifiers, the operation, its phase (intent before the
 * work, result afterwards), the resulting status and the acting identity.
 * Passwords, keys, values and encryption keys are never written.
 *
 * ## Durability
 * Every append is synchronised to disk before success is reported. A failed
 * write permanently poisons the handle, because the on-disk state is then
 * uncertain.
 *
 * ## Ownership
 * One owner thread or process per file; the handle holds an exclusive lock for
 * its whole lifetime. Existing files must authenticate completely, including
 * the final record; no automatic repair or truncation is ever performed. See
 * docs/security.md for the file format and the export schema.
 */

#ifndef CVAULT_AUDIT_H
#define CVAULT_AUDIT_H

#include "cvault/auth.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/** Opaque handle to an open audit log. */
typedef struct cv_audit cv_audit;

/**
 * @brief Kind of action an event describes.
 *
 * The numeric values are stored in the file format: never renumber them.
 */
typedef enum {
    CV_AUDIT_AUTH = 1, /**< AUTH attempt. */
    CV_AUDIT_SET,      /**< SET command. */
    CV_AUDIT_GET,      /**< GET command. */
    CV_AUDIT_DEL,      /**< DEL command. */
    CV_AUDIT_EXPIRE,   /**< EXPIRE command. */
    CV_AUDIT_TTL,      /**< TTL command. */
    CV_AUDIT_INVALID,  /**< Malformed or unsupported request. */
    CV_AUDIT_START,    /**< Service start-up. */
    CV_AUDIT_STOP,     /**< Orderly service shutdown. */
    CV_AUDIT_EXPORT,   /**< EXPORT command (added after the first release of the format). */
    CV_AUDIT_PURGE     /**< PURGE command (added after the first release of the format). */
} cv_audit_operation;

/** Moment of an operation an event refers to. */
typedef enum {
    CV_AUDIT_INTENT = 1, /**< Recorded before the action runs. */
    CV_AUDIT_RESULT = 2  /**< Recorded after the action, with its outcome. */
} cv_audit_phase;

/** One audit event as supplied by the caller. */
typedef struct {
    uint64_t client_id, request_id; /**< Transport and per-run request identifiers. */
    cv_audit_operation operation;   /**< What happened. */
    cv_audit_phase phase;           /**< Intent or result. */
    cv_status result;               /**< Outcome (#CV_OK for intent events). */
    const char *identity;           /**< Validated ASCII user name, "anonymous" or "server". */
} cv_audit_event;

/**
 * @brief Open (and optionally create) an audit log.
 *
 * A domain-separated key is derived from the private 32-byte master key; the
 * derived copy is kept internally and wiped on close. An existing file is
 * authenticated from beginning to end before the handle is returned.
 *
 * @param path   Log file path (the lock lives next to it as `<path>.lock`).
 * @param key    Private 32-byte master key.
 * @param create When false the file must already exist.
 * @param out    Receives the handle; set to NULL on failure.
 * @return #CV_OK; #CV_ERR_INVALID_ARGUMENT; #CV_ERR_NOT_FOUND (missing file with
 *         @p create false); #CV_ERR_BUSY (already open elsewhere);
 *         #CV_ERR_CORRUPT (authentication failure); #CV_ERR_NO_MEMORY;
 *         #CV_ERR_CRYPTO; #CV_ERR_IO.
 */
cv_status cv_audit_open(const char *path, const unsigned char key[32], bool create, cv_audit **out);

/**
 * @brief Append one event and synchronise it to disk.
 *
 * @param audit Open log.
 * @param event Event to record; its identity must be a valid user name.
 * @return #CV_OK; #CV_ERR_INVALID_ARGUMENT for malformed events; #CV_ERR_IO when
 *         the handle is poisoned or the write/sync fails (the handle then
 *         refuses all further appends).
 */
cv_status cv_audit_record(cv_audit *audit, const cv_audit_event *event);

/**
 * @brief Export every validated event as JSON Lines.
 *
 * The whole stream is authenticated twice before and during output, so nothing
 * unverified is ever printed. Append state is restored on success; any failure
 * poisons the handle.
 *
 * @param audit  Open log.
 * @param output Destination stream, borrowed and not closed.
 * @return #CV_OK, #CV_ERR_INVALID_ARGUMENT, #CV_ERR_CORRUPT or #CV_ERR_IO.
 */
cv_status cv_audit_export(cv_audit *audit, FILE *output);

/**
 * @brief Close the file, release the lock and wipe the derived key and buffers.
 *
 * Resources are always released, even for a poisoned handle.
 *
 * @param audit Handle to close; NULL is safe.
 * @return #CV_OK, or #CV_ERR_IO when the handle was poisoned or closing failed.
 */
cv_status cv_audit_close(cv_audit *audit);

#endif /* CVAULT_AUDIT_H */
