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
 * ## Rotation
 * A log can be sealed and continued in a new file (see cv_audit_rotate()). The
 * sealed file is renamed to an archive that carries its last sequence number, the
 * new file continues the numbering, and the new file may use a different key.
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

/** Size of a buffer that can hold the archive path reported by cv_audit_rotate(). */
#define CV_AUDIT_ARCHIVE_BYTES ((size_t)4096)

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
    CV_AUDIT_PURGE,    /**< PURGE command (added after the first release of the format). */
    CV_AUDIT_ROTATE,   /**< The log was sealed (intent) and continued in a new file (result). */
    CV_AUDIT_RELOAD /**< The security policy was reloaded; the result tells whether it applied. */
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
 * @brief Report whether the handle is still usable.
 *
 * @param audit Handle to inspect; NULL reports #CV_OK.
 * @return #CV_OK, or #CV_ERR_IO once a failed write has poisoned the handle.
 */
cv_status cv_audit_status(const cv_audit *audit);

/**
 * @brief Report the current size of the log file.
 *
 * @param audit Open log.
 * @param bytes Receives the size in bytes; zero on error.
 * @return #CV_OK, #CV_ERR_INVALID_ARGUMENT or #CV_ERR_IO.
 */
cv_status cv_audit_size(cv_audit *audit, uint64_t *bytes);

/**
 * @brief Seal the log and continue it in a new file, optionally under a new key.
 *
 * The sequence is: an INTENT event of operation #CV_AUDIT_ROTATE ends the old file;
 * a new file is prepared next to it with a fresh identity, a header that continues
 * the sequence numbering and a RESULT event as its first record; the old file is
 * renamed to `<path>.<last sequence, 20 digits>` and the new file takes its place.
 * Reading the archive with the key it was written under shows the whole history
 * up to the seal, and the sequence numbers of the archive and of the new file are
 * contiguous. No cryptographic link joins them: deleting a complete archive can
 * only be noticed by comparing sequence numbers, or with an external anchor.
 *
 * A crash at any point leaves either the old file or the new file in place. If the
 * process dies after the old file was renamed, the next cv_audit_open() finishes
 * the swap, and the new file must then be opened with the new key.
 *
 * @param audit    Open log; its file is replaced.
 * @param new_key  Private 32-byte master key for the new file, or NULL to keep the
 *                 current one.
 * @param archive  Optional buffer receiving the archive path; empty on failure.
 * @param capacity Size of @p archive.
 * @return #CV_OK; #CV_ERR_INVALID_ARGUMENT; #CV_ERR_BUSY when the archive name is
 *         taken; #CV_ERR_LIMIT for a path or sequence that does not fit;
 *         #CV_ERR_IO, #CV_ERR_CRYPTO or #CV_ERR_NO_MEMORY. A failure *before* the
 *         old file is renamed leaves the handle usable (it only gained the intent
 *         event); a later failure poisons it, see cv_audit_status().
 */
cv_status
cv_audit_rotate(cv_audit *audit, const unsigned char *new_key, char *archive, size_t capacity);

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
