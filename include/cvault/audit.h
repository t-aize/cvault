#ifndef CVAULT_AUDIT_H
#define CVAULT_AUDIT_H

#include "cvault/auth.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
/** Encrypted, authenticated, chained audit stream. One owner thread/process.
 * Events contain no supplied passwords, storage keys, values or encryption keys.
 * Every append synchronizes before success. Failure permanently poisons handle.
 * Existing files must authenticate completely, including the final record; no
 * automatic audit repair or truncation is performed. See docs/security.md. */
typedef struct cv_audit cv_audit;

typedef enum {
    CV_AUDIT_AUTH = 1,
    CV_AUDIT_SET,
    CV_AUDIT_GET,
    CV_AUDIT_DEL,
    CV_AUDIT_EXPIRE,
    CV_AUDIT_TTL,
    CV_AUDIT_INVALID,
    CV_AUDIT_START,
    CV_AUDIT_STOP
} cv_audit_operation;

typedef enum {
    CV_AUDIT_INTENT = 1,
    CV_AUDIT_RESULT = 2
} cv_audit_phase;

typedef struct {
    uint64_t client_id, request_id;
    cv_audit_operation operation;
    cv_audit_phase phase;
    cv_status result;
    const char *identity; /* Validated ASCII username, or "anonymous"/"server". */
} cv_audit_event;

/** Derive a domain-separated key from a private 32-byte master key. Copy/wipe it
 * internally. create=false requires an existing file. Resets *out on failure. */
cv_status cv_audit_open(const char *path, const unsigned char key[32], bool create, cv_audit **out);
cv_status cv_audit_record(cv_audit *audit, const cv_audit_event *event);

/** Export validated events as JSON Lines after full authentication. The handle
 * holds its exclusive file lock throughout its lifetime. Append state is restored
 * on success; export failure poisons the handle. output is borrowed, not closed. */
cv_status cv_audit_export(cv_audit *audit, FILE *output);

/** Close files, release lock and wipe the derived key/buffers. NULL is safe.
 * Always frees resources; returns IO for a poisoned handle or close failure. */
cv_status cv_audit_close(cv_audit *audit);

#endif
