#ifndef CVAULT_AUTH_H
#define CVAULT_AUTH_H

#include "cvault/common.h"
#include <stdbool.h>
#include <stddef.h>

/** Immutable, bounded credentials and literal prefix allow-lists. Single owner
 * thread; policy must outlive sessions. No plaintext passwords are retained. */
#define CV_AUTH_HASH_BYTES 128
#define CV_AUTH_USER_BYTES 64
#define CV_AUTH_PASSWORD_BYTES 1024
typedef struct cv_auth_policy cv_auth_policy;

/** Per-connection state. The policy is borrowed; user is an internal policy
 * index, meaningful only while authenticated. Manage through the functions below. */
typedef struct {
    bool authenticated;
    const cv_auth_policy *policy;
    size_t user;
} cv_auth_session;

/** Generate an Argon2id v1.3 PHC string (64 MiB, two passes, random salt).
 * password is borrowed for this call; length is 1..CV_AUTH_PASSWORD_BYTES.
 * Caller owns/wipes the password. out has CV_AUTH_HASH_BYTES bytes and resets on
 * errors. Returns INVALID_ARGUMENT for bounds/NULL, CRYPTO on hashing failure. */
cv_status
cv_auth_hash_password(const unsigned char *password, size_t length, char out[CV_AUTH_HASH_BYTES]);

/** Load an owned, immutable policy from a private regular file. Format/limits are
 * documented in docs/security.md. Imported hashes require the exact above cost.
 * *out resets on failure. Returns INVALID_ARGUMENT, NO_MEMORY, IO, NOT_FOUND,
 * CORRUPT/LIMIT for malformed or oversized files, or CRYPTO on initialization. */
cv_status cv_auth_policy_load(const char *path, cv_auth_policy **out);

/** Wipe credentials/grants and free the policy. NULL is safe. Reset/destroy all
 * borrowing sessions first; calling them after policy destruction is invalid. */
void cv_auth_policy_destroy(cv_auth_policy *policy);

/** Clear a session, including borrowed policy/identity. NULL is safe.
 * Initialize before first use; callers must not modify session fields directly. */
void cv_auth_session_init(cv_auth_session *session);

/** Revoke existing privileges, then verify the borrowed password against policy.
 * policy must outlive the session. Success grants only that identity's explicit
 * rules. All failures leave the session unauthenticated. Unknown users and wrong
 * passwords return UNAUTHORIZED; NULL/bad lengths return INVALID_ARGUMENT.
 * The C API is binary-safe; transport passwords have additional framing bounds.
 * Verification blocks synchronously; admission throttling belongs to the caller. */
cv_status cv_authenticate(cv_auth_session *session,
                          const cv_auth_policy *policy,
                          const char *username,
                          const unsigned char *password,
                          size_t length);

/** Deny by default; matching literal prefixes combine independent read/write
 * grants. This call never inspects storage or reveals whether a key exists. */
cv_status cv_auth_authorize(const cv_auth_session *session, const char *key, bool write);

/** Borrow a validated authenticated name, otherwise the static "anonymous" name.
 * Successful identity remains valid until policy destruction. No allocation. */
const char *cv_auth_identity(const cv_auth_session *session);

#endif
