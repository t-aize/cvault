/**
 * @file auth.h
 * @brief Argon2id password verification and per-prefix access control.
 *
 * A *policy* is an immutable, bounded set of users and prefix rules loaded from
 * a private file (format in docs/security.md). A *session* is the per-connection
 * authentication state: it borrows the policy and records which user, if any,
 * proved their identity.
 *
 * ## Security properties
 *  - Passwords are verified against Argon2id v1.3 PHC strings (64 MiB, two
 *    passes); imported hashes must use exactly that cost, so a policy file can
 *    not make the server burn unbounded memory or CPU.
 *  - Unknown users take the same expensive verification path as known users
 *    (against a random dummy hash), which blunts account enumeration by timing.
 *  - Authorisation is deny-by-default. Rules are literal, case-sensitive prefix
 *    matches combined as a union of independent read and write grants; write
 *    permission never implies read permission.
 *  - No plaintext password or candidate identity is retained.
 *
 * ## Threading
 * A policy is read-only after loading, but the API is designed for a single
 * owner thread, and the policy must outlive every session that borrows it.
 */

#ifndef CVAULT_AUTH_H
#define CVAULT_AUTH_H

#include "cvault/common.h"

#include <stdbool.h>
#include <stddef.h>

/** Size of a NUL-terminated Argon2id PHC string, including the terminator. */
#define CV_AUTH_HASH_BYTES 128

/** Longest user name, in characters (excluding the terminator). */
#define CV_AUTH_USER_BYTES 64

/** Longest accepted password, in bytes. */
#define CV_AUTH_PASSWORD_BYTES 1024

/** Opaque, immutable set of credentials and prefix grants. */
typedef struct cv_auth_policy cv_auth_policy;

/**
 * @brief Per-connection authentication state.
 *
 * The policy is borrowed and #user is an internal index that is meaningful only
 * while #authenticated is true. Treat the fields as private: create and reset
 * sessions with cv_auth_session_init() and cv_authenticate().
 */
typedef struct {
    bool authenticated;           /**< True after a successful cv_authenticate(). */
    const cv_auth_policy *policy; /**< Borrowed policy that vouched for the user. */
    size_t user;                  /**< Index of the user inside the policy. */
} cv_auth_session;

/**
 * @brief Hash a password into an Argon2id v1.3 PHC string.
 *
 * Uses 64 MiB of memory, two passes and a random salt. The caller keeps
 * ownership of @p password and is responsible for wiping it.
 *
 * @param password Password bytes (binary safe), borrowed for this call.
 * @param length   Password length, 1..#CV_AUTH_PASSWORD_BYTES.
 * @param out      Receives the NUL-terminated hash; zeroed on every error.
 * @return #CV_OK; #CV_ERR_INVALID_ARGUMENT for NULL or out-of-range input;
 *         #CV_ERR_CRYPTO when hashing fails.
 */
cv_status
cv_auth_hash_password(const unsigned char *password, size_t length, char out[CV_AUTH_HASH_BYTES]);

/**
 * @brief Load an immutable policy from a private regular file.
 *
 * The file format and limits are documented in docs/security.md. Imported
 * hashes must use exactly the cost produced by cv_auth_hash_password().
 *
 * @param path Policy file path.
 * @param out  Receives the owned policy; set to NULL on failure.
 * @return #CV_OK; #CV_ERR_INVALID_ARGUMENT; #CV_ERR_NO_MEMORY; #CV_ERR_IO;
 *         #CV_ERR_NOT_FOUND; #CV_ERR_CORRUPT or #CV_ERR_LIMIT for malformed or
 *         oversized files; #CV_ERR_CRYPTO when libsodium cannot initialise.
 */
cv_status cv_auth_policy_load(const char *path, cv_auth_policy **out);

/**
 * @brief Wipe credentials and grants, then free the policy.
 *
 * Reset or discard every session that borrows the policy first; using such a
 * session afterwards is invalid.
 *
 * @param policy Policy to destroy; NULL is safe.
 */
void cv_auth_policy_destroy(cv_auth_policy *policy);

/**
 * @brief Reset a session to the unauthenticated state.
 *
 * Call it before first use. Callers must not edit session fields directly.
 *
 * @param session Session to clear; NULL is safe.
 */
void cv_auth_session_init(cv_auth_session *session);

/**
 * @brief Revoke existing privileges, then verify a password.
 *
 * Success grants exactly the explicit rules of that identity. Every failure
 * leaves the session unauthenticated. Verification blocks synchronously; any
 * admission throttling is the caller's responsibility.
 *
 * @param session  Session to (re)authenticate.
 * @param policy   Policy to check against; must outlive the session.
 * @param username NUL-terminated candidate user name.
 * @param password Candidate password bytes (binary safe in the C API; the
 *                 network transport adds its own framing limits).
 * @param length   Password length, 1..#CV_AUTH_PASSWORD_BYTES.
 * @return #CV_OK; #CV_ERR_UNAUTHORIZED for an unknown user or wrong password;
 *         #CV_ERR_INVALID_ARGUMENT for NULL or out-of-range input.
 */
cv_status cv_authenticate(cv_auth_session *session,
                          const cv_auth_policy *policy,
                          const char *username,
                          const unsigned char *password,
                          size_t length);

/**
 * @brief Decide whether a session may read or write a key.
 *
 * Deny by default; matching literal prefixes combine independent read and
 * write grants. The call never inspects storage, so it cannot reveal whether a
 * key exists.
 *
 * @param session Session to check.
 * @param key     NUL-terminated key, at most #CV_MAX_KEY_BYTES long.
 * @param write   True to request write access (SET, DEL, EXPIRE), false for
 *                read access (GET, TTL).
 * @return #CV_OK when allowed, otherwise #CV_ERR_UNAUTHORIZED.
 */
cv_status cv_auth_authorize(const cv_auth_session *session, const char *key, bool write);

/**
 * @brief Borrow the validated name of the authenticated user.
 *
 * @param session Session to inspect.
 * @return The user name, valid until the policy is destroyed, or the static
 *         string "anonymous" when the session is not authenticated. Never NULL;
 *         nothing is allocated.
 */
const char *cv_auth_identity(const cv_auth_session *session);

#endif /* CVAULT_AUTH_H */
