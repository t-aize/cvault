/**
 * @file hashtable.h
 * @brief In-memory, binary-safe key/value store with relative expiration.
 *
 * Keys are non-empty NUL-terminated strings of at most #CV_MAX_KEY_BYTES bytes
 * (excluding the terminator). Values are limited to #CV_MAX_VALUE_BYTES bytes
 * and may contain embedded NUL bytes. The table owns private copies of both and
 * wipes them before releasing the memory.
 *
 * ## Concurrency
 * There is no internal locking: callers must serialise every access. The
 * server drives a single table from its one event-loop thread.
 *
 * ## Expiration
 * Deadlines are process-local monotonic milliseconds, never wall-clock times.
 * An expired entry is hidden immediately but stays physically stored until it
 * is deleted, overwritten or swept by cv_hashtable_purge_expired().
 *
 * ## Complexity
 * Lookup, insert and delete are O(1) on average. The table doubles at 75 %
 * occupancy and uses a keyed SipHash so that attackers cannot force collisions.
 */

#ifndef CVAULT_HASHTABLE_H
#define CVAULT_HASHTABLE_H

#include "cvault/common.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Opaque handle to a hash table. */
typedef struct cv_hashtable cv_hashtable;

/**
 * @brief Source of monotonic milliseconds for expiration decisions.
 *
 * Readings must never decrease or wrap. The callback must not re-enter the
 * table, and @p context is borrowed: it must outlive the table.
 *
 * @param context Opaque pointer supplied at creation.
 * @param now_ms  Receives the current reading; written only on #CV_OK.
 * @return #CV_OK, or an error that the table propagates to its caller.
 */
typedef cv_status (*cv_hashtable_clock)(void *context, uint64_t *now_ms);

/** Physical table counts, including expired entries not yet reclaimed. */
typedef struct {
    size_t entries;          /**< Stored entries. */
    size_t buckets;          /**< Allocated buckets (always a power of two). */
    size_t max_chain_length; /**< Longest collision chain currently present. */
} cv_hashtable_stats;

/** TTL result for a live key that never expires. */
#define CV_TTL_PERSISTENT INT64_C(-1)

/** TTL result for a key that does not exist (or has already expired). */
#define CV_TTL_MISSING INT64_C(-2)

/**
 * @brief Create an empty table driven by the platform monotonic clock.
 *
 * Initialises libsodium and generates a private SipHash key.
 *
 * @param out Receives the new table; set to NULL on failure.
 * @return #CV_OK, #CV_ERR_INVALID_ARGUMENT, #CV_ERR_NO_MEMORY or #CV_ERR_CRYPTO.
 */
cv_status cv_hashtable_create(cv_hashtable **out);

/**
 * @brief Create an empty table with a custom clock, typically for tests.
 *
 * @param out     Receives the new table; set to NULL on failure.
 * @param clock   Time source; NULL is invalid.
 * @param context Opaque pointer handed to @p clock; borrowed, may be NULL.
 * @return Same codes as cv_hashtable_create().
 */
cv_status
cv_hashtable_create_with_clock(cv_hashtable **out, cv_hashtable_clock clock, void *context);

/**
 * @brief Wipe every key, value and the hash key, then free the table.
 *
 * @param table Table to destroy; NULL is safe.
 */
void cv_hashtable_destroy(cv_hashtable *table);

/**
 * @brief SET: copy a value in, replacing any previous one and clearing its TTL.
 *
 * The input may be a value borrowed from this very table. A failed allocation
 * leaves existing values and TTLs untouched.
 *
 * @param table        Target table.
 * @param key          Non-empty key within #CV_MAX_KEY_BYTES.
 * @param value        Bytes to store; NULL is valid only when @p value_length is 0.
 * @param value_length Number of bytes, at most #CV_MAX_VALUE_BYTES.
 * @return #CV_OK, #CV_ERR_INVALID_ARGUMENT, #CV_ERR_LIMIT (input or capacity)
 *         or #CV_ERR_NO_MEMORY.
 */
cv_status cv_hashtable_set(cv_hashtable *table,
                           const char *key,
                           const unsigned char *value,
                           size_t value_length);

/**
 * @brief GET: borrow the value stored under a key.
 *
 * The returned pointer stays valid until the next mutation or destruction of
 * the table; do not modify or free it. Empty values succeed with a NULL
 * pointer and zero length. Expired values are reported as not found, and clock
 * failures are propagated without exposing expired data.
 *
 * @param table        Source table.
 * @param key          Key to look up.
 * @param value        Receives the borrowed bytes; reset to NULL on every error.
 * @param value_length Receives the length; reset to 0 on every error.
 * @return #CV_OK, #CV_ERR_NOT_FOUND, #CV_ERR_INVALID_ARGUMENT, #CV_ERR_LIMIT or
 *         a clock error.
 */
cv_status cv_hashtable_get(const cv_hashtable *table,
                           const char *key,
                           const unsigned char **value,
                           size_t *value_length);

/**
 * @brief DEL: wipe and remove a live entry.
 *
 * An expired entry found here is reclaimed too, but reported as not found.
 *
 * @param table Target table.
 * @param key   Key to delete.
 * @return #CV_OK, #CV_ERR_NOT_FOUND, #CV_ERR_INVALID_ARGUMENT, #CV_ERR_LIMIT or
 *         a clock error.
 */
cv_status cv_hashtable_delete(cv_hashtable *table, const char *key);

/**
 * @brief EXPIRE: replace the time to live of a live entry, in seconds.
 *
 * Non-positive @p seconds delete the entry immediately.
 *
 * @param table   Target table.
 * @param key     Key to update.
 * @param seconds Relative lifetime.
 * @return #CV_OK; #CV_ERR_NOT_FOUND for a missing or expired key;
 *         #CV_ERR_LIMIT when the deadline would overflow (the previous TTL is
 *         preserved); #CV_ERR_INVALID_ARGUMENT or a clock error.
 */
cv_status cv_hashtable_expire(cv_hashtable *table, const char *key, int64_t seconds);

/**
 * @brief TTL: report the remaining lifetime in whole seconds, rounded down.
 *
 * A result of zero can still belong to a live key. A key whose deadline has
 * been reached is considered expired.
 *
 * @param table   Source table.
 * @param key     Key to inspect.
 * @param seconds Receives the remaining seconds, #CV_TTL_PERSISTENT for a key
 *                without expiry, or #CV_TTL_MISSING on every error.
 * @return #CV_OK (including persistent keys), #CV_ERR_NOT_FOUND,
 *         #CV_ERR_INVALID_ARGUMENT, #CV_ERR_LIMIT or a clock error.
 */
cv_status cv_hashtable_ttl(const cv_hashtable *table, const char *key, int64_t *seconds);

/**
 * @brief Wipe and free every expired entry in O(buckets + entries).
 *
 * No background thread exists: the owner calls this periodically. A clock
 * failure leaves the table unchanged.
 *
 * @param table   Table to sweep.
 * @param removed Receives the number of reclaimed entries; reset to 0 on error.
 * @return #CV_OK, #CV_ERR_INVALID_ARGUMENT or a clock error.
 */
cv_status cv_hashtable_purge_expired(cv_hashtable *table, size_t *removed);

/**
 * @brief Read physical counts without allocating or reading the clock.
 *
 * @param table Source table.
 * @param out   Receives the counters; zeroed on error.
 * @return #CV_OK or #CV_ERR_INVALID_ARGUMENT.
 */
cv_status cv_hashtable_get_stats(const cv_hashtable *table, cv_hashtable_stats *out);

/**
 * @brief Millisecond-resolution variant of cv_hashtable_expire().
 *
 * Zero deletes the entry. Overflow returns #CV_ERR_LIMIT and preserves it.
 *
 * @param table        Target table.
 * @param key          Key to update.
 * @param milliseconds Relative lifetime in milliseconds.
 * @return Same codes as cv_hashtable_expire().
 */
cv_status cv_hashtable_expire_ms(cv_hashtable *table, const char *key, uint64_t milliseconds);

/**
 * @brief Callback invoked by cv_hashtable_visit() for each entry.
 *
 * Slices are borrowed and valid only during the call. The callback must not
 * mutate or re-enter the table being visited; a non-OK return stops the walk.
 *
 * @param context      Opaque pointer given to cv_hashtable_visit().
 * @param key          NUL-terminated key.
 * @param value        Value bytes (may be NULL when @p length is 0).
 * @param length       Value length.
 * @param expires      Whether the entry carries a deadline.
 * @param remaining_ms Milliseconds until expiry; 0 when persistent or expired.
 */
typedef cv_status (*cv_hashtable_visitor)(void *context,
                                          const char *key,
                                          const unsigned char *value,
                                          size_t length,
                                          bool expires,
                                          uint64_t remaining_ms);

/**
 * @brief Visit entries using a single clock reading.
 *
 * With @p include_expired set, physically present expired entries are reported
 * with @p expires true and a remaining time of zero; this preserves history for
 * snapshot replay.
 *
 * @param table           Table to walk.
 * @param include_expired Whether to report expired but unreclaimed entries.
 * @param visitor         Callback; NULL is invalid.
 * @param context         Opaque pointer forwarded to @p visitor.
 * @return #CV_OK, #CV_ERR_INVALID_ARGUMENT, a clock error or the first error
 *         returned by @p visitor.
 */
cv_status cv_hashtable_visit(const cv_hashtable *table,
                             bool include_expired,
                             cv_hashtable_visitor visitor,
                             void *context);

/**
 * @brief Deep-copy the live entries of a table.
 *
 * Exact monotonic deadlines are preserved and the clock and its context are
 * shared with the copy, so the context must outlive both tables. Cost is
 * O(buckets + entries + copied bytes). A failed clone leaves the source intact.
 *
 * @param table Source table.
 * @param out   Receives the copy; set to NULL on failure.
 * @return #CV_OK, #CV_ERR_INVALID_ARGUMENT, #CV_ERR_NO_MEMORY, #CV_ERR_CRYPTO
 *         or a clock error.
 */
cv_status cv_hashtable_clone(const cv_hashtable *table, cv_hashtable **out);

#endif /* CVAULT_HASHTABLE_H */
