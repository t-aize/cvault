#ifndef CVAULT_HASHTABLE_H
#define CVAULT_HASHTABLE_H

#include "cvault/common.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** @file
 * Owned, binary-safe storage with relative expiration. Keys are nonempty
 * NUL-terminated strings, limited to CV_MAX_KEY_BYTES bytes (excluding NUL).
 * Values are limited to CV_MAX_VALUE_BYTES bytes and may contain embedded NULs.
 * Callers must serialize all access: there is no internal locking.
 */
typedef struct cv_hashtable cv_hashtable;

/** Supply monotonic milliseconds; fill now_ms on CV_OK, otherwise return an error.
 * Readings must never decrease/wrap. Do not reenter the table from this callback.
 * The context is borrowed and must outlive the table.
 */
typedef cv_status (*cv_hashtable_clock)(void *context, uint64_t *now_ms);

/** Physical counts, including expired entries not yet reclaimed. */
typedef struct {
    size_t entries;
    size_t buckets;
    size_t max_chain_length;
} cv_hashtable_stats;

#define CV_TTL_PERSISTENT INT64_C(-1)
#define CV_TTL_MISSING INT64_C(-2)

/** Create an empty table with the platform monotonic clock.
 * Initializes libsodium and generates a private SipHash key. On failure *out is
 * NULL. Errors: INVALID_ARGUMENT, NO_MEMORY, CRYPTO.
 */
cv_status cv_hashtable_create(cv_hashtable **out);

/** Create with a custom clock, typically for deterministic testing.
 * NULL clock is invalid. Allocation/initialization behave as in create().
 */
cv_status
cv_hashtable_create_with_clock(cv_hashtable **out, cv_hashtable_clock clock, void *context);

/** Wipe keys, values and hash key before freeing. NULL is safe. */
void cv_hashtable_destroy(cv_hashtable *table);

/** SET copies inputs, inserts/replaces a value and clears its previous TTL.
 * NULL value is valid only for zero length. A borrowed table value may be used
 * as input. Allocation failure preserves existing values/TTLs.
 * Errors: INVALID_ARGUMENT, LIMIT (input/capacity), NO_MEMORY.
 */
cv_status cv_hashtable_set(cv_hashtable *table,
                           const char *key,
                           const unsigned char *value,
                           size_t value_length);

/** GET returns a borrowed value, valid until the next mutation or destruction.
 * Do not modify/free it. Empty values succeed with NULL/zero. Missing/expired
 * entries return NOT_FOUND. Supplied outputs are reset on errors.
 * Expired values are hidden immediately but retained until deletion or a sweep.
 * Time-dependent operations propagate clock errors without exposing expired data.
 */
cv_status cv_hashtable_get(const cv_hashtable *table,
                           const char *key,
                           const unsigned char **value,
                           size_t *value_length);

/** DEL wipes/removes a live entry. Missing/expired entries return NOT_FOUND;
 * an expired entry encountered here is reclaimed too.
 */
cv_status cv_hashtable_delete(cv_hashtable *table, const char *key);

/** EXPIRE replaces the TTL of a live entry, in seconds.
 * Nonpositive seconds delete immediately. Missing/expired keys return NOT_FOUND.
 * Deadline overflow returns LIMIT, preserving a live entry's previous TTL.
 */
cv_status cv_hashtable_expire(cv_hashtable *table, const char *key, int64_t seconds);

/** TTL returns remaining whole seconds, rounded down (zero can still be live).
 * Persistent: CV_OK / CV_TTL_PERSISTENT. Missing: NOT_FOUND / CV_TTL_MISSING.
 * Other errors also reset *seconds to CV_TTL_MISSING. Exact deadlines are expired.
 */
cv_status cv_hashtable_ttl(const cv_hashtable *table, const char *key, int64_t *seconds);

/** Wipe/free all expired entries in O(buckets + entries). Call periodically from
 * the future event loop; no background thread is created. *removed is reset on
 * errors. Clock failure leaves the table unchanged.
 */
cv_status cv_hashtable_purge_expired(cv_hashtable *table, size_t *removed);

/** Read physical counts without allocation/clock access. Resets output on error. */
cv_status cv_hashtable_get_stats(const cv_hashtable *table, cv_hashtable_stats *out);

/** Millisecond version of EXPIRE; zero deletes. Overflow preserves the entry. */
cv_status cv_hashtable_expire_ms(cv_hashtable *table, const char *key, uint64_t milliseconds);

/** Visit entries using one clock reading. No mutation/reentry into this table is
 * allowed during visitation. Slices are borrowed. With include_expired=true,
 * expired physical entries are included with expires=true and remaining_ms=0.
 * Callback errors stop traversal. This preserves history for snapshot replay.
 */
typedef cv_status (*cv_hashtable_visitor)(void *context,
                                          const char *key,
                                          const unsigned char *value,
                                          size_t length,
                                          bool expires,
                                          uint64_t remaining_ms);
cv_status cv_hashtable_visit(const cv_hashtable *table,
                             bool include_expired,
                             cv_hashtable_visitor visitor,
                             void *context);

/** Deep-copy live entries, preserving exact monotonic deadlines and borrowed
 * clock/context. Resets *out on failure. The context must outlive both tables.
 * O(buckets + entries + copied bytes); failed cloning leaves the source unchanged.
 */
cv_status cv_hashtable_clone(const cv_hashtable *table, cv_hashtable **out);

#endif
