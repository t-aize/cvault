#ifndef CVAULT_PERSIST_H
#define CVAULT_PERSIST_H

#include "cvault/common.h"
#include "cvault/hashtable.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** @file Encrypted append-only storage and authenticated checkpoints.
 * One owner thread/process per directory. Use a private, trusted local directory.
 * Successful mutations synchronize the journal before publishing new memory state.
 * I/O failure makes the handle unusable until close/reopen; a failed operation may
 * still appear after recovery. No plaintext key/value records are written to disk.
 */
#define CV_PERSIST_KEY_BYTES ((size_t)32)
typedef struct cv_persist cv_persist;

/** Unix-epoch milliseconds for persisted deadlines; defaults to the system clock.
 * Clock/context are borrowed until close; POSIX snapshot children inherit them.
 * Callbacks must be nonblocking and fork-safe in a single-threaded process.
 */
typedef cv_status (*cv_persist_clock)(void *context, uint64_t *epoch_ms);

typedef struct {
    const char *directory;
    const unsigned char *key;
    size_t key_length;
    cv_persist_clock clock;
    void *clock_context;
} cv_persist_options;

typedef struct {
    uint64_t sequence;
    uint64_t snapshot_sequence;
    bool repaired_tail;
    bool failed;
} cv_persist_stats;

/** Create the directory if absent, lock it exclusively, authenticate/replay its
 * snapshot and journal, and restore live state. Only an incomplete final journal
 * record is truncated. Complete invalid records or malformed snapshots fail closed.
 * *out resets on error. Options/key are copied; clock context remains borrowed.
 */
cv_status cv_persist_open(const cv_persist_options *options, cv_persist **out);

/** Durable operations. SET clears TTL; EXPIRE nonpositive seconds deletes.
 * Missing DEL/EXPIRE returns NOT_FOUND without writing. Cloning prepares changes
 * before I/O, so allocation failure leaves disk/memory unchanged. Mutations are
 * O(live state size); this favors transactional correctness over write throughput.
 */
cv_status
cv_persist_set(cv_persist *store, const char *key, const unsigned char *value, size_t length);

cv_status cv_persist_delete(cv_persist *store, const char *key);

cv_status cv_persist_expire(cv_persist *store, const char *key, int64_t seconds);

cv_status cv_persist_get(const cv_persist *store,
                         const char *key,
                         const unsigned char **value,
                         size_t *length);

cv_status cv_persist_ttl(const cv_persist *store, const char *key, int64_t *seconds);

cv_status cv_persist_get_stats(const cv_persist *store, cv_persist_stats *out);

/** Borrow a read-only table until the next mutation or close. NULL on failed handle.
 * Do not cast away const: direct mutations bypass the journal.
 */
const cv_hashtable *cv_persist_table(const cv_persist *store);

/** Synchronous atomic snapshot; journal is retained (no compaction yet). */
cv_status cv_persist_snapshot(cv_persist *store);

/** Start a background snapshot: POSIX fork (single-threaded process only), or a
 * Windows worker using an owned, frozen copy. Only one job may run per handle.
 * The job captures a sequence boundary; later writes remain in the journal.
 */
cv_status cv_persist_snapshot_start(cv_persist *store);

/** Poll without blocking, or join the active job. Poll resets *done on errors;
 * completed jobs are reclaimed and their status returned. No active job means done.
 */
cv_status cv_persist_snapshot_poll(cv_persist *store, bool *done);

cv_status cv_persist_snapshot_wait(cv_persist *store);

/** Join any snapshot, close files/release lock, wipe keys and destroy memory state.
 * NULL is safe. Always releases resources, even when returning an I/O/job error.
 */
cv_status cv_persist_close(cv_persist *store);

/** Generate a new 32-byte key file exclusively (never overwrite), or load an exact
 * 32-byte private regular file. POSIX requires owner-only permissions on load.
 * Windows creation uses a protected owner/System DACL. Caller owns/wipes loaded key.
 */
cv_status cv_persist_key_generate(const char *path);

cv_status cv_persist_key_load(const char *path, unsigned char key[CV_PERSIST_KEY_BYTES]);

#endif
