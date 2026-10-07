/**
 * @file persist.h
 * @brief Encrypted append-only storage with authenticated checkpoints.
 *
 * A persistent store keeps the live key/value state in memory and mirrors every
 * mutation into an XChaCha20-Poly1305 encrypted journal. Periodic snapshots
 * checkpoint the state; on start-up the snapshot and the journal tail are
 * authenticated and replayed. No plaintext key or value ever reaches the disk.
 *
 * ## Guarantees
 *  - One owner thread or process per directory (enforced with a lock file).
 *  - Use a private, trusted local directory.
 *  - A successful mutation has synchronised the journal *before* the new state
 *    becomes visible in memory.
 *  - An I/O failure makes the handle unusable until it is closed and reopened;
 *    the failed operation may or may not appear after recovery.
 *  - Only an incomplete final journal record is repaired (truncated). Any
 *    complete but invalid record, or a malformed snapshot, fails closed.
 *
 * See docs/persistence.md for the on-disk formats and recovery rules.
 */

#ifndef CVAULT_PERSIST_H
#define CVAULT_PERSIST_H

#include "cvault/common.h"
#include "cvault/hashtable.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Size of the encryption key, in bytes. */
#define CV_PERSIST_KEY_BYTES ((size_t)32)

/** Opaque handle to an open persistent store. */
typedef struct cv_persist cv_persist;

/**
 * @brief Source of Unix-epoch milliseconds for persisted deadlines.
 *
 * Defaults to the system clock. The clock and its context are borrowed until
 * the store is closed, and POSIX snapshot children inherit them, so callbacks
 * must be non-blocking and fork-safe in a single-threaded process.
 *
 * @param context   Opaque pointer supplied in #cv_persist_options.
 * @param epoch_ms  Receives the current time; written only on #CV_OK.
 */
typedef cv_status (*cv_persist_clock)(void *context, uint64_t *epoch_ms);

/** Parameters for cv_persist_open(); the structure is copied. */
typedef struct {
    const char *directory;    /**< Data directory, created privately if absent. */
    const unsigned char *key; /**< Encryption key (copied and wiped on close). */
    size_t key_length;        /**< Must equal #CV_PERSIST_KEY_BYTES. */
    cv_persist_clock clock;   /**< Optional clock; NULL selects the system clock. */
    void *clock_context;      /**< Borrowed argument for #clock. */
} cv_persist_options;

/** Counters describing the durable state. */
typedef struct {
    uint64_t sequence;          /**< Sequence number of the last journal record. */
    uint64_t snapshot_sequence; /**< Sequence covered by the newest snapshot. */
    uint64_t journal_baseline;  /**< Sequence before the first record kept in the journal. */
    bool repaired_tail;         /**< An incomplete final record was truncated on open. */
    bool failed;                /**< The handle is poisoned after an I/O failure. */
} cv_persist_stats;

/**
 * @brief Open a store: lock the directory, replay snapshot and journal.
 *
 * The directory is created if absent. Options and key are copied; the clock
 * context stays borrowed.
 *
 * @param options Open parameters.
 * @param out     Receives the store; set to NULL on failure.
 * @return #CV_OK; #CV_ERR_INVALID_ARGUMENT; #CV_ERR_BUSY (directory in use);
 *         #CV_ERR_CRYPTO (wrong key); #CV_ERR_CORRUPT; #CV_ERR_IO;
 *         #CV_ERR_NO_MEMORY.
 */
cv_status cv_persist_open(const cv_persist_options *options, cv_persist **out);

/**
 * @brief SET: durably store a value, clearing any previous TTL.
 *
 * Changes are prepared on a copy before any I/O, so an allocation failure
 * leaves both disk and memory unchanged. Mutations cost O(live state size);
 * the design favours transactional correctness over write throughput.
 *
 * @return #CV_OK, #CV_ERR_INVALID_ARGUMENT, #CV_ERR_LIMIT, #CV_ERR_NO_MEMORY,
 *         #CV_ERR_CRYPTO or #CV_ERR_IO.
 */
cv_status
cv_persist_set(cv_persist *store, const char *key, const unsigned char *value, size_t length);

/**
 * @brief DEL: durably delete a key.
 *
 * A missing key returns #CV_ERR_NOT_FOUND without writing anything.
 */
cv_status cv_persist_delete(cv_persist *store, const char *key);

/**
 * @brief EXPIRE: durably set a relative TTL; non-positive seconds delete.
 *
 * A missing key returns #CV_ERR_NOT_FOUND without writing anything.
 */
cv_status cv_persist_expire(cv_persist *store, const char *key, int64_t seconds);

/**
 * @brief GET: borrow a value from the in-memory state.
 *
 * Same contract as cv_hashtable_get(): the pointer stays valid until the next
 * mutation or close.
 */
cv_status cv_persist_get(const cv_persist *store,
                         const char *key,
                         const unsigned char **value,
                         size_t *length);

/** @brief TTL: remaining whole seconds, see cv_hashtable_ttl(). */
cv_status cv_persist_ttl(const cv_persist *store, const char *key, int64_t *seconds);

/**
 * @brief Read the durable-state counters.
 *
 * @param out Receives the counters; zeroed on error.
 */
cv_status cv_persist_get_stats(const cv_persist *store, cv_persist_stats *out);

/**
 * @brief Borrow the live table for read-only iteration.
 *
 * Valid until the next mutation or close. Never cast away const: direct
 * mutations would bypass the journal.
 *
 * @return The table, or NULL when the handle has failed.
 */
const cv_hashtable *cv_persist_table(const cv_persist *store);

/**
 * @brief Write an atomic snapshot and wait for it.
 *
 * The journal is retained; compaction is not implemented yet.
 */
cv_status cv_persist_snapshot(cv_persist *store);

/**
 * @brief Wipe and free the expired entries held in memory.
 *
 * Expired values are already invisible to readers, but they stay in memory until
 * something touches them. Calling this on a timer erases them promptly, so a value
 * whose lifetime is over does not linger in the process. Nothing is written to the
 * journal: expiry derives from the persisted deadlines, and recovery drops expired
 * entries by itself. Cost is O(buckets + entries).
 *
 * @param store   Store to sweep.
 * @param removed Receives the number of entries erased; reset to 0 on error.
 * @return #CV_OK, #CV_ERR_INVALID_ARGUMENT, #CV_ERR_IO (failed handle or clock failure).
 */
cv_status cv_persist_purge_expired(cv_persist *store, size_t *removed);

/**
 * @brief Compact the journal: drop the records already covered by the newest snapshot.
 *
 * A snapshot makes older journal records redundant but does not remove them, so
 * the journal only ever grows. Compaction rewrites it with just the records that
 * follow the snapshot: a new journal (same identity, baseline equal to the
 * snapshot sequence) is written next to the old one, synchronised and atomically
 * renamed over it. A crash at any point leaves either the complete old journal or
 * the complete new one, and both recover to the same state.
 *
 * Take a snapshot first (cv_persist_snapshot() or a finished background
 * snapshot); with no newer snapshot than the journal baseline there is nothing to
 * drop and the call succeeds without touching the disk. The dropped records, which
 * hold the previous encrypted versions of every value, are gone from the file
 * system afterwards; on SSDs and backups physical erasure cannot be promised.
 *
 * Cost is proportional to the records kept (those written since the snapshot).
 *
 * @return #CV_OK; #CV_ERR_BUSY while a background snapshot is running;
 *         #CV_ERR_IO for a failed handle or a failure *before* the swap (the
 *         journal is untouched and the store stays usable); a failure after the
 *         swap point poisons the handle, which must then be closed and reopened.
 */
cv_status cv_persist_compact(cv_persist *store);

/**
 * @brief Start a snapshot in the background.
 *
 * POSIX forks a child (single-threaded processes only); Windows uses a worker
 * thread on an owned, frozen copy. Only one job may run per handle. The job
 * captures a sequence boundary and later writes remain in the journal.
 */
cv_status cv_persist_snapshot_start(cv_persist *store);

/**
 * @brief Check on the background snapshot without blocking.
 *
 * Completed jobs are reclaimed and their status returned. With no active job,
 * @p done is true.
 *
 * @param done Receives whether the job has finished; reset on errors.
 */
cv_status cv_persist_snapshot_poll(cv_persist *store, bool *done);

/** @brief Block until the active background snapshot (if any) finishes. */
cv_status cv_persist_snapshot_wait(cv_persist *store);

/**
 * @brief Join any snapshot, close files, release the lock and wipe all secrets.
 *
 * Resources are always released, even when an I/O or job error is returned.
 *
 * @param store Store to close; NULL is safe.
 */
cv_status cv_persist_close(cv_persist *store);

/**
 * @brief Re-encrypt a data directory under a new key (offline).
 *
 * The store is opened with the old key (which authenticates all of its history),
 * its live state is written as a snapshot plus an empty journal under the new key
 * into a sibling directory `<directory>.rekey`, that copy is reopened and compared
 * with the original, and only then are the directories swapped: the old one is
 * renamed to `<directory>.rekey-old`, the new one takes its name, and the old one
 * is deleted. Afterwards nothing under the old key remains in the file system
 * (physical erasure from SSDs and backups cannot be promised).
 *
 * The new store gets a fresh identity and its sequence numbers restart at zero;
 * expired entries are dropped and the journal history is not carried over, which
 * also makes this a compaction. The directory is locked for the whole operation, so
 * the server must be stopped.
 *
 * A crash before the swap leaves the original directory untouched and a stale
 * `<directory>.rekey` that must be removed by hand before trying again. A crash
 * between the two renames is completed by the next cv_persist_open(): the data
 * directory is then missing, the verified copy is moved into place and the old
 * directory is deleted.
 *
 * @param directory Data directory to rotate.
 * @param old_key   Current 32-byte key.
 * @param new_key   New 32-byte key; must differ from @p old_key.
 * @return #CV_OK; #CV_ERR_INVALID_ARGUMENT (including equal keys); #CV_ERR_NOT_FOUND
 *         (no such directory: a rotation never creates one); #CV_ERR_BUSY (the
 *         directory is in use, or a `.rekey` / `.rekey-old` sibling exists);
 *         #CV_ERR_CRYPTO (wrong old key); #CV_ERR_CORRUPT (the copy did not match
 *         the original, nothing was swapped); #CV_ERR_IO, #CV_ERR_NO_MEMORY. An
 *         #CV_ERR_IO after the swap means the old directory could not be deleted:
 *         the rotation itself succeeded and `<directory>.rekey-old` must be removed.
 */
cv_status cv_persist_rotate_key(const char *directory,
                                const unsigned char old_key[CV_PERSIST_KEY_BYTES],
                                const unsigned char new_key[CV_PERSIST_KEY_BYTES]);

/**
 * @brief Generate a new random key file; an existing file is never overwritten.
 *
 * POSIX creates the file with owner-only permissions; Windows uses a protected
 * owner/SYSTEM DACL.
 *
 * @return #CV_OK, #CV_ERR_BUSY if the path exists, #CV_ERR_CRYPTO or #CV_ERR_IO.
 */
cv_status cv_persist_key_generate(const char *path);

/**
 * @brief Load a key from an exact 32-byte private regular file.
 *
 * POSIX requires owner-only permissions. The caller owns the output and must
 * wipe it with cv_crypto_wipe().
 *
 * @param path Key file path.
 * @param key  Receives the 32 key bytes.
 * @return #CV_OK, #CV_ERR_NOT_FOUND, #CV_ERR_CORRUPT (wrong size) or #CV_ERR_IO.
 */
cv_status cv_persist_key_load(const char *path, unsigned char key[CV_PERSIST_KEY_BYTES]);

#endif /* CVAULT_PERSIST_H */
