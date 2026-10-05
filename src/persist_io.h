/**
 * @file persist_io.h
 * @brief Private platform file layer shared by persistence and security.
 *
 * Paths name trusted local locations as bounded, NUL-terminated UTF-8 strings.
 * These internal calls are serialised by their owning module. On POSIX every
 * opened file must be owned by the effective user and have no group or world
 * permission bits; on Windows new files and directories are created with a
 * protected DACL granting access only to the owner and SYSTEM. Pre-existing
 * Windows permissions and trusted parent directories remain the operator's
 * responsibility.
 */

#ifndef CVAULT_PERSIST_IO_H
#define CVAULT_PERSIST_IO_H

#include "cvault/common.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/** Longest accepted path in bytes, including the terminator. */
#define CV_PERSIST_PATH_LIMIT ((size_t)4096)

/** Exclusive process-wide lock on a lock file; `native` is -1 when not held. */
typedef struct {
    intptr_t native; /**< File descriptor (POSIX) or HANDLE (Windows). */
} cv_file_lock;

/**
 * @brief Join a directory and a name into a newly allocated path.
 *
 * @param directory Directory path.
 * @param name      Entry name; an empty name yields a trailing slash.
 * @return A heap string the caller must free, or NULL for invalid or oversized
 *         input and allocation failure.
 */
char *cv_io_path(const char *directory, const char *name);

/**
 * @brief Create a private directory, or validate an existing one.
 *
 * An existing directory must be a real directory (no symlink or reparse point)
 * owned by the caller and not writable by others.
 *
 * @return #CV_OK, #CV_ERR_INVALID_ARGUMENT, #CV_ERR_NO_MEMORY or #CV_ERR_IO.
 */
cv_status cv_io_directory(const char *path);

/**
 * @brief Take an exclusive lock without waiting.
 *
 * @param path Lock file path, created privately when missing.
 * @param lock Receives the lock; `native` is reset to -1 first.
 * @return #CV_OK, #CV_ERR_BUSY when another owner holds it, or #CV_ERR_IO.
 */
cv_status cv_io_lock(const char *path, cv_file_lock *lock);

/**
 * @brief Release a lock acquired with cv_io_lock(); safe when not held.
 */
void cv_io_unlock(cv_file_lock *lock);

/**
 * @brief Open a private regular file.
 *
 * Leaf symbolic links, reparse points and hard links are rejected. When
 * @p exclusive is set the file must be new; existing contents are never
 * truncated.
 *
 * @param path      File path.
 * @param create    Create the file when missing.
 * @param exclusive Require creation of a new file (fails with #CV_ERR_BUSY if it exists).
 * @param writable  Open for reading and writing instead of read only.
 * @param out       Receives the stream (caller must fclose); NULL on failure.
 * @return #CV_OK, #CV_ERR_NOT_FOUND when the file is absent, #CV_ERR_BUSY,
 *         #CV_ERR_INVALID_ARGUMENT or #CV_ERR_IO.
 */
cv_status cv_io_open(const char *path, bool create, bool exclusive, bool writable, FILE **out);

/**
 * @brief Write every requested byte to the stdio stream.
 *
 * Durability requires a later cv_io_sync().
 */
cv_status cv_io_write(FILE *file, const void *bytes, size_t length);

/**
 * @brief Flush stdio and synchronise file contents to stable storage.
 *
 * macOS additionally requests a full drive cache flush. A failure leaves the
 * on-disk outcome uncertain, so owners must fail closed.
 */
cv_status cv_io_sync(FILE *file);

/** @brief Seek to an absolute offset (at most INT64_MAX). */
cv_status cv_io_seek(FILE *file, uint64_t offset);

/** @brief Report the current absolute offset. */
cv_status cv_io_tell(FILE *file, uint64_t *offset);

/**
 * @brief Truncate to @p offset, seek there and synchronise.
 *
 * Only for explicitly recoverable tails.
 */
cv_status cv_io_truncate(FILE *file, uint64_t offset);

/**
 * @brief Atomically replace @p destination with a synchronised temporary file.
 *
 * Directory metadata is synchronised where the platform supports it. Both paths
 * must live in @p directory.
 */
cv_status cv_io_publish(const char *temporary, const char *destination, const char *directory);

/** @brief Synchronise a directory so that renames inside it are durable. */
cv_status cv_io_sync_directory(const char *path);

/** @brief Synchronise the directory that contains @p path. */
cv_status cv_io_sync_parent(const char *path);

/** @brief Best-effort removal of a file; errors are ignored. */
void cv_io_remove(const char *path);

#endif /* CVAULT_PERSIST_IO_H */
