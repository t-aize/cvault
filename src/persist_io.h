#ifndef CVAULT_PERSIST_IO_H
#define CVAULT_PERSIST_IO_H

#include "cvault/common.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define CV_PERSIST_PATH_LIMIT ((size_t)4096)

/** @file Private platform file layer, shared by persistence and security.
 * Paths name trusted local locations, with bounded NUL-terminated UTF-8 strings.
 * These internal calls are serialized by their owning module. POSIX checks
 * ownership/mode; Windows creation uses a protected owner/System DACL. Existing
 * Windows permissions and trusted parent directories belong to the operator.
 */

typedef struct {
    intptr_t native;
} cv_file_lock;

/** Allocate a joined path; caller frees it. Empty name allows a trailing slash. */
char *cv_io_path(const char *directory, const char *name);

/** Create a private directory or validate the existing directory. */
cv_status cv_io_directory(const char *path);

/** Acquire an exclusive process lock without waiting; initialize native to -1.
 * BUSY means another owner holds the file. unlock closes/releases the handle. */
cv_status cv_io_lock(const char *path, cv_file_lock *lock);

void cv_io_unlock(cv_file_lock *lock);

/** Open a private regular file, rejecting leaf symlinks/reparse points and hard
 * links. exclusive requires a new file; no existing contents are truncated.
 * *out resets on failure; caller owns fclose. NOT_FOUND distinguishes absence. */
cv_status cv_io_open(const char *path, bool create, bool exclusive, bool writable, FILE **out);

/** Write all requested bytes to stdio; durability requires a later sync. */
cv_status cv_io_write(FILE *file, const void *bytes, size_t length);

/** Flush stdio and synchronize file contents (including full sync on macOS).
 * Failure leaves an uncertain on-disk outcome; owners must fail closed. */
cv_status cv_io_sync(FILE *file);

cv_status cv_io_seek(FILE *file, uint64_t offset);

cv_status cv_io_tell(FILE *file, uint64_t *offset);

/** Truncate, seek and synchronize. Use only for explicitly recoverable tails. */
cv_status cv_io_truncate(FILE *file, uint64_t offset);

/** Atomically replace the destination with a synchronized temporary file and
 * synchronize directory metadata where supported. Both paths share a directory. */
cv_status cv_io_publish(const char *temporary, const char *destination, const char *directory);

cv_status cv_io_sync_directory(const char *path);

cv_status cv_io_sync_parent(const char *path);

void cv_io_remove(const char *path);

#endif
