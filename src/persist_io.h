#ifndef CVAULT_PERSIST_IO_H
#define CVAULT_PERSIST_IO_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "cvault/common.h"

#define CV_PERSIST_PATH_LIMIT ((size_t)4096)

typedef struct {
    intptr_t native;
} cv_file_lock;

char *cv_io_path(const char *directory, const char *name);

cv_status cv_io_directory(const char *path);

cv_status cv_io_lock(const char *path, cv_file_lock *lock);

void cv_io_unlock(cv_file_lock *lock);

cv_status cv_io_open(const char *path, bool create, bool exclusive, bool writable, FILE **out);

cv_status cv_io_write(FILE *file, const void *bytes, size_t length);

cv_status cv_io_sync(FILE * file);

cv_status cv_io_seek(FILE *file, uint64_t offset);

cv_status cv_io_tell(FILE * file, uint64_t * offset);

cv_status cv_io_truncate(FILE *file, uint64_t offset);

cv_status cv_io_publish(const char *temporary, const char *destination, const char *directory);

cv_status cv_io_sync_directory(const char *path);

cv_status cv_io_sync_parent(const char *path);

void cv_io_remove(const char *path);

#endif
