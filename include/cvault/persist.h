#ifndef CVAULT_PERSIST_H
#define CVAULT_PERSIST_H

#include "cvault/common.h"
#include "cvault/hashtable.h"

/* TODO: versioned encrypted append-only format, crash-safe replay,
 * fsync policy, snapshots and atomic compaction. No files are touched yet. */
cv_status cv_persist_replay(const char *directory, cv_hashtable *table);
cv_status cv_persist_snapshot(const char *directory, const cv_hashtable *table);

#endif
