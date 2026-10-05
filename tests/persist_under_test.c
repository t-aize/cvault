/* Compile production logic with private I/O/allocation fault redirects. */
#if !defined(_WIN32)
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "cvault/persist.h"
#include "persist_io.h"
cv_status cv_test_sync(FILE *file);

cv_status cv_test_clone(const cv_hashtable *table, cv_hashtable **out);

#define cv_io_sync cv_test_sync
#define cv_hashtable_clone cv_test_clone
#include "../src/persist.c"
