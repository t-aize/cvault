/**
 * @file audit_under_test.c
 * @brief The real audit log, compiled with an injectable synchronisation fault.
 *
 * Production targets always use the platform durability implementation; only
 * the security fixture links this variant.
 */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "../src/persist_io.h"

cv_status cv_test_audit_sync(FILE *file);

#define cv_io_sync cv_test_audit_sync

#include "../src/audit.c"
