/* Compile the real audit implementation with a private synchronization fault.
 * Production targets always use the platform durability implementation. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include "../src/persist_io.h"
cv_status cv_test_audit_sync(FILE *file);
#define cv_io_sync cv_test_audit_sync
#include "../src/audit.c"
