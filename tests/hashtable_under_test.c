/**
 * @file hashtable_under_test.c
 * @brief The real hash table, compiled with allocation and hash fault injection.
 *
 * System headers are included before the redirects so that their own
 * declarations stay intact. This translation unit is used exclusively by
 * cvault-test-hashtable-faults.
 */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "hashtable_test_hooks.h"

#include <sodium.h>
#include <stdlib.h>

#define malloc           cv_test_malloc
#define calloc           cv_test_calloc
#define free             cv_test_free
#define crypto_shorthash cv_test_shorthash

#include "../src/hashtable.c"
