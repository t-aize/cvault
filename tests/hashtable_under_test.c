/* Compile the actual implementation with private fault/hash injection.
 * Include system headers before redirects so their declarations stay intact.
 * This translation unit is used exclusively by cvault-test-hashtable-faults.
 */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdlib.h>
#include <sodium.h>
#include "hashtable_test_hooks.h"
#define malloc cv_test_malloc
#define calloc cv_test_calloc
#define free cv_test_free
#define crypto_shorthash cv_test_shorthash
#include "../src/hashtable.c"
