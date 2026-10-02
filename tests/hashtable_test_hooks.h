#ifndef CVAULT_HASHTABLE_TEST_HOOKS_H
#define CVAULT_HASHTABLE_TEST_HOOKS_H

#include <stdbool.h>
#include <stddef.h>

/* Private harness controls; never linked into the production library. */
extern long cv_test_allocations_left;
extern bool cv_test_force_collisions;
extern size_t cv_test_live_allocations;
extern size_t cv_test_wipe_failures;
void *cv_test_malloc(size_t size);
void *cv_test_calloc(size_t count, size_t size);
void cv_test_free(void *pointer);
int cv_test_shorthash(unsigned char *out, const unsigned char *input,
                      unsigned long long length, const unsigned char *key);

#endif
