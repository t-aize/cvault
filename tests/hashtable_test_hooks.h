/**
 * @file hashtable_test_hooks.h
 * @brief Fault-injection controls for the hash table failure tests.
 *
 * These symbols belong to the private test harness and are never linked into
 * the production library.
 */

#ifndef CVAULT_HASHTABLE_TEST_HOOKS_H
#define CVAULT_HASHTABLE_TEST_HOOKS_H

#include <stdbool.h>
#include <stddef.h>

/** Allocations still allowed before malloc/calloc start failing (negative: unlimited). */
extern long cv_test_allocations_left;

/** When true, every key hashes to the same value, forcing one long chain. */
extern bool cv_test_force_collisions;

/** Number of allocations currently outstanding (detects leaks). */
extern size_t cv_test_live_allocations;

/** Number of frees that observed an unwiped buffer. */
extern size_t cv_test_wipe_failures;

/** @brief Counting, fault-injecting replacement for malloc(). */
void *cv_test_malloc(size_t size);

/** @brief Counting, fault-injecting replacement for calloc(). */
void *cv_test_calloc(size_t count, size_t size);

/** @brief Counting replacement for free(). */
void cv_test_free(void *pointer);

/** @brief Replacement for crypto_shorthash() that can force collisions. */
int cv_test_shorthash(unsigned char *out,
                      const unsigned char *input,
                      unsigned long long length,
                      const unsigned char *key);

#endif /* CVAULT_HASHTABLE_TEST_HOOKS_H */
