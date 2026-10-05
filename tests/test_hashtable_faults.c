#include "cvault/hashtable.h"
#include "hashtable_test_hooks.h"
#include "test_util.h"
#include <sodium.h>
#include <string.h>

long cv_test_allocations_left = -1;
bool cv_test_force_collisions = true;
size_t cv_test_live_allocations = 0;
size_t cv_test_wipe_failures = 0;

typedef struct {
    void *pointer;
    size_t size;
    bool must_be_wiped;
} allocation;

static allocation allocations[2048];

static void *track(void *pointer, size_t size, bool wipe) {
    if (pointer != NULL) {
        for (size_t i = 0; i < sizeof(allocations) / sizeof(allocations[0]); ++i) {
            if (allocations[i].pointer == NULL) {
                allocations[i] = (allocation){pointer, size, wipe};
                ++cv_test_live_allocations;
                return pointer;
            }
        }
        fputs("Test allocation tracker exhausted\n", stderr);
        abort();
    }
    return NULL;
}

static bool should_fail(void) {
    if (cv_test_allocations_left == 0) {
        return true;
    }
    if (cv_test_allocations_left > 0) {
        --cv_test_allocations_left;
    }
    return false;
}

void *cv_test_malloc(size_t size) {
    return should_fail() ? NULL : track(malloc(size), size, true);
}

void *cv_test_calloc(size_t count, size_t size) {
    return should_fail() ? NULL : track(calloc(count, size), count * size, false);
}

void cv_test_free(void *pointer) {
    if (pointer == NULL) {
        return;
    }
    for (size_t i = 0; i < sizeof(allocations) / sizeof(allocations[0]); ++i) {
        if (allocations[i].pointer == pointer) {
            if (allocations[i].must_be_wiped) {
                const unsigned char *bytes = pointer;
                for (size_t j = 0; j < allocations[i].size; ++j) {
                    if (bytes[j] != 0) {
                        ++cv_test_wipe_failures;
                        break;
                    }
                }
            }
            allocations[i].pointer = NULL;
            --cv_test_live_allocations;
            free(pointer);
            return;
        }
    }
    fputs("Untracked or duplicate free\n", stderr);
    abort();
}

int cv_test_shorthash(unsigned char *out,
                      const unsigned char *input,
                      unsigned long long length,
                      const unsigned char *key) {
    if (cv_test_force_collisions) {
        memset(out, 0, crypto_shorthash_BYTES);
        return 0;
    }
    return crypto_shorthash(out, input, length, key);
}

static cv_status fixed_clock(void *context, uint64_t *now) {
    *now = *(const uint64_t *)context;
    return CV_OK;
}

static int forced_collisions(void) {
    uint64_t now = 0;
    cv_hashtable *table = NULL;
    CHECK(cv_hashtable_create_with_clock(&table, fixed_clock, &now) == CV_OK);
    char key[32];
    for (unsigned int i = 0; i < 128; ++i) {
        (void)snprintf(key, sizeof(key), "collision:%u", i);
        CHECK(cv_hashtable_set(table, key, (const unsigned char *)&i, sizeof(i)) == CV_OK);
    }
    cv_hashtable_stats stats;
    CHECK(cv_hashtable_get_stats(table, &stats) == CV_OK);
    CHECK(stats.entries == 128 && stats.max_chain_length == 128 && stats.buckets > 16);
    /* Every key has the same full hash: matching must compare actual key bytes. */
    for (unsigned int i = 0; i < 128; ++i) {
        (void)snprintf(key, sizeof(key), "collision:%u", i);
        const unsigned char *value = NULL;
        size_t length = 0;
        CHECK(cv_hashtable_get(table, key, &value, &length) == CV_OK);
        CHECK(length == sizeof(i) && memcmp(value, &i, length) == 0);
    }
    CHECK(cv_hashtable_delete(table, "collision:127") == CV_OK);
    CHECK(cv_hashtable_delete(table, "collision:64") == CV_OK);
    CHECK(cv_hashtable_delete(table, "collision:0") == CV_OK);
    CHECK(cv_hashtable_set(table, "collision:10", (const unsigned char *)"changed", 7) == CV_OK);
    /* Expired chain heads/interiors/tails must all be reclaimed correctly. */
    for (unsigned int i = 1; i < 127; ++i) {
        if (i != 64) {
            (void)snprintf(key, sizeof(key), "collision:%u", i);
            CHECK(cv_hashtable_expire(table, key, 1) == CV_OK);
        }
    }
    now = 1000;
    size_t removed = 0;
    CHECK(cv_hashtable_purge_expired(table, &removed) == CV_OK && removed == 125);
    CHECK(cv_hashtable_get_stats(table, &stats) == CV_OK && stats.entries == 0);
    cv_hashtable_destroy(table);
    CHECK(cv_test_live_allocations == 0 && cv_test_wipe_failures == 0);
    return EXIT_SUCCESS;
}

static int allocation_failures(void) {
    uint64_t now = 0;
    cv_hashtable *table = NULL;
    for (long fail = 0; fail < 2; ++fail) {
        cv_test_allocations_left = fail;
        CHECK(cv_hashtable_create(&table) == CV_ERR_NO_MEMORY && table == NULL);
        CHECK(cv_test_live_allocations == 0);
    }
    cv_test_allocations_left = -1;
    CHECK(cv_hashtable_create_with_clock(&table, fixed_clock, &now) == CV_OK);
    CHECK(cv_hashtable_set(table, "original", (const unsigned char *)"keep", 4) == CV_OK);
    CHECK(cv_hashtable_expire(table, "original", 10) == CV_OK);
    size_t live = cv_test_live_allocations;
    /* Clone failures must discard partial copies without touching source TTLs. */
    for (long fail = 0; fail < 5; ++fail) {
        cv_hashtable *copy = table;
        cv_test_allocations_left = fail;
        CHECK(cv_hashtable_clone(table, &copy) == CV_ERR_NO_MEMORY && copy == NULL);
        CHECK(cv_test_live_allocations == live && cv_test_wipe_failures == 0);
    }
    cv_test_allocations_left = -1;
    /* Failure at value, entry and key allocation; partial copies must be wiped. */
    for (long fail = 0; fail < 3; ++fail) {
        cv_test_allocations_left = fail;
        CHECK(cv_hashtable_set(table, "new", (const unsigned char *)"secret", 6) ==
              CV_ERR_NO_MEMORY);
        CHECK(cv_test_live_allocations == live);
    }
    cv_test_allocations_left = 0;
    CHECK(cv_hashtable_set(table, "original", (const unsigned char *)"replace", 7) ==
          CV_ERR_NO_MEMORY);
    cv_test_allocations_left = -1;
    const unsigned char *value = NULL;
    size_t length = 0;
    int64_t ttl = 0;
    CHECK(cv_hashtable_get(table, "original", &value, &length) == CV_OK);
    CHECK(length == 4 && memcmp(value, "keep", length) == 0);
    CHECK(cv_hashtable_ttl(table, "original", &ttl) == CV_OK && ttl == 10);
    char key[32];
    for (unsigned int i = 0; i < 11; ++i) {
        (void)snprintf(key, sizeof(key), "fill:%u", i);
        CHECK(cv_hashtable_set(table, key, NULL, 0) == CV_OK);
    }
    /* A thirteenth entry needs growth: fail only the new bucket allocation. */
    live = cv_test_live_allocations;
    cv_test_allocations_left = 3;
    CHECK(cv_hashtable_set(table, "grow", (const unsigned char *)"secret", 6) == CV_ERR_NO_MEMORY);
    CHECK(cv_test_live_allocations == live);
    cv_test_allocations_left = -1;
    cv_hashtable_stats stats;
    CHECK(cv_hashtable_get_stats(table, &stats) == CV_OK);
    CHECK(stats.entries == 12 && stats.buckets == 16 && stats.max_chain_length == 12);
    for (unsigned int i = 0; i < 11; ++i) {
        (void)snprintf(key, sizeof(key), "fill:%u", i);
        CHECK(cv_hashtable_get(table, key, &value, &length) == CV_OK);
    }
    CHECK(cv_hashtable_set(table, "grow", (const unsigned char *)"secret", 6) == CV_OK);
    CHECK(cv_hashtable_get_stats(table, &stats) == CV_OK && stats.buckets == 32);
    CHECK(cv_hashtable_ttl(table, "original", &ttl) == CV_OK && ttl == 10);
    /* Successful replacement also has to wipe the previous allocation. */
    CHECK(cv_hashtable_set(table, "original", (const unsigned char *)"changed", 7) == CV_OK);
    CHECK(cv_hashtable_ttl(table, "original", &ttl) == CV_OK && ttl == CV_TTL_PERSISTENT);
    cv_hashtable_destroy(table);
    CHECK(cv_test_live_allocations == 0 && cv_test_wipe_failures == 0);
    return EXIT_SUCCESS;
}

int main(void) {
    CHECK(forced_collisions() == EXIT_SUCCESS);
    CHECK(allocation_failures() == EXIT_SUCCESS);
    puts("Hash table faults: forced collisions, allocation rollback and secure cleanup verified.");
    return EXIT_SUCCESS;
}
