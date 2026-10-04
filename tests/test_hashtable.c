#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "cvault/config.h"
#include "cvault/hashtable.h"
#include "test_util.h"

typedef struct {
    uint64_t now;
    cv_status status;
} fake_time;

static cv_status fake_clock(void *context, uint64_t *now) {
    fake_time *time = context;
    *now = time->now;
    return time->status;
}

static int ownership_and_bounds(void) {
    cv_hashtable *table = NULL;
    CHECK(cv_hashtable_create(&table) == CV_OK);
    char key[] = "owned";
    unsigned char input[] = {0, 1, 255, 0, 42};
    CHECK(cv_hashtable_set(table, key, input, sizeof(input)) == CV_OK);
    key[0] = 'X';
    input[1] = 99;
    const unsigned char *value = NULL;
    size_t length = 0;
    CHECK(cv_hashtable_get(table, "owned", &value, &length) == CV_OK);
    CHECK(length == 5 && memcmp(value, (unsigned char[]){0, 1, 255, 0, 42}, 5) == 0);
    CHECK(cv_hashtable_set(table, "owned", value, length) == CV_OK);
    CHECK(cv_hashtable_get(table, "owned", &value, &length) == CV_OK && value[1] == 1);
    /* Copying another entry's borrowed bytes must work across a later resize. */
    CHECK(cv_hashtable_set(table, "copy", value, length) == CV_OK);
    CHECK(cv_hashtable_delete(table, "owned") == CV_OK);
    CHECK(cv_hashtable_get(table, "copy", &value, &length) == CV_OK && value[1] == 1);
    CHECK(cv_hashtable_set(table, "copy", NULL, 0) == CV_OK);
    CHECK(cv_hashtable_get(table, "copy", &value, &length) == CV_OK);
    CHECK(value == NULL && length == 0);

    char maximum_key[CV_MAX_KEY_BYTES + 1];
    memset(maximum_key, 'K', CV_MAX_KEY_BYTES);
    maximum_key[CV_MAX_KEY_BYTES] = '\0';
    unsigned char *maximum_value = malloc(CV_MAX_VALUE_BYTES);
    CHECK(maximum_value != NULL);
    memset(maximum_value, 0xa5, CV_MAX_VALUE_BYTES);
    CHECK(cv_hashtable_set(table, maximum_key, maximum_value, CV_MAX_VALUE_BYTES) == CV_OK);
    CHECK(cv_hashtable_get(table, maximum_key, &value, &length) == CV_OK);
    CHECK(length == CV_MAX_VALUE_BYTES && memcmp(value, maximum_value, length) == 0);
    CHECK(cv_hashtable_set(table, maximum_key, maximum_value, CV_MAX_VALUE_BYTES + 1) == CV_ERR_LIMIT);
    free(maximum_value);
    char too_long[CV_MAX_KEY_BYTES + 2];
    memset(too_long, 'K', sizeof(too_long));
    too_long[sizeof(too_long) - 1] = '\0';
    CHECK(cv_hashtable_set(table, too_long, NULL, 0) == CV_ERR_LIMIT);
    CHECK(cv_hashtable_get(table, too_long, &value, &length) == CV_ERR_LIMIT);
    CHECK(cv_hashtable_delete(table, too_long) == CV_ERR_LIMIT);
    CHECK(cv_hashtable_expire(table, too_long, 1) == CV_ERR_LIMIT);
    int64_t ttl = 0;
    CHECK(cv_hashtable_ttl(table, too_long, &ttl) == CV_ERR_LIMIT && ttl == CV_TTL_MISSING);
    CHECK(cv_hashtable_get(table, "missing", &value, &length) == CV_ERR_NOT_FOUND);
    CHECK(value == NULL && length == 0);
    CHECK(cv_hashtable_delete(table, "missing") == CV_ERR_NOT_FOUND);
    cv_hashtable_destroy(table);
    cv_hashtable_destroy(NULL);
    return EXIT_SUCCESS;
}

static int invalid_arguments(void) {
    cv_hashtable *table = NULL;
    CHECK(cv_hashtable_create(NULL) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_create_with_clock(&table, NULL, NULL) == CV_ERR_INVALID_ARGUMENT);
    CHECK(table == NULL);
    CHECK(cv_hashtable_create_with_clock(NULL, fake_clock, NULL) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_create(&table) == CV_OK);
    const unsigned char *value = (const unsigned char *)"old";
    size_t length = 3;
    int64_t ttl = 3;
    size_t removed = 3;
    cv_hashtable_stats stats = {1, 1, 1};
    CHECK(cv_hashtable_get(NULL, "key", &value, &length) == CV_ERR_INVALID_ARGUMENT);
    CHECK(value == NULL && length == 0);
    CHECK(cv_hashtable_get(table, "key", NULL, &length) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_get(table, "key", &value, NULL) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_set(NULL, "key", NULL, 0) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_set(table, NULL, NULL, 0) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_set(table, "", NULL, 0) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_set(table, "key", NULL, 1) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_get(table, NULL, &value, &length) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_delete(NULL, "key") == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_delete(table, "") == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_expire(NULL, "key", 1) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_expire(table, NULL, 1) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_ttl(table, "key", NULL) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_ttl(NULL, "key", &ttl) == CV_ERR_INVALID_ARGUMENT && ttl == CV_TTL_MISSING);
    CHECK(cv_hashtable_ttl(table, "", &ttl) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_purge_expired(table, NULL) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_purge_expired(NULL, &removed) == CV_ERR_INVALID_ARGUMENT && removed == 0);
    CHECK(cv_hashtable_get_stats(table, NULL) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_hashtable_get_stats(NULL, &stats) == CV_ERR_INVALID_ARGUMENT);
    CHECK(stats.entries == 0 && stats.buckets == 0 && stats.max_chain_length == 0);
    cv_hashtable_destroy(table);
    return EXIT_SUCCESS;
}

static int expiration(void) {
    fake_time time = {1000, CV_OK};
    cv_hashtable *table = NULL;
    CHECK(cv_hashtable_create_with_clock(&table, fake_clock, &time) == CV_OK);
    int64_t ttl = 0;
    const unsigned char *value = NULL;
    size_t length = 0, removed = 0;
    CHECK(cv_hashtable_ttl(table, "key", &ttl) == CV_ERR_NOT_FOUND && ttl == CV_TTL_MISSING);
    CHECK(cv_hashtable_expire(table, "key", 1) == CV_ERR_NOT_FOUND);
    CHECK(cv_hashtable_set(table, "key", (const unsigned char *)"value", 5) == CV_OK);
    CHECK(cv_hashtable_ttl(table, "key", &ttl) == CV_OK && ttl == CV_TTL_PERSISTENT);
    CHECK(cv_hashtable_expire(table, "key", 2) == CV_OK);
    CHECK(cv_hashtable_ttl(table, "key", &ttl) == CV_OK && ttl == 2);
    time.now = 2001;
    CHECK(cv_hashtable_ttl(table, "key", &ttl) == CV_OK && ttl == 0);
    CHECK(cv_hashtable_get(table, "key", &value, &length) == CV_OK);
    /* Replacing a TTL starts a fresh relative deadline. */
    CHECK(cv_hashtable_expire(table, "key", 3) == CV_OK);
    CHECK(cv_hashtable_ttl(table, "key", &ttl) == CV_OK && ttl == 3);
    CHECK(cv_hashtable_expire(table, "key", INT64_MAX) == CV_ERR_LIMIT);
    CHECK(cv_hashtable_ttl(table, "key", &ttl) == CV_OK && ttl == 3);
    time.now = 5000;
    CHECK(cv_hashtable_get(table, "key", &value, &length) == CV_OK);
    time.now = 5001;
    CHECK(cv_hashtable_get(table, "key", &value, &length) == CV_ERR_NOT_FOUND);
    CHECK(value == NULL && length == 0);
    CHECK(cv_hashtable_ttl(table, "key", &ttl) == CV_ERR_NOT_FOUND && ttl == CV_TTL_MISSING);
    CHECK(cv_hashtable_expire(table, "key", 4) == CV_ERR_NOT_FOUND);
    CHECK(cv_hashtable_set(table, "key", NULL, 0) == CV_OK);
    CHECK(cv_hashtable_expire(table, "key", 0) == CV_OK);
    CHECK(cv_hashtable_delete(table, "key") == CV_ERR_NOT_FOUND);
    CHECK(cv_hashtable_set(table, "key", NULL, 0) == CV_OK);
    CHECK(cv_hashtable_expire(table, "key", INT64_MIN) == CV_OK);
    CHECK(cv_hashtable_set(table, "key", NULL, 0) == CV_OK);
    CHECK(cv_hashtable_expire(table, "key", 1) == CV_OK);
    CHECK(cv_hashtable_set(table, "key", (const unsigned char *)"new", 3) == CV_OK);
    CHECK(cv_hashtable_ttl(table, "key", &ttl) == CV_OK && ttl == CV_TTL_PERSISTENT);
    time.now += 10000;
    CHECK(cv_hashtable_get(table, "key", &value, &length) == CV_OK);
    CHECK(cv_hashtable_set(table, "expired", NULL, 0) == CV_OK);
    CHECK(cv_hashtable_expire(table, "expired", 1) == CV_OK);
    time.now += 1000;
    CHECK(cv_hashtable_delete(table, "expired") == CV_ERR_NOT_FOUND);
    CHECK(cv_hashtable_set(table, "expired", NULL, 0) == CV_OK);
    CHECK(cv_hashtable_expire(table, "expired", 1) == CV_OK);
    time.now += 1000;
    /* SET resurrects an expired physical entry and clears its TTL. */
    CHECK(cv_hashtable_set(table, "expired", NULL, 0) == CV_OK);
    CHECK(cv_hashtable_ttl(table, "expired", &ttl) == CV_OK && ttl == CV_TTL_PERSISTENT);
    CHECK(cv_hashtable_purge_expired(table, &removed) == CV_OK && removed == 0);

    time.now = UINT64_MAX - 999;
    CHECK(cv_hashtable_expire(table, "key", 1) == CV_ERR_LIMIT);
    CHECK(cv_hashtable_ttl(table, "key", &ttl) == CV_OK && ttl == CV_TTL_PERSISTENT);
    cv_hashtable_destroy(table);
    /* Largest representable deadline, including exact UINT64_MAX. */
    time.now = UINT64_MAX - 1000;
    CHECK(cv_hashtable_create_with_clock(&table, fake_clock, &time) == CV_OK);
    CHECK(cv_hashtable_set(table, "last", NULL, 0) == CV_OK);
    CHECK(cv_hashtable_expire(table, "last", 1) == CV_OK);
    CHECK(cv_hashtable_ttl(table, "last", &ttl) == CV_OK && ttl == 1);
    time.now = UINT64_MAX;
    CHECK(cv_hashtable_get(table, "last", &value, &length) == CV_ERR_NOT_FOUND);
    CHECK(cv_hashtable_purge_expired(table, &removed) == CV_OK && removed == 1);
    cv_hashtable_destroy(table);
    return EXIT_SUCCESS;
}

static int clock_errors(void) {
    fake_time time = {0, CV_OK};
    cv_hashtable *table = NULL;
    CHECK(cv_hashtable_create_with_clock(&table, fake_clock, &time) == CV_OK);
    CHECK(cv_hashtable_set(table, "key", NULL, 0) == CV_OK);
    CHECK(cv_hashtable_expire(table, "key", 2) == CV_OK);
    time.status = CV_ERR_IO;
    const unsigned char *value = (const unsigned char *)"old";
    size_t length = 3, removed = 3;
    int64_t ttl = 3;
    CHECK(cv_hashtable_get(table, "key", &value, &length) == CV_ERR_IO);
    CHECK(value == NULL && length == 0);
    CHECK(cv_hashtable_ttl(table, "key", &ttl) == CV_ERR_IO && ttl == CV_TTL_MISSING);
    CHECK(cv_hashtable_delete(table, "key") == CV_ERR_IO);
    CHECK(cv_hashtable_expire(table, "key", 0) == CV_ERR_IO);
    CHECK(cv_hashtable_purge_expired(table, &removed) == CV_ERR_IO && removed == 0);
    time.status = CV_OK;
    CHECK(cv_hashtable_ttl(table, "key", &ttl) == CV_OK && ttl == 2);
    cv_hashtable_destroy(table);
    return EXIT_SUCCESS;
}

static int resizing_and_sweeping(void) {
    fake_time time = {0, CV_OK};
    cv_hashtable *table = NULL;
    CHECK(cv_hashtable_create_with_clock(&table, fake_clock, &time) == CV_OK);
    char key[32];
    for (unsigned int i = 0; i < 4096; ++i) {
        (void)snprintf(key, sizeof(key), "item:%u", i);
        CHECK(cv_hashtable_set(table, key, (const unsigned char *)&i, sizeof(i)) == CV_OK);
        if (i % 2 == 0) {
            CHECK(cv_hashtable_expire(table, key, 1) == CV_OK);
        }
    }
    cv_hashtable_stats stats;
    CHECK(cv_hashtable_get_stats(table, &stats) == CV_OK);
    CHECK(stats.entries == 4096 && stats.buckets > 16);
    for (unsigned int i = 0; i < 4096; ++i) {
        (void)snprintf(key, sizeof(key), "item:%u", i);
        const unsigned char *value = NULL;
        size_t length = 0;
        CHECK(cv_hashtable_get(table, key, &value, &length) == CV_OK);
        CHECK(length == sizeof(i) && memcmp(value, &i, length) == 0);
    }
    time.now = 1000;
    size_t removed = 0;
    CHECK(cv_hashtable_purge_expired(table, &removed) == CV_OK && removed == 2048);
    CHECK(cv_hashtable_get_stats(table, &stats) == CV_OK && stats.entries == 2048);
    CHECK(cv_hashtable_purge_expired(table, &removed) == CV_OK && removed == 0);
    for (unsigned int i = 0; i < 4096; ++i) {
        (void)snprintf(key, sizeof(key), "item:%u", i);
        CHECK(cv_hashtable_delete(table, key) == (i % 2 == 0 ? CV_ERR_NOT_FOUND : CV_OK));
    }
    CHECK(cv_hashtable_get_stats(table, &stats) == CV_OK && stats.entries == 0);
    CHECK(cv_hashtable_set(table, "reuse", NULL, 0) == CV_OK);
    cv_hashtable_destroy(table);
    return EXIT_SUCCESS;
}

typedef struct { size_t count, expired; uint64_t remaining; cv_status status; } visit_result;
static cv_status count_entry(void *opaque, const char *key, const unsigned char *value,
    size_t length, bool expires, uint64_t remaining) {
    (void)key; (void)value; (void)length;
    visit_result *result = opaque;
    ++result->count;
    if (expires && remaining == 0) ++result->expired;
    if (expires) result->remaining = remaining;
    return result->status;
}
static int persistence_helpers(void) {
    fake_time time = {100, CV_OK};
    cv_hashtable *table = NULL, *copy = NULL;
    CHECK(cv_hashtable_create_with_clock(&table, fake_clock, &time) == CV_OK);
    CHECK(cv_hashtable_set(table, "key", (const unsigned char *)"secret", 6) == CV_OK);
    CHECK(cv_hashtable_expire_ms(table, "key", 1500) == CV_OK);
    time.now = 600;
    CHECK(cv_hashtable_clone(table, &copy) == CV_OK);
    CHECK(cv_hashtable_set(table, "key", NULL, 0) == CV_OK);
    const unsigned char *value; size_t length;
    CHECK(cv_hashtable_get(copy, "key", &value, &length) == CV_OK);
    CHECK(length == 6 && memcmp(value, "secret", 6) == 0);
    visit_result result = {0, 0, 0, CV_OK};
    CHECK(cv_hashtable_visit(copy, false, count_entry, &result) == CV_OK);
    CHECK(result.count == 1 && result.remaining == 1000);
    CHECK(cv_hashtable_expire_ms(copy, "key", UINT64_MAX) == CV_ERR_LIMIT);
    time.now = 1600;
    CHECK(cv_hashtable_get(copy, "key", &value, &length) == CV_ERR_NOT_FOUND);
    result = (visit_result){0, 0, 0, CV_OK};
    CHECK(cv_hashtable_visit(copy, false, count_entry, &result) == CV_OK && result.count == 0);
    CHECK(cv_hashtable_visit(copy, true, count_entry, &result) == CV_OK);
    CHECK(result.count == 1 && result.expired == 1 && result.remaining == 0);
    result.status = CV_ERR_IO;
    CHECK(cv_hashtable_visit(copy, true, count_entry, &result) == CV_ERR_IO);
    time.status = CV_ERR_IO;
    cv_hashtable *failed = copy;
    CHECK(cv_hashtable_clone(copy, &failed) == CV_ERR_IO && failed == NULL);
    CHECK(cv_hashtable_visit(copy, true, count_entry, &result) == CV_ERR_IO);
    CHECK(cv_hashtable_expire_ms(copy, "key", 10) == CV_ERR_IO);
    CHECK(cv_hashtable_clone(NULL, &failed) == CV_ERR_INVALID_ARGUMENT && failed == NULL);
    CHECK(cv_hashtable_visit(table, false, NULL, NULL) == CV_ERR_INVALID_ARGUMENT);
    cv_hashtable_destroy(copy); cv_hashtable_destroy(table);
    return EXIT_SUCCESS;
}

int main(void) {
    CHECK(invalid_arguments() == EXIT_SUCCESS);
    CHECK(ownership_and_bounds() == EXIT_SUCCESS);
    CHECK(expiration() == EXIT_SUCCESS);
    CHECK(clock_errors() == EXIT_SUCCESS);
    CHECK(resizing_and_sweeping() == EXIT_SUCCESS);
    CHECK(persistence_helpers() == EXIT_SUCCESS);
    puts("Hash table: ownership, binary values, bounds, resizing and expiration verified.");
    return EXIT_SUCCESS;
}
