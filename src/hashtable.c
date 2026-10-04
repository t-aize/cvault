#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <time.h>
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "cvault/config.h"
#include "cvault/crypto.h"
#include "cvault/hashtable.h"

#define CV_INITIAL_BUCKETS ((size_t)16)
#define CV_MS_PER_SECOND UINT64_C(1000)

typedef struct cv_entry {
    struct cv_entry *next;
    char *key;
    unsigned char *value;
    size_t key_length;
    size_t value_length;
    uint64_t hash;
    uint64_t deadline_ms;
    bool expires;
} cv_entry;

struct cv_hashtable {
    cv_entry **buckets;
    size_t bucket_count;
    size_t entry_count;
    unsigned char hash_key[crypto_shorthash_KEYBYTES];
    cv_hashtable_clock clock;
    void *clock_context;
};

/* Deadlines are process-local, never wall-clock timestamps or persisted records. */
static cv_status platform_clock(void *context, uint64_t *now_ms) {
    (void)context;
#ifdef _WIN32
    *now_ms = (uint64_t)GetTickCount64();
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) {
        return CV_ERR_IO;
    }
    uint64_t seconds = (uint64_t)now.tv_sec;
    uint64_t fraction = (uint64_t)now.tv_nsec / UINT64_C(1000000);
    if (seconds > (UINT64_MAX - fraction) / CV_MS_PER_SECOND) {
        return CV_ERR_LIMIT;
    }
    *now_ms = seconds * CV_MS_PER_SECOND + fraction;
#endif
    return CV_OK;
}

/* Bound the scan instead of strlen(): input cannot trigger an unbounded scan. */
static cv_status key_length(const char *key, size_t *length) {
    if (key == NULL || key[0] == '\0') {
        return CV_ERR_INVALID_ARGUMENT;
    }
    for (size_t i = 0; i <= CV_MAX_KEY_BYTES; ++i) {
        if (key[i] == '\0') {
            *length = i;
            return CV_OK;
        }
    }
    return CV_ERR_LIMIT;
}

static uint64_t hash_key(const cv_hashtable *table, const char *key, size_t length) {
    unsigned char bytes[crypto_shorthash_BYTES];
    (void)crypto_shorthash(bytes, (const unsigned char *)key,
                         (unsigned long long)length, table->hash_key);
    /* Explicit byte order avoids alignment and strict-aliasing assumptions. */
    uint64_t hash = 0;
    for (size_t i = 0; i < sizeof(bytes); ++i) {
        hash |= (uint64_t)bytes[i] << (i * 8);
    }
    return hash;
}

/* Keyed SipHash distributes low bits across power-of-two bucket counts. */
static size_t bucket_index(uint64_t hash, size_t count) {
    return (size_t)(hash & (uint64_t)(count - 1));
}

/* Link-to-link lookup handles chain heads and interiors without special cases. */
static cv_entry **find_link(const cv_hashtable *table, const char *key,
                            size_t length, uint64_t hash) {
    cv_entry **link = &table->buckets[bucket_index(hash, table->bucket_count)];
    while (*link != NULL) {
        if ((*link)->hash == hash && (*link)->key_length == length &&
            memcmp((*link)->key, key, length) == 0) {
            break;
        }
        link = &(*link)->next;
    }
    return link;
}

static void free_entry(cv_entry *entry) {
    cv_crypto_wipe(entry->key, entry->key_length + 1);
    cv_crypto_wipe(entry->value, entry->value_length);
    free(entry->key);
    free(entry->value);
    cv_crypto_wipe(entry, sizeof(*entry));
    free(entry);
}

static void remove_link(cv_hashtable *table, cv_entry **link) {
    cv_entry *entry = *link;
    *link = entry->next;
    --table->entry_count;
    free_entry(entry);
}

static cv_status entry_expired(const cv_hashtable *table, const cv_entry *entry,
                               bool *expired) {
    *expired = false;
    if (!entry->expires) {
        return CV_OK;
    }
    uint64_t now = 0;
    cv_status status = table->clock(table->clock_context, &now);
    if (status == CV_OK) {
        *expired = now >= entry->deadline_ms;
    }
    return status;
}

/* Allocate before relinking: failed growth preserves every existing chain. */
static cv_status grow(cv_hashtable *table) {
    if (table->bucket_count > SIZE_MAX / 2 / sizeof(*table->buckets)) {
        return CV_ERR_LIMIT;
    }
    size_t count = table->bucket_count * 2;
    cv_entry **buckets = calloc(count, sizeof(*buckets));
    if (buckets == NULL) {
        return CV_ERR_NO_MEMORY;
    }
    for (size_t i = 0; i < table->bucket_count; ++i) {
        cv_entry *entry = table->buckets[i];
        while (entry != NULL) {
            cv_entry *next = entry->next;
            size_t index = bucket_index(entry->hash, count);
            entry->next = buckets[index];
            buckets[index] = entry;
            entry = next;
        }
    }
    free(table->buckets);
    table->buckets = buckets;
    table->bucket_count = count;
    return CV_OK;
}

cv_status cv_hashtable_create(cv_hashtable **out) {
    return cv_hashtable_create_with_clock(out, platform_clock, NULL);
}

cv_status cv_hashtable_create_with_clock(cv_hashtable **out,
                                        cv_hashtable_clock clock, void *context) {
    if (out == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    if (clock == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    cv_status status = cv_crypto_init();
    if (status != CV_OK) {
        return status;
    }
    cv_hashtable *table = calloc(1, sizeof(*table));
    if (table == NULL) {
        return CV_ERR_NO_MEMORY;
    }
    table->buckets = calloc(CV_INITIAL_BUCKETS, sizeof(*table->buckets));
    if (table->buckets == NULL) {
        free(table);
        return CV_ERR_NO_MEMORY;
    }
    table->bucket_count = CV_INITIAL_BUCKETS;
    table->clock = clock;
    table->clock_context = context;
    crypto_shorthash_keygen(table->hash_key);
    *out = table;
    return CV_OK;
}

void cv_hashtable_destroy(cv_hashtable *table) {
    if (table == NULL) {
        return;
    }
    for (size_t i = 0; i < table->bucket_count; ++i) {
        cv_entry *entry = table->buckets[i];
        while (entry != NULL) {
            cv_entry *next = entry->next;
            free_entry(entry);
            entry = next;
        }
    }
    free(table->buckets);
    cv_crypto_wipe(table, sizeof(*table));
    free(table);
}

cv_status cv_hashtable_set(cv_hashtable *table, const char *key,
                           const unsigned char *value, size_t value_length) {
    if (table == NULL || (value == NULL && value_length != 0)) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    size_t length = 0;
    cv_status status = key_length(key, &length);
    if (status != CV_OK) {
        return status;
    }
    if (value_length > CV_MAX_VALUE_BYTES) {
        return CV_ERR_LIMIT;
    }
    uint64_t hash = hash_key(table, key, length);
    cv_entry *existing = *find_link(table, key, length, hash);
    unsigned char *copy = NULL;
    if (value_length != 0) {
        copy = malloc(value_length);
        if (copy == NULL) {
            return CV_ERR_NO_MEMORY;
        }
        memcpy(copy, value, value_length);
    }
    if (existing != NULL) {
        /* Copy first: SET may receive a value borrowed from this very entry. */
        cv_crypto_wipe(existing->value, existing->value_length);
        free(existing->value);
        existing->value = copy;
        existing->value_length = value_length;
        existing->expires = false;
        existing->deadline_ms = 0;
        return CV_OK;
    }
    cv_entry *entry = calloc(1, sizeof(*entry));
    if (entry == NULL) {
        cv_crypto_wipe(copy, value_length);
        free(copy);
        return CV_ERR_NO_MEMORY;
    }
    entry->value = copy;
    entry->value_length = value_length;
    entry->key_length = length;
    entry->key = malloc(length + 1);
    if (entry->key == NULL) {
        free_entry(entry);
        return CV_ERR_NO_MEMORY;
    }
    memcpy(entry->key, key, length + 1);
    entry->hash = hash;
    /* Grow at 75% occupancy; arithmetic stays within allocated capacity. */
    if (table->entry_count >= table->bucket_count - table->bucket_count / 4) {
        status = grow(table);
        if (status != CV_OK) {
            free_entry(entry);
            return status;
        }
    }
    size_t index = bucket_index(hash, table->bucket_count);
    entry->next = table->buckets[index];
    table->buckets[index] = entry;
    ++table->entry_count;
    return CV_OK;
}

cv_status cv_hashtable_get(const cv_hashtable *table, const char *key,
                           const unsigned char **value, size_t *value_length) {
    if (value != NULL) {
        *value = NULL;
    }
    if (value_length != NULL) {
        *value_length = 0;
    }
    if (table == NULL || value == NULL || value_length == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    size_t length = 0;
    cv_status status = key_length(key, &length);
    if (status != CV_OK) {
        return status;
    }
    cv_entry *entry = *find_link(table, key, length, hash_key(table, key, length));
    if (entry == NULL) {
        return CV_ERR_NOT_FOUND;
    }
    bool expired = false;
    status = entry_expired(table, entry, &expired);
    if (status != CV_OK || expired) {
        return status != CV_OK ? status : CV_ERR_NOT_FOUND;
    }
    *value = entry->value;
    *value_length = entry->value_length;
    return CV_OK;
}

cv_status cv_hashtable_delete(cv_hashtable *table, const char *key) {
    if (table == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    size_t length = 0;
    cv_status status = key_length(key, &length);
    if (status != CV_OK) {
        return status;
    }
    cv_entry **link = find_link(table, key, length, hash_key(table, key, length));
    if (*link == NULL) {
        return CV_ERR_NOT_FOUND;
    }
    bool expired = false;
    status = entry_expired(table, *link, &expired);
    if (status != CV_OK) {
        return status;
    }
    remove_link(table, link);
    return expired ? CV_ERR_NOT_FOUND : CV_OK;
}

cv_status cv_hashtable_expire(cv_hashtable *table, const char *key, int64_t seconds) {
    if (table == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    size_t length = 0;
    cv_status status = key_length(key, &length);
    if (status != CV_OK) {
        return status;
    }
    cv_entry **link = find_link(table, key, length, hash_key(table, key, length));
    if (*link == NULL) {
        return CV_ERR_NOT_FOUND;
    }
    uint64_t now = 0;
    status = table->clock(table->clock_context, &now);
    if (status != CV_OK) {
        return status;
    }
    cv_entry *entry = *link;
    if (entry->expires && now >= entry->deadline_ms) {
        remove_link(table, link);
        return CV_ERR_NOT_FOUND;
    }
    if (seconds <= 0) {
        remove_link(table, link);
        return CV_OK;
    }
    if ((uint64_t)seconds > (UINT64_MAX - now) / CV_MS_PER_SECOND) {
        return CV_ERR_LIMIT;
    }
    entry->deadline_ms = now + (uint64_t)seconds * CV_MS_PER_SECOND;
    entry->expires = true;
    return CV_OK;
}

cv_status cv_hashtable_ttl(const cv_hashtable *table, const char *key, int64_t *seconds) {
    if (seconds == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    *seconds = CV_TTL_MISSING;
    if (table == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    size_t length = 0;
    cv_status status = key_length(key, &length);
    if (status != CV_OK) {
        return status;
    }
    cv_entry *entry = *find_link(table, key, length, hash_key(table, key, length));
    if (entry == NULL) {
        return CV_ERR_NOT_FOUND;
    }
    if (!entry->expires) {
        *seconds = CV_TTL_PERSISTENT;
        return CV_OK;
    }
    uint64_t now = 0;
    status = table->clock(table->clock_context, &now);
    if (status != CV_OK) {
        return status;
    }
    if (now >= entry->deadline_ms) {
        return CV_ERR_NOT_FOUND;
    }
    /* Millisecond deadlines imply remaining seconds always fit in int64_t. */
    *seconds = (int64_t)((entry->deadline_ms - now) / CV_MS_PER_SECOND);
    return CV_OK;
}

cv_status cv_hashtable_purge_expired(cv_hashtable *table, size_t *removed) {
    if (removed == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    *removed = 0;
    if (table == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    uint64_t now = 0;
    cv_status status = table->clock(table->clock_context, &now);
    if (status != CV_OK) {
        return status;
    }
    for (size_t i = 0; i < table->bucket_count; ++i) {
        cv_entry **link = &table->buckets[i];
        while (*link != NULL) {
            if ((*link)->expires && now >= (*link)->deadline_ms) {
                remove_link(table, link);
                ++*removed;
            } else {
                link = &(*link)->next;
            }
        }
    }
    return CV_OK;
}

cv_status cv_hashtable_get_stats(const cv_hashtable *table, cv_hashtable_stats *out) {
    if (out == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    *out = (cv_hashtable_stats){0};
    if (table == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    out->entries = table->entry_count;
    out->buckets = table->bucket_count;
    for (size_t i = 0; i < table->bucket_count; ++i) {
        size_t length = 0;
        for (cv_entry *entry = table->buckets[i]; entry != NULL; entry = entry->next) {
            ++length;
        }
        if (length > out->max_chain_length) {
            out->max_chain_length = length;
        }
    }
    return CV_OK;
}

cv_status cv_hashtable_expire_ms(cv_hashtable *table, const char *key, uint64_t milliseconds) {
    if (table == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    size_t length = 0;
    cv_status status = key_length(key, &length);
    if (status != CV_OK) {
        return status;
    }
    cv_entry **link = find_link(table, key, length, hash_key(table, key, length));
    if (*link == NULL) {
        return CV_ERR_NOT_FOUND;
    }
    uint64_t now = 0;
    status = table->clock(table->clock_context, &now);
    if (status != CV_OK) {
        return status;
    }
    if ((*link)->expires && now >= (*link)->deadline_ms) {
        remove_link(table, link);
        return CV_ERR_NOT_FOUND;
    }
    if (milliseconds == 0) {
        remove_link(table, link);
        return CV_OK;
    }
    if (milliseconds > UINT64_MAX - now) {
        return CV_ERR_LIMIT;
    }
    (*link)->expires = true;
    (*link)->deadline_ms = now + milliseconds;
    return CV_OK;
}

cv_status cv_hashtable_visit(const cv_hashtable *table, bool include_expired,
                             cv_hashtable_visitor visitor, void *context) {
    if (table == NULL || visitor == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    uint64_t now = 0;
    cv_status status = table->clock(table->clock_context, &now);
    if (status != CV_OK) {
        return status;
    }
    for (size_t i = 0; i < table->bucket_count; ++i) {
        for (cv_entry *entry = table->buckets[i]; entry != NULL; entry = entry->next) {
            bool expired = entry->expires && now >= entry->deadline_ms;
            if (expired && !include_expired) {
                continue;
            }
            uint64_t remaining = entry->expires && !expired ? entry->deadline_ms - now : 0;
            status = visitor(context, entry->key, entry->value, entry->value_length,
                             entry->expires, remaining);
            if (status != CV_OK) {
                return status;
            }
        }
    }
    return CV_OK;
}

cv_status cv_hashtable_clone(const cv_hashtable *table, cv_hashtable **out) {
    if (out == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    if (table == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    uint64_t now = 0;
    cv_status status = table->clock(table->clock_context, &now);
    if (status != CV_OK) {
        return status;
    }
    cv_hashtable *copy = NULL;
    status = cv_hashtable_create_with_clock(&copy, table->clock, table->clock_context);
    if (status != CV_OK) {
        return status;
    }
    for (size_t i = 0; i < table->bucket_count && status == CV_OK; ++i) {
        for (cv_entry *entry = table->buckets[i]; entry != NULL; entry = entry->next) {
            if (entry->expires && now >= entry->deadline_ms) {
                continue;
            }
            status = cv_hashtable_set(copy, entry->key, entry->value, entry->value_length);
            if (status != CV_OK) {
                break;
            }
            cv_entry *added = *find_link(copy, entry->key, entry->key_length,
                                         hash_key(copy, entry->key, entry->key_length));
            added->expires = entry->expires;
            added->deadline_ms = entry->deadline_ms;
        }
    }
    if (status != CV_OK) {
        cv_hashtable_destroy(copy);
        return status;
    }
    *out = copy;
    return CV_OK;
}
