#include "cvault/hashtable.h"

cv_status cv_hashtable_create(cv_hashtable **out) {
    if (out == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    /* TODO: buckets, collision handling, resizing, secure value cleanup, TTL. */
    return CV_ERR_NOT_IMPLEMENTED;
}

void cv_hashtable_destroy(cv_hashtable *table) {
    (void)table;
    /* TODO: free entries and wipe sensitive buffers. NULL must remain safe. */
}

cv_status cv_hashtable_set(cv_hashtable *table, const char *key,
                           const unsigned char *value, size_t value_length) {
    (void)table;
    (void)key;
    (void)value;
    (void)value_length;
    return CV_ERR_NOT_IMPLEMENTED;
}

cv_status cv_hashtable_get(const cv_hashtable *table, const char *key,
                           const unsigned char **value, size_t *value_length) {
    (void)table;
    (void)key;
    if (value == NULL || value_length == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    *value = NULL;
    *value_length = 0;
    return CV_ERR_NOT_IMPLEMENTED;
}

cv_status cv_hashtable_delete(cv_hashtable *table, const char *key) {
    (void)table;
    (void)key;
    return CV_ERR_NOT_IMPLEMENTED;
}
