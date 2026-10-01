#ifndef CVAULT_HASHTABLE_H
#define CVAULT_HASHTABLE_H

#include <stddef.h>
#include "cvault/common.h"

typedef struct cv_hashtable cv_hashtable;

/* Planned: table owns copied keys/values; get returns a borrowed value.
 * A borrowed value remains valid until the next table mutation/destruction.
 * The scaffold returns NOT_IMPLEMENTED and resets output parameters. */
cv_status cv_hashtable_create(cv_hashtable **out);
void cv_hashtable_destroy(cv_hashtable *table);
cv_status cv_hashtable_set(cv_hashtable *table, const char *key,
                           const unsigned char *value, size_t value_length);
cv_status cv_hashtable_get(const cv_hashtable *table, const char *key,
                           const unsigned char **value, size_t *value_length);
cv_status cv_hashtable_delete(cv_hashtable *table, const char *key);

#endif
