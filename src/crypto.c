/**
 * @file crypto.c
 * @brief Thin wrappers around libsodium initialisation and secure wiping.
 */

#include "cvault/crypto.h"

#include <sodium.h>

cv_status cv_crypto_init(void) {
    /* sodium_init() is idempotent and thread-safe; it returns 1 when the
     * library was already initialised, which is not an error. */
    return sodium_init() < 0 ? CV_ERR_CRYPTO : CV_OK;
}

void cv_crypto_wipe(void *buffer, size_t length) {
    if (buffer != NULL && length != 0) {
        /* sodium_memzero() cannot be optimised away by the compiler, unlike a
         * plain memset() on a buffer that is about to go out of scope. */
        sodium_memzero(buffer, length);
    }
}
