/**
 * @file crypto.h
 * @brief libsodium bootstrap and secret-wiping helpers.
 *
 * The authenticated encryption used by the journal, the snapshots and the audit
 * log lives in the internal persistence codec; this header only exposes the
 * primitives that every module needs before touching secrets.
 */

#ifndef CVAULT_CRYPTO_H
#define CVAULT_CRYPTO_H

#include "cvault/common.h"

#include <stddef.h>

/**
 * @brief Initialise libsodium.
 *
 * Must succeed before any hashing, random-number or AEAD primitive is used.
 * Safe to call repeatedly and from several threads.
 *
 * @return #CV_OK, or #CV_ERR_CRYPTO when the library cannot start (for example
 *         because no secure random source is available).
 */
cv_status cv_crypto_init(void);

/**
 * @brief Overwrite a buffer with zeroes in a way the compiler cannot elide.
 *
 * Use it for passwords, keys and any other secret before the memory is freed
 * or leaves scope.
 *
 * @param buffer Memory to clear; NULL is accepted and ignored.
 * @param length Number of bytes to clear; zero is accepted and ignored.
 */
void cv_crypto_wipe(void *buffer, size_t length);

#endif /* CVAULT_CRYPTO_H */
