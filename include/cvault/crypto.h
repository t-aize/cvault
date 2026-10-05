#ifndef CVAULT_CRYPTO_H
#define CVAULT_CRYPTO_H

#include "cvault/common.h"
#include <stddef.h>

/* Initialize libsodium before using any cryptographic primitive. */
cv_status cv_crypto_init(void);
void cv_crypto_wipe(void *buffer, size_t length);

/* TODO: authenticated XChaCha20-Poly1305 wrappers, nonce generation,
 * persistent key loading and associated data binding (key + metadata).
 * No encryption/storage format exists yet. */

#endif
