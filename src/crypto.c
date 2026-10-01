#include <sodium.h>
#include "cvault/crypto.h"

cv_status cv_crypto_init(void) {
    return sodium_init() < 0 ? CV_ERR_CRYPTO : CV_OK;
}

void cv_crypto_wipe(void *buffer, size_t length) {
    if (buffer != NULL && length != 0) {
        sodium_memzero(buffer, length);
    }
}
