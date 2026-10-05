/**
 * @file test_sodium.c
 * @brief Dependency check: libsodium links and XChaCha20-Poly1305 behaves.
 *
 * This verifies the third-party library the whole project relies on (round trip
 * and tamper detection). It is not a test of cvault's own encryption layer,
 * which is covered by the persistence and security tests.
 */

#include "cvault/crypto.h"
#include "test_util.h"

#include <sodium.h>
#include <string.h>

int main(void) {
    /* Dependency integration check, not a test of future cvault encryption wrappers. */
    CHECK(cv_crypto_init() == CV_OK);

    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    const unsigned char message[] = "dependency smoke test";
    const unsigned char metadata[] = "user:test";
    unsigned char ciphertext[sizeof(message) + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned char plaintext[sizeof(message)];
    unsigned long long ciphertext_length = 0;
    unsigned long long plaintext_length = 0;

    crypto_aead_xchacha20poly1305_ietf_keygen(key);
    randombytes_buf(nonce, sizeof(nonce));

    /* Round trip: encrypt, then decrypt with the same associated data. */
    CHECK(crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext,
                                                     &ciphertext_length,
                                                     message,
                                                     sizeof(message),
                                                     metadata,
                                                     sizeof(metadata),
                                                     NULL,
                                                     nonce,
                                                     key) == 0);
    CHECK(ciphertext_length == sizeof(ciphertext));
    CHECK(crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext,
                                                     &plaintext_length,
                                                     NULL,
                                                     ciphertext,
                                                     ciphertext_length,
                                                     metadata,
                                                     sizeof(metadata),
                                                     nonce,
                                                     key) == 0);
    CHECK(plaintext_length == sizeof(message));
    CHECK(memcmp(plaintext, message, sizeof(message)) == 0);

    /* Tampering with a single bit must be rejected. */
    ciphertext[0] ^= 1;

    CHECK(crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext,
                                                     &plaintext_length,
                                                     NULL,
                                                     ciphertext,
                                                     ciphertext_length,
                                                     metadata,
                                                     sizeof(metadata),
                                                     nonce,
                                                     key) == -1);

    cv_crypto_wipe(key, sizeof(key));
    cv_crypto_wipe(plaintext, sizeof(plaintext));

    puts("libsodium linked: XChaCha20-Poly1305 roundtrip and tamper rejection passed.");

    return EXIT_SUCCESS;
}
