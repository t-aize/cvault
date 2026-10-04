#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "cvault/crypto.h"
#include "persist_codec.h"
#include "persist_io.h"

static const unsigned char log_magic[8] = {'C', 'V', 'A', 'O', 'F', '0', '0', '1'};
static const unsigned char snapshot_magic[8] = {'C', 'V', 'S', 'N', 'P', '0', '0', '1'};

static void encode_u32(unsigned char *out, uint32_t value) {
    for (unsigned int i = 0; i < 4; ++i) { out[i] = (unsigned char) (value >> (i * 8)); }
}

static uint32_t decode_u32(const unsigned char *in) {
    uint32_t value = 0;
    for (unsigned int i = 0; i < 4; ++i) { value |= (uint32_t) in[i] << (i * 8); }
    return value;
}

void cv_encode_u64(unsigned char *out, uint64_t value) {
    for (unsigned int i = 0; i < 8; ++i) { out[i] = (unsigned char) (value >> (i * 8)); }
}

uint64_t cv_decode_u64(const unsigned char *in) {
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i) { value |= (uint64_t) in[i] << (i * 8); }
    return value;
}

static cv_status buffers(cv_record_stream *stream) {
    stream->plain = malloc(CV_RECORD_PLAIN_BYTES);
    stream->cipher = malloc(CV_RECORD_CIPHER_BYTES);
    return stream->plain != NULL && stream->cipher != NULL ? CV_OK : CV_ERR_NO_MEMORY;
}

cv_status cv_stream_create(FILE *file, bool snapshot, const unsigned char uuid[16],
                           uint64_t baseline, const unsigned char *key, cv_record_stream *stream) {
    *stream = (cv_record_stream){0};
    stream->file = file;
    stream->key = key;
    stream->snapshot = snapshot;
    stream->baseline = baseline;
    stream->sequence = snapshot ? 0 : baseline;
    cv_status status = buffers(stream);
    if (status != CV_OK) { return status; }
    memcpy(stream->header, snapshot ? snapshot_magic : log_magic, 8);
    memcpy(stream->header + 8, uuid, 16);
    cv_encode_u64(stream->header + 24, baseline);
    randombytes_buf(stream->header + 32, 24);
    unsigned long long length = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(stream->header + 56, &length,
                                                   NULL, 0, stream->header, 32, NULL, stream->header + 32,
                                                   key) != 0 || length != 16) {
        return CV_ERR_CRYPTO;
    }
    memcpy(stream->previous_tag, stream->header + 56, 16);
    return cv_io_write(file, stream->header, sizeof(stream->header));
}

cv_status cv_stream_open(FILE *file, bool snapshot, const unsigned char *key, cv_record_stream *stream) {
    *stream = (cv_record_stream){0};
    stream->file = file;
    stream->key = key;
    stream->snapshot = snapshot;
    if (fread(stream->header, 1, sizeof(stream->header), file) != sizeof(stream->header)) {
        return ferror(file) ? CV_ERR_IO : CV_ERR_CORRUPT;
    }
    if (memcmp(stream->header, snapshot ? snapshot_magic : log_magic, 8) != 0) {
        return CV_ERR_CORRUPT;
    }
    unsigned char unused[1];
    unsigned long long length = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(unused, &length, NULL,
                                                   stream->header + 56, 16, stream->header, 32, stream->header + 32,
                                                   key) != 0) {
        return CV_ERR_CRYPTO;
    }
    stream->baseline = cv_decode_u64(stream->header + 24);
    stream->sequence = snapshot ? 0 : stream->baseline;
    memcpy(stream->previous_tag, stream->header + 56, 16);
    return buffers(stream);
}

static void associated_data(const cv_record_stream *stream,
                            const unsigned char frame[CV_RECORD_HEADER_BYTES], unsigned char out[88]) {
    memcpy(out, stream->header, 32);
    memcpy(out + 32, frame, CV_RECORD_HEADER_BYTES);
    memcpy(out + 72, stream->previous_tag, 16);
}

cv_status cv_stream_append(cv_record_stream *stream, unsigned int operation, const char *key,
                           const unsigned char *value, size_t length, uint64_t expiry_ms) {
    if (stream->sequence == UINT64_MAX) { return CV_ERR_LIMIT; }
    size_t key_length = key != NULL ? strlen(key) : 0;
    if (key_length > CV_MAX_KEY_BYTES || length > CV_MAX_VALUE_BYTES) { return CV_ERR_LIMIT; }
    size_t plain_length = 17 + key_length + length;
    stream->plain[0] = (unsigned char) operation;
    encode_u32(stream->plain + 1, (uint32_t) key_length);
    encode_u32(stream->plain + 5, (uint32_t) length);
    cv_encode_u64(stream->plain + 9, expiry_ms);
    if (key_length != 0) { memcpy(stream->plain + 17, key, key_length); }
    if (length != 0) { memcpy(stream->plain + 17 + key_length, value, length); }
    unsigned char frame[CV_RECORD_HEADER_BYTES] = {0};
    encode_u32(frame, (uint32_t) (plain_length + 16));
    cv_encode_u64(frame + 8, stream->sequence + 1);
    randombytes_buf(frame + 16, 24);
    unsigned char aad[88];
    associated_data(stream, frame, aad);
    unsigned long long encrypted_length = 0;
    int result = crypto_aead_xchacha20poly1305_ietf_encrypt(stream->cipher, &encrypted_length,
                                                            stream->plain, (unsigned long long) plain_length, aad,
                                                            sizeof(aad), NULL, frame + 16, stream->key);
    cv_crypto_wipe(stream->plain, plain_length);
    if (result != 0 || encrypted_length != plain_length + 16) { return CV_ERR_CRYPTO; }
    cv_status status = cv_io_write(stream->file, frame, sizeof(frame));
    if (status == CV_OK) { status = cv_io_write(stream->file, stream->cipher, (size_t) encrypted_length); }
    if (status == CV_OK) {
        ++stream->sequence;
        memcpy(stream->previous_tag, stream->cipher + encrypted_length - 16, 16);
    }
    return status;
}

cv_status cv_stream_next(cv_record_stream *stream, cv_disk_record *record, bool *eof, bool *partial) {
    *eof = false;
    *partial = false;
    *record = (cv_disk_record){0};
    unsigned char frame[CV_RECORD_HEADER_BYTES];
    size_t count = fread(frame, 1, sizeof(frame), stream->file);
    if (count != sizeof(frame)) {
        if (ferror(stream->file)) { return CV_ERR_IO; }
        *eof = true;
        *partial = count != 0;
        return CV_OK;
    }
    uint32_t cipher_length = decode_u32(frame);
    if (decode_u32(frame + 4) != 0 || stream->sequence == UINT64_MAX ||
        cv_decode_u64(frame + 8) != stream->sequence + 1 ||
        cipher_length < 33 || cipher_length > CV_RECORD_CIPHER_BYTES) {
        return CV_ERR_CORRUPT;
    }
    count = fread(stream->cipher, 1, cipher_length, stream->file);
    if (count != cipher_length) {
        if (ferror(stream->file)) { return CV_ERR_IO; }
        *eof = true;
        *partial = true;
        return CV_OK;
    }
    unsigned char aad[88];
    associated_data(stream, frame, aad);
    unsigned long long length = 0;
    cv_crypto_wipe(stream->plain, CV_RECORD_PLAIN_BYTES);
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(stream->plain, &length, NULL,
                                                   stream->cipher, cipher_length, aad, sizeof(aad), frame + 16,
                                                   stream->key) != 0) {
        return CV_ERR_CRYPTO;
    }
    uint32_t key_length = decode_u32(stream->plain + 1);
    uint32_t value_length = decode_u32(stream->plain + 5);
    if (key_length > CV_MAX_KEY_BYTES || value_length > CV_MAX_VALUE_BYTES ||
        length != (unsigned long long) 17 + key_length + value_length ||
        memchr(stream->plain + 17, '\0', key_length) != NULL) {
        return CV_ERR_CORRUPT;
    }
    record->operation = stream->plain[0];
    record->expiry_ms = cv_decode_u64(stream->plain + 9);
    if (record->operation == CV_RECORD_END) {
        if (key_length != 0 || value_length != 8 || record->expiry_ms != 0) { return CV_ERR_CORRUPT; }
    } else if (key_length == 0 ||
               (record->operation != CV_RECORD_SET && record->operation != CV_RECORD_DELETE &&
                record->operation != CV_RECORD_EXPIRE) ||
               (record->operation != CV_RECORD_SET && value_length != 0) ||
               (record->operation == CV_RECORD_DELETE && record->expiry_ms != 0) ||
               (record->operation == CV_RECORD_EXPIRE && record->expiry_ms == 0)) {
        return CV_ERR_CORRUPT;
    }
    memcpy(record->key, stream->plain + 17, key_length);
    record->key[key_length] = '\0';
    record->value = stream->plain + 17 + key_length;
    record->value_length = value_length;
    ++stream->sequence;
    memcpy(stream->previous_tag, stream->cipher + cipher_length - 16, 16);
    return CV_OK;
}

void cv_stream_clear(cv_record_stream *stream) {
    cv_crypto_wipe(stream->plain, CV_RECORD_PLAIN_BYTES);
    cv_crypto_wipe(stream->cipher, CV_RECORD_CIPHER_BYTES);
    free(stream->plain);
    free(stream->cipher);
    cv_crypto_wipe(stream, sizeof(*stream));
}
