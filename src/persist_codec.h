#ifndef CVAULT_PERSIST_CODEC_H
#define CVAULT_PERSIST_CODEC_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "cvault/config.h"
#include "cvault/persist.h"

#define CV_FILE_HEADER_BYTES ((size_t)72)
#define CV_RECORD_HEADER_BYTES ((size_t)40)
#define CV_RECORD_PLAIN_BYTES ((size_t)17 + CV_MAX_KEY_BYTES + CV_MAX_VALUE_BYTES)
#define CV_RECORD_CIPHER_BYTES (CV_RECORD_PLAIN_BYTES + (size_t)16)
#define CV_RECORD_SET 1u
#define CV_RECORD_DELETE 2u
#define CV_RECORD_EXPIRE 3u
#define CV_RECORD_END 127u

typedef struct {
    FILE *file;
    const unsigned char *key;
    unsigned char header[CV_FILE_HEADER_BYTES];
    unsigned char previous_tag[16];
    unsigned char *plain;
    unsigned char *cipher;
    uint64_t sequence;
    uint64_t baseline;
    bool snapshot;
} cv_record_stream;

typedef struct {
    unsigned int operation;
    char key[CV_MAX_KEY_BYTES + 1];
    const unsigned char *value;
    size_t value_length;
    uint64_t expiry_ms;
} cv_disk_record;

void cv_encode_u64(unsigned char *out, uint64_t value);

uint64_t cv_decode_u64(const unsigned char *in);

cv_status cv_stream_create(FILE *file, bool snapshot, const unsigned char uuid[16],
                           uint64_t baseline, const unsigned char *key, cv_record_stream *stream);

cv_status cv_stream_open(FILE *file, bool snapshot, const unsigned char *key, cv_record_stream *stream);

cv_status cv_stream_append(cv_record_stream *stream, unsigned int operation, const char *key,
                           const unsigned char *value, size_t length, uint64_t expiry_ms);

cv_status cv_stream_next(cv_record_stream *stream, cv_disk_record *record, bool *eof, bool *partial);

void cv_stream_clear(cv_record_stream *stream);

#endif
