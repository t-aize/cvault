#ifndef CVAULT_PERSIST_CODEC_H
#define CVAULT_PERSIST_CODEC_H

#include "cvault/config.h"
#include "cvault/persist.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define CV_FILE_HEADER_BYTES ((size_t)72)
#define CV_RECORD_HEADER_BYTES ((size_t)40)
#define CV_RECORD_PLAIN_BYTES ((size_t)17 + CV_MAX_KEY_BYTES + CV_MAX_VALUE_BYTES)
#define CV_RECORD_CIPHER_BYTES (CV_RECORD_PLAIN_BYTES + (size_t)16)
#define CV_RECORD_SET 1u
#define CV_RECORD_DELETE 2u
#define CV_RECORD_EXPIRE 3u
#define CV_RECORD_END 127u

/** @file Private, versioned AEAD record codec. Integer fields are explicitly
 * little-endian; no C struct is serialized. Header magic/UUID/baseline, record
 * framing/sequence and the previous tag are authenticated. Owners choose a
 * separate key/domain for independent uses and control file synchronization.
 */

/** Owns fixed-size plain/cipher buffers; file and 32-byte key are borrowed and
 * must outlive the stream. clear releases/wipes buffers, never closes the file. */
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

/** Initialize a fresh stream and write its authenticated header. On all outcomes
 * call clear eventually, including failed allocation/header writes. The supplied
 * stream must not already own live buffers. Header synchronization is external. */
cv_status cv_stream_create(FILE *file,
                           bool snapshot,
                           const unsigned char uuid[16],
                           uint64_t baseline,
                           const unsigned char *key,
                           cv_record_stream *stream);

/** Initialize/authenticate an existing stream header. Same ownership as create. */
cv_status
cv_stream_open(FILE *file, bool snapshot, const unsigned char *key, cv_record_stream *stream);

/** Encode/encrypt one validated application record with a fresh nonce. Advances
 * sequence/tag only on a successful write; uncertain failure poisons the owner.
 * This call writes buffered stdio; the owner must synchronize before publishing. */
cv_status cv_stream_append(cv_record_stream *stream,
                           unsigned int operation,
                           const char *key,
                           const unsigned char *value,
                           size_t length,
                           uint64_t expiry_ms);

/** Authenticate/validate the next record. Value is borrowed until the next codec
 * call or clear. Resets record/eof/partial. EOF with partial=true means incomplete
 * framing/ciphertext, not authenticated content; the owning format decides whether
 * such a tail may be repaired. Complete invalid records always return errors. */
cv_status
cv_stream_next(cv_record_stream *stream, cv_disk_record *record, bool *eof, bool *partial);

void cv_stream_clear(cv_record_stream *stream);

#endif
