/**
 * @file persist_codec.h
 * @brief Private, versioned AEAD record codec shared by journals, snapshots and
 *        the audit log.
 *
 * ## File layout
 * A stream starts with a 72-byte header followed by records:
 *
 *     header  : magic[8] | uuid[16] | baseline[8] | nonce[24] | tag[16]
 *     record  : frame[40] | ciphertext (plaintext + 16-byte tag)
 *     frame   : ciphertext length[4] | reserved[4] | sequence[8] | nonce[24]
 *     plain   : operation[1] | key length[4] | value length[4] | expiry[8] | key | value
 *
 * Integer fields are explicitly little-endian and no C struct is ever
 * serialised. The header magic, UUID and baseline, each record frame, its
 * sequence number and the tag of the previous record are all authenticated, so
 * reordering, replaying, truncating or splicing records is detected. Owners
 * select a separate key or domain for independent uses and control when files
 * are synchronised.
 */

#ifndef CVAULT_PERSIST_CODEC_H
#define CVAULT_PERSIST_CODEC_H

#include "cvault/config.h"
#include "cvault/persist.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/** Size of the authenticated file header. */
#define CV_FILE_HEADER_BYTES ((size_t)72)

/** Size of the per-record frame that precedes each ciphertext. */
#define CV_RECORD_HEADER_BYTES ((size_t)40)

/** Largest plaintext of one record. */
#define CV_RECORD_PLAIN_BYTES ((size_t)17 + CV_MAX_KEY_BYTES + CV_MAX_VALUE_BYTES)

/** Largest ciphertext of one record (plaintext plus the Poly1305 tag). */
#define CV_RECORD_CIPHER_BYTES (CV_RECORD_PLAIN_BYTES + (size_t)16)

/** @name Record operations @{ */
#define CV_RECORD_SET    1u   /**< Store a value. */
#define CV_RECORD_DELETE 2u   /**< Delete a key. */
#define CV_RECORD_EXPIRE 3u   /**< Set an absolute expiry for a key. */
#define CV_RECORD_END    127u /**< Snapshot trailer carrying the record count. */
/** @} */

/**
 * @brief State of an open record stream.
 *
 * The stream owns fixed-size plaintext and ciphertext buffers. The file and the
 * 32-byte key are borrowed and must outlive the stream. cv_stream_clear()
 * wipes and releases the buffers but never closes the file.
 */
typedef struct {
    FILE *file;                                 /**< Borrowed file handle. */
    const unsigned char *key;                   /**< Borrowed 32-byte AEAD key. */
    unsigned char header[CV_FILE_HEADER_BYTES]; /**< Authenticated file header. */
    unsigned char previous_tag[16];             /**< Tag chained into the next record. */
    unsigned char *plain;                       /**< Owned plaintext buffer. */
    unsigned char *cipher;                      /**< Owned ciphertext buffer. */
    uint64_t sequence;                          /**< Sequence number of the last record. */
    uint64_t baseline;                          /**< Sequence offset recorded in the header. */
    bool snapshot;                              /**< True for snapshot files, false for logs. */
} cv_record_stream;

/** A decoded, validated record; the value is borrowed from the stream buffer. */
typedef struct {
    unsigned int operation;         /**< One of the CV_RECORD_* constants. */
    char key[CV_MAX_KEY_BYTES + 1]; /**< NUL-terminated key. */
    const unsigned char *value;     /**< Borrowed value bytes. */
    size_t value_length;            /**< Value length. */
    uint64_t expiry_ms;             /**< Absolute expiry, or 0 when not applicable. */
} cv_disk_record;

/** @brief Store a 64-bit value as 8 little-endian bytes. */
void cv_encode_u64(unsigned char *out, uint64_t value);

/** @brief Load a 64-bit value from 8 little-endian bytes. */
uint64_t cv_decode_u64(const unsigned char *in);

/**
 * @brief Initialise a fresh stream and write its authenticated header.
 *
 * Always call cv_stream_clear() eventually, including after a failed
 * allocation or header write. The stream must not already own live buffers.
 * Synchronising the header is the caller's job.
 *
 * @param file     Writable file positioned at offset 0.
 * @param snapshot True to create a snapshot header, false for a log header.
 * @param uuid     16 random bytes identifying this file.
 * @param baseline Sequence offset stored in the header (log compaction point).
 * @param key      32-byte AEAD key, borrowed.
 * @param stream   Receives the stream state.
 * @return #CV_OK, #CV_ERR_NO_MEMORY, #CV_ERR_CRYPTO or #CV_ERR_IO.
 */
cv_status cv_stream_create(FILE *file,
                           bool snapshot,
                           const unsigned char uuid[16],
                           uint64_t baseline,
                           const unsigned char *key,
                           cv_record_stream *stream);

/**
 * @brief Read and authenticate the header of an existing stream.
 *
 * Ownership rules are the same as for cv_stream_create().
 *
 * @return #CV_OK, #CV_ERR_CORRUPT (short or wrong magic), #CV_ERR_CRYPTO (header
 *         authentication failed, e.g. wrong key), #CV_ERR_IO or #CV_ERR_NO_MEMORY.
 */
cv_status
cv_stream_open(FILE *file, bool snapshot, const unsigned char *key, cv_record_stream *stream);

/**
 * @brief Encrypt and write one validated application record with a fresh nonce.
 *
 * The sequence number and tag chain advance only after a successful write; an
 * uncertain failure must poison the owner. The data goes to buffered stdio, so
 * the owner has to synchronise before publishing the file.
 *
 * @param stream    Open stream.
 * @param operation One of the CV_RECORD_* constants.
 * @param key       NUL-terminated key (may be NULL for the END record).
 * @param value     Value bytes (may be NULL when @p length is 0).
 * @param length    Value length.
 * @param expiry_ms Absolute expiry for CV_RECORD_EXPIRE, otherwise 0.
 * @return #CV_OK, #CV_ERR_LIMIT, #CV_ERR_CRYPTO or #CV_ERR_IO.
 */
cv_status cv_stream_append(cv_record_stream *stream,
                           unsigned int operation,
                           const char *key,
                           const unsigned char *value,
                           size_t length,
                           uint64_t expiry_ms);

/**
 * @brief Authenticate and decode the next record.
 *
 * The record value is borrowed until the next codec call or cv_stream_clear().
 * Outputs are reset on entry. EOF with @p partial true means the framing or
 * ciphertext was cut short: that tail is *not* authenticated content, and the
 * owning format decides whether it may be repaired. A complete but invalid
 * record always returns an error.
 *
 * @param eof     True at the end of the stream.
 * @param partial True when the stream ended in the middle of a record.
 * @return #CV_OK, #CV_ERR_CORRUPT, #CV_ERR_CRYPTO (authentication failure) or
 *         #CV_ERR_IO.
 */
cv_status
cv_stream_next(cv_record_stream *stream, cv_disk_record *record, bool *eof, bool *partial);

/** @brief Wipe and free the stream buffers and clear its state. */
void cv_stream_clear(cv_record_stream *stream);

#endif /* CVAULT_PERSIST_CODEC_H */
