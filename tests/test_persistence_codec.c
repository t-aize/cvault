#include "cvault/crypto.h"
#include "persist_codec.h"
#include "persist_io.h"
#include "test_util.h"
#include <string.h>

static int roundtrip(
    unsigned int operation, const char *name, size_t length, uint64_t expiry, cv_status expected) {
    FILE *file = tmpfile();
    CHECK(file != NULL);
    /* Fixed bytes are exclusively synthetic test material. */
    unsigned char key[CV_PERSIST_KEY_BYTES] = {0}, uuid[16] = {1};
    const unsigned char value[] = {0, 255, 42, 0, 10, 20, 30, 40};
    cv_record_stream writer = {0}, reader = {0};
    CHECK(cv_stream_create(file, false, uuid, 0, key, &writer) == CV_OK);
    CHECK(cv_stream_append(&writer, operation, name, value, length, expiry) == CV_OK);
    CHECK(cv_io_seek(file, 0) == CV_OK);
    CHECK(cv_stream_open(file, false, key, &reader) == CV_OK);
    cv_disk_record record;
    bool eof, partial;
    CHECK(cv_stream_next(&reader, &record, &eof, &partial) == expected);
    if (expected == CV_OK) {
        CHECK(!eof && !partial && record.operation == operation);
        CHECK(strcmp(record.key, name) == 0 && record.expiry_ms == expiry);
        CHECK(record.value_length == length && memcmp(record.value, value, length) == 0);
        CHECK(cv_stream_next(&reader, &record, &eof, &partial) == CV_OK && eof && !partial);
    }
    cv_stream_clear(&reader);
    cv_stream_clear(&writer);
    CHECK(fclose(file) == 0);
    return EXIT_SUCCESS;
}

int main(void) {
    CHECK(cv_crypto_init() == CV_OK);
    CHECK(roundtrip(CV_RECORD_SET, "binary", 8, 123456, CV_OK) == EXIT_SUCCESS);
    CHECK(roundtrip(CV_RECORD_DELETE, "binary", 0, 0, CV_OK) == EXIT_SUCCESS);
    CHECK(roundtrip(CV_RECORD_EXPIRE, "binary", 0, UINT64_MAX, CV_OK) == EXIT_SUCCESS);
    CHECK(roundtrip(CV_RECORD_END, "", 8, 0, CV_OK) == EXIT_SUCCESS);
    /* Authenticated malformed plaintext must still be rejected. */
    CHECK(roundtrip(255, "key", 0, 0, CV_ERR_CORRUPT) == EXIT_SUCCESS);
    CHECK(roundtrip(CV_RECORD_SET, "", 0, 0, CV_ERR_CORRUPT) == EXIT_SUCCESS);
    CHECK(roundtrip(CV_RECORD_DELETE, "key", 1, 0, CV_ERR_CORRUPT) == EXIT_SUCCESS);
    CHECK(roundtrip(CV_RECORD_DELETE, "key", 0, 1, CV_ERR_CORRUPT) == EXIT_SUCCESS);
    CHECK(roundtrip(CV_RECORD_EXPIRE, "key", 0, 0, CV_ERR_CORRUPT) == EXIT_SUCCESS);
    CHECK(roundtrip(CV_RECORD_END, "key", 8, 0, CV_ERR_CORRUPT) == EXIT_SUCCESS);
    CHECK(roundtrip(CV_RECORD_END, "", 7, 0, CV_ERR_CORRUPT) == EXIT_SUCCESS);
    CHECK(roundtrip(CV_RECORD_END, "", 8, 1, CV_ERR_CORRUPT) == EXIT_SUCCESS);
    puts("Persistence codec: binary roundtrips and authenticated malformed payload rejection "
         "verified.");
    return EXIT_SUCCESS;
}
