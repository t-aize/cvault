/**
 * @file persist_codec_under_test.c
 * @brief The real record codec, compiled with an injectable write fault.
 */

#include "persist_io.h"

cv_status cv_test_write(FILE *file, const void *bytes, size_t length);

#define cv_io_write cv_test_write

#include "../src/persist_codec.c"
