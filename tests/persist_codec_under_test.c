#include "persist_io.h"

cv_status cv_test_write(FILE *file, const void *bytes, size_t length);

#define cv_io_write cv_test_write
#include "../src/persist_codec.c"
