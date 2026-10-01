#ifndef CVAULT_CONFIG_H
#define CVAULT_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#define CV_MAX_KEY_BYTES ((size_t)256)
#define CV_MAX_VALUE_BYTES ((size_t)65536)
#define CV_MAX_LINE_BYTES (CV_MAX_KEY_BYTES + CV_MAX_VALUE_BYTES + (size_t)32)
#define CV_MAX_CLIENTS ((size_t)128)

typedef struct {
    const char *bind_address;
    uint16_t port;
    const char *data_directory;
    size_t max_clients;
} cv_server_config;

cv_server_config cv_server_config_default(void);

#endif
