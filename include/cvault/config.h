#ifndef CVAULT_CONFIG_H
#define CVAULT_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#define CV_MAX_KEY_BYTES ((size_t)256)
#define CV_MAX_VALUE_BYTES ((size_t)65536)
#define CV_MAX_LINE_BYTES (CV_MAX_KEY_BYTES + CV_MAX_VALUE_BYTES + (size_t)32)
#define CV_MAX_CLIENTS ((size_t)128)
#define CV_HARD_MAX_CLIENTS ((size_t)1024)
#define CV_MAX_RESPONSE_BYTES (CV_MAX_VALUE_BYTES + (size_t)128)

typedef enum {
    CV_NETWORK_AUTO = 0,
    CV_NETWORK_POLL,
    CV_NETWORK_EPOLL
} cv_network_backend;

typedef struct {
    /** Numeric IPv4/IPv6 address, consumed during server creation. */
    const char *bind_address;
    /** TCP port; zero requests an OS-selected ephemeral port. */
    uint16_t port;
    /** Reserved for the future persistence layer; unused by the transport. */
    const char *data_directory;
    /** Active connection cap, between 1 and CV_HARD_MAX_CLIENTS. */
    size_t max_clients;
    /** AUTO: epoll on Linux, poll/WSAPoll elsewhere. */
    cv_network_backend backend;
    /** Timeouts are monotonic milliseconds, each between 1 and INT_MAX. */
    uint32_t idle_timeout_ms;
    uint32_t frame_timeout_ms;
    uint32_t shutdown_timeout_ms;
} cv_server_config;

cv_server_config cv_server_config_default(void);

#endif
