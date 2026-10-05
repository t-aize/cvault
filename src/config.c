/**
 * @file config.c
 * @brief Default values for the TCP server configuration.
 */

#include "cvault/config.h"

cv_server_config cv_server_config_default(void) {
    /* Field order follows cv_server_config: address, port, data directory,
     * client cap, backend, then the idle / frame / shutdown timeouts. */
    const cv_server_config config = {
        "127.0.0.1", 6380, "./data", CV_MAX_CLIENTS, CV_NETWORK_AUTO, 30000, 5000, 2000};

    return config;
}
