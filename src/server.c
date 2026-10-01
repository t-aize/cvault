#include <stddef.h>
#include "cvault/server.h"

cv_status cv_server_run(const cv_server_config *config) {
    if (config == NULL || config->bind_address == NULL || config->data_directory == NULL
        || config->port == 0 || config->max_clients == 0) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    /* TODO: Linux poll/epoll backend, Windows socket backend, signal handling. */
    return CV_ERR_NOT_IMPLEMENTED;
}
