#ifndef CVAULT_SERVER_H
#define CVAULT_SERVER_H

#include "cvault/common.h"
#include "cvault/config.h"

/* TODO: sockets, bounded per-client buffers, event loop, graceful shutdown.
 * Scaffold returns NOT_IMPLEMENTED without opening a listener. */
cv_status cv_server_run(const cv_server_config *config);

#endif
