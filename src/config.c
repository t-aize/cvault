#include "cvault/config.h"

cv_server_config cv_server_config_default(void) {
    const cv_server_config config = {"127.0.0.1", 6380, "./data", CV_MAX_CLIENTS};
    return config;
}
