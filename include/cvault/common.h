#ifndef CVAULT_COMMON_H
#define CVAULT_COMMON_H

typedef enum {
    CV_OK = 0,
    CV_ERR_INVALID_ARGUMENT,
    CV_ERR_NOT_IMPLEMENTED,
    CV_ERR_NOT_FOUND,
    CV_ERR_NO_MEMORY,
    CV_ERR_CRYPTO,
    CV_ERR_UNAUTHORIZED,
    CV_ERR_IO,
    CV_ERR_LIMIT,
    CV_ERR_CORRUPT,
    CV_ERR_BUSY
} cv_status;

const char *cv_status_string(cv_status status);

#endif
