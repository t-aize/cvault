#include "cvault/common.h"

const char *cv_status_string(cv_status status) {
    switch (status) {
    case CV_OK: return "success";
    case CV_ERR_INVALID_ARGUMENT: return "invalid argument";
    case CV_ERR_NOT_IMPLEMENTED: return "not implemented (project scaffold)";
    case CV_ERR_NOT_FOUND: return "not found";
    case CV_ERR_NO_MEMORY: return "out of memory";
    case CV_ERR_CRYPTO: return "cryptographic initialization/operation failed";
    case CV_ERR_UNAUTHORIZED: return "unauthorized";
    case CV_ERR_IO: return "I/O error";
    case CV_ERR_LIMIT: return "size limit exceeded";
    case CV_ERR_CORRUPT: return "invalid or inconsistent persistence format";
    case CV_ERR_BUSY: return "resource already in use";
    default: return "unknown status";
    }
}
