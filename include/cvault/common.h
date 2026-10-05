/**
 * @file common.h
 * @brief Status codes shared by every cvault module.
 *
 * Every fallible function in the public C API returns a #cv_status. Callers
 * compare against #CV_OK and may turn any other value into a human readable
 * message with cv_status_string().
 */

#ifndef CVAULT_COMMON_H
#define CVAULT_COMMON_H

/**
 * @brief Result of a fallible cvault operation.
 *
 * The numeric values are part of the encrypted audit-log format (one byte per
 * result), so existing enumerators must never be reordered or renumbered. New
 * codes are appended at the end.
 */
typedef enum {
    CV_OK = 0,               /**< The operation succeeded. */
    CV_ERR_INVALID_ARGUMENT, /**< A pointer was NULL or a value was out of range. */
    CV_ERR_NOT_IMPLEMENTED,  /**< The feature is planned but not available yet. */
    CV_ERR_NOT_FOUND,        /**< The key, file or user does not exist (or has expired). */
    CV_ERR_NO_MEMORY,        /**< A heap allocation failed. */
    CV_ERR_CRYPTO,           /**< libsodium failed to initialise, hash, encrypt or decrypt. */
    CV_ERR_UNAUTHORIZED,     /**< Authentication failed or the ACL denied the operation. */
    CV_ERR_IO,               /**< A system call on a file, socket or lock failed. */
    CV_ERR_LIMIT,            /**< A documented size or count limit was exceeded. */
    CV_ERR_CORRUPT,          /**< Persisted data failed validation or authentication. */
    CV_ERR_BUSY              /**< The resource is locked, in use or temporarily throttled. */
} cv_status;

/**
 * @brief Describe a status code for logs and diagnostics.
 *
 * @param status Any value; unknown values are tolerated.
 * @return A static, NUL-terminated English description. Never NULL and never
 *         to be freed or modified by the caller.
 */
const char *cv_status_string(cv_status status);

#endif /* CVAULT_COMMON_H */
