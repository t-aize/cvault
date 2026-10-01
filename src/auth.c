#include <stddef.h>
#include "cvault/auth.h"

void cv_auth_session_init(cv_auth_session *session) {
    if (session != NULL) {
        session->authenticated = false;
    }
}

cv_status cv_authenticate(cv_auth_session *session, const char *password) {
    if (session == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    session->authenticated = false;
    if (password == NULL) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    /* TODO: Argon2id password verification, no default or hard-coded password. */
    return CV_ERR_NOT_IMPLEMENTED;
}

cv_status cv_auth_authorize(const cv_auth_session *session, const char *key, bool write) {
    (void)session;
    (void)key;
    (void)write;
    /* TODO: deny by default; explicit per-identity prefix rules. */
    return CV_ERR_UNAUTHORIZED;
}
