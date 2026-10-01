#ifndef CVAULT_AUTH_H
#define CVAULT_AUTH_H

#include <stdbool.h>
#include "cvault/common.h"

typedef struct {
    bool authenticated;
} cv_auth_session;

void cv_auth_session_init(cv_auth_session *session);
/* Placeholder: always leaves the session unauthenticated. */
cv_status cv_authenticate(cv_auth_session *session, const char *password);
/* Placeholder: denies every request until prefix ACLs are implemented. */
cv_status cv_auth_authorize(const cv_auth_session *session, const char *key, bool write);

#endif
