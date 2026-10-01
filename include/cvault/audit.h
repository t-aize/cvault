#ifndef CVAULT_AUDIT_H
#define CVAULT_AUDIT_H

#include "cvault/common.h"

/* TODO: bounded structured events, identity, timestamps, log rotation.
 * Never log passwords, plaintext values or encryption keys. */
cv_status cv_audit_record(const char *operation, cv_status result);

#endif
