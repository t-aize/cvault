#include "cvault/audit.h"
#include "cvault/auth.h"
#include "cvault/crypto.h"
#include "cvault/persist.h"
#include "persist_io.h"
#include "security_service.h"
#include "test_util.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned int fail_at, sync_calls;

cv_status cv_test_audit_sync(FILE *file) {
    if (++sync_calls == fail_at) {
        return CV_ERR_IO;
    }
    return cv_io_sync(file);
}

static const unsigned char password[] = "test password with spaces";

static cv_status authenticate(cv_auth_session *session, cv_auth_policy *policy, const char *name) {
    return cv_authenticate(session, policy, name, password, sizeof(password) - 1);
}

static int api(const char *policy_path, const char *audit_path, const char *key_path) {
    cv_auth_policy *policy = NULL;
    CHECK(cv_auth_policy_load(policy_path, &policy) == CV_OK);
    cv_auth_session session;
    cv_auth_session_init(&session);
    CHECK(cv_auth_authorize(&session, "alice:x", false) == CV_ERR_UNAUTHORIZED);
    CHECK(authenticate(&session, policy, "alice") == CV_OK);
    CHECK(!strcmp(cv_auth_identity(&session), "alice"));
    CHECK(cv_auth_authorize(&session, "alice:x", true) == CV_OK);
    CHECK(cv_auth_authorize(&session, "shared:x", false) == CV_OK);
    CHECK(cv_auth_authorize(&session, "shared:x", true) == CV_ERR_UNAUTHORIZED);
    CHECK(cv_auth_authorize(&session, "aliceevil:x", false) == CV_ERR_UNAUTHORIZED);
    CHECK(cv_authenticate(&session, policy, "alice", (const unsigned char *)"wrong", 5) ==
          CV_ERR_UNAUTHORIZED);
    CHECK(!session.authenticated);
    CHECK(authenticate(&session, policy, "missing") == CV_ERR_UNAUTHORIZED);
    CHECK(authenticate(&session, policy, "alice") == CV_OK);
    CHECK(cv_authenticate(&session, policy, NULL, password, sizeof(password) - 1) ==
          CV_ERR_INVALID_ARGUMENT);
    CHECK(!session.authenticated);
    CHECK(cv_authenticate(&session, policy, "alice", password, CV_AUTH_PASSWORD_BYTES + 1) ==
          CV_ERR_INVALID_ARGUMENT);
    CHECK(authenticate(&session, policy, "writer") == CV_OK);
    CHECK(cv_auth_authorize(&session, "shared:x", true) == CV_OK);
    CHECK(cv_auth_authorize(&session, "shared:x", false) == CV_ERR_UNAUTHORIZED);
    cv_auth_session_init(&session);
    cv_auth_policy_destroy(policy);
    char hash[CV_AUTH_HASH_BYTES], other[CV_AUTH_HASH_BYTES];
    const unsigned char binary[] = {0, 1, 0, 2};
    CHECK(cv_auth_hash_password(binary, sizeof(binary), hash) == CV_OK);
    CHECK(cv_auth_hash_password(binary, sizeof(binary), other) == CV_OK);
    CHECK(crypto_pwhash_str_verify(hash, (const char *)binary, sizeof(binary)) == 0);
    CHECK(crypto_pwhash_str_verify(hash, (const char *)binary, sizeof(binary) - 1) != 0);
    CHECK(strcmp(hash, other) != 0);
    CHECK(strncmp(hash, "$argon2id$v=19$m=65536,t=2,p=1$", 28) == 0);
    CHECK(cv_auth_hash_password(NULL, 0, hash) == CV_ERR_INVALID_ARGUMENT && hash[0] == 0);
    cv_crypto_wipe(hash, sizeof(hash));
    cv_crypto_wipe(other, sizeof(other));
    unsigned char key[32];
    CHECK(cv_persist_key_load(key_path, key) == CV_OK);
    cv_audit *audit = NULL, *second = NULL;
    CHECK(cv_audit_open(audit_path, key, true, &audit) == CV_OK);
    CHECK(cv_audit_open(audit_path, key, true, &second) == CV_ERR_BUSY && !second);
    cv_audit_event event = {12, 34, CV_AUDIT_SET, CV_AUDIT_INTENT, CV_OK, "alice"};
    CHECK(cv_audit_record(audit, &event) == CV_OK);
    event.identity = "injected\nidentity";
    CHECK(cv_audit_record(audit, &event) == CV_ERR_INVALID_ARGUMENT);
    event.identity = "alice";
    event.phase = CV_AUDIT_RESULT;
    CHECK(cv_audit_record(audit, &event) == CV_OK);
    FILE *output = tmpfile();
    CHECK(output != NULL);
    CHECK(cv_audit_export(audit, output) == CV_OK);
    rewind(output);
    char line[512];
    CHECK(fgets(line, sizeof(line), output) && strstr(line, "\"phase\":\"intent\""));
    CHECK(fgets(line, sizeof(line), output) && strstr(line, "\"phase\":\"result\""));
    CHECK(fgetc(output) == EOF);
    fclose(output);
    CHECK(cv_audit_record(audit, &event) == CV_OK); /* Export preserves append state. */
    CHECK(cv_audit_close(audit) == CV_OK);
    CHECK(cv_audit_open(audit_path, key, false, &audit) == CV_OK);
    CHECK(cv_audit_close(audit) == CV_OK);
    cv_crypto_wipe(key, sizeof(key));
    return EXIT_SUCCESS;
}

static int faults(const char *policy_path,
                  const char *audit_path,
                  const char *key_path,
                  const char *data,
                  unsigned int fault) {
    unsigned char key[32];
    CHECK(cv_persist_key_load(key_path, key) == CV_OK);
    cv_persist *store = NULL;
    cv_persist_options options = {data, key, sizeof(key), NULL, NULL};
    CHECK(cv_persist_open(&options, &store) == CV_OK);
    cv_crypto_wipe(key, sizeof(key));
    cv_security *security = NULL;
    CHECK(cv_security_open(policy_path, audit_path, key_path, store, 2, &security) == CV_OK);
    unsigned char out[CV_MAX_RESPONSE_BYTES];
    size_t written;
    bool close_after;
    const char *auth = "AUTH alice test password with spaces\n";
    CHECK(cv_security_handler(security,
                              1,
                              (const unsigned char *)auth,
                              strlen(auth),
                              out,
                              sizeof(out),
                              &written,
                              &close_after) == CV_OK);
    CHECK(written == 4 && !memcmp(out, "+OK\n", 4));
    sync_calls = 0;
    fail_at = fault;
    const char *set = "SET alice:x value\n";
    CHECK(cv_security_handler(security,
                              1,
                              (const unsigned char *)set,
                              strlen(set),
                              out,
                              sizeof(out),
                              &written,
                              &close_after) == CV_ERR_IO);
    CHECK(written == 0 && cv_security_status(security) == CV_ERR_IO);
    const unsigned char *value = NULL;
    size_t length = 0;
    CHECK(cv_persist_get(store, "alice:x", &value, &length) ==
          (fault == 1 ? CV_ERR_NOT_FOUND : CV_OK));
    if (fault == 2) {
        CHECK(length == 5 && !memcmp(value, "value", 5));
    }
    CHECK(cv_security_handler(security,
                              2,
                              (const unsigned char *)auth,
                              strlen(auth),
                              out,
                              sizeof(out),
                              &written,
                              &close_after) == CV_ERR_IO);
    cv_security_disconnect(security, 1);
    CHECK(cv_security_close(security) == CV_ERR_IO);
    CHECK(cv_persist_close(store) == CV_OK);
    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    if (argc == 5 && !strcmp(argv[1], "--api")) {
        return api(argv[2], argv[3], argv[4]);
    }
    if (argc == 7 && !strcmp(argv[1], "--fault")) {
        return faults(argv[2], argv[3], argv[4], argv[5], (unsigned int)atoi(argv[6]));
    }
    return EXIT_FAILURE;
}
