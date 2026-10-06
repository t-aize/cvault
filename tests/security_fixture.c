/**
 * @file security_fixture.c
 * @brief C-level tests of authentication, authorisation and the audit log.
 *
 * Two modes, both driven by test_security.py:
 *
 *     security-fixture --api <policy> <audit> <audit-key>
 *         Exercises cv_auth_* and cv_audit_* directly.
 *
 *     security-fixture --expiry <policy> <audit> <audit-key>
 *         Checks that the periodic sweep erases expired entries of the volatile
 *         storage and nothing else.
 *
 *     security-fixture --fault <policy> <audit> <audit-key> <data-dir> <n>
 *         Makes the n-th audit synchronisation fail while a SET is processed,
 *         and checks that the service fails closed in both cases (n = 1: the
 *         intent could not be recorded, so nothing may be executed; n = 2: the
 *         result could not be recorded, so the client must not be answered).
 */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

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
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

/** Number of audit syncs so far, and the one that must fail (0: never). */
static unsigned int fail_at, sync_calls;

cv_status cv_test_audit_sync(FILE *file) {
    if (++sync_calls == fail_at) {
        return CV_ERR_IO;
    }

    return cv_io_sync(file);
}

static const unsigned char password[] = "test password with spaces";

/** @brief Authenticate as @p name with the shared test password. */
static cv_status authenticate(cv_auth_session *session, cv_auth_policy *policy, const char *name) {
    return cv_authenticate(session, policy, name, password, sizeof(password) - 1);
}

/** @brief Direct API checks: sessions, ACLs, hashing and the audit log. */
static int api(const char *policy_path, const char *audit_path, const char *key_path) {
    cv_auth_policy *policy = NULL;

    CHECK(cv_auth_policy_load(policy_path, &policy) == CV_OK);

    /* Before authentication nothing is allowed. */
    cv_auth_session session;

    cv_auth_session_init(&session);

    CHECK(cv_auth_authorize(&session, "alice:x", false) == CV_ERR_UNAUTHORIZED);

    /* alice: read/write on her own prefix, read-only on the shared prefix. */
    CHECK(authenticate(&session, policy, "alice") == CV_OK);
    CHECK(!strcmp(cv_auth_identity(&session), "alice"));
    CHECK(cv_auth_authorize(&session, "alice:x", true) == CV_OK);
    CHECK(cv_auth_authorize(&session, "shared:x", false) == CV_OK);
    CHECK(cv_auth_authorize(&session, "shared:x", true) == CV_ERR_UNAUTHORIZED);

    /* Prefixes are literal: "alice" must not grant "aliceevil". */
    CHECK(cv_auth_authorize(&session, "aliceevil:x", false) == CV_ERR_UNAUTHORIZED);

    /* A failed login revokes the previous session; unknown users are refused. */
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

    /* writer: write-only on the shared prefix; write never implies read. */
    CHECK(authenticate(&session, policy, "writer") == CV_OK);
    CHECK(cv_auth_authorize(&session, "shared:x", true) == CV_OK);
    CHECK(cv_auth_authorize(&session, "shared:x", false) == CV_ERR_UNAUTHORIZED);

    cv_auth_session_init(&session);
    cv_auth_policy_destroy(policy);

    /* Password hashing: binary safe, salted, bounded, exact cost parameters. */
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

    /* Audit log: exclusive lock, identity validation, export, reopen. */
    unsigned char key[32];

    CHECK(cv_persist_key_load(key_path, key) == CV_OK);

    cv_audit *audit = NULL, *second = NULL;

    CHECK(cv_audit_open(audit_path, key, true, &audit) == CV_OK);
    CHECK(cv_audit_open(audit_path, key, true, &second) == CV_ERR_BUSY && !second);

    cv_audit_event event = {12, 34, CV_AUDIT_SET, CV_AUDIT_INTENT, CV_OK, "alice"};

    CHECK(cv_audit_record(audit, &event) == CV_OK);

    /* An identity that could inject JSON is refused. */
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

/** @brief Sleep for roughly the given number of milliseconds. */
static void pause_ms(unsigned int milliseconds) {
#ifdef _WIN32
    Sleep(milliseconds);
#else
    struct timespec length = {milliseconds / 1000, (long)(milliseconds % 1000) * 1000000L};

    while (nanosleep(&length, &length) != 0) {
    }
#endif
}

/** @brief Send one request line as client @p id and compare the reply with @p expected. */
static int exchange(cv_security *security, uint64_t id, const char *line, const char *expected) {
    unsigned char reply[CV_MAX_RESPONSE_BYTES];
    size_t written = 0;
    bool close_after = false;

    CHECK(cv_security_handler(security,
                              id,
                              (const unsigned char *)line,
                              strlen(line),
                              reply,
                              sizeof(reply),
                              &written,
                              &close_after) == CV_OK);
    CHECK(written == strlen(expected) && memcmp(reply, expected, written) == 0);

    return EXIT_SUCCESS;
}

/** @brief The sweep erases expired entries of the volatile storage, and only those. */
static int expiry(const char *policy_path, const char *audit_path, const char *key_path) {
    cv_security *security = NULL;
    size_t removed = 99;

    CHECK(cv_security_open(policy_path, audit_path, key_path, NULL, 2, &security) == CV_OK);
    CHECK(exchange(security, 1, "AUTH alice test password with spaces\n", "+OK\n") == EXIT_SUCCESS);
    CHECK(exchange(security, 1, "SET alice:short a\n", "+OK\n") == EXIT_SUCCESS);
    CHECK(exchange(security, 1, "SET alice:long b\n", "+OK\n") == EXIT_SUCCESS);
    CHECK(exchange(security, 1, "SET alice:forever c\n", "+OK\n") == EXIT_SUCCESS);
    CHECK(exchange(security, 1, "EXPIRE alice:short 1\n", "+OK\n") == EXIT_SUCCESS);
    CHECK(exchange(security, 1, "EXPIRE alice:long 100000\n", "+OK\n") == EXIT_SUCCESS);

    /* Nothing has expired yet. */
    CHECK(cv_security_purge_expired(security, &removed) == CV_OK && removed == 0);

    pause_ms(1300);

    /* Expired but not yet erased: invisible to readers, then removed by the sweep. */
    CHECK(exchange(security, 1, "GET alice:short\n", "$-1\n") == EXIT_SUCCESS);
    CHECK(cv_security_purge_expired(security, &removed) == CV_OK && removed == 1);
    CHECK(cv_security_purge_expired(security, &removed) == CV_OK && removed == 0);
    CHECK(exchange(security, 1, "GET alice:long\n", "$1\nb\n") == EXIT_SUCCESS);
    CHECK(exchange(security, 1, "GET alice:forever\n", "$1\nc\n") == EXIT_SUCCESS);

    /* Invalid arguments leave the output reset. */
    removed = 99;

    CHECK(cv_security_purge_expired(NULL, &removed) == CV_ERR_INVALID_ARGUMENT && removed == 0);
    CHECK(cv_security_purge_expired(security, NULL) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_security_close(security) == CV_OK);

    return EXIT_SUCCESS;
}

/**
 * @brief Make one audit sync fail during a SET and verify the service fails closed.
 *
 * @param fault 1 = fail the intent record, 2 = fail the result record.
 */
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

    /* Log in as alice (client 1) while the audit log still works. */
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

    /* Arm the fault, then SET: the call must fail without a reply. */
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

    /* Intent failure: never executed. Result failure: executed, but not acknowledged. */
    const unsigned char *value = NULL;
    size_t length = 0;

    CHECK(cv_persist_get(store, "alice:x", &value, &length) ==
          (fault == 1 ? CV_ERR_NOT_FOUND : CV_OK));

    if (fault == 2) {
        CHECK(length == 5 && !memcmp(value, "value", 5));
    }

    /* A poisoned service refuses every further request, from any client. */
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

    if (argc == 5 && !strcmp(argv[1], "--expiry")) {
        return expiry(argv[2], argv[3], argv[4]);
    }

    if (argc == 7 && !strcmp(argv[1], "--fault")) {
        return faults(argv[2], argv[3], argv[4], argv[5], (unsigned int)atoi(argv[6]));
    }

    return EXIT_FAILURE;
}
