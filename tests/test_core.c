#include "cvault/audit.h"
#include "cvault/auth.h"
#include "cvault/crypto.h"
#include "cvault/parser.h"
#include "cvault/persist.h"
#include "cvault/server.h"
#include "test_util.h"
#include <string.h>

int main(void) {
    /* Link every module and verify invalid inputs cannot accidentally grant access. */
    CHECK(cv_crypto_init() == CV_OK);
    CHECK(cv_crypto_init() == CV_OK);
    unsigned char secret[] = {1, 2, 3, 4};
    cv_crypto_wipe(secret, sizeof(secret));
    CHECK(memcmp(secret, (unsigned char[4]){0}, sizeof(secret)) == 0);

    cv_server_config config = cv_server_config_default();
    CHECK(strcmp(config.bind_address, "127.0.0.1") == 0);
    CHECK(config.port == 6380 && config.max_clients == CV_MAX_CLIENTS);
    config.max_clients = 0;
    CHECK(cv_server_run(&config) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_server_run(NULL) == CV_ERR_INVALID_ARGUMENT);

    cv_auth_session session;
    cv_auth_session_init(&session);
    CHECK(!session.authenticated);
    CHECK(cv_authenticate(&session, NULL, "test", (const unsigned char *)"secret", 6) ==
          CV_ERR_INVALID_ARGUMENT);
    CHECK(!session.authenticated);
    CHECK(cv_auth_authorize(&session, "user:key", false) == CV_ERR_UNAUTHORIZED);
    CHECK(cv_auth_authorize(&session, "user:key", true) == CV_ERR_UNAUTHORIZED);

    cv_hashtable *table = NULL;
    CHECK(cv_hashtable_create(&table) == CV_OK && table != NULL);
    const unsigned char *value = secret;
    size_t value_length = sizeof(secret);
    CHECK(cv_hashtable_get(table, "key", &value, &value_length) == CV_ERR_NOT_FOUND);
    CHECK(value == NULL && value_length == 0);
    CHECK(cv_hashtable_set(table, "key", secret, sizeof(secret)) == CV_OK);
    CHECK(cv_hashtable_delete(table, "key") == CV_OK);
    cv_hashtable_destroy(table);
    cv_persist *store = (cv_persist *)&config;
    CHECK(cv_persist_open(NULL, &store) == CV_ERR_INVALID_ARGUMENT && store == NULL);
    CHECK(cv_persist_open(NULL, NULL) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_persist_close(NULL) == CV_OK);
    value = secret;
    value_length = sizeof(secret);
    CHECK(cv_persist_get(NULL, "key", &value, &value_length) == CV_ERR_INVALID_ARGUMENT);
    CHECK(value == NULL && value_length == 0);
    int64_t ttl = 100;
    CHECK(cv_persist_ttl(NULL, "key", &ttl) == CV_ERR_INVALID_ARGUMENT && ttl == CV_TTL_MISSING);
    CHECK(cv_persist_set(NULL, "key", NULL, 0) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_persist_snapshot(NULL) == CV_ERR_INVALID_ARGUMENT);
    bool done = true;
    CHECK(cv_persist_snapshot_poll(NULL, &done) == CV_ERR_INVALID_ARGUMENT && !done);
    CHECK(cv_audit_record(NULL, NULL) == CV_ERR_INVALID_ARGUMENT);

    cv_command command;
    CHECK(cv_parse_line((const unsigned char *)"GET key\n", 8, &command) == CV_OK);
    CHECK(command.type == CV_CMD_GET && command.key_length == 3);
    CHECK(cv_parse_line(NULL, 0, &command) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_parse_line((const unsigned char *)"GET key", 7, &command) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_parse_line((const unsigned char *)"GET\0key\n", 8, &command) ==
          CV_ERR_INVALID_ARGUMENT);
    unsigned char line[CV_MAX_LINE_BYTES + 1];
    memset(line, 'A', sizeof(line));
    line[CV_MAX_LINE_BYTES - 1] = '\n';
    CHECK(cv_parse_line(line, CV_MAX_LINE_BYTES, &command) == CV_ERR_NOT_IMPLEMENTED);
    CHECK(cv_parse_line(line, sizeof(line), &command) == CV_ERR_LIMIT);
    puts("Core modules linked, bounds checked, access denied by default.");
    return EXIT_SUCCESS;
}
