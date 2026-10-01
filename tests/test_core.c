#include <string.h>
#include "cvault/audit.h"
#include "cvault/auth.h"
#include "cvault/crypto.h"
#include "cvault/parser.h"
#include "cvault/persist.h"
#include "cvault/server.h"
#include "test_util.h"

int main(void) {
    /* Link every module and verify the scaffold cannot accidentally grant access. */
    CHECK(cv_crypto_init() == CV_OK);
    CHECK(cv_crypto_init() == CV_OK);
    unsigned char secret[] = {1, 2, 3, 4};
    cv_crypto_wipe(secret, sizeof(secret));
    CHECK(memcmp(secret, (unsigned char[4]){0}, sizeof(secret)) == 0);

    cv_server_config config = cv_server_config_default();
    CHECK(strcmp(config.bind_address, "127.0.0.1") == 0);
    CHECK(config.port == 6380 && config.max_clients == CV_MAX_CLIENTS);
    CHECK(cv_server_run(&config) == CV_ERR_NOT_IMPLEMENTED);
    CHECK(cv_server_run(NULL) == CV_ERR_INVALID_ARGUMENT);

    cv_auth_session session;
    cv_auth_session_init(&session);
    CHECK(!session.authenticated);
    CHECK(cv_authenticate(&session, "scaffold-test") == CV_ERR_NOT_IMPLEMENTED);
    CHECK(!session.authenticated);
    CHECK(cv_auth_authorize(&session, "user:key", false) == CV_ERR_UNAUTHORIZED);
    CHECK(cv_auth_authorize(&session, "user:key", true) == CV_ERR_UNAUTHORIZED);

    cv_hashtable *table = NULL;
    CHECK(cv_hashtable_create(&table) == CV_ERR_NOT_IMPLEMENTED && table == NULL);
    const unsigned char *value = secret;
    size_t value_length = sizeof(secret);
    CHECK(cv_hashtable_get(table, "key", &value, &value_length) == CV_ERR_NOT_IMPLEMENTED);
    CHECK(value == NULL && value_length == 0);
    CHECK(cv_hashtable_set(table, "key", secret, sizeof(secret)) == CV_ERR_NOT_IMPLEMENTED);
    CHECK(cv_hashtable_delete(table, "key") == CV_ERR_NOT_IMPLEMENTED);
    cv_hashtable_destroy(table);
    CHECK(cv_persist_replay("./data", table) == CV_ERR_NOT_IMPLEMENTED);
    CHECK(cv_persist_snapshot("./data", table) == CV_ERR_NOT_IMPLEMENTED);
    CHECK(cv_audit_record("GET", CV_ERR_UNAUTHORIZED) == CV_ERR_NOT_IMPLEMENTED);

    cv_command command;
    CHECK(cv_parse_line((const unsigned char *)"GET key\n", 8, &command) == CV_ERR_NOT_IMPLEMENTED);
    CHECK(command.type == CV_CMD_UNKNOWN && command.arguments == NULL);
    CHECK(cv_parse_line(NULL, 0, &command) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_parse_line((const unsigned char *)"GET key", 7, &command) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_parse_line((const unsigned char *)"GET\0key\n", 8, &command) == CV_ERR_INVALID_ARGUMENT);
    unsigned char line[CV_MAX_LINE_BYTES + 1];
    memset(line, 'A', sizeof(line));
    line[CV_MAX_LINE_BYTES - 1] = '\n';
    CHECK(cv_parse_line(line, CV_MAX_LINE_BYTES, &command) == CV_ERR_NOT_IMPLEMENTED);
    CHECK(cv_parse_line(line, sizeof(line), &command) == CV_ERR_LIMIT);
    puts("Core scaffold: modules linked, bounds checked, access denied by default.");
    return EXIT_SUCCESS;
}
