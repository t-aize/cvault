#include "cvault/auth.h"
#include "cvault/config.h"
#include "cvault/crypto.h"
#include "persist_io.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CV_AUTH_MAX_USERS 32
#define CV_AUTH_MAX_RULES 256
#define CV_AUTH_MEMORY_BYTES ((size_t)67108864)
#define CV_AUTH_PASSES 2ULL

/** Fixed-size records keep policy loading and session lookup strictly bounded. */
typedef struct {
    char name[CV_AUTH_USER_BYTES + 1];
    char hash[CV_AUTH_HASH_BYTES];
} auth_user;

typedef struct {
    size_t user;
    unsigned int permissions;
    char prefix[CV_MAX_KEY_BYTES + 1];
} auth_rule;

struct cv_auth_policy {
    auth_user users[CV_AUTH_MAX_USERS];
    auth_rule rules[CV_AUTH_MAX_RULES];
    size_t user_count, rule_count;
    char dummy[CV_AUTH_HASH_BYTES];
};

static bool valid_name(const char *name) {
    if (!name || !*name) {
        return false;
    }
    for (size_t n = 0; name[n]; ++n) {
        unsigned char character = (unsigned char)name[n];
        if (n == CV_AUTH_USER_BYTES ||
            !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
              (character >= '0' && character <= '9') || character == '_' || character == '-' ||
              character == '.')) {
            return false;
        }
    }
    return true;
}

cv_status
cv_auth_hash_password(const unsigned char *password, size_t length, char out[CV_AUTH_HASH_BYTES]) {
    if (!out) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    memset(out, 0, CV_AUTH_HASH_BYTES);
    if (!password || !length || length > CV_AUTH_PASSWORD_BYTES) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    if (cv_crypto_init() != CV_OK) {
        return CV_ERR_CRYPTO;
    }
    int result = crypto_pwhash_str_alg(out,
                                       (const char *)password,
                                       (unsigned long long)length,
                                       CV_AUTH_PASSES,
                                       CV_AUTH_MEMORY_BYTES,
                                       crypto_pwhash_ALG_ARGON2ID13);
    if (result != 0) {
        cv_crypto_wipe(out, CV_AUTH_HASH_BYTES);
        return CV_ERR_CRYPTO;
    }
    return CV_OK;
}

/* Unknown users take the same expensive verification path through a random
 * dummy hash. This reduces account-enumeration timing differences; lookup and
 * malformed-input handling are not claimed to be perfectly constant-time. */
static size_t find_user(const cv_auth_policy *policy, const char *name) {
    for (size_t i = 0; i < policy->user_count; ++i) {
        if (strcmp(policy->users[i].name, name) == 0) {
            return i;
        }
    }
    return policy->user_count;
}

/* Validate the exact cost before verification: a PHC string controls resources. */
static bool valid_hash(const char *hash) {
    const char prefix[] = "$argon2id$v=19$m=65536,t=2,p=1$";
    return strlen(hash) < CV_AUTH_HASH_BYTES && strncmp(hash, prefix, sizeof(prefix) - 1) == 0 &&
           crypto_pwhash_str_needs_rehash(hash, CV_AUTH_PASSES, CV_AUTH_MEMORY_BYTES) == 0;
}

/* Independent bits make the grant union explicit: write never implies read. */
enum {
    CV_AUTH_READ = 1u,
    CV_AUTH_WRITE = 2u
};

static unsigned int parse_permissions(const char *text) {
    if (strcmp(text, "r") == 0) {
        return CV_AUTH_READ;
    }
    if (strcmp(text, "w") == 0) {
        return CV_AUTH_WRITE;
    }
    if (strcmp(text, "rw") == 0) {
        return CV_AUTH_READ | CV_AUTH_WRITE;
    }
    return 0;
}

/* Records use explicit single-space separators. No wildcard grammar is
 * supported: an ACL prefix is always matched literally and case-sensitively. */
static cv_status parse_policy_record(cv_auth_policy *policy, char *line) {
    if (!*line || *line == '#') {
        return CV_OK;
    }
    char *tokens[5] = {0};
    size_t token_count = 0;
    char *cursor = line;
    while (*cursor && token_count < 5) {
        tokens[token_count++] = cursor;
        while (*cursor && *cursor != ' ') {
            ++cursor;
        }
        if (*cursor) {
            *cursor++ = 0;
        }
    }
    if (token_count == 3 && strcmp(tokens[0], "user") == 0 && valid_name(tokens[1]) &&
        policy->user_count < CV_AUTH_MAX_USERS &&
        find_user(policy, tokens[1]) == policy->user_count && valid_hash(tokens[2])) {
        auth_user *entry = &policy->users[policy->user_count++];
        /* Names and PHC strings were bounded before copying, including NUL. */
        memcpy(entry->name, tokens[1], strlen(tokens[1]) + 1);
        memcpy(entry->hash, tokens[2], strlen(tokens[2]) + 1);
    } else if (token_count == 4 && strcmp(tokens[0], "allow") == 0 && valid_name(tokens[1]) &&
               policy->rule_count < CV_AUTH_MAX_RULES && *tokens[3] &&
               strlen(tokens[3]) <= CV_MAX_KEY_BYTES) {
        size_t index = find_user(policy, tokens[1]);
        unsigned int permissions = parse_permissions(tokens[2]);
        if (index == policy->user_count || !permissions || strchr(tokens[3], '*') ||
            strchr(tokens[3], '\r')) {
            return CV_ERR_CORRUPT;
        }
        auth_rule *entry = &policy->rules[policy->rule_count++];
        entry->user = index;
        entry->permissions = permissions;
        memcpy(entry->prefix, tokens[3], strlen(tokens[3]) + 1);
    } else {
        return CV_ERR_CORRUPT;
    }
    return CV_OK;
}

cv_status cv_auth_policy_load(const char *path, cv_auth_policy **out) {
    if (!out) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    if (!path || !*path) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    if (cv_crypto_init() != CV_OK) {
        return CV_ERR_CRYPTO;
    }
    FILE *file = NULL;
    cv_status status = cv_io_open(path, false, false, false, &file);
    if (status != CV_OK) {
        return status;
    }
    cv_auth_policy *policy = calloc(1, sizeof(*policy));
    if (!policy) {
        fclose(file);
        return CV_ERR_NO_MEMORY;
    }
    char line[512];
    size_t line_length = 0, file_bytes = 0;
    bool header_seen = false;
    int character;
    while ((character = fgetc(file)) != EOF) {
        if (++file_bytes > 131072 || character == 0 ||
            (character != '\n' && character != '\r' && (character < 32 || character > 126))) {
            status = CV_ERR_CORRUPT;
            break;
        }
        if (character != '\n') {
            if (line_length == sizeof(line) - 1) {
                status = CV_ERR_LIMIT;
                break;
            }
            line[line_length++] = (char)character;
            continue;
        }
        if (line_length && line[line_length - 1] == '\r') {
            --line_length;
        }
        line[line_length] = 0;
        line_length = 0;
        if (!header_seen) {
            if (strcmp(line, "CVAULT-SECURITY-1") != 0) {
                status = CV_ERR_CORRUPT;
                break;
            }
            header_seen = true;
            continue;
        }
        status = parse_policy_record(policy, line);
        if (status != CV_OK) {
            break;
        }
    }
    if (ferror(file)) {
        status = CV_ERR_IO;
    }
    if (line_length || !header_seen || !policy->user_count) {
        status = CV_ERR_CORRUPT;
    }
    if (fclose(file) != 0 && status == CV_OK) {
        status = CV_ERR_IO;
    }
    cv_crypto_wipe(line, sizeof(line));
    if (status == CV_OK) {
        unsigned char dummy[32];
        randombytes_buf(dummy, sizeof(dummy));
        status = cv_auth_hash_password(dummy, sizeof(dummy), policy->dummy);
        cv_crypto_wipe(dummy, sizeof(dummy));
    }
    if (status != CV_OK) {
        cv_auth_policy_destroy(policy);
        return status;
    }
    *out = policy;
    return CV_OK;
}

void cv_auth_policy_destroy(cv_auth_policy *policy) {
    if (policy) {
        cv_crypto_wipe(policy, sizeof(*policy));
        free(policy);
    }
}

void cv_auth_session_init(cv_auth_session *session) {
    if (session) {
        cv_crypto_wipe(session, sizeof(*session));
    }
}

cv_status cv_authenticate(cv_auth_session *session,
                          const cv_auth_policy *policy,
                          const char *username,
                          const unsigned char *password,
                          size_t length) {
    cv_auth_session_init(session);
    if (!session || !policy || !username || !password || !length ||
        length > CV_AUTH_PASSWORD_BYTES) {
        return CV_ERR_INVALID_ARGUMENT;
    }
    /* Never retain the supplied password or the untrusted candidate identity. */
    size_t index = valid_name(username) ? find_user(policy, username) : policy->user_count;
    const char *hash = index < policy->user_count ? policy->users[index].hash : policy->dummy;
    int result = crypto_pwhash_str_verify(hash, (const char *)password, (unsigned long long)length);
    if (result != 0 || index == policy->user_count) {
        return CV_ERR_UNAUTHORIZED;
    }
    session->authenticated = true;
    session->policy = policy;
    session->user = index;
    return CV_OK;
}

const char *cv_auth_identity(const cv_auth_session *session) {
    return session && session->authenticated && session->policy &&
                   session->user < session->policy->user_count
               ? session->policy->users[session->user].name
               : "anonymous";
}

cv_status cv_auth_authorize(const cv_auth_session *session, const char *key, bool write) {
    if (!session || !session->authenticated || !session->policy || !key || !*key ||
        session->user >= session->policy->user_count) {
        return CV_ERR_UNAUTHORIZED;
    }
    /* Match the table's bounded key contract even for direct C API callers. */
    size_t length = 0;
    while (length <= CV_MAX_KEY_BYTES && key[length]) {
        ++length;
    }
    if (length > CV_MAX_KEY_BYTES) {
        return CV_ERR_UNAUTHORIZED;
    }
    /* Grants are a union of independent read/write bits. No grant, no access;
     * write permission never implies permission to read the value or its TTL. */
    const cv_auth_policy *policy = session->policy;
    for (size_t i = 0; i < policy->rule_count; ++i) {
        const auth_rule *entry = &policy->rules[i];
        if (entry->user == session->user &&
            (entry->permissions & (write ? CV_AUTH_WRITE : CV_AUTH_READ)) &&
            strncmp(key, entry->prefix, strlen(entry->prefix)) == 0) {
            return CV_OK;
        }
    }
    return CV_ERR_UNAUTHORIZED;
}
