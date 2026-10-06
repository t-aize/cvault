/**
 * @file test_parser.c
 * @brief Complete validation of the request-line parser.
 *
 * Three layers of evidence:
 *  1. A table of explicit cases that documents the grammar: every command, every
 *     boundary of every limit and every kind of malformed input, with the exact
 *     status and fields expected.
 *  2. Exhaustive single-byte mutation and truncation of every valid line, compared
 *     with an independent reference implementation (parser_reference.c).
 *  3. A large pseudo-random sweep over grammar-shaped and arbitrary lines, again
 *     compared with the reference.
 */

#include "cvault/auth.h"
#include "cvault/config.h"
#include "cvault/parser.h"
#include "parser_reference.h"
#include "test_util.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** One explicit test case. */
typedef struct {
    const char *line;     /* Request including its terminator (length given separately). */
    size_t length;        /* Number of bytes of @p line. */
    cv_status status;     /* Expected status. */
    cv_command_type type; /* Expected command type on success. */
    const char *key;      /* Expected key on success (NULL: not checked). */
    const char *value;    /* Expected payload on success (NULL: not checked). */
    int64_t seconds;      /* Expected EXPIRE seconds. */
} parse_case;

#define LINE(text) text, sizeof(text) - 1

/** @brief Check one explicit case. */
static int check_case(const parse_case *test) {
    cv_command command;
    cv_status status = cv_parse_line((const unsigned char *)test->line, test->length, &command);

    if (status != test->status) {
        fprintf(stderr, "case %.30s: status %d, expected %d\n", test->line, status, test->status);

        return EXIT_FAILURE;
    }

    if (status != CV_OK) {
        /* Every failure leaves a fully zeroed command. */
        cv_command zero = {0};

        CHECK(memcmp(&command, &zero, sizeof(zero)) == 0);

        return EXIT_SUCCESS;
    }

    CHECK(command.type == test->type);
    CHECK(command.seconds == test->seconds);

    if (test->key) {
        CHECK(command.key_length == strlen(test->key));
        CHECK(memcmp(command.key, test->key, command.key_length) == 0);
    }

    if (test->value) {
        CHECK(command.value_length == strlen(test->value));
        CHECK(memcmp(command.value, test->value, command.value_length) == 0);
    }

    return EXIT_SUCCESS;
}

/** @brief The explicit grammar table. */
static int explicit_cases(void) {
    const parse_case cases[] = {
        /* Commands without arguments. */
        {LINE("PING\n"), CV_OK, CV_CMD_PING, NULL, NULL, 0},
        {LINE("PING\r\n"), CV_OK, CV_CMD_PING, NULL, NULL, 0},
        {LINE("QUIT\n"), CV_OK, CV_CMD_QUIT, NULL, NULL, 0},
        {LINE("PING \n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("PING x\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("QUIT now\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},

        /* Commands with a key only. */
        {LINE("GET key\n"), CV_OK, CV_CMD_GET, "key", NULL, 0},
        {LINE("GET key\r\n"), CV_OK, CV_CMD_GET, "key", NULL, 0},
        {LINE("DEL a:b-c_d.e\n"), CV_OK, CV_CMD_DEL, "a:b-c_d.e", NULL, 0},
        {LINE("TTL !~\n"), CV_OK, CV_CMD_TTL, "!~", NULL, 0},
        {LINE("GET\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("GET \n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("GET  key\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("GET key \n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("GET key extra\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("DEL a b\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("TTL\tkey\n"), CV_ERR_NOT_IMPLEMENTED, 0, NULL, NULL, 0},
        {LINE("GET k\x01y\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("GET k\x7f\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("GET k\xc3\xa9\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},

        /* SET: payload is everything after exactly one separator. */
        {LINE("SET key value\n"), CV_OK, CV_CMD_SET, "key", "value", 0},
        {LINE("SET key a value with spaces\n"), CV_OK, CV_CMD_SET, "key", "a value with spaces", 0},
        {LINE("SET key  two leading\n"), CV_OK, CV_CMD_SET, "key", " two leading", 0},
        {LINE("SET key trailing \n"), CV_OK, CV_CMD_SET, "key", "trailing ", 0},
        {LINE("SET key \n"), CV_OK, CV_CMD_SET, "key", "", 0},
        {LINE("SET key \r\n"), CV_OK, CV_CMD_SET, "key", "", 0},
        {LINE("SET key\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("SET  value\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("SET\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},

        /* EXPIRE: strict signed decimal. */
        {LINE("EXPIRE key 10\n"), CV_OK, CV_CMD_EXPIRE, "key", "10", 10},
        {LINE("EXPIRE key 0\n"), CV_OK, CV_CMD_EXPIRE, "key", "0", 0},
        {LINE("EXPIRE key -1\n"), CV_OK, CV_CMD_EXPIRE, "key", "-1", -1},
        {LINE("EXPIRE key 007\n"), CV_OK, CV_CMD_EXPIRE, "key", "007", 7},
        {LINE("EXPIRE key 9223372036854775807\n"), CV_OK, CV_CMD_EXPIRE, "key", NULL, INT64_MAX},
        {LINE("EXPIRE key -9223372036854775808\n"), CV_OK, CV_CMD_EXPIRE, "key", NULL, INT64_MIN},
        {LINE("EXPIRE key 9223372036854775808\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("EXPIRE key -9223372036854775809\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("EXPIRE key 18446744073709551616\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("EXPIRE key +1\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("EXPIRE key -\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("EXPIRE key --1\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("EXPIRE key 1.5\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("EXPIRE key 1e3\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("EXPIRE key 0x10\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("EXPIRE key 1 2\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("EXPIRE key  1\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("EXPIRE key 1 \n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("EXPIRE key \n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("EXPIRE key\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},

        /* AUTH: user name up to 64, non-empty password up to 1024. */
        {LINE("AUTH alice secret\n"), CV_OK, CV_CMD_AUTH, "alice", "secret", 0},
        {LINE("AUTH alice a password with spaces\n"),
         CV_OK,
         CV_CMD_AUTH,
         "alice",
         "a password with spaces",
         0},
        {LINE("AUTH alice\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("AUTH alice \n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("AUTH  secret\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("AUTH\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},

        /* Reserved and unknown commands. */
        {LINE("EXPORT x\n"), CV_ERR_NOT_IMPLEMENTED, 0, NULL, NULL, 0},
        {LINE("PURGE\n"), CV_ERR_NOT_IMPLEMENTED, 0, NULL, NULL, 0},
        {LINE("HELLO\n"), CV_ERR_NOT_IMPLEMENTED, 0, NULL, NULL, 0},
        {LINE("get key\n"), CV_ERR_NOT_IMPLEMENTED, 0, NULL, NULL, 0},
        {LINE("Get key\n"), CV_ERR_NOT_IMPLEMENTED, 0, NULL, NULL, 0},
        {LINE("GETS key\n"), CV_ERR_NOT_IMPLEMENTED, 0, NULL, NULL, 0},
        {LINE("GE key\n"), CV_ERR_NOT_IMPLEMENTED, 0, NULL, NULL, 0},
        {LINE(" GET key\n"), CV_ERR_NOT_IMPLEMENTED, 0, NULL, NULL, 0},

        /* Framing. */
        {LINE("GET key"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("\r\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("GET key\r\r\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("GET k\rey\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("GET key\nGET key\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {LINE("GET key\n\n"), CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {"GET k\0y\n", 8, CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
        {"\0\n", 2, CV_ERR_INVALID_ARGUMENT, 0, NULL, NULL, 0},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        CHECK(check_case(&cases[i]) == EXIT_SUCCESS);
    }

    return EXIT_SUCCESS;
}

/** @brief Build "<prefix><count x 'a'><suffix>" in @p out and return its length. */
static size_t build(unsigned char *out, const char *prefix, size_t count, const char *suffix) {
    size_t prefix_length = strlen(prefix), suffix_length = strlen(suffix);

    memcpy(out, prefix, prefix_length);
    memset(out + prefix_length, 'a', count);
    memcpy(out + prefix_length + count, suffix, suffix_length);

    return prefix_length + count + suffix_length;
}

/** @brief Each size limit accepts its maximum and refuses one more. */
static int size_boundaries(void) {
    static unsigned char line[CV_MAX_LINE_BYTES + 16];
    cv_command command;
    size_t length;

    /* Keys: 256 bytes for ordinary commands, 64 for the AUTH user name. */
    length = build(line, "GET ", CV_MAX_KEY_BYTES, "\n");

    CHECK(cv_parse_line(line, length, &command) == CV_OK && command.key_length == CV_MAX_KEY_BYTES);

    length = build(line, "GET ", CV_MAX_KEY_BYTES + 1, "\n");

    CHECK(cv_parse_line(line, length, &command) == CV_ERR_INVALID_ARGUMENT);

    length = build(line, "AUTH ", CV_AUTH_USER_BYTES, " pw\n");

    CHECK(cv_parse_line(line, length, &command) == CV_OK &&
          command.key_length == CV_AUTH_USER_BYTES);

    length = build(line, "AUTH ", CV_AUTH_USER_BYTES + 1, " pw\n");

    CHECK(cv_parse_line(line, length, &command) == CV_ERR_INVALID_ARGUMENT);

    /* Passwords: 1..1024 bytes. */
    length = build(line, "AUTH u ", CV_AUTH_PASSWORD_BYTES, "\n");

    CHECK(cv_parse_line(line, length, &command) == CV_OK &&
          command.value_length == CV_AUTH_PASSWORD_BYTES);

    length = build(line, "AUTH u ", CV_AUTH_PASSWORD_BYTES + 1, "\n");

    CHECK(cv_parse_line(line, length, &command) == CV_ERR_INVALID_ARGUMENT);

    /* Values: up to 65536 bytes; one more is a limit error, not a syntax error. */
    length = build(line, "SET k ", CV_MAX_VALUE_BYTES, "\n");

    CHECK(cv_parse_line(line, length, &command) == CV_OK &&
          command.value_length == CV_MAX_VALUE_BYTES);

    length = build(line, "SET k ", CV_MAX_VALUE_BYTES + 1, "\n");

    CHECK(cv_parse_line(line, length, &command) == CV_ERR_LIMIT);

    /* The whole line: CV_MAX_LINE_BYTES including the terminator is the ceiling. */
    memset(line, 'x', sizeof(line));

    line[CV_MAX_LINE_BYTES - 1] = '\n';

    CHECK(cv_parse_line(line, CV_MAX_LINE_BYTES, &command) == CV_ERR_NOT_IMPLEMENTED);
    CHECK(cv_parse_line(line, CV_MAX_LINE_BYTES + 1, &command) == CV_ERR_LIMIT);

    /* Invalid arguments to the function itself. */
    CHECK(cv_parse_line((const unsigned char *)"PING\n", 5, NULL) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_parse_line(NULL, 5, &command) == CV_ERR_INVALID_ARGUMENT);
    CHECK(cv_parse_line((const unsigned char *)"PING\n", 0, &command) == CV_ERR_INVALID_ARGUMENT);

    return EXIT_SUCCESS;
}

/** Seed lines mutated by the exhaustive sweep. */
static const char *const seeds[] = {
    "PING\n",
    "QUIT\r\n",
    "GET key\n",
    "DEL a:b\n",
    "TTL key\r\n",
    "SET key some value\n",
    "SET key \n",
    "EXPIRE key 120\n",
    "EXPIRE key -9223372036854775808\n",
    "AUTH alice a password\n",
};

/** @brief Compare against the reference, reporting the first disagreement. */
static int agree(const unsigned char *line, size_t length) {
    char why[160];

    if (!reference_agrees(line, length, why, sizeof(why))) {
        fprintf(stderr,
                "parser disagrees with reference on %zu bytes (first: %02x): %s\n",
                length,
                length ? line[0] : 0,
                why);

        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/** @brief Every byte value at every position, and every truncation, of every seed. */
static int exhaustive_mutations(void) {
    unsigned char line[128];

    for (size_t s = 0; s < sizeof(seeds) / sizeof(seeds[0]); ++s) {
        size_t length = strlen(seeds[s]);

        memcpy(line, seeds[s], length);

        CHECK(agree(line, length) == EXIT_SUCCESS);

        for (size_t position = 0; position < length; ++position) {
            unsigned char original = line[position];

            for (unsigned int value = 0; value < 256; ++value) {
                line[position] = (unsigned char)value;

                CHECK(agree(line, length) == EXIT_SUCCESS);
            }

            line[position] = original;
        }

        /* Truncations and one-byte insertions. */
        for (size_t cut = 0; cut <= length; ++cut) {
            CHECK(agree(line, cut) == EXIT_SUCCESS);
        }

        for (size_t position = 0; position <= length; ++position) {
            for (unsigned int value = 0; value < 256; value += 5) {
                unsigned char longer[130];

                memcpy(longer, line, position);

                longer[position] = (unsigned char)value;

                memcpy(longer + position + 1, line + position, length - position);

                CHECK(agree(longer, length + 1) == EXIT_SUCCESS);
            }
        }
    }

    return EXIT_SUCCESS;
}

/** xorshift64* generator: tiny, fast and reproducible across platforms. */
static uint64_t next_random(uint64_t *state) {
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;

    return *state * UINT64_C(2685821657736338717);
}

/** @brief Pick a pseudo-random fragment that is likely to matter to the grammar. */
static size_t fragment(uint64_t *state, unsigned char *out) {
    static const char *const pieces[] = {
        "AUTH",
        "SET",
        "GET",
        "DEL",
        "EXPIRE",
        "TTL",
        "EXPORT",
        "PURGE",
        "PING",
        "QUIT",
        " ",
        "  ",
        "\n",
        "\r\n",
        "\r",
        "key",
        "alice:x",
        "-",
        "0",
        "1",
        "9223372036854775807",
        "9223372036854775808",
        "-9223372036854775808",
        "+1",
        "\t",
        "\x01",
        "\x7f",
        "\xff",
    };
    uint64_t pick = next_random(state);

    if (pick % 4 == 0) {
        out[0] = (unsigned char)(next_random(state) & 0xff);

        return 1;
    }

    const char *piece = pieces[pick % (sizeof(pieces) / sizeof(pieces[0]))];
    size_t length = strlen(piece);

    memcpy(out, piece, length);

    return length;
}

/** @brief Random lines assembled from grammar fragments and from arbitrary bytes. */
static int random_sweep(uint64_t iterations) {
    uint64_t state = UINT64_C(0x9e3779b97f4a7c15);
    unsigned char line[512];

    for (uint64_t i = 0; i < iterations; ++i) {
        size_t length = 0;
        unsigned int count = (unsigned int)(next_random(&state) % 8);

        for (unsigned int part = 0; part <= count && length < 400; ++part) {
            length += fragment(&state, line + length);
        }

        /* Most lines end like real requests, some are left unterminated. */
        if (next_random(&state) % 8 != 0 && length < sizeof(line) - 1) {
            line[length++] = '\n';
        }

        CHECK(agree(line, length) == EXIT_SUCCESS);
    }

    return EXIT_SUCCESS;
}

int main(void) {
    CHECK(explicit_cases() == EXIT_SUCCESS);
    CHECK(size_boundaries() == EXIT_SUCCESS);
    CHECK(exhaustive_mutations() == EXIT_SUCCESS);
    CHECK(random_sweep(400000) == EXIT_SUCCESS);

    puts("Parser: grammar table, size limits, exhaustive mutations and random sweep match the "
         "reference.");

    return EXIT_SUCCESS;
}
