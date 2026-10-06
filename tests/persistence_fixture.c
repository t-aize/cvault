/**
 * @file persistence_fixture.c
 * @brief Line-driven harness around the persistence API, used by test_persistence.py.
 *
 * This is a test harness, not a public protocol. Arguments:
 *
 *     persistence-fixture <data-dir> <key-file> [initial-epoch-ms]
 *
 * The first output line is the numeric status of cv_persist_open(). Afterwards
 * each stdin line is a command and each reply is one status line, optionally
 * followed by data:
 *
 *     SET <key> <hex|->     store a value (`-` means empty)
 *     DEL <key>             delete
 *     EXPIRE <key> <secs>   set a relative TTL
 *     GET <key>             prints "<status> <hex value>"
 *     TTL <key>             prints "<status> <seconds>"
 *     STATS                 prints "<status> <seq> <snapshot seq> <repaired> <failed>"
 *     SNAP / ASYNC / WAIT   synchronous, background start, wait for a snapshot
 *     COMPACT               drop the journal records covered by the snapshot
 *     SWEEP                 erase expired entries; prints "<status> <removed> <entries left>"
 *     BASE                  prints "<status> <journal baseline sequence>"
 *     POLL                  prints "<status> <done>"
 *     NOW <epoch-ms>        move the deterministic wall clock
 *     CRASH                 exit immediately without closing the store
 *     EXIT                  close the store and exit
 *
 * When compiled with CV_PERSIST_FAULT_TEST, `FAULT <n>` arms a one-shot fault:
 * 1 = fail the next sync, 2 = write half of the next record then fail,
 * 3 = fail the next table clone.
 */

#ifdef _MSC_VER
/* Test-only tokenization operates on bounded, owned input buffers. */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "cvault/config.h"
#include "cvault/crypto.h"
#include "cvault/persist.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef CV_PERSIST_FAULT_TEST
#include "persist_io.h"

/** Armed one-shot fault (0: none). */
int cv_test_fault;

cv_status cv_test_sync(FILE *file) {
    cv_status status = cv_io_sync(file);

    if (cv_test_fault == 1) {
        cv_test_fault = 0;

        return CV_ERR_IO;
    }

    return status;
}

cv_status cv_test_write(FILE *file, const void *bytes, size_t length) {
    if (cv_test_fault == 2) {
        cv_test_fault = 0;

        /* A torn write: only half of the bytes reach the file. */
        (void)cv_io_write(file, bytes, length / 2);

        return CV_ERR_IO;
    }

    return cv_io_write(file, bytes, length);
}

cv_status cv_test_clone(const cv_hashtable *table, cv_hashtable **out) {
    if (cv_test_fault == 3) {
        cv_test_fault = 0;
        *out = NULL;

        return CV_ERR_NO_MEMORY;
    }

    return cv_hashtable_clone(table, out);
}
#endif

/** @brief Wall clock whose value is the uint64_t that `context` points to. */
static cv_status fixed_wall(void *context, uint64_t *now) {
    *now = *(const uint64_t *)context;

    return CV_OK;
}

/** @brief Value of a lowercase hexadecimal digit, or -1. */
static int nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    return -1;
}

/* This is a test harness, not a public network protocol. Paths arrive via argv;
 * stdin commands exercise public storage APIs and deterministic epoch clocks. */
int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) {
        return EXIT_FAILURE;
    }

    unsigned char key[CV_PERSIST_KEY_BYTES];
    cv_status status = cv_persist_key_load(argv[2], key);
    uint64_t wall = argc == 4 ? strtoull(argv[3], NULL, 10) : UINT64_C(1000000);
    cv_persist_options options = {argv[1], key, sizeof(key), fixed_wall, &wall};
    cv_persist *store = NULL;

    if (status == CV_OK) {
        status = cv_persist_open(&options, &store);
    }

    cv_crypto_wipe(key, sizeof(key));

    printf("%d\n", (int)status);
    fflush(stdout);

    if (status != CV_OK) {
        return EXIT_FAILURE;
    }

    char *line = malloc(2 * CV_MAX_VALUE_BYTES + CV_MAX_KEY_BYTES + 128);
    unsigned char *bytes = malloc(CV_MAX_VALUE_BYTES);

    if (!line || !bytes) {
        free(line);
        free(bytes);

        (void)cv_persist_close(store);

        return EXIT_FAILURE;
    }

    while (fgets(line, (int)(2 * CV_MAX_VALUE_BYTES + CV_MAX_KEY_BYTES + 128), stdin)) {
        char *operation = strtok(line, " \r\n");
        char *name = strtok(NULL, " \r\n");
        char *argument = strtok(NULL, " \r\n");

        if (!operation) {
            break;
        }

        if (strcmp(operation, "EXIT") == 0) {
            break;
        }

        /* Simulate a power loss: no close, no flush, no cleanup. */
        if (strcmp(operation, "CRASH") == 0) {
            _Exit(EXIT_SUCCESS);
        }

        status = CV_ERR_INVALID_ARGUMENT;

        if (strcmp(operation, "SET") == 0 && name && argument) {
            /* Decode the hexadecimal argument into raw bytes. */
            size_t length = strcmp(argument, "-") == 0 ? 0 : strlen(argument) / 2;
            bool valid = length <= CV_MAX_VALUE_BYTES && (length == 0 || strlen(argument) % 2 == 0);

            for (size_t i = 0; valid && i < length; ++i) {
                int high = nibble(argument[i * 2]), low = nibble(argument[i * 2 + 1]);

                valid = high >= 0 && low >= 0;
                bytes[i] = (unsigned char)((high < 0 ? 0 : high) * 16 + (low < 0 ? 0 : low));
            }

            if (valid) {
                status = cv_persist_set(store, name, bytes, length);
            }
        } else if (strcmp(operation, "DEL") == 0) {
            status = cv_persist_delete(store, name);
        } else if (strcmp(operation, "EXPIRE") == 0 && argument) {
            status = cv_persist_expire(store, name, strtoll(argument, NULL, 10));
        } else if (strcmp(operation, "GET") == 0) {
            const unsigned char *value;
            size_t length;

            status = cv_persist_get(store, name, &value, &length);

            printf("%d ", (int)status);

            for (size_t i = 0; i < length; ++i) {
                printf("%02x", (unsigned int)value[i]);
            }

            puts("");
            fflush(stdout);
            continue;
        } else if (strcmp(operation, "TTL") == 0) {
            int64_t seconds;

            status = cv_persist_ttl(store, name, &seconds);

            printf("%d %" PRId64 "\n", (int)status, seconds);
            fflush(stdout);
            continue;
        } else if (strcmp(operation, "STATS") == 0) {
            cv_persist_stats stats;

            status = cv_persist_get_stats(store, &stats);

            printf("%d %" PRIu64 " %" PRIu64 " %d %d\n",
                   (int)status,
                   stats.sequence,
                   stats.snapshot_sequence,
                   (int)stats.repaired_tail,
                   (int)stats.failed);
            fflush(stdout);
            continue;
        } else if (strcmp(operation, "SWEEP") == 0) {
            size_t removed = 0;
            cv_hashtable_stats table = {0};

            status = cv_persist_purge_expired(store, &removed);

            (void)cv_hashtable_get_stats(cv_persist_table(store), &table);

            printf("%d %zu %zu\n", (int)status, removed, table.entries);
            fflush(stdout);
            continue;
        } else if (strcmp(operation, "COMPACT") == 0) {
            status = cv_persist_compact(store);
        } else if (strcmp(operation, "BASE") == 0) {
            cv_persist_stats stats;

            status = cv_persist_get_stats(store, &stats);

            printf("%d %" PRIu64 "\n", (int)status, stats.journal_baseline);
            fflush(stdout);
            continue;
        } else if (strcmp(operation, "SNAP") == 0) {
            status = cv_persist_snapshot(store);
        } else if (strcmp(operation, "ASYNC") == 0) {
            status = cv_persist_snapshot_start(store);
        } else if (strcmp(operation, "WAIT") == 0) {
            status = cv_persist_snapshot_wait(store);
        } else if (strcmp(operation, "POLL") == 0) {
            bool done;

            status = cv_persist_snapshot_poll(store, &done);

            printf("%d %d\n", (int)status, (int)done);
            fflush(stdout);
            continue;
        } else if (strcmp(operation, "NOW") == 0 && name) {
            wall = strtoull(name, NULL, 10);
            status = CV_OK;
        }
#ifdef CV_PERSIST_FAULT_TEST
        else if (strcmp(operation, "FAULT") == 0 && name) {
            cv_test_fault = atoi(name);
            status = CV_OK;
        }
#endif

        printf("%d\n", (int)status);
        fflush(stdout);
    }

    cv_crypto_wipe(bytes, CV_MAX_VALUE_BYTES);
    free(bytes);

    cv_crypto_wipe(line, 2 * CV_MAX_VALUE_BYTES + CV_MAX_KEY_BYTES + 128);
    free(line);

    status = cv_persist_close(store);

    return status == CV_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
