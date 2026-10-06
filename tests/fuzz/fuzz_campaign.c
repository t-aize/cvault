/**
 * @file fuzz_campaign.c
 * @brief Portable in-process fuzzing campaign with oracles, runnable anywhere.
 *
 * AFL++ (see docs/fuzzing.md) needs a Linux or macOS host. This program applies
 * the same idea (mutate valid inputs, feed the code, watch for crashes) with
 * stronger checks, on every platform and under every sanitizer, and it is
 * deterministic: a seed reproduces a run exactly. Four targets:
 *
 *  - parser:  mutated request lines and lines built on every size limit; the
 *             production parser must agree with the independent reference
 *             implementation on every single input.
 *  - codec:   encrypted record streams with bytes flipped, inserted, removed or
 *             duplicated; whatever is accepted must be an exact prefix of what
 *             was written (nothing forged, reordered or altered gets through).
 *  - policy:  mutated security policy files; loading must never crash, and any
 *             policy it accepts must deny access to an unauthenticated session.
 *  - service: random request lines sent to the complete security service; every
 *             reply is checked against a model of the expected storage and ACL
 *             behaviour, the service must never fail, and the audit log written
 *             meanwhile must authenticate completely afterwards.
 *
 * Usage: fuzz-campaign [--iterations N] [--seed S] [--target NAME]...
 *                      [--corpus DIR] [--scratch DIR]
 */

#include "cvault/audit.h"
#include "cvault/auth.h"
#include "cvault/config.h"
#include "cvault/crypto.h"
#include "cvault/parser.h"
#include "cvault/persist.h"
#include "parser_reference.h"
#include "persist_codec.h"
#include "persist_io.h"
#include "security_service.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** Maximum size of a mutated buffer. */
#define BUFFER_BYTES 4096

/** Failure helper: print the context, then make the calling function return false. */
#define FAIL(...)                                                                                  \
    do {                                                                                           \
        fprintf(stderr, "FUZZ FAILURE (%s:%d) ", __FILE__, __LINE__);                              \
        fprintf(stderr, __VA_ARGS__);                                                              \
        fprintf(stderr, "\n");                                                                     \
        return false;                                                                              \
    } while (0)

/** Campaign state shared by all targets. */
typedef struct {
    uint64_t iterations;
    uint64_t seed;
    uint64_t rng;
    const char *corpus;
    const char *scratch;
} campaign;

/** @brief xorshift64* generator: tiny, fast and identical on every platform. */
static uint64_t random64(campaign *run) {
    run->rng ^= run->rng >> 12;
    run->rng ^= run->rng << 25;
    run->rng ^= run->rng >> 27;

    return run->rng * UINT64_C(2685821657736338717);
}

/** @brief Uniform value in [0, bound). */
static size_t below(campaign *run, size_t bound) {
    return bound ? (size_t)(random64(run) % bound) : 0;
}

/** Strings that tend to sit on grammar boundaries. */
static const char *const interesting[] = {
    "AUTH ",
    "SET ",
    "GET ",
    "DEL ",
    "EXPIRE ",
    "TTL ",
    "EXPORT ",
    "PURGE ",
    "PING",
    "QUIT",
    " ",
    "  ",
    "\n",
    "\r\n",
    "\r",
    "\t",
    "-",
    "0",
    "9223372036854775807",
    "-9223372036854775808",
    "99999999999999999999",
    "k:1",
    "\xff",
    "\x7f",
    "\x01",
};

/**
 * @brief Apply one to four random mutations to a buffer.
 *
 * @return The new length (never above @p capacity).
 */
static size_t mutate(campaign *run, unsigned char *buffer, size_t length, size_t capacity) {
    unsigned int rounds = 1 + (unsigned int)below(run, 4);

    for (unsigned int round = 0; round < rounds; ++round) {
        switch (below(run, 9)) {
            case 0:
                if (length) {
                    buffer[below(run, length)] ^= (unsigned char)(1u << below(run, 8));
                }
                break;

            case 1:
                if (length) {
                    buffer[below(run, length)] = (unsigned char)below(run, 256);
                }
                break;

            case 2:
                if (length) {
                    static const unsigned char bytes[] = {0, '\n', '\r', ' ', 0xff, 0x7f, '-', '0'};

                    buffer[below(run, length)] = bytes[below(run, sizeof(bytes))];
                }
                break;

            case 3:
                if (length) {
                    size_t start = below(run, length);
                    size_t count = 1 + below(run, 8);

                    if (start + count > length) {
                        count = length - start;
                    }

                    memmove(buffer + start, buffer + start + count, length - start - count);

                    length -= count;
                }
                break;

            case 4: {
                size_t count = 1 + below(run, 8);

                if (length + count <= capacity) {
                    size_t position = below(run, length + 1);

                    memmove(buffer + position + count, buffer + position, length - position);

                    for (size_t i = 0; i < count; ++i) {
                        buffer[position + i] = (unsigned char)below(run, 256);
                    }

                    length += count;
                }
                break;
            }

            case 5:
                if (length) {
                    size_t start = below(run, length);
                    size_t count = 1 + below(run, 16);

                    if (start + count > length) {
                        count = length - start;
                    }

                    if (length + count <= capacity) {
                        size_t position = below(run, length + 1);

                        memmove(buffer + position + count, buffer + position, length - position);

                        /* The source moved if the insertion point was before it. */
                        size_t source = position <= start ? start + count : start;

                        memmove(buffer + position, buffer + source, count);

                        length += count;
                    }
                }
                break;

            case 6:
                if (length > 1) {
                    size_t a = below(run, length), b = below(run, length);
                    unsigned char swap = buffer[a];

                    buffer[a] = buffer[b];
                    buffer[b] = swap;
                }
                break;

            case 7:
                if (length) {
                    length = below(run, length + 1);
                }
                break;

            default: {
                const char *text =
                    interesting[below(run, sizeof(interesting) / sizeof(interesting[0]))];
                size_t count = strlen(text);

                if (length + count <= capacity) {
                    size_t position = below(run, length + 1);

                    memmove(buffer + position + count, buffer + position, length - position);
                    memcpy(buffer + position, text, count);

                    length += count;
                }
                break;
            }
        }
    }

    return length;
}

/** Seed lines used when the corpus directory cannot be read. */
static const char *const builtin_seeds[] = {
    "PING\n",
    "GET key\n",
    "SET key value\n",
    "EXPIRE key 100\n",
    "TTL key\n",
    "DEL key\n",
    "AUTH alice password\n",
};

/** Seeds loaded from the corpus directory (or the built-in ones). */
typedef struct {
    unsigned char data[16][BUFFER_BYTES / 4];
    size_t length[16];
    size_t count;
} seed_set;

/** @brief Load the corpus files; fall back to built-in seeds when none is found. */
static void load_seeds(const char *corpus, seed_set *seeds) {
    static const char *const names[] = {
        "auth.txt", "expire.txt", "get.txt", "ping.txt", "set.txt", "ttl.txt"};

    seeds->count = 0;

    for (size_t i = 0; corpus && i < sizeof(names) / sizeof(names[0]); ++i) {
        char *path = cv_io_path(corpus, names[i]);
        FILE *file = path ? fopen(path, "rb") : NULL;

        free(path);

        if (!file) {
            continue;
        }

        size_t length = fread(seeds->data[seeds->count], 1, sizeof(seeds->data[0]), file);

        fclose(file);

        if (length) {
            seeds->length[seeds->count++] = length;
        }
    }

    if (seeds->count != 0) {
        return;
    }

    for (size_t i = 0; i < sizeof(builtin_seeds) / sizeof(builtin_seeds[0]); ++i) {
        size_t length = strlen(builtin_seeds[i]);

        memcpy(seeds->data[seeds->count], builtin_seeds[i], length);

        seeds->length[seeds->count++] = length;
    }
}

/**
 * @brief Build a request whose key and payload sizes sit on the grammar's limits.
 *
 * Plain mutation of short seeds practically never reaches a 257 byte key or a
 * 65537 byte value, so these boundaries are generated directly.
 */
static size_t boundary_line(campaign *run, unsigned char *buffer) {
    static const size_t key_sizes[] = {1, 2, 63, 64, 65, 255, 256, 257, 258};
    static const size_t payload_sizes[] = {0, 1, 1023, 1024, 1025, 65535, 65536, 65537};
    static const char *const commands[] = {
        "GET", "DEL", "TTL", "SET", "AUTH", "EXPIRE", "EXPORT", "PURGE"};
    const char *command = commands[below(run, sizeof(commands) / sizeof(commands[0]))];
    size_t key = key_sizes[below(run, sizeof(key_sizes) / sizeof(key_sizes[0]))];
    size_t payload = payload_sizes[below(run, sizeof(payload_sizes) / sizeof(payload_sizes[0]))];
    size_t length = strlen(command);

    memcpy(buffer, command, length);

    buffer[length++] = ' ';

    memset(buffer + length, 'k', key);

    length += key;

    if (strcmp(command, "SET") == 0 || strcmp(command, "AUTH") == 0 || below(run, 6) == 0) {
        buffer[length++] = ' ';

        memset(buffer + length, 'v', payload);

        length += payload;
    } else if (strcmp(command, "EXPIRE") == 0) {
        const char *seconds = below(run, 2) ? " 9223372036854775807" : " -1";
        size_t count = strlen(seconds);

        memcpy(buffer + length, seconds, count);

        length += count;
    }

    /* Most lines are terminated (LF or CRLF); some are left unfinished. */
    if (below(run, 8) != 0) {
        if (below(run, 4) == 0) {
            buffer[length++] = '\r';
        }

        buffer[length++] = '\n';
    }

    return length;
}

/** @brief Production parser versus reference on mutated seeds and size boundaries. */
static bool fuzz_parser(campaign *run) {
    static unsigned char buffer[CV_MAX_LINE_BYTES + 64];
    seed_set seeds;
    uint64_t accepted = 0;
    char why[160];

    load_seeds(run->corpus, &seeds);

    for (uint64_t i = 0; i < run->iterations; ++i) {
        size_t length;

        if (below(run, 6) == 0) {
            length = boundary_line(run, buffer);
        } else if (below(run, 400) == 0) {
            /* Lines around the global size ceiling, with a plausible prefix. */
            length = CV_MAX_LINE_BYTES - 3 + below(run, 7);

            memset(buffer, 'v', length);
            memcpy(buffer, "SET key ", 8);

            if (below(run, 4)) {
                buffer[length - 1] = '\n';
            }
        } else {
            size_t pick = below(run, seeds.count);

            length = seeds.length[pick];

            memcpy(buffer, seeds.data[pick], length);

            if (below(run, 3) == 0) {
                /* Splice the tail of another seed to cross command boundaries. */
                size_t other = below(run, seeds.count);
                size_t cut = below(run, length + 1);
                size_t tail = below(run, seeds.length[other] + 1);

                memcpy(buffer + cut, seeds.data[other] + (seeds.length[other] - tail), tail);

                length = cut + tail;
            }

            if (below(run, 8) != 0) {
                length = mutate(run, buffer, length, BUFFER_BYTES);
            }
        }

        if (!reference_agrees(buffer, length, why, sizeof(why))) {
            FAIL("parser disagrees with reference (iteration %" PRIu64 ", %zu bytes): %s",
                 i,
                 length,
                 why);
        }

        cv_command command;

        if (cv_parse_line(length ? buffer : NULL, length, &command) == CV_OK) {
            ++accepted;
        }
    }

    printf("  parser : %" PRIu64 " inputs, %" PRIu64 " accepted, all identical to the reference\n",
           run->iterations,
           accepted);

    return true;
}

/** One record as written to the stream, kept to verify what is read back. */
typedef struct {
    unsigned int operation;
    char key[24];
    unsigned char value[48];
    size_t value_length;
    uint64_t expiry;
} written_record;

/** @brief Read a whole stdio file into @p buffer; returns its size. */
static size_t slurp(FILE *file, unsigned char *buffer, size_t capacity) {
    if (fflush(file) != 0 || fseek(file, 0, SEEK_SET) != 0) {
        return 0;
    }

    return fread(buffer, 1, capacity, file);
}

/** @brief Compare a decoded record with the one that was written. */
static bool same_record(const cv_disk_record *record, const written_record *original) {
    return record->operation == original->operation && strcmp(record->key, original->key) == 0 &&
           record->value_length == original->value_length &&
           (original->value_length == 0 ||
            memcmp(record->value, original->value, original->value_length) == 0) &&
           record->expiry_ms == original->expiry;
}

/**
 * @brief Read an image back and check the prefix property.
 *
 * @param image      Bytes of the (possibly mutated) stream file.
 * @param expect_all When true the image is untouched and must read back completely.
 */
static bool check_stream(const unsigned char *image,
                         size_t image_length,
                         const unsigned char *key,
                         const written_record *originals,
                         size_t count,
                         bool expect_all) {
    FILE *file = tmpfile();

    if (!file) {
        FAIL("tmpfile failed");
    }

    if (image_length && fwrite(image, 1, image_length, file) != image_length) {
        fclose(file);
        FAIL("short write");
    }

    rewind(file);

    cv_record_stream stream = {0};
    cv_status status = cv_stream_open(file, false, key, &stream);
    size_t read = 0;
    bool clean_end = false;

    while (status == CV_OK) {
        cv_disk_record record;
        bool eof, partial;

        status = cv_stream_next(&stream, &record, &eof, &partial);

        if (status != CV_OK) {
            break;
        }

        if (eof) {
            clean_end = !partial;
            break;
        }

        if (read >= count) {
            cv_stream_clear(&stream);
            fclose(file);
            FAIL("stream yielded more records than were written");
        }

        if (!same_record(&record, &originals[read])) {
            cv_stream_clear(&stream);
            fclose(file);
            FAIL("record %zu was altered but accepted", read);
        }

        ++read;
    }

    cv_stream_clear(&stream);
    fclose(file);

    if (expect_all && !(read == count && clean_end)) {
        FAIL("untouched stream did not read back completely (%zu of %zu)", read, count);
    }

    return true;
}

/**
 * @brief Rearrange whole records: swap, duplicate, remove or overwrite one.
 *
 * Byte-level mutation can never turn one valid record into another, so this
 * exercises the part of the format that binds records to their position
 * (sequence numbers and the chained previous tag).
 *
 * @param ends Offset just past each of the @p count records; the first starts
 *             right after the file header.
 * @return Length of the rearranged image written to @p out.
 */
static size_t mutate_records(campaign *run,
                             const unsigned char *image,
                             size_t length,
                             const size_t *ends,
                             size_t count,
                             unsigned char *out) {
    size_t start[7];
    size_t used = CV_FILE_HEADER_BYTES;

    start[0] = CV_FILE_HEADER_BYTES;

    for (size_t r = 0; r < count; ++r) {
        start[r + 1] = ends[r];
    }

    memcpy(out, image, CV_FILE_HEADER_BYTES);

    size_t a = below(run, count), b = below(run, count);
    unsigned int operation = (unsigned int)below(run, 4);

    for (size_t r = 0; r < count; ++r) {
        size_t source = r;

        if (operation == 0 && r == a) {
            source = b;              /* The record at a is replaced by a copy of b. */
        } else if (operation == 1 && (r == a || r == b)) {
            source = r == a ? b : a; /* a and b trade places. */
        }

        if (operation == 2 && r == a) {
            continue; /* a is removed. */
        }

        memcpy(out + used, image + start[source], start[source + 1] - start[source]);

        used += start[source + 1] - start[source];

        if (operation == 3 && r == a) {
            /* a is followed by a second copy of b. */
            memcpy(out + used, image + start[b], start[b + 1] - start[b]);

            used += start[b + 1] - start[b];
        }
    }

    (void)length;

    return used;
}

/** @brief Mutated encrypted streams: only exact prefixes of the original may be read. */
static bool fuzz_codec(campaign *run) {
    static unsigned char image[BUFFER_BYTES * 16], mutated[BUFFER_BYTES * 16 + 64];
    uint64_t cut_in_header = 0;

    for (uint64_t i = 0; i < run->iterations; ++i) {
        unsigned char key[CV_PERSIST_KEY_BYTES], uuid[16];
        written_record records[6];
        size_t ends[6];
        size_t count = 1 + below(run, 6);
        FILE *file = tmpfile();

        if (!file) {
            FAIL("tmpfile failed");
        }

        for (size_t k = 0; k < sizeof(key); ++k) {
            key[k] = (unsigned char)below(run, 256);
        }

        for (size_t k = 0; k < sizeof(uuid); ++k) {
            uuid[k] = (unsigned char)below(run, 256);
        }

        cv_record_stream writer = {0};

        if (cv_stream_create(file, false, uuid, 0, key, &writer) != CV_OK) {
            FAIL("cannot create the stream");
        }

        for (size_t r = 0; r < count; ++r) {
            written_record *record = &records[r];
            size_t name = 1 + below(run, sizeof(record->key) - 1);

            memset(record, 0, sizeof(*record));

            for (size_t c = 0; c < name; ++c) {
                record->key[c] = (char)('a' + below(run, 26));
            }

            switch (below(run, 3)) {
                case 0:
                    record->operation = CV_RECORD_SET;
                    record->value_length = below(run, sizeof(record->value) + 1);
                    record->expiry = below(run, 2) ? 1 + random64(run) % 1000000 : 0;

                    for (size_t c = 0; c < record->value_length; ++c) {
                        record->value[c] = (unsigned char)below(run, 256);
                    }
                    break;

                case 1:
                    record->operation = CV_RECORD_DELETE;
                    break;

                default:
                    record->operation = CV_RECORD_EXPIRE;
                    record->expiry = 1 + random64(run) % 1000000;
                    break;
            }

            if (cv_stream_append(&writer,
                                 record->operation,
                                 record->key,
                                 record->value,
                                 record->value_length,
                                 record->expiry) != CV_OK) {
                FAIL("cannot append record %zu", r);
            }

            /* Remember where each record ends, for the record-level mutations. */
            if (fflush(file) != 0 || ftell(file) < 0) {
                FAIL("cannot locate record %zu", r);
            }

            ends[r] = (size_t)ftell(file);
        }

        cv_stream_clear(&writer);

        size_t length = slurp(file, image, sizeof(image));

        fclose(file);

        if (length == 0 || !check_stream(image, length, key, records, count, true)) {
            FAIL("valid stream rejected (iteration %" PRIu64 ")", i);
        }

        /* Damage the file and require that nothing forged is accepted. */
        size_t damaged;

        if (below(run, 2) == 0) {
            damaged = mutate_records(run, image, length, ends, count, mutated);
        } else {
            memcpy(mutated, image, length);

            damaged = mutate(run, mutated, length, sizeof(mutated));
        }

        if (damaged == length && memcmp(mutated, image, length) == 0) {
            continue;
        }

        if (damaged < CV_FILE_HEADER_BYTES) {
            ++cut_in_header;
        }

        if (!check_stream(mutated, damaged, key, records, count, false)) {
            FAIL("mutated stream broke the authentication guarantee (iteration %" PRIu64 ")", i);
        }
    }

    printf("  codec  : %" PRIu64 " streams, every mutation rejected or an exact prefix (%" PRIu64
           " cut inside the header)\n",
           run->iterations,
           cut_in_header);

    return true;
}

/** @brief Write @p length bytes to a new private file. */
static bool write_private(const char *path, const unsigned char *data, size_t length) {
    FILE *file = NULL;

    cv_io_remove(path);

    if (cv_io_open(path, true, true, true, &file) != CV_OK) {
        return false;
    }

    bool ok = length == 0 || fwrite(data, 1, length, file) == length;

    return fclose(file) == 0 && ok;
}

/** @brief Mutated policy files: never crash, and accepted policies deny anonymous access. */
static bool fuzz_policy(campaign *run) {
    static unsigned char base[BUFFER_BYTES], buffer[BUFFER_BYTES + 64];
    char hash[CV_AUTH_HASH_BYTES];
    const unsigned char password[] = "fuzz password";
    char *path = cv_io_path(run->scratch, "fuzz-policy.conf");
    uint64_t accepted = 0;

    if (!path || cv_auth_hash_password(password, sizeof(password) - 1, hash) != CV_OK) {
        free(path);
        FAIL("cannot prepare the policy target");
    }

    int base_length =
        snprintf((char *)base,
                 sizeof(base),
                 "CVAULT-SECURITY-1\n# comment\nuser alice %s\nuser bob %s\n"
                 "allow alice rw alice:\nallow alice r shared:\nallow bob w shared:\n",
                 hash,
                 hash);

    /* Policies are expensive to accept (one Argon2 hash each), so keep the count modest. */
    uint64_t budget = run->iterations < 400 ? run->iterations : 400;

    for (uint64_t i = 0; i < budget; ++i) {
        memcpy(buffer, base, (size_t)base_length);

        size_t length = mutate(run, buffer, (size_t)base_length, BUFFER_BYTES);

        if (!write_private(path, buffer, length)) {
            free(path);
            FAIL("cannot write the policy file");
        }

        cv_auth_policy *policy = NULL;
        cv_status status = cv_auth_policy_load(path, &policy);

        if (status == CV_OK) {
            ++accepted;

            cv_auth_session session;

            cv_auth_session_init(&session);

            if (!policy || cv_auth_authorize(&session, "alice:x", false) != CV_ERR_UNAUTHORIZED) {
                cv_auth_policy_destroy(policy);
                free(path);
                FAIL("accepted policy grants access to an anonymous session");
            }
        } else if (policy) {
            free(path);
            FAIL("a failed load must not return a policy");
        }

        cv_auth_policy_destroy(policy);
    }

    cv_io_remove(path);
    free(path);

    printf("  policy : %" PRIu64 " mutated files, %" PRIu64
           " accepted, none granted anonymous access\n",
           budget,
           accepted);

    return true;
}

/** Expected state of one key in the model. */
typedef struct {
    enum {
        ABSENT,
        PRESENT,
        UNKNOWN
    } state;

    unsigned char value[64];
    size_t length;
} model_entry;

/** Keys the model tracks (all under alice's read/write prefix `k:`). */
static const char *const pool[] = {"k:a", "k:b", "k:c", "k:d"};

/** @brief True for the first four bytes "AUTH" followed by a separator or the end. */
static bool looks_like_auth(const unsigned char *line, size_t length) {
    return length >= 4 && memcmp(line, "AUTH", 4) == 0 && (length == 4 || line[4] <= ' ');
}

/** @brief True when the line parses as QUIT. */
static bool is_quit(const unsigned char *line, size_t length) {
    cv_command command;

    return cv_parse_line(line, length, &command) == CV_OK && command.type == CV_CMD_QUIT;
}

/** @brief Compose a plausible request line for the pooled keys. */
static size_t make_line(campaign *run, unsigned char *line, size_t capacity) {
    static const char *const commands[] = {
        "SET", "GET", "DEL", "EXPIRE", "TTL", "PING", "SET", "GET"};
    static const char *const keys[] = {
        "k:a", "k:b", "k:c", "k:d", "k:e", "other:x", "K:a", "shared:z"};
    static const char *const seconds[] = {"0", "-1", "100000", "5", "x"};
    const char *command = commands[below(run, sizeof(commands) / sizeof(commands[0]))];
    const char *key = keys[below(run, sizeof(keys) / sizeof(keys[0]))];
    int length;

    if (strcmp(command, "SET") == 0) {
        char value[32];
        size_t count = below(run, sizeof(value) - 1);

        for (size_t i = 0; i < count; ++i) {
            value[i] = (char)(below(run, 6) == 0 ? ' ' : 'a' + below(run, 26));
        }

        value[count] = '\0';
        length = snprintf((char *)line, capacity, "SET %s %s", key, value);
    } else if (strcmp(command, "EXPIRE") == 0) {
        length = snprintf((char *)line,
                          capacity,
                          "EXPIRE %s %s",
                          key,
                          seconds[below(run, sizeof(seconds) / sizeof(seconds[0]))]);
    } else if (strcmp(command, "PING") == 0) {
        length = snprintf((char *)line, capacity, "PING");
    } else {
        length = snprintf((char *)line, capacity, "%s %s", command, key);
    }

    size_t used = (size_t)length;

    if (below(run, 4) == 0) {
        used = mutate(run, line, used, capacity - 2);
    }

    line[used++] = '\n';

    return used;
}

/** @brief Index of a pooled key, or -1. */
static int pool_index(const unsigned char *key, size_t length) {
    for (size_t i = 0; i < sizeof(pool) / sizeof(pool[0]); ++i) {
        if (strlen(pool[i]) == length && memcmp(pool[i], key, length) == 0) {
            return (int)i;
        }
    }

    return -1;
}

/** @brief True when @p reply is exactly @p text. */
static bool reply_is(const unsigned char *reply, size_t length, const char *text) {
    return length == strlen(text) && memcmp(reply, text, length) == 0;
}

/**
 * @brief Check one reply against the model and update the model.
 *
 * @param authenticated Whether the sender is logged in as alice (rw on `k:`).
 */
static bool check_reply(model_entry *model,
                        bool authenticated,
                        const unsigned char *line,
                        size_t length,
                        const unsigned char *reply,
                        size_t reply_length) {
    cv_command command;
    cv_status status = cv_parse_line(line, length, &command);

    if (status != CV_OK) {
        if (!reply_is(reply, reply_length, "-ERR invalid command\n")) {
            FAIL("malformed line did not get the invalid-command reply");
        }

        return true;
    }

    if (command.type == CV_CMD_PING) {
        if (!reply_is(reply, reply_length, "+PONG\n")) {
            FAIL("PING did not get +PONG");
        }

        return true;
    }

    bool allowed = authenticated && command.key_length >= 2 && memcmp(command.key, "k:", 2) == 0;

    if (!allowed) {
        if (!reply_is(reply, reply_length, "-ERR access denied\n")) {
            FAIL("forbidden access was not denied (reply: %.20s)", reply);
        }

        return true;
    }

    int index = pool_index(command.key, command.key_length);
    model_entry unknown = {UNKNOWN, {0}, 0};
    model_entry *entry = index >= 0 ? &model[index] : &unknown;

    switch (command.type) {
        case CV_CMD_SET:
            if (!reply_is(reply, reply_length, "+OK\n")) {
                FAIL("SET was not acknowledged");
            }

            if (command.value_length <= sizeof(entry->value)) {
                entry->state = PRESENT;
                entry->length = command.value_length;

                memcpy(entry->value, command.value, command.value_length);
            } else {
                entry->state = UNKNOWN;
            }
            return true;

        case CV_CMD_GET: {
            bool absent = reply_is(reply, reply_length, "$-1\n");

            if (entry->state == ABSENT && !absent) {
                FAIL("GET returned a value for an absent key");
            }

            if (entry->state == PRESENT) {
                char header[24];
                int header_length = snprintf(header, sizeof(header), "$%zu\n", entry->length);
                size_t expected = (size_t)header_length + entry->length + 1;

                if (reply_length != expected || memcmp(reply, header, (size_t)header_length) != 0 ||
                    memcmp(reply + header_length, entry->value, entry->length) != 0 ||
                    reply[expected - 1] != '\n') {
                    FAIL("GET returned the wrong value");
                }
            }

            if (entry->state == UNKNOWN && !absent && reply[0] != '$') {
                FAIL("GET returned a malformed reply");
            }
            return true;
        }

        case CV_CMD_DEL:
        case CV_CMD_EXPIRE: {
            bool deletes = command.type == CV_CMD_DEL || command.seconds <= 0;
            bool missing = reply_is(reply, reply_length, "$-1\n");
            bool done = reply_is(reply, reply_length, "+OK\n");

            /* A deadline too far in the future is refused and changes nothing. */
            if (command.type == CV_CMD_EXPIRE && command.seconds > 0 &&
                reply_is(reply, reply_length, "-ERR operation failed\n")) {
                return true;
            }

            if (!missing && !done) {
                FAIL("DEL/EXPIRE reply is neither +OK nor $-1");
            }

            if ((entry->state == ABSENT && !missing) || (entry->state == PRESENT && !done)) {
                FAIL("DEL/EXPIRE disagrees with the model");
            }

            entry->state = deletes ? ABSENT : (done ? UNKNOWN : ABSENT);
            return true;
        }

        case CV_CMD_TTL:
            if (reply_length < 3 || reply[0] != ':' || reply[reply_length - 1] != '\n') {
                FAIL("TTL reply is malformed");
            }

            if (entry->state == ABSENT && !reply_is(reply, reply_length, ":-2\n")) {
                FAIL("TTL of an absent key must be -2");
            }
            return true;

        default:
            FAIL("unexpected command type in the model");
    }
}

/** @brief Remove a leftover scratch file and its lock. */
static void remove_with_lock(const char *path) {
    size_t length = strlen(path);
    char *lock = malloc(length + 6);

    cv_io_remove(path);

    if (lock) {
        memcpy(lock, path, length);
        memcpy(lock + length, ".lock", 6);
        cv_io_remove(lock);
        free(lock);
    }
}

/** @brief Random requests against the complete service, checked by a model and the audit log. */
static bool fuzz_service(campaign *run) {
    char *policy_path = cv_io_path(run->scratch, "fuzz-service-policy.conf");
    char *audit_path = cv_io_path(run->scratch, "fuzz-service-audit.bin");
    char *key_path = cv_io_path(run->scratch, "fuzz-service-audit.key");
    const unsigned char password[] = "fuzz password";
    char hash[CV_AUTH_HASH_BYTES];
    unsigned char policy[1024], line[BUFFER_BYTES], reply[CV_MAX_RESPONSE_BYTES];
    model_entry model[sizeof(pool) / sizeof(pool[0])] = {{ABSENT, {0}, 0}};
    cv_security *service = NULL;
    uint64_t handled = 0, denied = 0;
    bool ok = false;

    if (!policy_path || !audit_path || !key_path ||
        cv_auth_hash_password(password, sizeof(password) - 1, hash) != CV_OK) {
        fprintf(stderr, "cannot prepare the service target\n");
        goto cleanup;
    }

    int policy_length = snprintf((char *)policy,
                                 sizeof(policy),
                                 "CVAULT-SECURITY-1\nuser alice %s\nallow alice rw k:\n",
                                 hash);

    remove_with_lock(audit_path);
    cv_io_remove(key_path);

    if (!write_private(policy_path, policy, (size_t)policy_length) ||
        cv_persist_key_generate(key_path) != CV_OK ||
        cv_security_open(policy_path, audit_path, key_path, NULL, 4, &service) != CV_OK) {
        fprintf(stderr, "cannot start the service\n");
        goto cleanup;
    }

    size_t written;
    bool close_after;
    static const char login[] = "AUTH alice fuzz password\n";

    if (cv_security_handler(service,
                            1,
                            (const unsigned char *)login,
                            sizeof(login) - 1,
                            reply,
                            sizeof(reply),
                            &written,
                            &close_after) != CV_OK ||
        !reply_is(reply, written, "+OK\n")) {
        fprintf(stderr, "cannot log in to the service\n");
        goto cleanup;
    }

    /* Every request costs two synchronised audit writes, so this target runs fewer iterations. */
    uint64_t budget = run->iterations / 10 < 200 ? 200 : run->iterations / 10;

    for (uint64_t i = 0; i < budget; ++i) {
        size_t length = make_line(run, line, sizeof(line));
        uint64_t sender = below(run, 5) == 0 ? 2 : 1; /* 2 is never logged in. */

        /* AUTH and QUIT would end the login; they are covered by dedicated tests. */
        if (looks_like_auth(line, length) || is_quit(line, length)) {
            continue;
        }

        if (cv_security_handler(
                service, sender, line, length, reply, sizeof(reply), &written, &close_after) !=
            CV_OK) {
            fprintf(stderr, "service failed at iteration %" PRIu64 "\n", i);
            goto cleanup;
        }

        if (written == 0 || written > sizeof(reply) || close_after) {
            fprintf(stderr, "malformed service response at iteration %" PRIu64 "\n", i);
            goto cleanup;
        }

        if (!check_reply(model, sender == 1, line, length, reply, written)) {
            fprintf(stderr, "  (iteration %" PRIu64 ", seed %" PRIu64 ")\n", i, run->seed);
            goto cleanup;
        }

        ++handled;
        denied += reply_is(reply, written, "-ERR access denied\n");
    }

    /* The audit log produced during the run must authenticate completely. */
    cv_status closed = cv_security_close(service);

    service = NULL;

    if (closed != CV_OK) {
        fprintf(stderr, "closing the service failed\n");
        goto cleanup;
    }

    unsigned char key[CV_PERSIST_KEY_BYTES];
    cv_audit *audit = NULL;
    FILE *export = tmpfile();

    if (!export || cv_persist_key_load(key_path, key) != CV_OK ||
        cv_audit_open(audit_path, key, false, &audit) != CV_OK ||
        cv_audit_export(audit, export) != CV_OK) {
        cv_audit_close(audit);

        if (export) {
            fclose(export);
        }

        fprintf(stderr, "the audit log written during the run does not authenticate\n");
        goto cleanup;
    }

    cv_crypto_wipe(key, sizeof(key));
    cv_audit_close(audit);

    long events = 0;
    int c;

    rewind(export);

    while ((c = fgetc(export)) != EOF) {
        events += c == '\n';
    }

    fclose(export);

    ok = events > 0;
    printf("  service: %" PRIu64 " requests (%" PRIu64
           " denied), model matched every reply, audit log of %ld events verified\n",
           handled,
           denied,
           events);

cleanup:
    cv_security_close(service);

    if (policy_path) {
        cv_io_remove(policy_path);
    }

    if (audit_path) {
        remove_with_lock(audit_path);
    }

    if (key_path) {
        cv_io_remove(key_path);
    }

    free(policy_path);
    free(audit_path);
    free(key_path);

    return ok;
}

/** @brief Parse an unsigned number option, returning false on junk. */
static bool number_option(const char *text, uint64_t *out) {
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);

    if (!*text || *end != '\0') {
        return false;
    }

    *out = value;

    return true;
}

int main(int argc, char **argv) {
    campaign run = {20000, 1, 0, "tests/fuzz/corpus", "."};
    bool want_parser = false, want_codec = false, want_policy = false, want_service = false;

    for (int i = 1; i < argc; ++i) {
        const char *option = argv[i];
        bool has_value = i + 1 < argc;

        if (strcmp(option, "--iterations") == 0 && has_value &&
            number_option(argv[i + 1], &run.iterations)) {
            ++i;
        } else if (strcmp(option, "--seed") == 0 && has_value &&
                   number_option(argv[i + 1], &run.seed)) {
            ++i;
        } else if (strcmp(option, "--corpus") == 0 && has_value) {
            run.corpus = argv[++i];
        } else if (strcmp(option, "--scratch") == 0 && has_value) {
            run.scratch = argv[++i];
        } else if (strcmp(option, "--target") == 0 && has_value) {
            const char *name = argv[++i];

            want_parser |= strcmp(name, "parser") == 0;
            want_codec |= strcmp(name, "codec") == 0;
            want_policy |= strcmp(name, "policy") == 0;
            want_service |= strcmp(name, "service") == 0;

            if (strcmp(name, "parser") && strcmp(name, "codec") && strcmp(name, "policy") &&
                strcmp(name, "service")) {
                fprintf(stderr, "unknown target %s\n", name);

                return EXIT_FAILURE;
            }
        } else {
            fprintf(stderr,
                    "usage: fuzz-campaign [--iterations N] [--seed S] [--target NAME]... "
                    "[--corpus DIR] [--scratch DIR]\n");

            return EXIT_FAILURE;
        }
    }

    if (!want_parser && !want_codec && !want_policy && !want_service) {
        want_parser = want_codec = want_policy = want_service = true;
    }

    if (run.seed == 0 || cv_crypto_init() != CV_OK) {
        fprintf(stderr, "invalid seed or libsodium failure\n");

        return EXIT_FAILURE;
    }

    run.rng = run.seed * UINT64_C(0x9e3779b97f4a7c15) | 1;

    printf("fuzz campaign: seed %" PRIu64 ", %" PRIu64 " iterations per target\n",
           run.seed,
           run.iterations);

    if ((want_parser && !fuzz_parser(&run)) || (want_codec && !fuzz_codec(&run)) ||
        (want_policy && !fuzz_policy(&run)) || (want_service && !fuzz_service(&run))) {
        fprintf(stderr, "campaign FAILED; rerun with --seed %" PRIu64 " to reproduce\n", run.seed);

        return EXIT_FAILURE;
    }

    puts("fuzz campaign: all targets passed");

    return EXIT_SUCCESS;
}
