#if !defined(_WIN32)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif
#include "cvault/persist.h"
#include "cvault/crypto.h"
#include "persist_codec.h"
#include "persist_io.h"
#include <errno.h>
#include <limits.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

/* The owner serializes public calls. Workers only read immutable job inputs. */
struct cv_persist {
    char *directory, *journal_path, *snapshot_path, *temporary;
    cv_file_lock lock;
    FILE *journal;
    cv_record_stream stream;
    unsigned char key[CV_PERSIST_KEY_BYTES], uuid[16];
    cv_hashtable *table, *job_table;
    cv_persist_clock clock;
    void *clock_context;
    uint64_t snapshot_sequence, job_sequence, job_wall;
    bool repaired_tail, failed;
    cv_status job_result;
#ifdef _WIN32
    HANDLE worker;
#else
    pid_t worker;
#endif
};

static cv_status wall_clock(void *context, uint64_t *out) {
    (void) context;
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    uint64_t ticks = ((uint64_t) ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    const uint64_t origin = UINT64_C(116444736000000000);
    if (ticks < origin) return CV_ERR_IO;
    *out = (ticks - origin) / UINT64_C(10000);
#else
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || now.tv_sec < 0 ||
        (uint64_t) now.tv_sec > (UINT64_MAX - 999) / 1000)
        return CV_ERR_IO;
    *out = (uint64_t) now.tv_sec * 1000 + (uint64_t) now.tv_nsec / 1000000;
#endif
    return *out > 0 ? CV_OK : CV_ERR_IO;
}

/* Preserve history until the entire journal tail has been applied. Filtering each
 * record by today's clock would lose keys whose later EXPIRE extends their TTL. */
static cv_status frozen_clock(void *context, uint64_t *out) {
    (void) context;
    *out = 0;
    return CV_OK;
}

static cv_status apply_record(cv_hashtable *table, const cv_disk_record *record) {
    cv_status status;
    switch (record->operation) {
        case CV_RECORD_SET:
            status = cv_hashtable_set(table, record->key, record->value, record->value_length);
            if (status == CV_OK && record->expiry_ms)
                status = cv_hashtable_expire_ms(table, record->key, record->expiry_ms);
            return status;
        case CV_RECORD_DELETE:
            status = cv_hashtable_delete(table, record->key);
            return status == CV_ERR_NOT_FOUND ? CV_OK : status;
        case CV_RECORD_EXPIRE:
            status = cv_hashtable_expire_ms(table, record->key, record->expiry_ms);
            return status == CV_ERR_NOT_FOUND ? CV_ERR_CORRUPT : status;
        default: return CV_ERR_CORRUPT;
    }
}

typedef struct {
    cv_hashtable *table;
    uint64_t wall;
    bool freeze;
} copy_context;

/* Frozen snapshot copies translate relative milliseconds to epoch deadlines;
 * live recovery copies translate epoch deadlines back to relative milliseconds. */

static cv_status copy_entry(void *opaque, const char *key, const unsigned char *value,
                            size_t length, bool expires, uint64_t remaining) {
    copy_context *context = opaque;
    if (!context->freeze && expires && remaining <= context->wall) return CV_OK;
    cv_status status = cv_hashtable_set(context->table, key, value, length);
    if (status == CV_OK && expires) {
        if (context->freeze && remaining > UINT64_MAX - context->wall) return CV_ERR_LIMIT;
        uint64_t duration = context->freeze ? context->wall + remaining : remaining - context->wall;
        if (duration == 0) return CV_ERR_IO;
        status = cv_hashtable_expire_ms(context->table, key, duration);
    }
    return status;
}

static cv_status load_snapshot(cv_persist *store, cv_hashtable *replay, bool *present) {
    *present = false;
    FILE *file = NULL;
    cv_status status = cv_io_open(store->snapshot_path, false, false, false, &file);
    if (status == CV_ERR_NOT_FOUND) return CV_OK;
    if (status != CV_OK) return status;
    cv_record_stream stream = {0};
    status = cv_stream_open(file, true, store->key, &stream);
    uint64_t count = 0;
    bool ended = false;
    while (status == CV_OK) {
        cv_disk_record record;
        bool eof, partial;
        status = cv_stream_next(&stream, &record, &eof, &partial);
        if (status != CV_OK) break;
        if (eof) {
            if (!ended || partial) status = CV_ERR_CORRUPT;
            break;
        }
        if (ended) {
            status = CV_ERR_CORRUPT;
            break;
        }
        if (record.operation == CV_RECORD_END) {
            if (cv_decode_u64(record.value) != count) status = CV_ERR_CORRUPT;
            ended = true;
        } else if (record.operation != CV_RECORD_SET) status = CV_ERR_CORRUPT;
        else {
            const unsigned char *old;
            size_t length;
            if (cv_hashtable_get(replay, record.key, &old, &length) != CV_ERR_NOT_FOUND)
                status = CV_ERR_CORRUPT;
            else status = apply_record(replay, &record);
            ++count;
        }
    }
    if (status == CV_OK) {
        memcpy(store->uuid, stream.header + 8, 16);
        store->snapshot_sequence = stream.baseline;
        *present = true;
    }
    cv_stream_clear(&stream);
    if (fclose(file) != 0 && status == CV_OK) status = CV_ERR_IO;
    return status;
}

static cv_status load_journal(cv_persist *store, cv_hashtable *replay, bool snapshot) {
    cv_status status = cv_io_open(store->journal_path, false, false, true, &store->journal);
    if (status == CV_ERR_NOT_FOUND) {
        if (!snapshot) randombytes_buf(store->uuid, sizeof(store->uuid));
        status = cv_io_open(store->journal_path, true, true, true, &store->journal);
        if (status == CV_OK)
            status = cv_stream_create(store->journal, false, store->uuid,
                                      store->snapshot_sequence, store->key, &store->stream);
        if (status == CV_OK) status = cv_io_sync(store->journal);
        if (status == CV_OK) status = cv_io_sync_directory(store->directory);
        return status;
    }
    if (status != CV_OK) return status;
    status = cv_stream_open(store->journal, false, store->key, &store->stream);
    if (status != CV_OK) return status;
    if ((snapshot && memcmp(store->uuid, store->stream.header + 8, 16) != 0) ||
        store->stream.baseline > store->snapshot_sequence)
        return CV_ERR_CORRUPT;
    if (!snapshot) memcpy(store->uuid, store->stream.header + 8, 16);
    uint64_t good = CV_FILE_HEADER_BYTES;
    while (status == CV_OK) {
        cv_disk_record record;
        bool eof, partial;
        status = cv_stream_next(&store->stream, &record, &eof, &partial);
        if (status != CV_OK) break;
        if (eof) {
            if (partial) {
                status = cv_io_truncate(store->journal, good);
                store->repaired_tail = status == CV_OK;
            } else {
                clearerr(store->journal);
                status = cv_io_seek(store->journal, good);
            }
            break;
        }
        if (record.operation == CV_RECORD_END) {
            status = CV_ERR_CORRUPT;
            break;
        }
        if (store->stream.sequence > store->snapshot_sequence) status = apply_record(replay, &record);
        if (status == CV_OK) status = cv_io_tell(store->journal, &good);
    }
    if (status == CV_OK && store->stream.sequence < store->snapshot_sequence) status = CV_ERR_CORRUPT;
    return status;
}

cv_status cv_persist_open(const cv_persist_options *options, cv_persist **out) {
    if (out) *out = NULL;
    if (!out || !options || !options->directory || options->directory[0] == '\0' || !options->key ||
        options->key_length != CV_PERSIST_KEY_BYTES)
        return CV_ERR_INVALID_ARGUMENT;
    cv_status status = cv_crypto_init();
    if (status != CV_OK) return status;
    cv_persist *store = calloc(1, sizeof(*store));
    if (!store) return CV_ERR_NO_MEMORY;
    store->lock.native = -1;
    store->directory = cv_io_path(options->directory, "");
    store->journal_path = cv_io_path(options->directory, "journal.aof");
    store->snapshot_path = cv_io_path(options->directory, "snapshot.cvs");
    char *lock_path = cv_io_path(options->directory, "writer.lock");
    memcpy(store->key, options->key, sizeof(store->key));
    store->clock = options->clock ? options->clock : wall_clock;
    store->clock_context = options->clock_context;
    if (!store->directory || !store->journal_path || !store->snapshot_path || !lock_path)
        status = CV_ERR_NO_MEMORY;
    if (status == CV_OK) status = cv_io_directory(options->directory);
    if (status == CV_OK) status = cv_io_lock(lock_path, &store->lock);
    free(lock_path);
    cv_hashtable *replay = NULL;
    if (status == CV_OK) status = cv_hashtable_create_with_clock(&replay, frozen_clock, NULL);
    bool snapshot = false;
    if (status == CV_OK) status = load_snapshot(store, replay, &snapshot);
    if (status == CV_OK) status = load_journal(store, replay, snapshot);
    uint64_t wall = 0;
    if (status == CV_OK) status = store->clock(store->clock_context, &wall);
    if (status == CV_OK) status = cv_hashtable_create(&store->table);
    copy_context context = {store->table, wall, false};
    if (status == CV_OK) status = cv_hashtable_visit(replay, true, copy_entry, &context);
    cv_hashtable_destroy(replay);
    if (status != CV_OK) {
        (void) cv_persist_close(store);
        return status;
    }
    *out = store;
    return CV_OK;
}

/* Prepare memory before disk I/O; publish it only after a synchronized record.
 * Reopening reconciles state after an uncertain write/flush failure. */
static cv_status mutate(cv_persist *store, unsigned int operation, const char *key,
                        const unsigned char *value, size_t length, int64_t seconds) {
    if (!store) return CV_ERR_INVALID_ARGUMENT;
    if (store->failed) return CV_ERR_IO;
    cv_hashtable *next = NULL;
    cv_status status = cv_hashtable_clone(store->table, &next);
    uint64_t expiry = 0;
    if (status == CV_OK) {
        if (operation == CV_RECORD_SET) status = cv_hashtable_set(next, key, value, length);
        else if (operation == CV_RECORD_DELETE || seconds <= 0) {
            operation = CV_RECORD_DELETE;
            status = cv_hashtable_delete(next, key);
        } else {
            uint64_t wall = 0;
            status = store->clock(store->clock_context, &wall);
            if (status == CV_OK && ((uint64_t) seconds > UINT64_MAX / 1000 ||
                                    (uint64_t) seconds * 1000 > UINT64_MAX - wall))
                status = CV_ERR_LIMIT;
            if (status == CV_OK) {
                expiry = wall + (uint64_t) seconds * 1000;
                status = cv_hashtable_expire(next, key, seconds);
            }
        }
    }
    if (status == CV_OK && store->stream.sequence == UINT64_MAX) status = CV_ERR_LIMIT;
    if (status == CV_OK) {
        status = cv_stream_append(&store->stream, operation, key, value, length, expiry);
        if (status == CV_OK) status = cv_io_sync(store->journal);
        if (status != CV_OK) store->failed = true;
        else {
            cv_hashtable *old = store->table;
            store->table = next;
            next = old;
        }
    }
    cv_hashtable_destroy(next);
    return status;
}

cv_status cv_persist_set(cv_persist *store, const char *key, const unsigned char *value, size_t length) {
    return mutate(store, CV_RECORD_SET, key, value, length, 0);
}

cv_status cv_persist_delete(cv_persist *store, const char *key) {
    return mutate(store, CV_RECORD_DELETE, key, NULL, 0, 0);
}

cv_status cv_persist_expire(cv_persist *store, const char *key, int64_t seconds) {
    return mutate(store, CV_RECORD_EXPIRE, key, NULL, 0, seconds);
}

cv_status cv_persist_get(const cv_persist *store, const char *key, const unsigned char **value, size_t *length) {
    if (value) *value = NULL;
    if (length) *length = 0;
    if (!store) return CV_ERR_INVALID_ARGUMENT;
    return store->failed ? CV_ERR_IO : cv_hashtable_get(store->table, key, value, length);
}

cv_status cv_persist_ttl(const cv_persist *store, const char *key, int64_t *seconds) {
    if (seconds) *seconds = CV_TTL_MISSING;
    if (!store) return CV_ERR_INVALID_ARGUMENT;
    return store->failed ? CV_ERR_IO : cv_hashtable_ttl(store->table, key, seconds);
}

const cv_hashtable *cv_persist_table(const cv_persist *store) {
    return store && !store->failed ? store->table : NULL;
}

cv_status cv_persist_get_stats(const cv_persist *store, cv_persist_stats *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!store || !out) return CV_ERR_INVALID_ARGUMENT;
    out->sequence = store->stream.sequence;
    out->snapshot_sequence = store->snapshot_sequence;
    out->repaired_tail = store->repaired_tail;
    out->failed = store->failed;
    return CV_OK;
}

typedef struct {
    cv_record_stream *stream;
    uint64_t wall, count;
} snapshot_context;

static cv_status snapshot_entry(void *opaque, const char *key, const unsigned char *value,
                                size_t length, bool expires, uint64_t remaining) {
    snapshot_context *context = opaque;
    if (expires && remaining > UINT64_MAX - context->wall) return CV_ERR_LIMIT;
    uint64_t expiry = expires ? context->wall + remaining : 0;
    if (expires && !expiry) return CV_ERR_IO;
    cv_status status = cv_stream_append(context->stream, CV_RECORD_SET, key, value, length, expiry);
    if (status == CV_OK) ++context->count;
    return status;
}

static cv_status temporary_path(cv_persist *store) {
    unsigned char nonce[16];
    char hex[33], name[64];
    randombytes_buf(nonce, sizeof(nonce));
    sodium_bin2hex(hex, sizeof(hex), nonce, sizeof(nonce));
    (void) snprintf(name, sizeof(name), ".snapshot-%s.tmp", hex);
    free(store->temporary);
    store->temporary = cv_io_path(store->directory, name);
    return store->temporary ? CV_OK : CV_ERR_NO_MEMORY;
}

static cv_status write_snapshot(cv_persist *store, const cv_hashtable *table,
                                uint64_t sequence, uint64_t wall) {
    FILE *file = NULL;
    cv_status status = cv_io_open(store->temporary, true, true, true, &file);
    if (status != CV_OK) return status; /* Never remove a pre-existing file. */
    cv_record_stream stream = {0};
    status = cv_stream_create(file, true, store->uuid, sequence, store->key, &stream);
    snapshot_context context = {&stream, wall, 0};
    if (status == CV_OK) status = cv_hashtable_visit(table, true, snapshot_entry, &context);
    unsigned char footer[8];
    cv_encode_u64(footer, context.count);
    if (status == CV_OK) status = cv_stream_append(&stream, CV_RECORD_END, "", footer, sizeof(footer), 0);
    if (status == CV_OK) status = cv_io_sync(file);
    cv_stream_clear(&stream);
    if (fclose(file) != 0 && status == CV_OK) status = CV_ERR_IO;
    if (status == CV_OK) status = cv_io_publish(store->temporary, store->snapshot_path, store->directory);
    if (status != CV_OK) cv_io_remove(store->temporary);
    return status;
}

cv_status cv_persist_snapshot(cv_persist *store) {
    if (!store) return CV_ERR_INVALID_ARGUMENT;
    if (store->failed) return CV_ERR_IO;
    if (store->worker) return CV_ERR_BUSY;
    uint64_t wall = 0;
    cv_status status = store->clock(store->clock_context, &wall);
    if (status == CV_OK) status = temporary_path(store);
    if (status == CV_OK) status = write_snapshot(store, store->table, store->stream.sequence, wall);
    if (status == CV_OK) store->snapshot_sequence = store->stream.sequence;
    return status;
}
#ifdef _WIN32
static unsigned int __stdcall snapshot_worker(void *opaque) {
    cv_persist *store = opaque;
    store->job_result = write_snapshot(store, store->job_table, store->job_sequence, 0);
    return 0;
}
#else
static void child_close_descriptors(void) {
    /* Never flock(LOCK_UN): the parent shares this open-file description. */
    (void) randombytes_close();
#ifdef __linux__
if (close_range(3, UINT_MAX, 0) == 0) { randombytes_stir(); return; }
#endif
long maximum = sysconf(_SC_OPEN_MAX);
    if (maximum<0) maximum = 65536;
    for (long descriptor = 3; descriptor<maximum && descriptor <= INT_MAX;++descriptor)
(void)close((int)descriptor);
randombytes_stir();
}
#endif
cv_status cv_persist_snapshot_start(cv_persist *store) {
    if (!store) return CV_ERR_INVALID_ARGUMENT;
    if (store->failed) return CV_ERR_IO;
    if (store->worker) return CV_ERR_BUSY;
    cv_status status = store->clock(store->clock_context, &store->job_wall);
    if (status == CV_OK) status = temporary_path(store);
    if (status != CV_OK) return status;
    store->job_sequence = store->stream.sequence;
#ifdef _WIN32
    status = cv_hashtable_create_with_clock(&store->job_table, frozen_clock, NULL);
    copy_context context = {store->job_table, store->job_wall, true};
    if (status == CV_OK) status = cv_hashtable_visit(store->table, true, copy_entry, &context);
    if (status == CV_OK) {
        /* The worker uses stdio/allocation, so create it through the CRT. */
        store->worker = (HANDLE) _beginthreadex(NULL, 0, snapshot_worker, store, 0, NULL);
        if (!store->worker) status = CV_ERR_IO;
    }
    if (status != CV_OK) {
        cv_hashtable_destroy(store->job_table);
        store->job_table = NULL;
    }
#else
    pid_t child = fork();
    if (child < 0) return CV_ERR_IO;
    if (child == 0) {
        child_close_descriptors();
        /* Pair wall/monotonic readings inside the child: delayed scheduling must
         * not subtract its delay twice. Include expired physical entries because
         * a later parent-side EXPIRE record may have extended them before expiry. */
        uint64_t wall = 0;
        status = store->clock(store->clock_context, &wall);
        if (status == CV_OK) status = write_snapshot(store, store->table, store->job_sequence, wall);
        _exit(status == CV_OK ? 0 : (int) status);
    }
    store->worker = child;
#endif
    return status;
}

static cv_status finish_job(cv_persist *store, bool wait, bool *done) {
    if (done) *done = false;
    if (!store || !done) return CV_ERR_INVALID_ARGUMENT;
    if (!store->worker) {
        *done = true;
        return CV_OK;
    }
    cv_status result;
#ifdef _WIN32
    DWORD state = WaitForSingleObject(store->worker, wait ? INFINITE : 0);
    if (state == WAIT_TIMEOUT) return CV_OK;
    if (state != WAIT_OBJECT_0) return CV_ERR_IO;
    result = store->job_result;
    (void) CloseHandle(store->worker);
    cv_hashtable_destroy(store->job_table);
    store->job_table = NULL;
#else
    int state;
    pid_t child;
    do { child = waitpid(store->worker, &state, wait ? 0 : WNOHANG); } while (child < 0 && errno == EINTR);
    if (child == 0) return CV_OK;
    if (child < 0) return CV_ERR_IO;
    result = WIFEXITED(state) && WEXITSTATUS(state) <= (int) CV_ERR_BUSY ? (cv_status) WEXITSTATUS(state) : CV_ERR_IO;
    if (result != CV_OK) cv_io_remove(store->temporary);
#endif
    store->worker = 0;
    if (result == CV_OK) {
        store->snapshot_sequence = store->job_sequence;
        *done = true;
    }
    return result;
}

cv_status cv_persist_snapshot_poll(cv_persist *store, bool *done) { return finish_job(store, false, done); }

cv_status cv_persist_snapshot_wait(cv_persist *store) {
    bool done;
    return finish_job(store, true, &done);
}

cv_status cv_persist_close(cv_persist *store) {
    if (!store) return CV_OK;
    cv_status status = cv_persist_snapshot_wait(store);
    cv_stream_clear(&store->stream);
    if (store->journal && fclose(store->journal) != 0 && status == CV_OK) status = CV_ERR_IO;
    cv_io_unlock(&store->lock);
    cv_hashtable_destroy(store->table);
    free(store->directory);
    free(store->journal_path);
    free(store->snapshot_path);
    free(store->temporary);
    cv_crypto_wipe(store, sizeof(*store));
    free(store);
    return status;
}

cv_status cv_persist_key_generate(const char *path) {
    cv_status status = cv_crypto_init();
    if (status != CV_OK) return status;
    unsigned char key[CV_PERSIST_KEY_BYTES];
    randombytes_buf(key, sizeof(key));
    FILE *file = NULL;
    status = cv_io_open(path, true, true, true, &file);
    if (status == CV_OK) {
        status = cv_io_write(file, key, sizeof(key));
        if (status == CV_OK) status = cv_io_sync(file);
        if (fclose(file) != 0 && status == CV_OK) status = CV_ERR_IO;
        if (status == CV_OK) status = cv_io_sync_parent(path);
        if (status != CV_OK) cv_io_remove(path);
    }
    cv_crypto_wipe(key, sizeof(key));
    return status;
}

cv_status cv_persist_key_load(const char *path, unsigned char key[CV_PERSIST_KEY_BYTES]) {
    if (!key) return CV_ERR_INVALID_ARGUMENT;
    cv_crypto_wipe(key, CV_PERSIST_KEY_BYTES);
    FILE *file = NULL;
    cv_status status = cv_io_open(path, false, false, false, &file);
    if (status != CV_OK) return status;
    if (fread(key, 1, CV_PERSIST_KEY_BYTES, file) != CV_PERSIST_KEY_BYTES || fgetc(file) != EOF)
        status = CV_ERR_CORRUPT;
    if (ferror(file)) status = CV_ERR_IO;
    if (fclose(file) != 0 && status == CV_OK) status = CV_ERR_IO;
    if (status != CV_OK) cv_crypto_wipe(key, CV_PERSIST_KEY_BYTES);
    return status;
}
