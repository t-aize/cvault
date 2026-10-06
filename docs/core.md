# In-memory core

The storage API implements `SET`, `GET`, `DEL`, `EXPIRE` and `TTL`. Its public
interface is documented in [`include/cvault/hashtable.h`](../include/cvault/hashtable.h);
the implementation lives in [`src/hashtable.c`](../src/hashtable.c). These are C
operations, also exposed through [authenticated TCP dispatch](security.md).
The application selects this in-memory table or the [durable store](persistence.md);
the [TCP transport](network.md) owns framing and connection lifetimes.

## Ownership and input bounds

The table owns copies of keys and values. Keys are nonempty, case-sensitive,
NUL-terminated byte strings, up to `CV_MAX_KEY_BYTES` (256) bytes excluding the
terminator. Embedded NULs cannot be part of a key. Inputs must point to valid
readable storage; the API cannot validate arbitrary pointers. Key scans are
bounded to 257 bytes. Values are binary buffers of up to `CV_MAX_VALUE_BYTES`
(65,536) bytes and may contain NULs, spaces or newlines.

`SET` accepts `NULL` with length zero for an empty value. `GET` then succeeds
with a NULL pointer and zero length; this differs from a missing key's status.
`GET` returns borrowed storage: never free or modify it. Treat it as invalid
after any table mutation or destruction. `SET` can safely copy a borrowed value,
including when replacing its own entry. Replacement and insertion allocate all
required buffers before changing existing entries; allocation failure preserves
previous values and TTLs.

Keys, values and the per-table hash key are wiped with libsodium before release.
Partial copies are also wiped if allocation fails. The caller remains responsible
for wiping its own input buffers. This is plaintext storage in process memory;
it provides neither encryption at rest nor protection against memory inspection
or swapping.

## Operation contracts

| Operation | Successful behavior | Missing or expired key |
|---|---|---|
| `cv_hashtable_set` | Insert/replace a copied value; clear previous TTL | Create a persistent entry |
| `cv_hashtable_get` | Return borrowed bytes and length | `CV_ERR_NOT_FOUND`; NULL/zero outputs |
| `cv_hashtable_delete` | Wipe and remove the entry | `CV_ERR_NOT_FOUND` |
| `cv_hashtable_expire` | Replace relative TTL; nonpositive seconds delete | `CV_ERR_NOT_FOUND` |
| `cv_hashtable_ttl` | Whole seconds remaining; `-1` for persistent | `CV_ERR_NOT_FOUND`; `-2` output |

Invalid pointers/empty keys return `CV_ERR_INVALID_ARGUMENT`; oversized keys or
values return `CV_ERR_LIMIT`. A NULL value with nonzero length is invalid.
Allocation failures return `CV_ERR_NO_MEMORY`. Supplied read/statistics outputs
are reset on failure. Initialization may return `CV_ERR_CRYPTO`; time-dependent
operations propagate clock errors. An unrepresentable expiration deadline returns
`CV_ERR_LIMIT` without modifying an existing live entry's TTL.

## Expiration and reclamation

Deadlines use monotonic milliseconds: `GetTickCount64` on Windows and
`clock_gettime(CLOCK_MONOTONIC)` on POSIX. Wall-clock adjustments do not move
deadlines. Platform suspend behavior follows the selected clock (Linux monotonic
time excludes suspend). Deadlines are process-local and must not be serialized
directly into future persistence files.

`EXPIRE key 2` sets the deadline to the current reading plus 2,000 ms. An entry
is expired at `now >= deadline`. `TTL` rounds remaining seconds down: a result of
zero can describe a live entry with less than one second remaining. Positive
expiration replaces the previous deadline. Zero or negative expiration deletes
immediately. `SET` always clears expiration, including when replacing an expired
physical entry. Expired entries cannot be revived by `EXPIRE`.

`GET` and `TTL` are read-only and hide expired entries without freeing them.
`DEL` and `EXPIRE` reclaim expired entries they encounter, while still reporting
`CV_ERR_NOT_FOUND`. `cv_hashtable_purge_expired` sweeps the whole table using one
clock reading and returns the number removed. The server calls it on a timer
(`--expiry-sweep-ms`) to reclaim untouched expired values; the table creates no
background thread. Clock failure leaves a sweep unchanged.

`cv_hashtable_get_stats` reports physical entries, bucket count and longest chain.
Expired entries remain included until reclaimed. It does not read the clock.
This distinguishes logical expiration from actual memory reclamation.

`cv_hashtable_create_with_clock` accepts a custom clock and borrowed context for
tests or embedding. Readings must be monotonically nondecreasing uint64 values
in milliseconds; wrapping/decreasing clocks violate the API contract. The callback
must not reenter the table, and its context must outlive it.

## Hashing, collisions and growth

Each table receives a private, random SipHash key via libsodium's
[`crypto_shorthash`](https://doc.libsodium.org/hashing/short-input_hashing).
Keyed hashing makes bucket placement harder to predict from external inputs.
It does not eliminate collisions: separate linked chains resolve them, and
lookups compare cached hash, key length and actual key bytes.

The table starts with 16 buckets. Before a new entry would exceed 75% occupancy,
it doubles the bucket array and redistributes entries using cached hashes.
Power-of-two bucket counts map SipHash's uniformly distributed low bits with a
mask. Rehashing does not recopy key/value buffers. Growth allocates the replacement
array first; failure leaves existing chains intact. Capacity arithmetic is
checked before allocation. Deletion does not shrink the bucket array, avoiding
resize churn when inserting/deleting repeatedly.

Average lookup/insertion/deletion cost is O(1), with bounded key hashing/comparison;
the worst case is O(n) if entries collide. Growth costs O(buckets + entries) with
amortized O(1) insertion. Sweeping, destruction and full statistics traversal
cost O(buckets + entries). Memory is proportional to buckets plus owned entries
and buffers. There is no global entry/memory quota yet; callers must provide
resource admission controls when exposing the store to clients.

## Example

```c
#include <stdio.h>
#include "cvault/hashtable.h"

int main(void) {
    cv_hashtable *table = NULL;
    cv_status status = cv_hashtable_create(&table);
    if (status != CV_OK) {
        return 1;
    }
    const unsigned char input[] = {'h', 'i', 0, '!'};
    status = cv_hashtable_set(table, "demo:key", input, sizeof(input));
    if (status == CV_OK) {
        status = cv_hashtable_expire(table, "demo:key", 30);
    }
    const unsigned char *value = NULL;
    size_t length = 0;
    if (status == CV_OK) {
        status = cv_hashtable_get(table, "demo:key", &value, &length);
    }
    if (status == CV_OK && length != 0) {
        if (fwrite(value, 1, length, stdout) != length) {
            status = CV_ERR_IO;
        }
    }
    cv_hashtable_destroy(table);
    return status == CV_OK ? 0 : 1;
}
```

All access requires external synchronization, even read-only operations if another
thread can mutate the table. Borrowed values must be consumed within that protected
scope. No internal locks or stable iterators are provided. `cv_hashtable_visit` uses one
clock reading and borrowed slices; its callback must not mutate/reenter the table.
It can include physically retained expired entries for snapshot-history recovery.
`cv_hashtable_clone` deep-copies live entries with exact monotonic deadlines and
preserves the borrowed clock/context. `cv_hashtable_expire_ms` supports millisecond
deadlines with the same overflow/deletion rules. [Persistence](persistence.md)
owns a table and uses these helpers; durable mutations must use its API.

## Verification

`hashtable` covers ownership, embedded NULs, empty/maximal values, key/value bounds,
replacement, borrowed-input copying, missing keys, invalid arguments, clock errors,
TTL replacement/clearing, exact deadlines, immediate deletion and integer overflow.
It inserts/retrieves 4,096 entries across multiple growth steps, expires half,
sweeps, deletes the rest and reuses the empty table.

`hashtable_faults` compiles the actual implementation in a private test translation
unit with allocator/hash redirects. It forces identical full hashes for 128 keys,
checks lookup/growth and chain deletion/sweeping, injects failures at every
allocation stage (including growth), tracks leaks/double frees and checks owned
key/value bytes are zero before they are freed. These redirects are absent from
production targets. Tests remain enabled in Release builds and run under the
existing CI's sanitizer preset on Linux.

Run `ctest --test-dir cmake-build-debug --output-on-failure` with the configured
CMake tools, or use the project's build/test presets described in
[development.md](development.md). Linux sanitizer execution still requires the
Linux/WSL toolchain or CI; a passing Windows build does not establish that result.
