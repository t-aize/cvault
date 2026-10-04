# Encrypted persistence

The persistence module owns a hash table, an authenticated append-only journal and
atomic snapshots. It restores state before the server binds its listening socket.
Both file types encrypt user keys and binary values with libsodium's
[XChaCha20-Poly1305 AEAD](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction).
The public interface and ownership/error contracts are in `include/cvault/persist.h`.
Authentication and text storage-command dispatch remain unfinished: PING/QUIT do
not access this database. Embedders use the durable C API directly.

## Enable storage

Persistence is opt-in. Without these options the server creates no data files.
Generate a private key once, keep it outside version control, and back it up
separately from the data. A lost key makes recovery impossible.

```powershell
.\cmake-build-debug\cvault-server.exe --generate-key .\master.key
.\cmake-build-debug\cvault-server.exe --data .\data --key-file .\master.key
```

```sh
./build/debug/cvault-server --generate-key ./master.key
./build/debug/cvault-server --data ./data --key-file ./master.key
```

Key generation creates an exact 32-byte random binary file exclusively; an existing
path is never overwritten. The server requires `--data` and `--key-file` together.
`--snapshot-interval-ms` accepts 1..INT_MAX, defaults to 60,000, and requires storage.
It schedules one background checkpoint at a time. Graceful shutdown joins the job
and makes a final synchronous snapshot. Disk operations and joining a worker can
block; the network response-drain timeout does not bound disk latency.

Files in the data directory:

| File | Purpose |
|---|---|
| `journal.aof` | Ordered encrypted mutations; synchronized on every success |
| `snapshot.cvs` | Complete authenticated checkpoint at a journal sequence |
| `writer.lock` | Exclusive writer lock, held until close |
| `.snapshot-<random>.tmp` | Temporary checkpoint; orphaned crash files are ignored |

Use a trusted private local directory whose parent already exists. POSIX creates
directories with mode 0700 and files with mode 0600; existing directories must be
owned by the caller and not group/world writable. Existing files must be owned,
regular, single-link and have no group/other permissions. Leaf symlinks are rejected.
Windows uses UTF-8 paths converted to UTF-16 and creates objects with a protected
DACL allowing the owner and SYSTEM; existing DACLs remain the operator's responsibility.
Leaf reparse points and hard-linked files are rejected. Parent paths must be trusted;
this is not a directory-descriptor-based defense against a malicious filesystem.
Do not remove/replace `writer.lock` while a writer is running. Network filesystems,
shared writers, and arbitrary third-party edits to these files are unsupported.

## Durable C API

```c
#include "cvault/crypto.h"
#include "cvault/persist.h"

cv_status example(const char *directory, const char *key_file) {
    unsigned char key[CV_PERSIST_KEY_BYTES];
    cv_status status = cv_persist_key_load(key_file, key);
    cv_persist *store = NULL;
    cv_persist_options options = {directory, key, sizeof(key), NULL, NULL};
    if (status == CV_OK) status = cv_persist_open(&options, &store);
    cv_crypto_wipe(key, sizeof(key));
    const unsigned char binary[] = {0, 42, 255};
    if (status == CV_OK) status = cv_persist_set(store, "demo:key", binary, sizeof(binary));
    if (status == CV_OK) status = cv_persist_expire(store, "demo:key", 60);
    if (status == CV_OK) status = cv_persist_snapshot_start(store);
    /* Continue serialized mutations here; later records remain in the journal. */
    if (status == CV_OK) status = cv_persist_snapshot_wait(store);
    cv_status closed = cv_persist_close(store);
    return status == CV_OK ? closed : status;
}
```

Serialize public calls on one owner thread. `cv_persist_get` returns borrowed
binary bytes until the next successful mutation or close. Empty values are valid.
SET clears a previous TTL; DEL/EXPIRE on a missing key writes nothing and returns
`CV_ERR_NOT_FOUND`. Nonpositive EXPIRE durably deletes. GET/TTL share the core's
limits and missing/persistent TTL conventions. The read-only table getter is for
inspection; casting away const and mutating it bypasses persistence.

Each mutation deep-copies the live table and prepares its change before disk I/O.
It appends an authenticated record, flushes stdio and synchronizes the file, then
swaps the owned table pointer. Allocation, argument or overflow errors preserve
both the journal and published memory. Mutations cost O(live entries + live bytes)
and temporarily hold two tables. This deliberate correctness-first implementation
is intended for small stores; it has no write batching, total-memory quota, file-size
quota or automatic log compaction. Monitor available storage and size externally.

An append/flush/synchronization failure makes the handle unusable for data access
and further writes; stats/close still work. **Close and reopen to reconcile state.**
A failed mutation may have reached disk and can appear after recovery. Do not retry
non-idempotent operations blindly. Snapshots failing before publication leave the
previous checkpoint intact and do not poison the journal handle. A rename followed
by directory-sync failure is an uncertain publication: a complete new checkpoint
may already be visible. Filesystem/device guarantees still apply; tests cannot
simulate every power-loss or hardware failure.

## Replay and expiration

Startup authenticates the snapshot (if present), then every journal record,
including records preceding the snapshot boundary. It applies only records beyond
that boundary. UUIDs must match, sequence numbers must be contiguous, and a snapshot
cannot reference history absent from an existing journal. A standalone complete
snapshot can restore a directory without a journal; a new journal starts at its
sequence. This discards mutations after that checkpoint, so keep a consistent
journal/snapshot pair when backing up a complete database.

Persisted expirations are absolute Unix-epoch milliseconds; runtime deadlines use
the monotonic clock. Recovery first applies history to a frozen table, then drops
expired entries and converts remaining deadlines to monotonic durations. This
avoids losing a historical key before a later EXPIRE extends it, and ensures downtime
consumes TTL. Snapshots retain expired physical entries with expired deadlines so
later tail operations can still reconstruct their history; they remain invisible
in the recovered live table unless a later operation revives/extends them.
Wall-clock adjustments affect persisted TTLs across restarts. Pairing clock readings
can conservatively shorten a deadline by the time between readings; submillisecond
precision is not provided. Maintain a trustworthy system clock.

Only an incomplete **final** journal frame (short header or body) is truncated to
the last authenticated boundary and synchronized. Stats report `repaired_tail`.
A complete malformed frame, bad tag, wrong key, invalid sequence or incomplete
snapshot fails closed. No listener opens on recovery failure. Keep the files for
inspection; never erase corrupt storage to make startup succeed automatically.
A torn file header is fatal rather than treated as a new empty database.

## Snapshot backends

Synchronous snapshots write a new exclusive temporary file in the same directory,
append an authenticated END footer, synchronize and close it, then replace the
checkpoint atomically. The journal is retained in full; snapshots speed up state
application but **all journal bytes are still read and authenticated** at startup.

POSIX background snapshots use `fork` and the inherited copy-on-write table. The
parent continues its event loop and appends later mutations. The child closes
inherited descriptors (including listening/client sockets and its lock descriptor)
without unlocking the shared lock, reseeds libsodium's RNG, writes the checkpoint
and exits with `_exit`. It includes physical expired entries because a later parent
operation may already have extended their TTL. The owner reaps its specific child
with `waitpid`; the application must not ignore SIGCHLD or reap this child itself.
**Start fork snapshots only from a single-threaded process**, with no reentrant
signal handlers or non-fork-safe injected callbacks. For multithreaded embedders,
use a synchronous snapshot while externally serializing storage access.

Windows background snapshots first copy an owned immutable table with frozen epoch
deadlines on the owner thread. A native worker thread writes that copy; it never
reads the mutable database or calls the borrowed clock callback. The copy briefly
blocks the caller and costs O(physical entries + bytes). Poll/wait joins and frees
it before reporting completion. Closing a store always joins an active job.
Only one job may be outstanding; starting another or requesting a synchronous
snapshot returns `CV_ERR_BUSY` until the owner polls/waits the first job.

POSIX uses file `fsync`, atomic same-directory `rename`, and directory `fsync`.
macOS additionally requests `F_FULLFSYNC` for file data to flush drive caches,
following [Apple's fsync guidance](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html).
Windows uses `FlushFileBuffers` and `MoveFileExW` with replacement/write-through;
it has no portable equivalent directory flush, so power-loss metadata guarantees
are weaker. Storage hardware, caches and filesystem implementation must honor the
requested operations. See [fsync](https://man7.org/linux/man-pages/man2/fsync.2.html)
and [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).

## Binary format v1

All integers are little-endian; there are no native structure dumps. Version changes
require a new magic and explicit migration support. The current format has no
password-derived keys or automatic key rotation.

| File header offset | Bytes | Field |
|---|---:|---|
| 0 | 8 | `CVAOF001` (journal) or `CVSNP001` (snapshot) |
| 8 | 16 | Random dataset UUID |
| 24 | 8 | Baseline journal sequence / snapshot boundary |
| 32 | 24 | Random XChaCha20 nonce |
| 56 | 16 | AEAD tag authenticating the first 32 bytes with empty plaintext |

Each frame has a 40-byte public header: encrypted-body length (4), reserved zero
(4), sequence (8), random nonce (24). AEAD associated data comprises the first 32
file-header bytes, this entire frame header, and the previous tag (16). The first
frame chains from the file-header tag. Journal sequences start at baseline + 1;
snapshot frame sequences start at 1 independently of their journal boundary.

The encrypted body contains operation (1), key length (4), value length (4), epoch
expiry (8; zero means persistent), key bytes and value bytes, followed by the AEAD
tag (16). Maximum body size is 65,825 bytes. Keys are 1..256 non-NUL bytes and values
0..65,536 arbitrary bytes. SET = 1; DELETE = 2 (no value/expiry); EXPIRE = 3 (positive
expiry, no value). Snapshots contain SET records followed by END = 127, with an empty
key, zero expiry and an eight-byte entry count value. Duplicate snapshot keys,
wrong counts, a missing END, trailing bytes or non-SET entries are rejected.

Random 192-bit nonces follow libsodium's recommendation. Sequence/UUID/tag chaining
detects corruption, reordering, duplication and cross-dataset splicing. Public
metadata reveals file type, sizes, UUID, record counts/order and snapshot boundaries.
There is **no external trusted counter**: removal of complete journal suffixes,
restoring older valid files, or substitution of an entire valid dataset cannot
always be detected. Snapshot footers detect valid-prefix snapshot truncation, but
this is not an anti-rollback system.

## Verification

`persistence` runs 26 black-box scenarios using Python's standard library, real
files and separate processes. Coverage includes binary/empty/maximal inputs, expiry
across downtime, historical TTL extension, full tail-byte truncation coverage,
header/tag corruption, record duplication/reordering, snapshot completeness,
standalone restore, dataset mismatch, wrong keys, single-writer locks, abrupt exit,
background checkpoint boundaries, concurrent journal mutations, close/join,
key-file policies, POSIX permissions/symlinks/hardlinks, and server recovery before
bind with periodic checkpoints. One POSIX-only permission scenario is skipped on
Windows. Private test builds inject clone, partial-write and post-sync failures;
these redirects are absent from production. Core helper tests cover exact cloned
deadlines, visitors, expired entries, clock errors and allocation cleanup/wiping.
Native `persistence_codec` tests also verify binary roundtrips and rejection of
authenticated malformed operation payloads.

Python 3.12+ is required for this suite; CI sets `CVAULT_REQUIRE_NETWORK_TESTS=ON`
to require both TCP and persistence integration tests. Run CTest using the existing
presets; tests remain active in Release. Windows GCC/MSVC and Linux WSL ASan/UBSan
have been exercised locally. macOS 26 Apple Silicon CI runs Apple Clang and current
LLVM in Debug/Release/ASan; its actual jobs require a push and a GitHub runner.
This is an educational implementation, not a production-security certification.
