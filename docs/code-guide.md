# Code organization and maintenance

This guide explains where behavior belongs, how ownership moves through the
application and which invariants a change must preserve. The public headers are
the API reference; [core](core.md), [network](network.md), [persistence](persistence.md)
and [security](security.md) describe runtime behavior and deployment.

## Source map

| Files | Responsibility |
|---|---|
| `main.c` | CLI validation, provisioning, startup, event loop, snapshot scheduling and shutdown |
| `server.c` | Socket ownership, bounded framing, backpressure, poll/epoll readiness and deadlines |
| `parser.c` | Allocation-free grammar, bounded borrowed slices and signed integer validation |
| `security_service.c` | Per-connection sessions, AUTH throttling, ACL-before-storage dispatch and fail-closed audit ordering |
| `auth.c` | Immutable credential policy, bounded PHC profiles and independent prefix grants |
| `audit.c` | Private encrypted event stream, schema validation, synchronization and verified JSON export |
| `hashtable.c` | Owned key/value memory, keyed hashing, collision chains, resizing and expiration |
| `persist.c` | Durable mutations, recovery, wall/monotonic deadline conversion and snapshot lifecycle |
| `persist_codec.c` | Versioned byte layout, little-endian encoding, AEAD and authenticated chaining |
| `persist_io.c` | Private files/locks, platform permissions, synchronization and atomic publication |
| `crypto.c`, `common.c`, `config.c` | Shared crypto initialization/wiping, status strings and defaults |

Private headers in `src/` support implementation collaboration; callers should use
the contracts in `include/cvault/`. The CLI client remains a guarded scaffold.
Test fixtures are separate executables: production servers expose no fault-injection
or test-only commands.

## Readability conventions

All project text is English. `.clang-format` defines four-space indentation,
100-column lines, explicit control-flow braces, expanded short functions/loops and
blank lines between definitions. Keep one statement per line and give variables
names that explain their role. Prefer small helpers for independent concerns:
reading policy bytes and parsing a policy record, for example, have separate
functions. Group a function into validation, preparation, execution and cleanup
with blank lines; comments should explain the invariant or reason for an ordering.
Do not repeat the code in prose or add banners around every trivial helper.

Document public entry points with input bounds, ownership/lifetime, output reset
behavior, errors, thread constraints and any non-obvious side effects. Local
comments explain details such as why Windows headers require a particular order,
why a deadline uses a monotonic clock, or why an intent must be synchronized before
a mutation. Keep error paths explicit and short. Do not compress independent
allocations, assignments or cleanup calls onto one line.

Use clang-format 23.1.2 (matching the current LLVM toolchain) for repository C files:

```powershell
$files = @(Get-ChildItem src, include, client, tests -Recurse -File |
    Where-Object { $_.Extension -in '.c', '.h' } | ForEach-Object FullName)
clang-format -i --style=file @files
clang-format --dry-run --Werror --style=file @files
```

Or, from a POSIX shell:

```sh
find src include client tests -type f \( -name '*.c' -o -name '*.h' \) \
  -exec clang-format -i --style=file {} +
```

Configure CLion to respect the repository's `.clang-format`. Keep order-dependent
platform includes separated with a comment so sorting cannot move SDDL before
Windows types or legacy Winsock before Winsock2. Formatting is optional tooling,
not a dependency of normal builds.

## A command's lifetime

1. The transport accumulates a bounded LF frame and gives the handler borrowed
   input/output buffers. One response is queued per client.
2. The parser validates the complete grammar and returns borrowed slices; it does
   not allocate or touch session/storage state.
3. AUTH first revokes previous privileges. Other data operations check the session
   and literal prefix permissions before any storage lookup.
4. The application synchronizes an audit intent, executes through the selected
   memory/durable storage API and synchronizes a result.
5. Only then does it format the response. GET's borrowed value is copied into the
   response before the handler returns or another mutation can invalidate it.
6. The transport wipes consumed input and sent output. Its disconnect notification
   wipes the session slot, including timeout/error/destruction paths.

Audit failure poisons the service. The owner checks that failure after each network
step and exits; further callbacks reject work. Persistence failure also poisons its
store. Do not convert these conditions into ordinary successful responses.

## Ownership and transactional boundaries

The transport owns sockets and peer buffers. The security service owns its policy,
audit handle and bounded sessions, plus an in-memory table when persistence is off.
The server entry point owns a persistent store; the security service borrows it.
Destroy the transport before the service, and the service before the persistent
store, so disconnect callbacks and borrowed handles remain valid through cleanup.

The table owns copies of keys/values. GET returns a borrowed value, valid only
until mutation/destruction. Durable mutations prepare a clone, synchronize their
record, then publish the prepared state. Allocation failure therefore leaves the
old state intact. An I/O failure can leave an unacknowledged committed record after
recovery; tests and callers must account for that ambiguity.

The storage/audit streams are independent, not a cross-file transaction. Intent
failure must prevent storage execution. Result failure can follow a committed
mutation and must stop further work. Neither a missing result nor an unreceived
response proves a mutation did not happen.

## Platform and clock boundaries

In-memory expiration and transport timers use monotonic milliseconds. Persisted
expiration and audit timestamps use Unix-epoch milliseconds. Persistence replay
first reconstructs history using a frozen clock, then materializes today's live
state; filtering intermediate expired records would lose later TTL extensions.

POSIX background snapshots use fork only from a single-threaded owner. Windows
uses an immutable copy on a worker. Never introduce an authentication worker thread
without redesigning the POSIX fork boundary. The audit handle belongs to the
parent; snapshot children close inherited descriptors and never write events.

File helpers own platform-specific permission/lock/durability details. The codec
owns the on-disk representation: never serialize C structs directly, rely on host
endianness, reuse nonces or discard authentication errors.

## Verification when changing behavior

Run the existing CTest suite in the relevant Debug/Release configurations. New
security/storage changes need meaningful negative and failure-path coverage, not
just success cases. `CHECK` remains enabled in Release. Integration tests use real
processes, files and TCP sockets; private compiled redirects inject allocation or
synchronization failures without changing production interfaces. Linux/macOS
sanitizer builds also exercise snapshot ownership and resource cleanup.

Formatting-only edits should preserve behavior; check the resulting diff for
include ordering and preprocessor/macro-sensitive code before compiling. Do not
claim remote CI ran until the corresponding pushed run has completed.
