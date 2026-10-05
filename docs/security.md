# Authentication, prefix permissions and audit logging

The server's security layer implements Argon2id password verification, independent
read/write prefix permissions and a durable encrypted audit trail. Configure all
three options (`--security`, `--audit`, `--audit-key-file`) to enable authenticated
storage commands. Without them, the default handler accepts only PING and QUIT.
An incomplete configuration, invalid policy or corrupt audit file prevents binding.

## Provision credentials

Passwords never appear in server command-line arguments. Generate a password hash
from stdin using `cvault-server --hash-password`. An attached terminal prompts with
echo disabled; redirected stdin is supported for secret-management tooling. The
command reads one line, removes LF/CRLF, prints only its PHC hash and wipes its
password buffer. Use a strong, unique password; there is no default account or
password. Generation and authentication accept 1..1,024 password bytes. This is a
byte limit, not a Unicode character limit. The wire protocol cannot carry NUL/CR/LF.

The explicit profile is Argon2id v1.3, 64 MiB, two passes, one lane, with a fresh
random salt. Verification uses libsodium's password API. Imported hashes must use
this exact algorithm/version/cost; weak hashes and excessive memory/time costs
are rejected before clients can trigger verification. The PHC string includes its
salt and parameters. See [libsodium's password API](https://doc.libsodium.org/password_hashing/default_phf).
Passwords are credentials, independent of storage and audit encryption keys.

### Windows / PowerShell

Run from the project root, with the Debug executable built:

```powershell
$server = '.\cmake-build-debug\cvault-server.exe'
New-Item -ItemType Directory -Path '.\runtime' -ErrorAction Stop
# Remove inherited access, grant only the current user and System.
icacls '.\runtime' /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" 'SYSTEM:(OI)(CI)F'
$hash = & $server --hash-password
if ($LASTEXITCODE -ne 0) { throw 'Password hashing failed' }
$policy = "CVAULT-SECURITY-1`nuser alice $hash`nallow alice rw alice:`n"
[IO.File]::WriteAllText((Join-Path $PWD 'runtime\security.conf'), $policy, [Text.UTF8Encoding]::new($false))
& $server --generate-key '.\runtime\audit.key'
& $server --security '.\runtime\security.conf' --audit '.\runtime\audit.bin' --audit-key-file '.\runtime\audit.key'
```

Use a trusted private directory. Key/audit creation uses a protected owner/System
DACL; existing Windows file ACLs remain the operator's responsibility. If running
under a service account, grant that account access instead. Never commit `runtime/`,
credentials or encryption keys. Inspect command exit codes when provisioning.

### Linux / macOS

```sh
umask 077
mkdir runtime
./build/debug/cvault-server --hash-password
# Put the returned PHC string into runtime/security.conf as shown below.
chmod 600 runtime/security.conf
./build/debug/cvault-server --generate-key runtime/audit.key
./build/debug/cvault-server --security runtime/security.conf \
  --audit runtime/audit.bin --audit-key-file runtime/audit.key
```

Policy/key/audit files must be owner-private regular files. Leaf symlinks and
multiple hard links are rejected. Keep their parent directories trusted: the
implementation does not promise protection against a malicious parent directory
or filesystem. New POSIX files use mode 0600. See [persistence permissions](persistence.md).

Add `--data runtime/data --key-file runtime/store.key` to use durable storage,
after separately generating `runtime/store.key`. Otherwise the authenticated
server owns an in-memory table, lost at shutdown. Use different audit/storage
master keys so access and retention can be managed independently.

## Policy format and permissions

```text
CVAULT-SECURITY-1
# Each user must precede its permission records.
user alice <Argon2id-PHC-hash>
user writer <another-Argon2id-PHC-hash>
allow alice rw alice:
allow alice r shared:
allow writer w shared:
```

Replace the placeholders with real generated hashes. The format is ASCII, has no
BOM, uses single-space separators and requires a final LF (CRLF is accepted).
Blank lines and whole-line comments starting with `#` are allowed after the header.
There must be at least one user. Usernames are case-sensitive, 1..64 bytes, using
ASCII letters, digits, underscore, hyphen or period. Duplicate usernames, unknown
users in grants, unknown permission tokens and malformed hashes fail startup.
Limits: 32 users, 256 grants, 511 bytes per physical line, 128 KiB per policy file,
and 256 bytes per nonempty printable prefix. Tabs/control characters are rejected.

| Permission | Commands allowed |
|---|---|
| `r` | GET, TTL |
| `w` | SET, DEL, EXPIRE |
| `rw` | Both groups |

No implicit permissions exist. An account without grants can authenticate but
cannot access any storage key. Matching grants combine as a union; write does not
imply read. Prefixes are literal byte prefixes, case-sensitive, without globbing,
regular expressions or path normalization. Wildcards are rejected. Use a separator
such as `alice:` to avoid unintentionally allowing `alice-other`. The prefix
`alice:` allows `alice:x` and rejects `aliceevil:x`. More specific grants do not
remove a broader grant; there are no deny rules or implicit administrator role.

Every storage command checks authorization before looking up or mutating its key.
Forbidden existing and missing keys produce the same access-denied response.
TTL is read-sensitive; changing expiration or deleting is write-sensitive.
EXPORT and PURGE remain reserved and cannot bypass this layer.

Policies are immutable for the server lifetime. Stop, edit hashes/grants, then
restart to rotate credentials or permissions. Restart revokes all sessions. Audit
and persistence keys require an explicit offline migration to rotate; no automatic
key rotation is implemented.

## Wire protocol

Commands are uppercase and terminate with LF or CRLF. Keys/usernames are single
printable ASCII tokens. AUTH passwords and SET values are the remaining bytes
following exactly one separator after the key; spaces are preserved, including
leading/trailing spaces. An empty SET value requires that separator.

```text
PING
AUTH <username> <password>
SET <key> <value>
GET <key>
DEL <key>
EXPIRE <key> <signed-seconds>
TTL <key>
QUIT
```

Keys are 1..256 bytes and SET values 0..65,536 bytes. NUL, embedded CR and embedded
LF cannot be represented in this text protocol; no escaping is interpreted.
The storage C API remains binary-safe. GET uses a length-prefixed response and
can return binary values originating through that API. Frame limits are documented
in [network.md](network.md). EXPIRE accepts decimal signed 64-bit seconds, optional
`-`, no `+`, whitespace or trailing junk; nonpositive values delete immediately.
Overflow is rejected, preserving the existing value and TTL.

| Reply | Meaning |
|---|---|
| `+PONG\n` | PING; available before authentication |
| `+OK\n` | Successful AUTH/SET/DEL/EXPIRE/QUIT |
| `$<length>\n<bytes>\n` | GET value; length excludes framing |
| `$-1\n` | Authorized GET/DEL/EXPIRE on a missing key |
| `:<seconds>\n` | TTL; `-1` persistent, `-2` missing, otherwise whole seconds |
| `-ERR authentication failed\n` | Failed, malformed or rate-limited AUTH |
| `-ERR access denied\n` | Unauthenticated or unauthorized storage operation |
| `-ERR invalid command\n` | Grammar error or unsupported/reserved command |
| `-ERR operation failed\n` | Other nonfatal storage error |

Each accepted connection has independent session state keyed by a unique transport
ID. Disconnects, errors, timeouts and shutdown wipe/reclaim the session slot.
Every AUTH attempt clears prior privileges before validation or rate checking.
Three failed attempts on a connection close it after the response; a successful
AUTH resets that connection's failure count. Unknown usernames are verified against
a random dummy hash and receive the same error as wrong passwords. This reduces
enumeration timing differences; the complete request path is not constant-time.

A global monotonic gate admits at most one expensive verification every 250 ms,
including attempts from newly connected clients. Excess attempts return the generic
AUTH failure and revoke any current session. This gate bounds Argon2id work; it is
not a general network/audit requests-per-second limit. Verification is synchronous
on the single owner thread and can briefly delay all clients. Only one 64 MiB
verification executes at a time. There is no authentication worker thread, keeping
POSIX fork snapshots compatible with the single-threaded process requirement.

## Audit guarantees and reading events

The audit stream records START/STOP, authentication attempts/results, authorized
storage intents/results, permission refusals and malformed/unsupported commands.
PING/QUIT, transport-level malformed frames and disconnects are not sensitive
operation events. Failed authentication records use `anonymous`; untrusted candidate
usernames are never logged. Successful/authenticated operations use the validated
account name. Events contain no storage key, value, password or master key.
This deliberately trades per-key investigation detail for data minimization.

Each event contains Unix-epoch milliseconds, a client ID, request ID, operation,
phase, numeric `cv_status` and identity. Wall-clock timestamps can move backwards;
sequence is the ordering authority. Client/request IDs can repeat after restart;
use the START-delimited run and global audit sequence to identify intent/result
pairs. A synchronized intent precedes any authorized storage access or mutation;
the synchronized result precedes delivery of its response. AUTH results must be
synchronized before the successful session can be used by another command.

Audit records reuse the bounded XChaCha20-Poly1305 chained record codec with a
separate domain-derived key, random file UUID/nonces and sequence/previous-tag
binding. The 32-byte audit master key is private, copied only to derive an owned
key and wiped from the caller buffer. The derivation is keyed BLAKE2b-256 over
`cvault-security-audit-v1`. Disk metadata can reveal event counts/sizes and timing
of writes, but identities and event bodies are encrypted. One exclusive `.lock`
file prevents concurrent writers/exporters. No plaintext mirror is written.

Stop the server before exporting:

```powershell
.\cmake-build-debug\cvault-server.exe --dump-audit '.\runtime\audit.bin' --audit-key-file '.\runtime\audit.key'
```

The same command works with the POSIX executable path. Export authenticates the
entire file before writing JSON Lines, then checks each record again while reading.
The output contains sensitive identity metadata: protect exports and their backups.
The option order above is required for this standalone command. It never creates
a missing audit file. A wrong key, altered/reordered record or partial final record
fails closed; partial audit tails are never silently repaired or truncated.

Any audit write/sync failure poisons the handle and stops the application loop.
If intent synchronization fails, the mutation is not attempted. If result
synchronization fails after a mutation, the mutation may already be committed and
no success response is sent. A crash between intent and result has the same
uncertain-outcome meaning; do not treat intent alone as proof of completion.
Audit and storage are separate durable streams, not one cross-file transaction.
Preserve damaged files and investigate or restore a verified backup before restart.
A previously failed synchronization can leave a complete event on disk; startup
accepts it if the full chain authenticates. Forced termination cannot write STOP.

There is no automatic rotation, compaction, remote anchor or retention scheduler.
Startup/export scan the complete audit stream in O(file size), with fixed codec
buffers and no event accumulation. Plan disk capacity and retention. For offline
rotation, stop the server, archive the audit file together with a secure backup of
its key, then start with a new audit path. Retain old files for investigations.
Authenticated chaining detects edits and reordering, but cannot detect removal of
a complete suffix, replacement by an older authentic file, or deletion of the whole
file without an external trusted sequence anchor. Keep independently protected
backups if rollback evidence matters.

## C API, ownership and tests

Public contracts are in `include/cvault/auth.h` and `include/cvault/audit.h`.
Policy objects own hashes/grants and must outlive their sessions. Sessions borrow
the policy; callers must serialize access and reset sessions before policy teardown.
Password buffers are borrowed for verification, never retained; C API callers own
and wipe them. The network transport wipes consumed password frames and released
buffers. All service callbacks run on the transport's owner thread; disconnect
notifications release bounded session state. A borrowed persistent store must
outlive the security service. See [code guide](code-guide.md) for implementation flow.

`tests/test_security.py` exercises real servers and native fixtures: authentication,
reauthentication revocation, session isolation/reuse, independent prefix grants,
protocol boundaries, expiration, durable restart/background snapshots, malformed
policies, audit export, wrong keys, record tampering/reordering/torn tails, exclusive
locks and injected synchronization failures before/after mutations. POSIX additionally
checks permissions and symlinks. These tests run in the existing Windows/Linux/macOS
CTest matrix, including POSIX sanitizer configurations.

## Scope and remaining work

Encryption at rest does not protect a compromised host or running process memory.
Passwords and values are plaintext in memory; buffers are wiped on release but are
not guaranteed to be locked against swapping. The TCP connection has no TLS: keep
loopback binding or use an authenticated encrypted tunnel. There is no interactive
storage CLI, online policy reload, automatic account lockout across reconnects,
remote audit anchoring, audit rotation, storage quota or journal compaction yet.
Expired values become unreadable at their deadline; physical reclamation on reads
is not guaranteed. Neither the tests nor this design claim a security certification
or regulatory compliance. See [persistence limitations](persistence.md).
