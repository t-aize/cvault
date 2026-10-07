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

### Linux

Run from the project root, with the Debug executable built (`build/debug/`).
`umask 077` makes every file created below owner-private:

```sh
umask 077
mkdir runtime
hash="$(./build/debug/cvault-server --hash-password)"
printf 'CVAULT-SECURITY-1\nuser alice %s\nallow alice rw alice:\n' "$hash" > runtime/security.conf
./build/debug/cvault-server --generate-key runtime/audit.key
stat -c '%a %n' runtime runtime/security.conf runtime/audit.key   # expect 700 / 600 / 600
./build/debug/cvault-server --security runtime/security.conf \
  --audit runtime/audit.bin --audit-key-file runtime/audit.key
```

### macOS

The commands are the same as on Linux (the executable path is also
`build/debug/cvault-server`); only `stat` differs because macOS ships the BSD
variant:

```sh
umask 077
mkdir runtime
hash="$(./build/debug/cvault-server --hash-password)"
printf 'CVAULT-SECURITY-1\nuser alice %s\nallow alice rw alice:\n' "$hash" > runtime/security.conf
./build/debug/cvault-server --generate-key runtime/audit.key
stat -f '%Lp %N' runtime runtime/security.conf runtime/audit.key   # expect 700 / 600 / 600
./build/debug/cvault-server --security runtime/security.conf \
  --audit runtime/audit.bin --audit-key-file runtime/audit.key
```

The password prompt appears on the terminal (stderr) and the hash is captured from
stdout. Add further `user` and `allow` lines to `runtime/security.conf` with an
editor as described in the next section.

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
EXPORT and PURGE name a prefix instead of a key, so they require a login and then
apply the same grants to every entry they touch: EXPORT only returns entries the
session may read, PURGE only erases entries it may write (see
[Export, erasure and expiry](#export-erasure-and-expiry)).

### Changing the policy while the server runs

A loaded policy is immutable; changing credentials or permissions means loading a
new one. A restart always works and revokes every session. To avoid the downtime
the running server can reload the file:

- **`SIGHUP`** (Linux and macOS) reloads the policy at once, even if the file did
  not change. It works whenever `--security` is set.
- **`--policy-reload-ms <ms>`** (all platforms) checks the file's modification time,
  size and identity this often and reloads when one changed. The default is off.

Replace the file atomically (write a new file next to it and rename it over the old
one, as `mv` and most editors do): a reload that happens to read a half-written
file is rejected, harmlessly, but needlessly noisy.

A reload is all or nothing. A valid file replaces the policy and **revokes every
session**: sessions borrow the policy that authenticated them, so no privilege may
outlive it. Clients receive `-ERR access denied` until they send `AUTH` again, and
then get exactly the grants of the new file. A user who was removed can no longer
log in; a user who lost a grant loses it at once. The per-connection failure
counters are kept, so a reload does not hand out fresh `AUTH` attempts. A file that
cannot be loaded changes nothing: the server keeps the previous policy, prints a
warning, and does not try the same file again until it changes.

Every reload attempt is an audit event: operation `RELOAD`, phase `result`, identity
`server`, and the status of the load (`0` applied, otherwise the rejection reason).
If that event cannot be written the service stops, like any audit failure.

Credentials of the *audit* and *storage* keys are not part of the policy. Rotate
them with the offline commands described in [audit rotation](#audit-rotation) and in
[persistence](persistence.md#rotating-the-encryption-key).

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
EXPORT <prefix> [<after>]
PURGE <prefix>
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
| `*<n>\n` ... | One EXPORT page, see below |
| `:<count>\n` | PURGE; number of keys erased by this call (at most 100) |
| `-ERR authentication failed\n` | Failed, malformed or rate-limited AUTH |
| `-ERR access denied\n` | Unauthenticated or unauthorized storage operation |
| `-ERR invalid command\n` | Grammar error or unknown command |
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

## The command-line client

`cvault-cli` speaks this protocol. It connects over TCP (IPv4 or IPv6), optionally
authenticates, and runs commands in one of three ways:

```sh
cvault-cli --user alice --password-file runtime/alice.pw SET alice:note "hello world"
cvault-cli --user alice --password-file runtime/alice.pw GET alice:note
printf 'GET alice:a\nGET alice:b\n' | cvault-cli --user alice --password-file runtime/alice.pw
cvault-cli --user alice          # prompts for the password, then an interactive prompt
```

The same commands work on Windows with `cvault-cli.exe` from the build directory.

| Option | Meaning |
|---|---|
| `--host`, `--port` | Server address (default `127.0.0.1:6380`); a host name is resolved. |
| `--user` | Authenticate as this user right after connecting. |
| `--password-file` | Private file whose first line is the password. Without it the password is read from stdin: with a hidden prompt on a terminal, or as the first line of a pipe. |
| `--timeout-ms` | Longest wait for connecting, sending or receiving (default 10000). |

Passwords are never accepted on the command line, where they would show up in the
process list and the shell history. On Linux and macOS the password file must be
owned by the caller and closed to group and others, like the server's own files. A
value given as a command argument is visible in the process list as well; send
sensitive values through stdin.

With command words after the options, the client runs that one command and exits.
Without them it reads one command per line from stdin: on a terminal it shows a
`cvault>` prompt (with `help` and `exit`), otherwise it runs silently, which makes it
scriptable. The command word is upper-cased for you; keys and values are sent as
typed. Replies are printed for people and scripts alike:

| Server reply | Output |
|---|---|
| `+OK` / `+PONG` | `OK` / `PONG` |
| `$<n>` value | the value, verbatim, followed by a newline |
| `$-1` | `(nil)` |
| `:<n>` | the number (TTL, PURGE count) |
| EXPORT pages | one line per entry: `key<TAB>ttl<TAB>value`; pages are followed automatically until `+DONE` |
| `-ERR ...` | `(error) ERR ...` on stderr |

The exit status is 0 when every command succeeded and 1 when the server answered
with an error, the connection failed, or an option was invalid.

The server closes idle connections (`--idle-timeout-ms`) and after three failed
logins. Before each command the client checks the connection; if the server hung up
it reconnects and authenticates again (printing `(reconnected)` on stderr). A
command that was already sent is never repeated, because its outcome would be
unknown: if the connection breaks while waiting for a reply the client reports the
failure and the next command starts on a fresh connection. Because the server
verifies at most four passwords per second across all clients, and answers a
throttled attempt like a wrong password, the client retries `AUTH` once after
300 ms.

## Export, erasure and expiry

These commands give the data protection features of the project a protocol. They
never see more than the session's grants allow.

**EXPORT `<prefix>` [`<after>`]** returns the live entries whose key starts with the
literal `<prefix>` and which the session may read, sorted by key. Expired entries are
skipped, keys that cannot be written in the text protocol are skipped, and a session
without read grants gets an empty page, not an error. One reply is one page:

```text
*<entries in this page>\n
=<key> <ttl> <length>\n<length value bytes>\n       once per entry
+MORE <last key of the page>\n      or      +DONE\n
```

`<ttl>` is the remaining whole seconds, or `-1` without expiry. Values are length
framed, so they are binary safe. A page holds as many entries as fit one reply
(`CV_MAX_RESPONSE_BYTES`, about 65 KiB, always enough for one maximum-size entry).
After `+MORE <key>` the client repeats the command with that key as `<after>`; only
keys strictly greater than it are returned, so no entry is repeated or skipped by
the paging itself. Entries changed between two pages are of course seen as they
are at the time of each call. Each call scans the table (O(entries)) and sorts the
matches.

```text
> AUTH alice s3cret
< +OK
> SET alice:b hello world
< +OK
> SET alice:a 1
< +OK
> EXPORT alice:
< *2
< =alice:a -1 1
< 1
< =alice:b -1 11
< hello world
< +DONE
```

**PURGE `<prefix>`** erases the live entries under the prefix that the session may
write and answers `:<count>`. At most 100 keys are erased per call, so a long
operation stays short for every other client: repeat until the answer is below 100.
Each deletion is journaled like a DEL (it survives a crash, and on a durable store
each one copies the table, which is why the batch is small), and the command as a
whole is audited. Run a snapshot and a
compaction (`--compact`) afterwards so that the old encrypted records disappear
from the files; the limits of physical erasure are described in
[persistence](persistence.md#compaction-and-expiry-sweep).

**Expiry.** A value is unreadable at its deadline. To also remove it from memory
the server wipes expired entries on a timer, `--expiry-sweep-ms` (default 1000).
The sweep is not an audited operation: it only removes data that was already
unreadable, and it writes nothing to the journal.

## Audit guarantees and reading events

The audit stream records START/STOP, authentication attempts/results, authorized
storage intents/results (including EXPORT and PURGE), permission refusals,
malformed/unsupported commands, policy reloads (RELOAD) and log rotations (ROTATE).
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

Stop the server before exporting.

Windows (PowerShell):

```powershell
.\cmake-build-debug\cvault-server.exe --dump-audit '.\runtime\audit.bin' --audit-key-file '.\runtime\audit.key'
```

Linux:

```sh
./build/debug/cvault-server --dump-audit runtime/audit.bin --audit-key-file runtime/audit.key
```

macOS:

```sh
./build/debug/cvault-server --dump-audit runtime/audit.bin --audit-key-file runtime/audit.key
```

Export authenticates the
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

Startup/export scan the complete audit stream in O(file size), with fixed codec
buffers and no event accumulation, which is what rotation keeps bounded.
Authenticated chaining detects edits and reordering, but cannot detect removal of
a complete suffix, replacement by an older authentic file, or deletion of the whole
file without an external trusted sequence anchor. Keep independently protected
backups if rollback evidence matters.

### Audit rotation

Rotation seals the current log and continues it in a new file, so no single file
grows without bound and an old file can be archived, backed up or handed to an
investigator on its own.

- **Online:** `--audit-max-bytes <n>` makes the running server rotate as soon as the
  log reaches `n` bytes. The check runs between event-loop steps, never inside a
  request, so the intent and the result of one request always end up in the same
  file. A file can exceed `n` by the events of the requests handled in one step.
- **Offline:** with the server stopped,
  `cvault-server --rotate-audit runtime/audit.bin --audit-key-file runtime/audit.key`
  does the same on demand. Adding `--new-audit-key-file <file>` encrypts the *new*
  file under another key: this is the audit key rotation, because the sealed file
  stays readable with the old key and the continuation only with the new one. Start
  the server with the new `--audit-key-file` afterwards.

What happens, in order: an event `ROTATE` / `intent` becomes the last record of the
old file; a new file is written next to it (`<audit>.next`) with a fresh identity, a
header that continues the sequence numbering and a `ROTATE` / `result` event as its
first record, and is synchronised; the old file is renamed to `<audit>.<N>` where
`N` is its last sequence number in 20 digits; the new file is renamed to the audit
path. A name that already exists is never overwritten: the rotation is refused before
anything is written. Read an archive with `--dump-audit <archive> --audit-key-file
<the key it was written under>`. The sequence numbers of the archives and of the
active file together run `1..N` without a gap; `ROTATE` events mark every seam.

A crash at any point leaves a log that opens: before the first rename the old file is
intact and a stale `<audit>.next` is deleted at the next start; between the two
renames the audit path is missing, and the next start moves the complete
`<audit>.next` into place (if that rotation changed the key, start with the new
key). A rotation that fails without touching the old file (for example a full disk)
is reported once and not retried for the rest of the run, so the log is not flooded
with intent events; the server keeps serving and the log keeps growing. A failure
after the old file was renamed stops the server like any audit failure.

There is no cryptographic link between a sealed file and its successor: removing
a *whole archive* is only noticeable by the gap in the sequence numbers, and
removing the newest archive together with the active file is not noticeable at all
without an external anchor. There is also no retention scheduler: archives are never
deleted. Moving them to protected storage and deciding how long to keep them is the
operator's job, because deleting evidence automatically would defeat the point of
the log.

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
locks and injected synchronization failures before/after mutations. EXPORT is
tested for per-grant filtering, ordering, TTLs, binary-safe values, anonymous
refusal, expired entries and pagination over more than 300 KB including a
maximum-size value; PURGE for grant filtering, the 100-key batches and durability
across a restart, with their audit events; audit rotation (continuity of the
sequence across files, offline rotation with and without a new key, interrupted
rotations, refused archive names) and policy reload (by timer and by SIGHUP,
session revocation, rejected files, removed users). POSIX additionally
checks permissions and symlinks. These tests run in the existing Windows/Linux/macOS
CTest matrix, including POSIX sanitizer configurations.

## Encrypting the connection

cvault has no TLS, and it will not gain it inside the server: that needs a large
third-party library (OpenSSL or similar) with its own certificate handling and
release cycle, which this project deliberately avoids. The text protocol and the
password in `AUTH` are therefore plaintext on the wire. Keep the server on
loopback and put an authenticated, encrypted channel in front of it whenever a
network is involved. The simplest is an SSH tunnel:

```sh
# On the client machine: local port 6380 now reaches the server's loopback port.
ssh -N -L 6380:127.0.0.1:6380 user@vault-host
cvault-cli --user alice --password-file alice.pw GET alice:note
```

A TLS-terminating proxy such as stunnel, a WireGuard or IPsec tunnel, or a service
mesh sidecar works the same way: the server keeps listening on `127.0.0.1` and only
the proxy faces the network. Never bind the server to a public address and rely on
the password alone.

## Scope and limitations

Encryption at rest does not protect a compromised host or running process memory.
Passwords and values are plaintext in memory; buffers are wiped on release but are
not guaranteed to be locked against swapping. The TCP connection has no TLS (see
above). There is no automatic account lockout across reconnects (the global
verification gate limits the rate instead), no remote audit anchoring, no audit
retention policy and no storage quota. Rotation of the policy, the audit log and
its key, and the storage key are available; see the sections above and
[persistence](persistence.md#rotating-the-encryption-key).
Expired values become unreadable at their deadline and are wiped from memory by the
periodic sweep (so up to one sweep interval later). Neither the tests nor this
design claim a security certification or regulatory compliance. See
[persistence limitations](persistence.md).
