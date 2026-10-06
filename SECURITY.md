# Security policy

## Do not use cvault to protect real data

cvault is a **learning project**. It has never been audited by a third party, it
carries no security or compliance certification, and it is **finished: it will not
receive security fixes or any other update**. Use it to study how such a system can be
built, not to hold secrets you care about. For real needs, use a mature, maintained
product.

## Supported versions

| Version | Supported |
|---|---|
| Any | **No.** There is no maintained version and no patch policy. |

## Reporting a vulnerability

You may still report what you find; it can be valuable to other learners.

1. Prefer GitHub's private channel: open the repository's **Security** tab and choose
   *Report a vulnerability* (private vulnerability reporting), if it is enabled.
2. If it is not available, open an issue that describes the *class* of the problem and
   the affected component, **without** a working exploit, keys, passwords or real data.
   Do not include your own secrets in any report.

Please understand what to expect:

- **No guaranteed answer, no timeline and no fix.** The maintainer does not monitor
  reports and has no obligation to respond.
- A confirmed finding may be recorded in the documentation (for example in the
  limitations of [docs/security.md](docs/security.md)) instead of being fixed.
- You are free to publish your findings. Coordinated disclosure is appreciated but not
  required, since there is nothing to patch and no users to protect through this
  repository.

## What is in scope

Flaws in this code base compared with its own documented design:

- bypass of authentication (Argon2id logins, the attempt limit and the rate gate) or
  of the per-prefix read/write permissions, including through EXPORT and PURGE;
- missing or wrong audit events, or a way to alter, reorder or remove audit records
  without detection;
- recovery, journal, snapshot or compaction behaviour that loses acknowledged data,
  accepts forged or altered records, or exposes plaintext on disk;
- memory-safety problems and undefined behaviour in the parser, transport or storage.

## What is out of scope

These are known limits, documented in [docs/security.md](docs/security.md) and
[docs/persistence.md](docs/persistence.md):

- there is **no TLS**: traffic on the network is not encrypted, so keep the server on
  loopback or behind an authenticated encrypted tunnel;
- a compromised host, access to process memory, swap or core dumps, and physical
  attacks on the machine;
- denial of service beyond the documented bounds (connection cap, frame limits,
  timeouts, one verification every 250 ms);
- physical erasure on SSDs, backups and file system snapshots, even after compaction;
- removal of a complete suffix or whole-file rollback of the audit log without an
  external trusted anchor;
- the absence of key rotation, online policy reload and audit rotation;
- weaknesses of third-party code that are not specific to how cvault uses it
  (libsodium, vendored argparse): report those upstream.

## What the project does to find problems

For transparency, and for anyone studying the method: the grammar is checked against
an independent reference implementation, a deterministic fuzzing campaign attacks the
parser, the encrypted record codec, the policy loader and the whole service,
sanitizer builds abort on undefined behaviour, and injected bugs are shown to be
detected. The results and their limits are written down in
[docs/fuzzing.md](docs/fuzzing.md). This is evidence, not proof of security.
