# Security notes and implementation work

The scaffold has no usable data store, authentication mechanism or TCP listener.
It initializes libsodium, can wipe buffers and defaults the planned listener to
`127.0.0.1:6380`. Authentication placeholders cannot grant access.
Neither build success nor the dependency roundtrip test proves application security.

Before implementing the planned modules:

- Specify bounded command framing and reply framing, including values containing
  spaces/newlines, numeric overflows and binary data handling.
- Require AUTH before every sensitive command and check prefix ACLs independently
  for reads, writes, exports, purges and expiry changes.
- Use libsodium's Argon2id password APIs; provide credential provisioning without
  default passwords or command-line secrets. Bound costly authentication work.
- Design key provisioning, permissions, rotation and recovery. Never commit
  passwords, real test secrets, encryption keys or runtime data.
- Use fresh XChaCha20-Poly1305 nonces and authenticated metadata. Verify tags
  before exposing plaintext. Define a versioned record format before persistence.
- Design crash recovery, durability, atomic compaction and snapshot consistency.
  Never write plaintext values to data files or audit logs.
- Bound each client buffer and output queue. Handle partial socket reads/writes,
  timeouts, disconnects and cleanup on all allocation/I/O failure paths.
- Wipe plaintext/password/key buffers before freeing them; document ownership.
- Do not record AUTH arguments or SET values in logs. Define retention rules for
  audit logs, snapshots, exports and backups separately from live values.

Encryption at rest does not protect keys and plaintext in a running process or
hide network traffic. A future plaintext protocol should be restricted to
localhost or an authenticated encrypted tunnel until TLS is implemented.

`PURGE` and compaction remove logical records from current files. They cannot
guarantee physical erasure on SSDs or erase external backups and snapshots.
This project explores data protection concepts and does not claim compliance.
