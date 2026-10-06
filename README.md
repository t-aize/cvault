# cvault

A small **encrypted key-value store written in C**, designed to be accessible over TCP.
Think "mini Redis", with security and data protection as the main goal.

> **Learning project: finished, and no further updates are planned.**
> cvault was written to learn low-level C, networking, applied cryptography and
> secure design. It is **not production software**, it has never been audited, and it
> makes no security or compliance claim. The repository is kept as a complete,
> documented snapshot for study: **there will be no new features, bug fixes,
> dependency updates or support**, and issues or pull requests may go unanswered.
> You are welcome to read it, learn from it and fork it (MIT license).
>
> What it does: an authenticated, encrypted key-value server over TCP with SET, GET,
> DEL, EXPIRE, TTL, prefix-scoped EXPORT and PURGE, literal prefix read/write
> permissions, Argon2id logins, a tamper-evident audit log, an encrypted journal and
> snapshots with optional compaction, and an automatic expiry sweep. Journal
> recovery and background snapshots use POSIX fork or a Windows immutable-copy
> worker. The interactive CLI client is only a scaffold. Configure security
> explicitly; the default handler exposes only PING/QUIT. Code, documentation, tests
> and CI are in English.

## Why this project?

`cvault` is a learning project for low-level C and system programming:

- Memory management and data structures written from scratch.
- Network programming with sockets.
- Applied security: encryption, authentication, auditing and fuzzing.
- Data protection: minimization, erasure, retention and export.

It is not production software.

## Setup and build

Current stable versions were checked on **2026-10-01** and pinned in
[`toolchain.json`](toolchain.json): CMake **4.4.3**, Ninja **1.13.2**, GCC **16.2.0**,
Clang **23.1.2**, GDB **17.2** and libsodium **1.0.22**, including its current stable
updates. CMake 4.4.3+ and libsodium 1.0.22+ are required. GCC/Clang builds use **C23**;
MSVC uses **C17**, its latest supported stable C dialect. Presets use schema **12**.
Project sources use `-Wall -Wextra -Wpedantic -Werror` with GCC/Clang, or `/W4 /WX` with MSVC.

### Windows / CLion

From PowerShell in the project directory:

```powershell
.\scripts\bootstrap-windows.ps1
```

The script installs **w64devkit 2.10.0** (GCC 16.2.0, Ninja 1.13.2 and GDB 17.2),
the official CMake 4.4.3 Windows binary and the latest verified stable libsodium
MinGW archive. It checks every download against its pinned SHA-256, generates
local presets, then builds and runs the Debug tests. Downloads and dependencies
stay in `.deps/`; machine-specific paths stay in ignored `CMakeUserPresets.json`.
It does not change the global PATH or install system packages. The libsodium DLL
is copied automatically beside each executable.

To also prepare the official MSVC libsodium libraries:

```powershell
.\scripts\bootstrap-windows.ps1 -IncludeMsvc
```

In CLion, select `.deps/w64devkit-2.10.0/w64devkit` as the MinGW toolchain and
`.deps/tools/cmake-4.4.3-windows-x86_64/bin/cmake.exe` as its CMake executable.
Open the root `CMakeLists.txt`, reload presets, and select
`windows-clion-debug` or `windows-clion-release`.
Build `cvault-server`, `cvault-cli` or the test targets.
See [development instructions](docs/development.md) for exact paths and commands.

### Debian / Ubuntu / WSL

```bash
sudo apt install build-essential python3 pkg-config
# Use GCC 16.2 or Clang 23.1.2; see docs/development.md for provisioning.
python3 scripts/bootstrap-linux.py
source .deps/env.sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug

# Equivalent convenience commands (Linux and macOS only):
make
make test
make asan          # GCC/Clang on Linux/macOS; also runs tests
make release
```

Windows has no `make` entry point: use the `windows-clion-debug` and
`windows-clion-release` presets as shown in the
[development guide](docs/development.md#quick-reference-by-operating-system).
Sanitizer builds (`asan`) are not available natively on Windows; use WSL.

Use `CC=clang-23` for the bootstrap and CMake configuration to choose Clang.
The Linux bootstrap requires Python 3.12+ and installs CMake/Ninja/libsodium
locally; the compiler must already be available. The CI provisions it explicitly.
For a custom dependency installation, pass `-DSODIUM_ROOT=/path/to/libsodium`.

### macOS / Apple Silicon

```sh
brew update
brew install llvm pkg-config
brew upgrade llvm pkg-config
export CC="$(brew --prefix llvm)/bin/clang"
python3 scripts/bootstrap-macos.py
source .deps/env.sh
cmake --preset debug -DCVAULT_REQUIRE_NETWORK_TESTS=ON
cmake --build --preset debug
ctest --preset debug
```

The macOS bootstrap supports arm64 and x86_64, using verified universal CMake/Ninja
binaries and the same verified libsodium source as Linux. Python 3.12+, Xcode
Command Line Tools and make are required. Use a fresh build directory to switch
to Apple Clang (`CC="$(xcrun --find clang)"`). See [development](docs/development.md).

### Current executable behavior

Windows (PowerShell):

```powershell
.\build\windows-gcc-16.2.0-debug\cvault-server.exe --help
.\build\windows-gcc-16.2.0-debug\cvault-cli.exe --version
.\build\windows-gcc-16.2.0-debug\cvault-server.exe --bind 127.0.0.1 --port 6380 --backend auto
```

Linux:

```bash
./build/debug/cvault-server --help
./build/debug/cvault-cli --version
./build/debug/cvault-server --bind 127.0.0.1 --port 6380 --backend auto
```

macOS:

```sh
./build/debug/cvault-server --help
./build/debug/cvault-cli --version
./build/debug/cvault-server --bind 127.0.0.1 --port 6380 --backend auto
```

CLion on Windows places its builds in `cmake-build-debug\` instead. The
[development guide](docs/development.md#quick-reference-by-operating-system) lists
the commands and folders for every system side by side.

Send `PING\n` to receive `+PONG\n`, or `QUIT\n` to receive `+OK\n` followed by closure.
Enable authenticated storage with `--security`, `--audit` and `--audit-key-file`.
See [security setup and protocol](docs/security.md) for account provisioning, prefix
permissions, examples and audit export. Without security configuration, storage
commands remain rejected.
See the [TCP transport guide](docs/network.md) for options, embedding and tests.
See [encrypted persistence](docs/persistence.md) for `--data`, key provisioning,
startup replay, durability, snapshot backends, compaction and the durable C API.
The interactive CLI client is a scaffold only.

## Features

| Area | Feature | Status |
|---|---|---|
| Setup | C23/C17, CMake presets, current toolchain, CLion bootstrap, strict warnings | ✅ |
| Setup | libsodium initialization and secure buffer wiping | ✅ |
| Setup | CTest smoke tests, AFL++ harness and CI definitions | ✅ |
| Core | Hash table, collisions, resizing | ✅ |
| Core | `SET`, `GET`, `DEL`, `EXPIRE`, `TTL` (in-memory C API) | ✅ |
| Network | TCP server, multiple clients (`poll` / `epoll`, Windows `WSAPoll`) | ✅ |
| Persistence | Encrypted append-only log replayed at startup | ✅ |
| Persistence | Atomic snapshots (POSIX `fork`, Windows immutable-copy worker) | ✅ |
| Security | Encryption at rest (XChaCha20-Poly1305 journal/snapshots) | ✅ |
| Security | `AUTH` with Argon2id password verification | ✅ |
| Security | Per-prefix read/write access control | ✅ |
| Security | Audit log of sensitive operations | ✅ |
| Robustness | Full parser validation (independent reference), fuzzing campaign, sanitizer runs | ✅ |
| Data protection | Journal compaction (`--compact`) | ✅ |
| Data protection | Automatic expiry sweep (`--expiry-sweep-ms`) | ✅ |
| Data protection | Per-prefix `EXPORT` (paginated) and `PURGE` | ✅ |

## Architecture

See the [in-memory core guide](docs/core.md) for API contracts, expiration rules,
memory ownership, examples, complexity and test coverage. The five operations
are implemented in the storage API and authenticated text command layer.
The [code guide](docs/code-guide.md) explains module boundaries, ownership and the
code and documentation style. Every public header carries Doxygen comments
(`@brief`, `@param`, `@return`), so `include/cvault/*.h` is the API reference.
The [TCP transport](docs/network.md) handles connections and frames;
[encrypted persistence](docs/persistence.md) owns durable state and startup recovery.

```text
CLI <-- TCP text protocol --> network loop
                                  |
                              command parser
                                  |
                         authentication + ACLs
                                  |
                           in-memory hash table
                                  |
                    libsodium encryption wrappers
                                  |
                   append-only log / snapshots / audit
```

```text
cvault/
├── CMakeLists.txt / CMakePresets.json / Makefile
├── toolchain.json    # Verified stable versions and download hashes
├── cmake/FindSodium.cmake
├── third_party/      # Vendored argparse (MIT), pinned to an upstream commit
├── include/cvault/    # Module interfaces, limits, status codes
├── src/              # Server entry point and module implementations
│   ├── main.c / server.c / config.c / common.c
│   ├── parser.c / hashtable.c / crypto.c / auth.c
│   └── persist.c / persist_codec.c / persist_io.c / audit.c / security_service.c
├── client/main.c     # CLI entry point
├── tests/            # Core, parser (reference oracle), network, persistence, security tests + fuzzing
├── scripts/          # Local Windows/CLion, Linux and macOS setup
├── docs/             # Core, network, persistence, development and security guides
└── .github/workflows/ci.yml
```

`CV_ERR_NOT_IMPLEMENTED` is returned for unknown commands and for an option that the
platform cannot provide (for example the epoll backend outside Linux).

## Protocol

One uppercase command per LF/CRLF line:

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

AUTH is required before storage access. Prefix grants independently authorize
reads (GET/TTL/EXPORT) and writes (SET/DEL/EXPIRE/PURGE). Replies use `+` for success,
`-` for errors, `:<seconds>` for TTL and `$<length>\n<bytes>\n` for GET. The text
protocol preserves spaces in passwords/values but cannot carry NUL/CR/LF in them; the
C storage API remains binary-safe.

`EXPORT` returns, one page at a time, the live entries under a prefix that the
session is allowed to read (with their TTL), sorted by key; `+MORE <key>` tells the
client where the next page starts. `PURGE` erases the entries under a prefix that the
session is allowed to write, at most 100 per call, and answers `:<count>`. See the
complete [protocol and security contract](docs/security.md) for bounds and failure
semantics.

## Security design and limitations

The intended design protects against disk inspection, unauthenticated clients,
malformed input and password-comparison timing attacks. It does not protect
against process-memory inspection, a compromised host or network eavesdropping
(TLS is not implemented and will not be). Bind to localhost by default.

All cryptographic primitives come from [libsodium](https://doc.libsodium.org/).
Its [official Windows installation guide](https://doc.libsodium.org/installation)
documents the prebuilt MinGW libraries used by the bootstrap script.
The journal, snapshots and audit stream use authenticated encryption. Argon2id
authentication and prefix ACLs are implemented; key rotation and TLS are not. See
[persistence guarantees and limits](docs/persistence.md). See
[security notes](docs/security.md) for provisioning, guarantees and limits.

## Data protection

| Principle | Mechanism |
|---|---|
| Storage limitation | `EXPIRE`, plus a periodic sweep (`--expiry-sweep-ms`) that wipes expired values from memory |
| Erasure | `PURGE` by prefix, then a snapshot and journal compaction (`--compact`) drop the old encrypted records |
| Access / portability | `EXPORT` by authorized prefix, paginated, with TTLs |
| Accountability | Tamper-evident audit trail, including EXPORT and PURGE |
| Minimization | Bounded inputs, no unnecessary metadata, no keys or values in the audit log |

Compaction alone cannot promise physical erasure from SSDs, backups or snapshots.
These are educational mechanisms, not a claim of GDPR compliance.

## Testing and known limitations

Current tests cover the hash table's binary values, ownership, input bounds,
collisions, resizing, expiration, clock failures and allocation rollback. A private
test build forces collisions and checks that key/value allocations are wiped before
freeing. Other tests check module linkage, safe scaffold behavior, parser input bounds,
libsodium initialization, an XChaCha20-Poly1305 dependency roundtrip and tamper rejection.
Checks remain enabled in Release builds.

The parser is validated against an independent reference implementation of the
grammar: an explicit table of cases, every size boundary, exhaustive single-byte
mutations of each valid line and a 400,000-line random sweep must give identical
results. A deterministic fuzzing campaign (`cvault-fuzz-campaign`) attacks the
parser, the encrypted record codec (only exact prefixes of what was written may be
accepted), the policy loader and the complete security service, whose replies are
checked against a model and whose audit log must authenticate afterwards. A short run
is part of the suite; a weekly CI job runs millions of iterations under
AddressSanitizer and UBSan, which abort on undefined behaviour. Bugs injected on
purpose into the parser, the codec, the ACL check and EXPIRE are all detected. See
[fuzzing](docs/fuzzing.md) for the method and the results.

Network tests exercise real TCP sockets: concurrency, frame fragmentation/pipelining,
partial writes, slow-reader isolation, half-closes, resets, connection limits,
IPv4/IPv6, timeouts, callback failures and bounded shutdown. Python 3.12+ enables
the integration suites; CI requires it. Linux runs both poll and epoll, Windows
WSAPoll and macOS poll. Persistence tests cover corruption, torn writes, recovery,
expiration, snapshot consistency, locks and injected allocation/I/O failures.

CI uses Ubuntu 26.04 runners with the official GCC 16.2.0 container and Clang 23
from LLVM's repository, testing Debug, Release and ASan/UBSan. Windows Server 2025
with Visual Studio 2026 tests GCC and MSVC in Debug and Release. macOS 26 Apple
Silicon tests Apple Clang and current stable LLVM in Debug, Release and ASan/UBSan.
Build tools and libsodium use the same verified downloads as local setup.
Checkout **7.0.1** and
setup-python **7.0.0** use explicit version tags; Dependabot checks
GitHub Actions daily. Remote CI execution requires pushing the repository.
The parser harness can be built now; see [fuzzing instructions](docs/fuzzing.md).

Security tests cover real AUTH/ACL dispatch, reauthentication revocation, session
isolation, strict grammar, persistence restart and authenticated audit export.
Private synchronization faults prove that failed audit intents prevent mutations
and failed audit results stop further work. Compaction, the expiry sweep, EXPORT and
PURGE have their own unit, crash-window, fault-injection and end-to-end tests.

Not implemented, and not planned (the project is finished):

1. An interactive CLI client (only a scaffold exists).
2. TLS, key rotation and online policy reload.
3. Audit retention, rotation and remote sequence anchoring.
4. Storage quotas, benchmarks, Valgrind runs and power-loss testing.
5. Multi-day AFL++ campaigns on dedicated hardware.

## Third-party code

Command-line parsing uses [cofyc/argparse](https://github.com/cofyc/argparse) (MIT),
vendored in [`third_party/`](third_party/README.md) at commit `4e30aba` (2025-09-26),
the latest upstream revision. Cryptography comes from libsodium (see above).

## License

[MIT](LICENSE).
