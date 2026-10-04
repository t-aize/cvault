# cvault

A small **encrypted key-value store written in C**, designed to be accessible over TCP.
Think "mini Redis", with security and data protection as the main goal.

> **Current status: in-memory core, TCP transport and encrypted persistence implemented.**
> The C APIs support SET, GET, DEL, EXPIRE and TTL, an authenticated append-only
> journal, startup recovery and atomic background snapshots (POSIX fork / Windows
> worker). The server handles multiple clients, PING/QUIT and graceful shutdown.
> Authenticated storage command dispatch and the interactive CLI remain unfinished.
> Persistence is opt-in with `--data` and `--key-file`; the default server creates
> no data files. Documentation, code comments, tests and CI are in English.

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

# Equivalent convenience commands:
make
make test
make asan          # GCC/Clang on Linux/macOS; also runs tests
make release
```

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

```powershell
.\build\windows-gcc-16.2.0-debug\cvault-server.exe --help
.\build\windows-gcc-16.2.0-debug\cvault-cli.exe --version
```

On Linux the executables are `build/debug/cvault-server` and `build/debug/cvault-cli`.
The server accepts connections and configuration options:

```powershell
.\cmake-build-debug\cvault-server.exe --bind 127.0.0.1 --port 6380 --backend auto
```

Send `PING\n` to receive `+PONG\n`, or `QUIT\n` to receive `+OK\n` followed by closure.
Storage commands are rejected until command dispatch/authentication are implemented.
See the [TCP transport guide](docs/network.md) for options, embedding and tests.
See [encrypted persistence](docs/persistence.md) for `--data`, key provisioning,
startup replay, durability, snapshot backends and the durable C API. Interactive
CLI storage commands remain planned.

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
| Security | `AUTH` with Argon2id password verification | 🚧 |
| Security | Per-prefix read/write access control | 🚧 |
| Security | Audit log of sensitive operations | 🚧 |
| Robustness | Full parser validation, sustained fuzzing and sanitizer runs | 🚧 |
| Data protection | Compaction, automatic expiry and per-user export | 🚧 |

## Architecture

See the [in-memory core guide](docs/core.md) for API contracts, expiration rules,
memory ownership, examples, complexity and test coverage. The five operations
are implemented in the storage API; authenticated text command dispatch remains
planned. The [TCP transport](docs/network.md) handles connections and frames;
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
├── include/cvault/    # Module interfaces, limits, status codes
├── src/              # Server entry point and module skeletons
│   ├── main.c / server.c / config.c / common.c
│   ├── parser.c / hashtable.c / crypto.c / auth.c
│   └── persist.c / persist_codec.c / persist_io.c / audit.c
├── client/main.c     # CLI entry point
├── tests/            # Core, network, persistence and dependency tests + fuzz harness
├── scripts/          # Local Windows/CLion, Linux and macOS setup
├── docs/             # Core, network, persistence, development and security guides
└── .github/workflows/ci.yml
```

Interfaces are starting points and can evolve as each module is implemented.
`CV_ERR_NOT_IMPLEMENTED` distinguishes unfinished operations from success.

## Protocol (draft)

One command per line, terminated by LF (`\n`):

```text
AUTH <password>
SET <key> <value>
GET <key>
DEL <key>
EXPIRE <key> <seconds>
TTL <key>
EXPORT <prefix>
PURGE <key>
```

Replies will start with `+` (success), `-` (error) or `$` (value).
Exact escaping, value framing, numeric bounds and export framing still need a
specification before the parser and network layer are implemented.

## Security design and remaining work

The intended design protects against disk inspection, unauthenticated clients,
malformed input and password-comparison timing attacks. It does not protect
against process-memory inspection, a compromised host or network eavesdropping
(TLS is not planned for the first version). Bind to localhost by default.

All cryptographic primitives come from [libsodium](https://doc.libsodium.org/).
Its [official Windows installation guide](https://doc.libsodium.org/installation)
documents the prebuilt MinGW libraries used by the bootstrap script.
The journal and snapshots use authenticated encryption; client authentication,
key rotation and TLS remain unfinished. See [persistence guarantees and limits](docs/persistence.md).
See [security notes](docs/security.md) for the implementation checklist.

## Data protection goals

| Principle | Planned mechanism |
|---|---|
| Storage limitation | Automatic key expiry |
| Erasure | `PURGE` plus append-only log compaction |
| Access / portability | `EXPORT` by authorized prefix |
| Accountability | Sensitive-operation audit trail |
| Minimization | Bounded inputs, no unnecessary metadata |

Compaction alone cannot promise physical erasure from SSDs, backups or snapshots.
These are educational design goals, not a claim of GDPR compliance.

## Testing and roadmap

Current tests cover the hash table's binary values, ownership, input bounds,
collisions, resizing, expiration, clock failures and allocation rollback. A private
test build forces collisions and checks that key/value allocations are wiped before
freeing. Other tests check module linkage, safe scaffold behavior, parser input bounds,
libsodium initialization, an XChaCha20-Poly1305 dependency roundtrip and tamper rejection.
Checks remain enabled in Release builds. They do not validate unimplemented features.

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

1. Protocol specification and parser + negative/boundary tests.
2. Authenticated command dispatch and CLI integration; schedule expired-entry sweeps.
3. Journal compaction, storage quotas and benchmarks.
4. Authentication, key rotation and recovery tooling.
5. Audit log, prefix ACLs, export, purge and compaction.
6. Full fuzzing campaigns, Valgrind and power-loss testing.

## License

[MIT](LICENSE).
