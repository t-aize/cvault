# Fuzzing and robustness validation

Three layers check that malformed input cannot make the parser, the record codec,
the policy loader or the security service misbehave:

1. **Reference validation of the parser** (`parser` test): an independent
   implementation of the grammar must agree with the production parser.
2. **An in-process fuzzing campaign with oracles** (`fuzz_campaign` test, longer runs
   on demand and weekly in CI): runs on every platform and under every sanitizer.
3. **AFL++** (coverage guided, Linux and macOS): described at the end of this page.

What has and has not been run: the campaign has been run locally, and its short run
is part of the test suite. The weekly CI job has not run on GitHub so far, and no
multi-day AFL++ campaign has been run. The campaign covers the parser, the record
codec, the policy loader and the request pipeline; the rotation and reload paths
added later (audit rotation, key rotation, policy reload) are covered by the
end-to-end tests of their own, not by the fuzzer.

Sanitizer builds (`asan` preset on Linux and macOS) enable AddressSanitizer and
UBSan with `-fno-sanitize-recover=undefined`, so undefined behaviour aborts the test
instead of only printing a diagnostic.

## Parser validation against a reference

`tests/parser_reference.c` re-implements the request grammar of
[security.md](security.md) with different code (no shared helpers with
`src/parser.c`). `tests/test_parser.c` runs both on the same input and requires
identical status, command type, every field and every borrowed pointer:

* an explicit table of 79 cases that documents the grammar,
* every size limit on both sides of its boundary (keys 256 and 64, passwords 1024,
  values 65,536, whole line 65,824),
* every byte value at every position, every truncation and many insertions for
  each valid seed line,
* 400,000 pseudo-random lines made of grammar fragments and arbitrary bytes.

## In-process fuzzing campaign

`cvault-fuzz-campaign` mutates valid inputs (bit flips, byte substitutions, deletions,
insertions, copies, swaps, truncations, grammar-aware tokens and, for the codec,
whole-record swaps, duplications and removals). It is deterministic: a seed
reproduces a run exactly, and a failure prints the seed. Each target has an oracle,
so a failure is a wrong answer and not only a crash:

| Target | What it feeds | What must hold |
|---|---|---|
| `parser` | Mutated seed lines, lines built exactly on every size limit | The production parser agrees with the reference on every input |
| `codec` | Encrypted record streams damaged at byte and record level | Everything accepted is an exact prefix of what was written: nothing forged, altered, reordered, duplicated or spliced gets through |
| `policy` | Mutated security policy files | Loading never crashes, a failed load returns no policy, an accepted policy denies an anonymous session |
| `service` | Random requests (including EXPORT and PURGE) to the whole security service, logged in and anonymous | Every reply matches a model of the storage and ACL behaviour, the service never fails, and the audit log it wrote verifies completely |

Run it on any system (iterations are per target; the `service` target runs a tenth,
because every request costs two synchronised audit writes):

Windows (PowerShell):

```powershell
$paths = Get-Content .deps/paths.json -Raw | ConvertFrom-Json
$env:PATH = "$($paths.cmakeBinDirectory);$($paths.binDirectory);$env:PATH"
cmake --preset windows-clion-debug
cmake --build --preset windows-clion-debug --target cvault-fuzz-campaign
.\build\windows-gcc-16.2.0-debug\tests\cvault-fuzz-campaign.exe --iterations 1000000 --seed 42 --corpus tests/fuzz/corpus --scratch $env:TEMP
```

Linux (with sanitizers):

```sh
source .deps/env.sh
cmake --preset asan && cmake --build --preset asan --target cvault-fuzz-campaign
./build/asan/tests/cvault-fuzz-campaign --iterations 1000000 --seed 42 --corpus tests/fuzz/corpus --scratch /tmp
```

macOS (with sanitizers):

```sh
source .deps/env.sh
cmake --preset asan && cmake --build --preset asan --target cvault-fuzz-campaign
./build/asan/tests/cvault-fuzz-campaign --iterations 1000000 --seed 42 --corpus tests/fuzz/corpus --scratch "$TMPDIR"
```

`--target NAME` (repeatable) selects `parser`, `codec`, `policy` or `service`. The
CTest `fuzz_campaign` runs 20,000 iterations on every platform. The `fuzz` job of
the CI workflow runs two million iterations per target under AddressSanitizer and
UBSan every Monday and on demand, with a new seed each time.

### Results

Local runs of the final code on Linux (Ubuntu under WSL, GCC 16, AddressSanitizer +
UBSan), one million iterations per target for each seed, 331 seconds in total:

| Seed | Parser inputs (identical to reference) | Codec streams (no forged record accepted) | Policy files | Service |
|---|---|---|---|---|
| 21 | 1,000,000 | 1,000,000 | 400 | 99,972 requests, 131,103 audit events |
| 22 | 1,000,000 | 1,000,000 | 400 | 99,973 requests, 131,225 audit events |
| 23 | 1,000,000 | 1,000,000 | 400 | 99,976 requests, 131,403 audit events |

That is 3,000,000 parser inputs, 3,000,000 damaged record streams and
299,921 service requests without a crash, a sanitizer report or a wrong
answer. The same campaign also passes natively on Windows (MinGW GCC, 50,000
iterations). This is evidence, not proof: a campaign of this size cannot find every
bug, and it is not a multi-day coverage-guided campaign.

### Do the checks detect bugs?

A fuzzer that never fails proves little, so bugs were injected on purpose and the
campaign (20,000 iterations) was run against each:

| Injected defect | Detected by |
|---|---|
| Parser accepts 257-byte keys | `parser`: disagrees with the reference |
| Codec without sequence numbers and previous-tag binding | `codec`: a reordered or removed record is accepted |
| ACL check skipped for TTL | `service`: a forbidden access is not denied |
| EXPIRE with a non-positive time keeps the entry | `service`: GET returns a value for an absent key |

The first attempts were not all detected, and that improved the campaign. The parser
defect went unnoticed until lines built exactly on the size limits were generated
(plain mutation of short seeds practically never reaches a 257-byte key), and the
codec defect until whole-record swaps, duplications and removals were added (byte
damage can never turn one valid record into another). Two further attempts were
*equivalent* defects, which no input can expose: ignoring a failed decryption still
yields an all-zero plaintext that the structural checks reject, and the explicit
sequence check is redundant because the whole frame is already authenticated. The
format is deliberately protected twice.

Building the campaign also exposed two real bugs of the new EXPORT code through the
fatal UBSan mode (`memcpy` with a NULL pointer and a zero length, and `qsort` on an
empty array), both fixed before the first commit of the feature.

## AFL++ (coverage guided, Linux and macOS)

Use the verified current **AFL++ 5.03c** release and build it from its official
release tag.

### Linux

Prepare the build tools and libsodium with `scripts/bootstrap-linux.py` first. The
commands assume LLVM/Clang 23 development packages are available from the official
LLVM repository:

```bash
sudo apt install git make clang-23 llvm-23-dev libclang-23-dev
git clone --depth 1 --branch v5.03c https://github.com/AFLplusplus/AFLplusplus.git .deps/AFLplusplus
make -C .deps/AFLplusplus LLVM_CONFIG=llvm-config-23 CC=clang-23 CXX=clang++-23
source .deps/env.sh
export PATH="$PWD/.deps/AFLplusplus:$PATH"
make fuzz
afl-fuzz -i tests/fuzz/corpus -o tests/fuzz/findings -- ./build/fuzz/cvault-fuzz-parser
```

### macOS

Prepare the tools with `scripts/bootstrap-macos.py` first. Following the AFL++
installation guide, use Homebrew's LLVM and GNU tools. AFL++ documents that macOS
fuzzing is slower than on Linux, that `afl-clang-lto`, `afl-gcc-fast` and QEMU mode do
not work there, and that the crash reporting daemon must be turned off, which
`afl-system-config` does:

```sh
brew install git make cmake llvm lld coreutils
export HOMEBREW_BASE="$(brew --prefix)/opt"
export PATH="$HOMEBREW_BASE/coreutils/libexec/gnubin:$HOMEBREW_BASE/llvm/bin:$PATH"
export CC=clang CXX=clang++
git clone --depth 1 --branch v5.03c https://github.com/AFLplusplus/AFLplusplus.git .deps/AFLplusplus
gmake -C .deps/AFLplusplus
sudo .deps/AFLplusplus/afl-system-config
source .deps/env.sh
export PATH="$PWD/.deps/AFLplusplus:$PATH"
make fuzz
afl-fuzz -i tests/fuzz/corpus -o tests/fuzz/findings -- ./build/fuzz/cvault-fuzz-parser
```

### Windows

The AFL++ documentation describes no native Windows build. Run the Linux commands
above inside WSL 2 (an Ubuntu distribution with the repository checked out on the
Linux file system). Natively, only the launch check below is available.

The harness reads stdin, passes a bounded buffer to `cv_parse_line`, and treats
normal parser errors as valid outcomes. AFL++ detects crashes/hangs. Inputs over
the protocol limit are bounded to one extra byte, allowing the limit error path
to be exercised. The harness targets the parser only; it does not simulate the
network stream buffer or multiple commands.

Build it without AFL++ for a basic launch check. On Linux and macOS:

```bash
cmake -S . -B build/fuzz-smoke -G Ninja -DCVAULT_BUILD_FUZZER=ON -DBUILD_TESTING=OFF
cmake --build build/fuzz-smoke
./build/fuzz-smoke/cvault-fuzz-parser < tests/fuzz/corpus/get.txt
```

On Windows (PowerShell), after `bootstrap-windows.ps1`. The tools are added to `PATH`
for the current session only, and `cmd` performs the binary-safe input redirection:

```powershell
$paths = Get-Content .deps/paths.json -Raw | ConvertFrom-Json
$env:PATH = "$($paths.cmakeBinDirectory);$($paths.binDirectory);$env:PATH"
cmake -S . -B build/fuzz-smoke -G Ninja -DCVAULT_BUILD_FUZZER=ON -DBUILD_TESTING=OFF
cmake --build build/fuzz-smoke
cmd /c "build\fuzz-smoke\cvault-fuzz-parser.exe < tests\fuzz\corpus\get.txt"
```

Expand seeds with every command, extreme numbers,
empty values, control bytes and malformed frames. Add minimized regressions as
normal tests. Keep passwords and real user data out of corpora and reports.

For each finding, record the compiler/AFL++ version, command, minimized input,
sanitizer trace, root cause and regression test. `tests/fuzz/findings/` is ignored;
review a minimized case before committing it to the corpus.
