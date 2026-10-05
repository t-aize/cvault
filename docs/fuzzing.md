# Parser fuzzing

Status: the parser, input harness and seed corpus are implemented. The parser
validates command names/arity, key/password/value bounds, LF/CRLF framing and signed
64-bit expiration. No sustained AFL++ campaign or parser security certification is
recorded. See [the protocol contract](security.md).

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
