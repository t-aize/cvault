# Development and CLion setup

## Verified stable tool versions

The current stable releases were checked on **2026-10-01**. Versions and archive
SHA-256 values are recorded in `toolchain.json`.

| Component | Version | Official source |
|---|---|---|
| CMake | 4.4.3 | [Release](https://github.com/Kitware/CMake/releases/tag/v4.4.3) |
| CMake preset schema | 12 | [Documentation](https://cmake.org/cmake/help/v4.4/manual/cmake-presets.7.html) |
| Ninja | 1.13.2 | [Release](https://github.com/ninja-build/ninja/releases/tag/v1.13.2) |
| GCC | 16.2.0 | [GCC releases](https://gcc.gnu.org/) |
| Clang / LLVM | 23.1.2 | [Release](https://github.com/llvm/llvm-project/releases/tag/llvmorg-23.1.2) |
| Windows MinGW toolkit | w64devkit 2.10.0 | [Release](https://github.com/skeeto/w64devkit/releases/tag/v2.10.0) |
| GDB | 17.2 | [Toolkit components](https://github.com/skeeto/w64devkit/blob/v2.10.0/Dockerfile) |
| libsodium | 1.0.22 + current stable updates | [Official downloads](https://download.libsodium.org/libsodium/releases/) |
| AFL++ (optional) | 5.03c | [Release](https://github.com/AFLplusplus/AFLplusplus/releases/tag/v5.03c) |
| actions/checkout | v7.0.1 | [Release](https://github.com/actions/checkout/releases/tag/v7.0.1) |
| actions/setup-python | v7.0.0 | [Release](https://github.com/actions/setup-python/releases/tag/v7.0.0) |

GCC/Clang builds use C23, the latest published stable C language standard. MSVC
uses C17, its latest supported stable C dialect. The project does not require
experimental C2y features or prerelease tools.

## Windows: local setup

Open PowerShell at the repository root and run:

```powershell
.\scripts\bootstrap-windows.ps1
```

The script downloads and verifies the toolkit, official CMake binary and stable
libsodium archive. It generates local presets, builds Debug and runs CTest.
Subsequent runs reuse the downloads. Add `-SkipBuild` to prepare tools and presets
without building. CLion itself does not need to be installed to run the script.
Existing personal `CMakeUserPresets.json` settings are not overwritten.

All tools and dependencies remain in `.deps/`. No global PATH changes or system
installations are made. Each libsodium stable snapshot has its own directory
identified by its pinned hash. The MinGW build uses the official libsodium DLL
and copies it automatically beside every executable, including tests and the
fuzzing harness. Keep this DLL beside an executable when copying it elsewhere.

For MSVC libraries, add `-IncludeMsvc`. These use the official non-LTCG static
libraries, `/MT` in Release and `/MTd` in Debug. The upstream v143 libraries are
ABI-compatible with Visual Studio 2026; project code uses its current v145 toolset.
See Microsoft's [binary compatibility documentation](https://learn.microsoft.com/en-us/cpp/porting/binary-compat-2015-2017).

## In CLion

1. Open the project directory or its `CMakeLists.txt`.
2. Under **Settings -> Build, Execution, Deployment -> Toolchains**, add a MinGW
   toolchain with the environment directory `.deps/w64devkit-2.10.0/w64devkit`.
3. Select `.deps/tools/cmake-4.4.3-windows-x86_64/bin/cmake.exe` as its custom CMake
   executable and `.deps/w64devkit-2.10.0/w64devkit/bin/ninja.exe` as the build tool.
   The previously bundled CLion CMake 4.3.1 cannot read schema 12 or meet the new
   minimum version requirement.
4. Reload CMake and select `windows-clion-debug` or `windows-clion-release`.
5. Build `cvault-server`, `cvault-cli` or the tests. Add `--help` or `--version`
   to executable run arguments to try the scaffold.
6. Run CTest, or the `cvault-test-core` and `cvault-test-sodium` targets.

If presets are not imported automatically, use a Ninja profile with the C compiler
and Ninja paths from `.deps/paths.json`. CMake automatically finds the matching
bootstrapped libsodium installation for MinGW or MSVC. An explicit `SODIUM_ROOT`
overrides this default. Shared settings live in
CMake, `.editorconfig` and `.clang-format`; `.idea/` and local presets stay ignored.

After changing toolchains, use **Tools -> CMake -> Reset Cache and Reload Project**
if the build reports a missing `CMakeFiles/rules.ninja`. This regenerates the
active profile's incomplete build directory before compiling.

## Rebuilding from PowerShell

```powershell
$paths = Get-Content .deps/paths.json -Raw | ConvertFrom-Json
$cmakeExe = Join-Path $paths.cmakeBinDirectory 'cmake.exe'
$ctestExe = Join-Path $paths.cmakeBinDirectory 'ctest.exe'
& $cmakeExe --preset windows-clion-release
& $cmakeExe --build --preset windows-clion-release
& $ctestExe --preset windows-clion-release
```

Build directories include the compiler version, for example
`build/windows-gcc-16.2.0-debug`. They also contain `compile_commands.json`.
New compiler versions use new directories, preserving previous build artifacts.

To test Visual Studio 2026 with the optional libraries:

```powershell
.\scripts\bootstrap-windows.ps1 -SkipBuild -IncludeMsvc
$paths = Get-Content .deps/paths.json -Raw | ConvertFrom-Json
$cmakeExe = Join-Path $paths.cmakeBinDirectory 'cmake.exe'
$ctestExe = Join-Path $paths.cmakeBinDirectory 'ctest.exe'
& $cmakeExe -S . -B build/msvc2026 -G 'Visual Studio 18 2026' -A x64 "-DSODIUM_ROOT=$($paths.msvcSodiumRoot)"
& $cmakeExe --build build/msvc2026 --config Debug
& $ctestExe --test-dir build/msvc2026 -C Debug --output-on-failure
```

## Linux / WSL

The Linux x86_64 bootstrap requires Python 3.12+, make, a compiler and pkg-config.
Install GCC 16.2 or Clang 23.1.2 first. Distribution defaults can be older; the CI
uses the official `gcc:16.2.0-trixie` image and LLVM's Clang 23 repository rather
than assuming the runner's compiler is current.

```bash
sudo apt install build-essential python3 pkg-config
python3 scripts/bootstrap-linux.py
source .deps/env.sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug

cmake --preset asan
cmake --build --preset asan
ctest --preset asan
```

The script installs the verified CMake/Ninja binaries locally and compiles the
current stable libsodium source snapshot, including its upstream `make check`.
Use `CC=clang-23 python3 scripts/bootstrap-linux.py` and
`CC=clang-23 cmake --preset debug` to select Clang. Use a fresh build directory
when switching compilers. The script does not install or upgrade the compiler.

The `asan` profile instruments project sources, leaving the libsodium dependency
uninstrumented. ASan + UBSan is enabled for Linux/macOS GCC/Clang toolchains.
The automatic Linux download script supports Linux x86_64; macOS/other architectures
need native CMake 4.4.3+, Ninja and libsodium 1.0.22+ installations.

## Updating version pins

GitHub Actions use explicit release tags, as requested. Dependabot checks those
actions daily and proposes version updates after the configuration is pushed.
Tool versions and archive hashes are a reviewed snapshot, not floating downloads.
Stable libsodium archive URLs can change: a fresh download with a changed hash is
rejected until the new archive is verified and its pin updated.

Before upgrading libsodium, verify its official Minisign signature using the key
published in the [libsodium installation guide](https://doc.libsodium.org/installation).
All three current libsodium archives were verified when preparing their pins.
Bootstrap scripts then check SHA-256; they do not repeat Minisign verification.
For GitHub release assets, compare hashes against the upstream release metadata.
Update `toolchain.json`, CMake minimum versions/presets and version references
in the documentation together, then rebuild Debug and Release and run CTest.

## Code organization and CI

Public interfaces live in `include/cvault/`; `cvault_core` groups the modules.
Scaffold functions return `CV_ERR_NOT_IMPLEMENTED`, authorization denies access
by default, and sensitive buffers should be wiped before freeing. Register new
tests in `tests/CMakeLists.txt`. Use `CHECK` for checks that must stay active in
Release builds. Current tests cover setup and dependency integration.

The workflow defines six Linux combinations (GCC/Clang x Debug/Release/ASan), plus
four Windows combinations (GCC/MSVC x Debug/Release). Windows uses the
`windows-2025-vs2026` runner. Checkout and Python setup actions use current explicit
tags; the setup selects the latest stable Python 3.x. Compilers and actual tool
versions are printed or verified during setup. Creating the workflow does not
execute its remote jobs.
