# Convenience entry point for Linux and macOS. CMake remains the source of truth:
# every target below simply drives the matching CMake preset.

CMAKE ?= cmake
CTEST ?= ctest

.PHONY: all debug release test asan fuzz

# Default target.
all: debug

# Unoptimised build with debug information.
debug:
	$(CMAKE) --preset debug
	$(CMAKE) --build --preset debug

# Optimised build.
release:
	$(CMAKE) --preset release
	$(CMAKE) --build --preset release

# Build the debug preset and run the whole test suite.
test: debug
	$(CTEST) --preset debug

# Build with AddressSanitizer + UBSan and run the tests.
asan:
	$(CMAKE) --preset asan
	$(CMAKE) --build --preset asan
	$(CTEST) --preset asan

# Build the AFL++ parser harness (requires afl-clang-fast).
fuzz:
	$(CMAKE) -S . -B build/fuzz -G Ninja -DCMAKE_C_COMPILER=afl-clang-fast -DCMAKE_BUILD_TYPE=Debug -DCVAULT_BUILD_FUZZER=ON -DBUILD_TESTING=OFF
	$(CMAKE) --build build/fuzz
