# Convenience entry point for Linux/macOS. CMake remains the source of truth.
CMAKE ?= cmake
CTEST ?= ctest
.PHONY: all debug release test asan fuzz
all: debug
debug:
	$(CMAKE) --preset debug
	$(CMAKE) --build --preset debug
release:
	$(CMAKE) --preset release
	$(CMAKE) --build --preset release
test: debug
	$(CTEST) --preset debug
asan:
	$(CMAKE) --preset asan
	$(CMAKE) --build --preset asan
	$(CTEST) --preset asan
fuzz:
	$(CMAKE) -S . -B build/fuzz -G Ninja -DCMAKE_C_COMPILER=afl-clang-fast -DCMAKE_BUILD_TYPE=Debug -DCVAULT_BUILD_FUZZER=ON -DBUILD_TESTING=OFF
	$(CMAKE) --build build/fuzz
