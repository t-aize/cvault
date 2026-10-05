#!/usr/bin/env python3
"""Install verified POSIX build tools and the current stable libsodium snapshot locally.

The script downloads pinned archives listed in ``toolchain.json``, verifies their
SHA-256 digests *before* extracting anything, and installs them under ``.deps/``:

* CMake and Ninja (prebuilt binaries),
* libsodium, compiled from source as a static library.

It finally writes ``.deps/env.sh`` (and the GitHub Actions ``GITHUB_PATH`` /
``GITHUB_ENV`` files when present) so that later build steps find the tools.
Supported hosts: Linux x86_64 and macOS arm64/x86_64.
"""

import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import stat
import subprocess
import tarfile
import time
import urllib.error
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parent.parent
DEPS = ROOT / ".deps"
VERSIONS = json.loads((ROOT / "toolchain.json").read_text(encoding="utf-8"))


def download(spec):
    """Download one pinned archive and return its verified local path.

    ``spec`` is an entry of ``toolchain.json`` with ``file``, ``url`` and
    ``sha256``. Downloads go to a ``.part`` file and are retried with
    exponential backoff on transient network errors. The archive is moved into
    place only after its digest matches, and an already cached file is verified
    again so a corrupted cache can never be extracted.
    """
    archive = DEPS / "downloads" / spec["file"]
    archive.parent.mkdir(parents=True, exist_ok=True)

    if not archive.exists():
        print(f"Downloading {spec['file']}...", flush=True)

        request = urllib.request.Request(spec["url"], headers={"User-Agent": "cvault-bootstrap"})
        temporary = archive.with_name(archive.name + ".part")

        try:
            for attempt in range(5):
                try:
                    with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as output:
                        while block := response.read(1024 * 1024):
                            output.write(block)
                    break
                except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
                    temporary.unlink(missing_ok=True)

                    # Client errors (404, 403, ...) will not fix themselves: fail fast.
                    if (isinstance(error, urllib.error.HTTPError) and error.code not in
                        (408, 429, 500, 502, 503, 504)) or attempt == 4:
                        raise

                    delay = 2 ** (attempt + 1)
                    print(f"Download attempt {attempt + 1} failed; retrying in {delay}s: {error}", flush=True)
                    time.sleep(delay)

            with temporary.open("rb") as source:
                digest = hashlib.file_digest(source, "sha256").hexdigest()

            if digest != spec["sha256"]:
                raise RuntimeError(f"Archive checksum mismatch: {archive}. Nothing was extracted.")

            temporary.replace(archive)
        finally:
            temporary.unlink(missing_ok=True)

    with archive.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()

    if digest != spec["sha256"]:
        raise RuntimeError(f"Archive checksum mismatch: {archive}. Nothing was extracted.")

    return archive


def unpack_tar(archive, destination):
    """Extract a tar archive with the ``data`` filter (no absolute paths, no links out)."""
    destination.mkdir(parents=True, exist_ok=True)

    with tarfile.open(archive) as source:
        source.extractall(destination, filter="data")


def main():
    """Install the toolchain and write the environment file."""
    system = platform.system()
    supported = (system == "Linux" and platform.machine() in ("x86_64", "amd64")) or (
        system == "Darwin" and platform.machine() in ("arm64", "x86_64"))

    if not supported:
        raise RuntimeError("Supported hosts: Linux x86_64, macOS arm64/x86_64.")

    macos = system == "Darwin"
    platform_key = "Macos" if macos else "Linux"
    platform_name = "macos" if macos else "linux"
    sdk = None

    if macos:
        # The resolved Xcode clang binary does not necessarily discover its SDK.
        # Give Autoconf and CMake the same explicit native macOS SDK.
        sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()

        if not Path(sdk).is_dir():
            raise RuntimeError(f"Missing macOS SDK: {sdk}")

    # CMake.
    cmake_parent = DEPS / "tools"
    cmake_root = cmake_parent / (f"cmake-{VERSIONS['cmakeVersion']}-" + ("macos-universal" if macos else "linux-x86_64"))
    cmake_bin = cmake_root / ("CMake.app/Contents/bin" if macos else "bin")
    cmake_archive = download(VERSIONS["cmake" + platform_key])

    if not (cmake_bin / "cmake").exists():
        unpack_tar(cmake_archive, cmake_parent)

    # Ninja.
    ninja_root = cmake_parent / f"ninja-{platform_name}-{VERSIONS['ninjaVersion']}"
    ninja_archive = download(VERSIONS["ninja" + platform_key])

    ninja_root.mkdir(parents=True, exist_ok=True)

    if not (ninja_root / "ninja").exists():
        with zipfile.ZipFile(ninja_archive) as source:
            # Extract just the expected executable, never arbitrary ZIP paths.
            (ninja_root / "ninja").write_bytes(source.read("ninja"))

        (ninja_root / "ninja").chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

    # libsodium: build a static library once per archive digest.
    sodium_spec = VERSIONS["sodiumSource"]
    sodium_archive = download(sodium_spec)
    sodium_prefix = DEPS / ("sodium-" + platform_name + "-" + sodium_spec["sha256"][:12])

    if not (sodium_prefix / "lib/libsodium.a").exists():
        source_parent = DEPS / "sources" / sodium_spec["sha256"][:12]

        unpack_tar(sodium_archive, source_parent)

        configurations = list(source_parent.glob("*/configure"))

        if len(configurations) != 1:
            raise RuntimeError("Unexpected libsodium source archive layout.")

        source_root = configurations[0].parent
        environment = os.environ.copy()

        # Only project targets are instrumented; build the crypto dependency normally.
        environment["CFLAGS"] = "-O2"

        if sdk:
            environment["SDKROOT"] = sdk
            environment["CFLAGS"] += " -isysroot " + shlex.quote(sdk)

        environment.pop("LDFLAGS", None)

        for command in (
            ["sh", "configure", f"--prefix={sodium_prefix}", "--disable-shared"],
            ["make", f"-j{min(os.cpu_count() or 2, 4)}"],
            ["make", "check"],
            ["make", "install"],
        ):
            try:
                subprocess.run(command, cwd=source_root, env=environment, check=True)
            except subprocess.CalledProcessError:
                # Autoconf's summary hides the compiler/linker error. Preserve the
                # diagnostic in CI logs without requiring another run to retrieve it.
                diagnostic = source_root / "config.log"

                if diagnostic.exists():
                    print(diagnostic.read_text(errors="replace"), flush=True)

                raise

    # Publish the environment and double check the installed tool versions.
    executable_paths = [str(cmake_bin), str(ninja_root)]
    exports = {
        "PATH": os.pathsep.join(executable_paths) + os.pathsep + os.environ.get("PATH", ""),
        "SODIUM_ROOT": str(sodium_prefix),
    }

    if sdk:
        exports["SDKROOT"] = sdk

    for executable, expected in ((cmake_bin / "cmake", VERSIONS["cmakeVersion"]), (ninja_root / "ninja", VERSIONS["ninjaVersion"])):
        actual = subprocess.check_output([str(executable), "--version"], text=True)

        if expected not in actual.splitlines()[0]:
            raise RuntimeError(f"Unexpected tool version: {actual}")

    environment_file = DEPS / "env.sh"
    environment_file.write_text("".join(f"export {key}={shlex.quote(value)}\n" for key, value in exports.items()), encoding="utf-8")

    if os.environ.get("GITHUB_PATH"):
        with open(os.environ["GITHUB_PATH"], "a", encoding="utf-8") as target:
            target.write("\n".join(executable_paths) + "\n")

    if os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as target:
            for key in ("SODIUM_ROOT", "SDKROOT"):
                if key in exports:
                    target.write(f"{key}={exports[key]}\n")

    print(f"Setup complete. Run: source {shlex.quote(str(environment_file))}", flush=True)


if __name__ == "__main__":
    main()
