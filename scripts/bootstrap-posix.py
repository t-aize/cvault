#!/usr/bin/env python3
"""Install verified POSIX build tools and the current stable libsodium snapshot locally."""

import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import stat
import subprocess
import tarfile
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parent.parent
DEPS = ROOT / ".deps"
VERSIONS = json.loads((ROOT / "toolchain.json").read_text(encoding="utf-8"))


def download(spec):
    archive = DEPS / "downloads" / spec["file"]
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        print(f"Downloading {spec['file']}...", flush=True)
        request = urllib.request.Request(spec["url"], headers={"User-Agent": "cvault-bootstrap"})
        with urllib.request.urlopen(request, timeout=120) as response, archive.open("wb") as output:
            while block := response.read(1024 * 1024):
                output.write(block)
    with archive.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if digest != spec["sha256"]:
        raise RuntimeError(f"Archive checksum mismatch: {archive}. Nothing was extracted.")
    return archive


def unpack_tar(archive, destination):
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as source:
        source.extractall(destination, filter="data")


def main():
    system = platform.system()
    supported = (system == "Linux" and platform.machine() in ("x86_64", "amd64")) or (
        system == "Darwin" and platform.machine() in ("arm64", "x86_64"))
    if not supported:
        raise RuntimeError("Supported hosts: Linux x86_64, macOS arm64/x86_64.")
    macos = system == "Darwin"
    platform_key = "Macos" if macos else "Linux"
    platform_name = "macos" if macos else "linux"
    cmake_parent = DEPS / "tools"
    cmake_root = cmake_parent / (f"cmake-{VERSIONS['cmakeVersion']}-" + ("macos-universal" if macos else "linux-x86_64"))
    cmake_bin = cmake_root / ("CMake.app/Contents/bin" if macos else "bin")
    cmake_archive = download(VERSIONS["cmake" + platform_key])
    if not (cmake_bin / "cmake").exists():
        unpack_tar(cmake_archive, cmake_parent)
    ninja_root = cmake_parent / f"ninja-{platform_name}-{VERSIONS['ninjaVersion']}"
    ninja_archive = download(VERSIONS["ninja" + platform_key])
    ninja_root.mkdir(parents=True, exist_ok=True)
    if not (ninja_root / "ninja").exists():
        with zipfile.ZipFile(ninja_archive) as source:
            # Extract just the expected executable, never arbitrary ZIP paths.
            (ninja_root / "ninja").write_bytes(source.read("ninja"))
        (ninja_root / "ninja").chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

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
        environment.pop("LDFLAGS", None)
        for command in (
            ["sh", "configure", f"--prefix={sodium_prefix}", "--disable-shared"],
            ["make", f"-j{min(os.cpu_count() or 2, 4)}"],
            ["make", "check"],
            ["make", "install"],
        ):
            subprocess.run(command, cwd=source_root, env=environment, check=True)

    executable_paths = [str(cmake_bin), str(ninja_root)]
    exports = {
        "PATH": os.pathsep.join(executable_paths) + os.pathsep + os.environ.get("PATH", ""),
        "SODIUM_ROOT": str(sodium_prefix),
    }
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
            target.write(f"SODIUM_ROOT={sodium_prefix}\n")
    print(f"Setup complete. Run: source {shlex.quote(str(environment_file))}", flush=True)


if __name__ == "__main__":
    main()
