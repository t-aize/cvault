#!/usr/bin/env python3
"""Install verified CMake/Ninja and build libsodium on Linux; see bootstrap-posix.py."""

from pathlib import Path
import runpy


if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).with_name("bootstrap-posix.py")), run_name="__main__")
