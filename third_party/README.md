# Third-party code

Small dependencies that are copied into the repository instead of being
downloaded at build time. Each one is pinned to an exact upstream commit and must
stay byte-for-byte identical to it (`third_party/.clang-format` disables
formatting here).

## argparse

| | |
|---|---|
| Purpose | Command-line option parsing for `cvault-server` and `cvault-cli` |
| Upstream | <https://github.com/cofyc/argparse> |
| Version | `master` at commit `4e30aba50340af7f2d3932492c4bffdef7669db8` (2025-09-26) |
| License | MIT, see [`argparse/LICENSE`](argparse/LICENSE) |

The commit is 21 commits newer than the last tagged release (`v1.1.0`, 2022) and
includes fixes such as the crash when `argparse_usage()` is called twice.

SHA-256 of the vendored files:

```text
5045a20562e22363339c11692cda0cbf641c8921f22babfbf119ec068a21244d  argparse/argparse.c
9fc67e55d911f51b5d82a969f0796ed44699695905bbda2e3a1047cda8160025  argparse/argparse.h
b0d8a0bf3f08168138be5b10746acf1d7e2d82661ae043b8e1142b0696415cee  argparse/LICENSE
```

To update, download `argparse.c`, `argparse.h` and `LICENSE` from the new commit
(`https://raw.githubusercontent.com/cofyc/argparse/<commit>/<file>`), replace the
files, then update the commit, date and digests above.

The library is compiled as its own target (`cvault_argparse`) without the strict
project warning flags, because the code is not ours to change.
