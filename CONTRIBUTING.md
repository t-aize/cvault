# Contributing

## Status of this project

cvault is a **finished learning project**. It was written to study low-level C,
networking, applied cryptography and secure design, and it is kept as a complete,
documented snapshot. It will receive **no further updates, bug fixes, dependency
updates, new features or support** (see the notice at the top of the
[README](README.md)).

For that reason **contributions are not being accepted**:

- Pull requests, feature requests and bug reports may be closed without review or
  without any answer.
- Nobody is on call to triage issues, and no response time is promised.
- Please do not send code that you need to see merged: it will not be.

This is not a judgement of your work. The repository simply is not being developed
any more.

## What you are welcome to do

- **Read and learn from it.** The code is heavily documented on purpose: start with
  the [code guide](docs/code-guide.md), then the guides for the
  [core](docs/core.md), the [network transport](docs/network.md),
  [persistence](docs/persistence.md), [security](docs/security.md) and
  [fuzzing](docs/fuzzing.md).
- **Fork it and take it further.** The [MIT license](LICENSE) allows it. Keep the
  copyright notice, and if you change the security model, say so clearly in your fork:
  the guarantees written here describe this code only.
- **Use it as teaching material**, for example to explain authenticated encryption
  at rest, a poll/epoll event loop or crash-safe journaling.

## If you work on a fork

These are the conventions the code base follows. They are suggestions for a fork,
not requirements for anything sent here.

- **Build and test on your system.** [development.md](docs/development.md) has the
  commands for Windows, Linux and macOS (toolchain bootstrap, presets, CLion).
  Run the whole suite in the Debug and Release presets and, on Linux or macOS, in the
  `asan` preset: sanitizer builds abort on undefined behaviour.
- **Add tests with every change**, including failure paths. Parser changes must keep
  the reference implementation in `tests/parser_reference.c` and the fuzzing campaign
  in agreement; see [fuzzing.md](docs/fuzzing.md).
- **Follow the style.** Four-space indentation, 100 columns, braces on every control
  statement, and `clang-format` 23.1.2 with the repository's `.clang-format`. Public
  functions carry Doxygen comments (`@brief`, `@param`, `@return`); internal comments
  explain *why*. Do not add banner or separator comments. The rules and the reasons
  are in the [code guide](docs/code-guide.md#readability-conventions).
- **Keep dependencies pinned.** Tools and libraries are pinned with checksums in
  `toolchain.json`; the vendored `third_party/` code stays identical to upstream.
- **Write commit messages in the Conventional Commits style** used by the history
  (`feat:`, `fix:`, `docs:`, `test:`, `style:`), with a body that says why.
- **Treat security reports seriously in your own fork.** See [SECURITY.md](SECURITY.md)
  for what this project does and does not promise.

## Be kind

Whatever you do with the project, please follow the
[code of conduct](CODE_OF_CONDUCT.md).
