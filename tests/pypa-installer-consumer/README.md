# Packaged PyPA adopter conformance

This isolated project proves that a downstream program can compile only against
Cargo's extracted `sealr` package, delete a wheel after admission, and install
through PyPA `installer` 1.0.1 without giving Python the wheel path or bytes.
It is an adopter-ready repository contract, not evidence of independent
external adoption.

The controlled case covers root payloads, `.data` relocation, a `#!python`
rewrite, a generated console entry point, executable evidence, and the final
installed `RECORD`. The same path admits and installs the exact hash-pinned
`installer` distribution. Rust independently enumerates every output and binds
the realization identity. Negative gates refuse a lying source `RECORD`, a
traversal-bearing ZIP, a modified descriptor, and a modified staged member
before installation.

The first target model is deliberately narrow:

- Linux POSIX with `/usr/bin/python3`;
- separate `purelib`, `platlib`, `scripts`, `headers`, and `data` roots;
- no bytecode generation and no overwrite;
- 16 MiB per staged member and 64 MiB in aggregate;
- no transactional-install, macOS, Windows, or production-filesystem claim.

From the repository root on Linux with Rust 1.98:

```bash
set -euo pipefail
cargo package --locked -p sealr
cargo build --locked --release -p sealr-identity-verifier
python3 -m pip download \
  --disable-pip-version-check \
  --no-deps \
  --only-binary=:all: \
  --require-hashes \
  --requirement tests/pypa-installer-consumer/requirements.txt \
  --dest target/pypa-installer-download
python3 -m zipfile -e \
  target/pypa-installer-download/installer-1.0.1-py3-none-any.whl \
  target/pypa-installer-extracted
cargo run --locked --release \
  --manifest-path tests/pypa-installer-consumer/Cargo.toml -- \
  --python /usr/bin/python3 \
  --installer-root target/pypa-installer-extracted \
  --verifier target/release/sealr-identity-verifier \
  --real-wheel target/pypa-installer-download/installer-1.0.1-py3-none-any.whl
```

The conformance executable consumes and removes the downloaded `--real-wheel`
file after authenticating its bytes. The example keeps that input under
`target/`, where it can be reproduced by rerunning the pinned download.

The Python `WheelSource` and filesystem effects remain outside Sealr's trusted
computing base. The adapter uses `VerifiedArchive::read_member`, the public
`sealr::wheel` evaluator, canonical evidence, and `realize_identity`. It has no
dependency on the CLI, protocol crate, wheel laboratory, or internal features.
