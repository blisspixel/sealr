# Packaged PyPA repository conformance

This isolated project provides bounded repository conformance for the
packaged [copyable PyPA `WheelSource` handoff](../../crates/sealr/examples/pypa_installer_handoff/README.md).
It proves that a downstream program can compile only against Cargo's extracted
`sealr` package, delete a wheel after admission, and install through exact PyPA
`installer` 1.0.1 without giving Python the wheel path or bytes. It uses the
exact `wheel_source.py` packaged with the public example instead of maintaining
a second bridge. This is a repository-owned contract, not evidence of
independent external adoption.

The controlled case covers Store and Deflate members, prefix boundary reads,
root payloads, `.data` relocation, two `#!python` rewrites, a generated console
entry point, executable evidence, an unlisted legacy `RECORD.jws`, and the final
installed `RECORD`. The same path admits and installs the exact hash-pinned
`installer` distribution. Rust retains the exact plan, independently enumerates
every output, checks executable modes, and then binds the realization identity.
Python receives only a reduced SHA-256-bound manifest and opaque staged blobs;
the expected manifest and canonical receipt digests are supplied as separate
arguments. Negative gates refuse a lying source `RECORD`, a traversal-bearing
ZIP, a modified staged member, changed raw manifest bytes, an unknown manifest
key with a recomputed digest, a wrong out-of-band receipt digest, and an extra
empty installer directory before installation. A separate gate proves the
source is absent before Python starts.

The first target model is deliberately narrow:

- Linux POSIX with `/usr/bin/python3`;
- separate `purelib`, `platlib`, `scripts`, `headers`, and `data` roots;
- no bytecode generation and no overwrite;
- 16 MiB per staged member and 64 MiB in aggregate;
- no transactional-install, macOS, Windows, or production-filesystem claim.

From the repository root on Linux with Rust 1.98:

```bash
set -euo pipefail
umask 077
cargo package --locked -p sealr
cargo build --locked --release -p sealr-identity-verifier
mkdir -p target/pypa-controlled-output
python3 -m pip download \
  --disable-pip-version-check \
  --no-deps \
  --only-binary=:all: \
  --require-hashes \
  --requirement target/package/sealr-0.1.0-alpha.14/examples/pypa_installer_handoff/requirements.txt \
  --dest target/pypa-installer-download
python3 -m zipfile -e \
  target/pypa-installer-download/installer-1.0.1-py3-none-any.whl \
  target/pypa-installer-extracted
cargo run --locked --release \
  --manifest-path tests/pypa-installer-consumer/Cargo.toml -- \
  --python /usr/bin/python3 \
  --installer-root target/pypa-installer-extracted \
  --verifier target/release/sealr-identity-verifier \
  --real-wheel target/pypa-installer-download/installer-1.0.1-py3-none-any.whl \
  --bridge target/package/sealr-0.1.0-alpha.14/examples/pypa_installer_handoff/wheel_source.py \
  --controlled-wheel-output target/pypa-controlled-output/demo-1.0-py3-none-any.whl
```

The conformance executable consumes and removes the downloaded `--real-wheel`
file after authenticating its bytes. The example keeps that input under
`target/`, where it can be reproduced by rerunning the pinned download.

The Python `WheelSource` and filesystem effects remain outside Sealr's trusted
computing base. The adapter uses `VerifiedArchive::read_member`, the public
`sealr::wheel` evaluator, canonical evidence, and `realize_identity`. It has no
dependency on the CLI, protocol crate, wheel laboratory, or internal features.
The copyable example is separately built from the extracted `.crate` and run
against the helper manifest and verifier extracted from the Linux native
package through both supervised inspect and materialize origins. Required CI
compares their complete source-to-realization identity lineage. This fixture
keeps generators, hostile mutations, identity pins, and detailed output oracles
in repository tests rather than expanding the adopter example.
