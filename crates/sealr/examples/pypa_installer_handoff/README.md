# Copyable PyPA WheelSource handoff

This directory is a complete adopter-side example for PyPA `installer` 1.0.1.
It provides the standalone fresh-root target and the exact repository-owned
Poetry 2.4.2 update target. Its only Sealr dependency is the public `sealr`
crate. It uses no internal feature, workspace crate, CLI API, protocol API, or
wheel laboratory.

The Rust program authenticates the packaged Linux worker, admits a portable
UTF-8 wheel through `apply_supervised`, emits canonical evidence, and requires
the independently packaged verifier to accept that evidence against the live
source. It evaluates the wheel, retains the exact install plan in Rust, and
stages only bounded `VerifiedArchive::read_member` results. Python receives a
SHA-256-bound reduced manifest and opaque member blobs, never a wheel path or
wheel bytes. The input named by `--consume-wheel` is deleted before Python
starts in the standalone target and before the post-admission installer bridge
starts in the Poetry target.

In the standalone target, before any destination effect, `wheel_source.py`
authenticates the raw
manifest and canonical receipt digests supplied out of band, checks the closed
manifest schema, rehashes every staged member, validates `RECORD`, confirms
the exact installer distribution, and proves repeatable `WheelSource` reads.
It then installs into new, separate scheme roots with bytecode and overwrite
disabled. Rust independently enumerates the result, rejects links, missing or
extra files, and executable-mode drift, then derives the realization identity.
Both child processes have a 120-second deadline. Poll failures and expiry
enter the same process-group and direct-child termination path, with bounded
reap confirmation before control returns.

The Poetry target adds `--poetry-2-4-2-update CONTEXT_SHA256` and requires an
existing absolute CPython 3.12 virtual-environment root. It emits one closed
PREPARED JSON record on stdout only after source deletion, target-interpreter
identity validation, and a target-read-only dry installer pass. It then waits
up to 120 seconds for the exact stdin line `install CONTEXT_SHA256`. EOF, a
wrong context, or expiry fails without destination writes. A valid permit
starts installation, and the final success record echoes the context. The
controller must pass a private single-use copy of Poetry's already
hash-validated cache artifact, not the shared cache entry itself.

The Poetry mode maps `purelib` and `platlib` to the virtual environment's
`lib/python3.12/site-packages`, scripts to `bin`, headers to
`include/site/python3.12/<distribution>`, and data to the environment root. It
adds exact `INSTALLER` metadata `Poetry 2.4.2`, disables bytecode and overwrite,
rejects existing symlink components before every write, and verifies only the
new outputs against the retained plan. The exact repository fixture is
documented in [tests/poetry-consumer](../../../../tests/poetry-consumer/README.md).
This target exists for repository conformance and is not a general Poetry
adapter promise.

## Copy and build

Copy this directory and rename `Cargo.toml.example` to `Cargo.toml`:

```bash
cp -R pypa_installer_handoff sealr-wheel-source
cd sealr-wheel-source
mv Cargo.toml.example Cargo.toml
```

For current main, select Cargo's extracted `.crate` without changing the
copied manifest. Apply the same patch while creating the lockfile and building:

```bash
cargo generate-lockfile \
  --config 'patch.crates-io.sealr.path="/absolute/path/to/sealr-0.1.0-alpha.14"'
cargo build --locked --release \
  --config 'patch.crates-io.sealr.path="/absolute/path/to/sealr-0.1.0-alpha.14"'
```

After this exact Sealr version is available from the configured registry, the
ordinary published flow is `cargo generate-lockfile` followed by
`cargo build --locked --release`, without the temporary patch.

Acquire the exact Python dependency and extract it before running. Python is
given the extracted directory, not its wheel:

```bash
umask 077
python3 -m pip download \
  --disable-pip-version-check --no-deps --only-binary=:all: \
  --require-hashes --requirement requirements.txt --dest installer-download
python3 -m zipfile -e \
  installer-download/installer-1.0.1-py3-none-any.whl installer-extracted
```

Authenticate the native Sealr archive with its `SHA256SUMS` entry and GitHub
build provenance before extraction, following the [release verification
guide](https://github.com/blisspixel/sealr/blob/main/docs/release-verification.md).
The helper manifest binds the helper, and the verifier checks evidence, but
neither authenticates the archive that carried them. Use the helper manifest
and verifier from that same authenticated native package. The first target
model deliberately pins Linux and `/usr/bin/python3`:

```bash
./target/release/sealr-pypa-installer-handoff \
  --consume-wheel /absolute/path/demo-1.0-py3-none-any.whl \
  --worker-manifest /absolute/path/sealr-worker.manifest \
  --verifier /absolute/path/sealr-identity-verifier \
  --python /usr/bin/python3 \
  --installer-root "$PWD/installer-extracted" \
  --output-root "$PWD/installed"
```

Add `--materialize-raw NEW_DIR` to prove that the same verified capability can
originate from supervised materialization. That raw tree commits before the
later handoff begins and is not rolled back if installation fails.

The installer root and every output-root ancestor must be owned by root or the
effective user and must deny group and other writes. A root-owned sticky
ancestor such as `/tmp` is accepted. The installer tree itself must contain
only the files bound by the pinned `installer` RECORD, with safe ownership,
modes, and link counts. `umask 077` gives copied examples a straightforward
default for acquisition and output setup.

For the exact Poetry repository protocol, use an existing CPython 3.12 virtual
environment and a private wheel copy whose filename still matches the lock:

```bash
./target/release/sealr-pypa-installer-handoff \
  --consume-wheel /private/single-use/demo-1.0-py3-none-any.whl \
  --worker-manifest /absolute/path/sealr-worker.manifest \
  --verifier /absolute/path/sealr-identity-verifier \
  --python /usr/bin/python3 \
  --installer-root "$PWD/installer-extracted" \
  --output-root /tmp/sealr-poetry-2.4.2-fixture/stable-target \
  --poetry-2-4-2-update CONTEXT_SHA256
```

The controller reads PREPARED, preserves Poetry's real update uninstall, and
only then writes the permit. From PREPARED through completion, neither the
controller nor either installer bridge may open a `.whl` file.

The example caps each staged member at 16 MiB and all members at 64 MiB. It
does not claim transactional installation, rollback after installer effects,
concurrent safety against another process with the same effective user,
Windows or macOS source deletion, bytecode generation, overwrite, or external
adoption. In particular, the Poetry update target has no rollback after the
real uninstall. Repository conformance keeps fixture generation, hostile
mutations, identity pins, and detailed output oracles outside this copyable
directory.
