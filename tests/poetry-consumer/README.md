# Exact Poetry 2.4.2 repository fixture

This repository-owned fixture exercises one exact Poetry update seam on Ubuntu
24.04 x86_64 with CPython 3.12. It pins the Poetry 2.4.2 wheel at SHA-256
`a506d6ff7fcc54a3472b2618145b8e4a1ef8d76d52836d41b813fa1b36083a08`,
Poetry Core 2.4.0, PyPA installer 1.0.1, pip 26.2.1, and the complete
47-wheel acquisition set in `wheelhouse.json`. The controller contains the 46
Poetry runtime distributions plus the separately identified pip bootstrap
artifact. Required CI downloads only hash-pinned wheels, verifies the exact
file set, installs the controller without dependency resolution, and requires
`pip check` before the fixture starts.

`project/poetry.lock` contains one wheel-only `demo==1.0` package. The fixture
first installs a deterministic `demo==0.9` wheel into a real virtual
environment at the fixed path `/tmp/sealr-poetry-2.4.2-fixture/stable-target`.
An in-memory Simple repository on `127.0.0.1` serves the exact mixed
Store-and-Deflate 1.0 wheel produced by the packaged handoff conformance kit.
The configured Poetry repository pool contains only this loopback repository
during both updates.

The stock control uses the exact Poetry `Executor`, real repository chooser,
real pip uninstall, and stock `WheelInstaller`. After capturing the complete
non-bytecode target tree, the fixture restores 0.9 at the same path. The
adapted executor overrides only `_download`; its inherited `_install` and
`_remove` methods are identity-checked against Poetry 2.4.2. Poetry downloads
and accepts the lock hash first. The adapter then copies the validated shared
cache artifact to a private single-use path and gives only that copy to the
packaged Rust handoff.

PREPARED is emitted after supervised admission, independent canonical-evidence
verification, wheel evaluation, bounded member staging, private-source
deletion, exact target-interpreter validation, and a target-read-only installer
preflight. At that point the full target snapshot is unchanged and 0.9 remains
installed. The host then denies a deliberate `.whl` open, Poetry performs its
unchanged real pip uninstall, and the installer proxy sends the exact
digest-bound permit. Rust retains the install plan, invokes the staged
`WheelSource`, verifies every reported regular single-link output and
executable mode, and derives the pinned realization identity.

The required success order is:

```text
poetry-download-returned
poetry-lock-hash-confirmed
prepared
wheel-open-probe-denied
real-uninstall-entered
real-uninstall-returned
permit-written
handoff-completed
```

The final 13-file Poetry realization is
`76a81ee48ebc43ff7d6f60440dce5edd047f13f3ac9a6663fbe3f52322566142`.
The complete non-bytecode target snapshots are equal between the stock and
adapted runs. The Rust result audit covers exact `INSTALLER` and final `RECORD`
content, generated scripts, headers, data, file bytes, and executable modes
before deriving the realization identity.

A second fresh virtual environment runs the adapted download through PREPARED,
closes the permit channel, and requires the Rust child to reject EOF and reap.
Poetry never reaches uninstall, the installer proxy never runs, the old
distribution remains importable, and the complete target snapshot is
unchanged.

A third fresh environment places an absolute directory symlink at a planned
header-output ancestor. Target-read-only preflight rejects it before PREPARED
or uninstall. The complete target snapshot and a separately hashed outside
sentinel remain unchanged, so the gate also proves the symlink is never
followed for a write.

The controller also loads the exact bridge shipped in Cargo's extracted crate
in an isolated process and checks both orderings of a cross-scheme physical
file-ancestor collision. The dry preflight validator must reject both before
they can enter any Poetry update.

Required CI runs the fixture after building the copied handoff from Cargo's
extracted crate and extracting the authenticated native Linux package. The
core command is:

```bash
/absolute/controller/bin/python -I tests/poetry-consumer/poetry_driver.py \
  --handoff /absolute/sealr-pypa-installer-handoff \
  --bridge /absolute/extracted-package/examples/pypa_installer_handoff/wheel_source.py \
  --worker-manifest /absolute/sealr-worker.manifest \
  --verifier /absolute/sealr-identity-verifier \
  --installer-root /absolute/installer-extracted \
  --wheelhouse /absolute/poetry-wheelhouse \
  --wheelhouse-manifest "$PWD/tests/poetry-consumer/wheelhouse.json" \
  --requirements "$PWD/tests/poetry-consumer/requirements.txt" \
  --pip-requirement "$PWD/tests/poetry-consumer/pip-requirement.txt" \
  --controlled-wheel /absolute/demo-1.0-py3-none-any.whl \
  --project "$PWD/tests/poetry-consumer/project" \
  --runtime /tmp/sealr-poetry-2.4.2-fixture
```

This is evidence for exact private Poetry 2.4.2 behavior, not a public Poetry
extension API or a general Poetry support claim. It does not cover sdists,
builds, VCS or path dependencies, resolver or index trust, concurrent target
mutation, rollback after uninstall, transactional installation, macOS,
Windows, external adoption, or production readiness. A failure after Poetry's
real uninstall has no rollback, matching the pinned upstream behavior.
