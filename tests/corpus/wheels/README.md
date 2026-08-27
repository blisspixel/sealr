# Wheel compatibility pilot corpus

This directory defines a small compatibility pilot that now carries immutable structural and research reports plus the Alpha.8 supported-preview evaluator report. It does not advertise installation or general ecosystem compatibility and is not a representative sample of PyPI.

## Scope

The manifest pins 20 non-yanked artifacts returned by PyPI's official JSON API on 2026-08-22:

- eight universal wheels from packaging tools and pure Python libraries;
- four Linux x86_64 native wheels;
- four Windows x86_64 native wheels;
- three macOS arm64 native wheels and one macOS universal2 wheel.

The named projects are a judgmental pilot chosen to exercise packaging tools, pure libraries, native extensions, and larger scientific artifacts. Each platform-specific selection targets CPython 3.12 when the release publishes that tag. `cryptography` and `psutil` use compatible `abi3` artifacts. The manifest, rather than the mutable project endpoint, is the reproducibility authority.

Raw wheels are not committed. Each entry records project, release, cohort, exact filename and URL, SHA-256, size, upload time, and a PyPI provenance page. The acquisition script accepts only direct HTTPS URLs on `files.pythonhosted.org`, disables redirects, applies 512 MiB per-artifact and 2 GiB aggregate limits while streaming through a fixed buffer, and verifies size and digest before promoting a partial download into the ignored `.research/wheels` cache.

The analyzer separately caps the manifest at 1 MiB, each cached-artifact read at its declared size, the corpus inventory at 65,536 interpreted members and 65,536 finding occurrences, and each generated or verified report file at 32 MiB. These laboratory limits are not product policy and do not widen the default Sealr budget.

## Reproduce

From the repository root:

```powershell
cargo run --locked -p sealr-wheel-lab --bin sealr-wheel-lab -- validate-manifest tests/corpus/wheels/manifest.json
pwsh -NoLogo -NoProfile -File scripts/acquire_wheel_corpus.ps1
cargo run --locked -p sealr-wheel-lab --bin sealr-wheel-lab -- analyze `
  tests/corpus/wheels/manifest.json `
  .research/wheels `
  tests/corpus/wheels/report.json `
  docs/wheel-compatibility-pilot.md `
  --worker-manifest /absolute/path/to/sealr-worker.manifest
cargo run --locked -p sealr-wheel-lab --bin sealr-wheel-lab -- check `
  tests/corpus/wheels/manifest.json `
  .research/wheels `
  tests/corpus/wheels/report.json `
  docs/wheel-compatibility-pilot.md `
  --worker-manifest /absolute/path/to/sealr-worker.manifest
cargo run --locked -p sealr-wheel-lab --bin sealr-wheel-lab -- verify-report `
  tests/corpus/wheels/manifest.json `
  tests/corpus/wheels/report.json `
  docs/wheel-compatibility-pilot.md
cargo run --locked -p sealr-wheel-lab --bin wheel_inventory_v2 -- analyze `
  tests/corpus/wheels/manifest.json `
  .research/wheels `
  tests/corpus/wheels/report-v2.json `
  docs/wheel-compatibility-v2.md
cargo run --locked -p sealr-wheel-lab --bin wheel_inventory_v2 -- verify `
  tests/corpus/wheels/manifest.json `
  tests/corpus/wheels/report-v2.json `
  docs/wheel-compatibility-v2.md
cargo run --locked -p sealr-wheel-lab --bin wheel_inventory_v3 -- analyze `
  tests/corpus/wheels/manifest.json `
  .research/wheels `
  tests/corpus/wheels/report-v3.json `
  docs/wheel-compatibility-v3.md
cargo run --locked -p sealr-wheel-lab --bin wheel_inventory_v3 -- verify `
  tests/corpus/wheels/manifest.json `
  tests/corpus/wheels/report-v3.json `
  docs/wheel-compatibility-v3.md
```

The analyzer requires the exact production-helper manifest and uses only Sealr's public fail-closed `apply_supervised` outcome and read-only `ArchiveIR`. It does not call Python `zipfile`, an external extractor, another ZIP parser, or the in-process fallback. Rejected artifacts are not reopened through a fallback parser, so feature counts are available only when current interpretation produced an IR.

The committed report binds the analyzer revision plus exact manifest, interpretation-profile, and default-policy digests. It records current admission results, affected-artifact and finding-occurrence counts, structured denial details, methods, general-purpose flags, extra fields by site and disposition, normalization actions, `.dist-info` path candidates, candidate metadata basenames, and per-artifact structural totals. The offline `verify-report` command checks those bindings, internal rollups, canonical JSON, and Markdown rendering without raw wheels. It does not re-execute corpus analysis or validate wheel metadata, `RECORD`, relocation, target compatibility, or installation semantics.

The successor `report-v2.json` is a separate, predecessor-bound semantic inventory. It applies the exact non-shipping wheel UTF-8 profile, consumes only `VerifiedArchive`, and records wheel and core metadata, producers, expanded filename tags, `.data` scheme use, Unicode paths, creator systems, PyPA installer 0.7.0 executable facts, the four-way research outcome, and investigated rejection clusters. It never overwrites the v1 structural pilot and never falls back to another ZIP reader.

The additive `report-v3.json` binds the supported-preview `sealr::wheel` evaluator to `sealr.profile.zip.portable-utf8.v1`. It preserves the v2 report as immutable historical evidence, verifies the same pinned artifact bytes through the shipped public surface, and records the one deliberate executable-mode tightening separately from compatibility outcomes.
