# Linux helper packaging contract

The native Linux release archive has one fixed production-helper boundary. The helper is present only in the `x86_64-unknown-linux-gnu` archive at `libexec/sealr/sealr-worker`. It is not a command, is never selected through `PATH`, and is absent from the macOS and Windows archives.

This contract packages the authenticated helper consumed by the explicit Linux supervisor. Packaging alone does not change the default library or CLI path; callers select it through the manifest-backed fail-closed API or CLI option.

## Exact archive shape

The Linux archive contains exactly these eight files beneath its single versioned root:

```text
CHANGELOG.md
LICENSE
README.md
THIRD_PARTY_LICENSES.txt
sealr
sealr-identity-verifier
libexec/sealr/sealr-worker
libexec/sealr/sealr-worker.manifest
```

The CLI, identity verifier, and helper have mode `0755`. Documentation, licenses, and the manifest have mode `0644`; both `libexec` directories have mode `0755`. The macOS and Windows archives have exact six-file contracts containing the two root executables, documentation, licenses, and no `libexec` directory.

## Artifact identity

`sealr-worker.manifest` is BOM-free UTF-8 JSON with LF line endings and exactly these fields:

```json
{
  "schema": "sealr.worker-artifact.v1",
  "release_version": "0.1.0-alpha.12",
  "target": "x86_64-unknown-linux-musl",
  "bootstrap_abi": 1,
  "byte_len": 0,
  "sha256": "64 lowercase hexadecimal characters"
}
```

The example `byte_len` is schematic. Every real manifest binds the exact positive helper length and SHA-256. `bootstrap_abi` remains 1 because the bootstrap frame layout is unchanged. The authenticated runtime hello separately requires helper feature generation 2, which binds support for the additive supervised prefix-read request and frame flag. A helper with any other feature generation is rejected before source transfer. The feature generation is intentionally not a manifest field. The enclosing release archive checksum and build-provenance attestation authenticate the helper and manifest transitively. At execution, the supervisor independently opens, hashes, seals, launches, and proves the running object before transferring archive authority, as specified in the [reduced-authority design](sandbox.md).

The helper is built as a static `x86_64-unknown-linux-musl` ELF and must have no program interpreter. The repository lab is a separate verification executable and is never included in a native release archive.

## License closure

Every committed `THIRD_PARTY_LICENSES.txt` is generated from an exact private dependency anchor containing the native CLI and independent-verifier graphs. Linux adds the production-only helper graph with default lab features disabled. The generator therefore includes every shipped runtime dependency while excluding repository fault-lab dependencies. The verifier currently adds no dependency family beyond the CLI graph.

## Required verification

Required CI builds each native package with the same scripts used by the tag workflow, inspects entry names before extraction, rejects absolute paths, traversal, backslashes, duplicates, links, and extra files or directories, and extracts beneath a path containing spaces. It then checks the exact target license hash, CLI version and help, and Unix modes.

All targets also check the extracted verifier's version, help, misuse exit, admitted and rejected canonical-evidence success, observed-source binding, and refusal of view, receipt, source, and pair-substitution mutations. These tests invoke no repository verifier binary.

Linux additionally requires:

- exact manifest fields, release version, helper target, bootstrap ABI, length, and SHA-256, plus runtime helper feature generation 2;
- ELF64 x86-64 identity and absence of `PT_INTERP`;
- bounded refusal of direct invocation and `--help`;
- an authenticated extracted-helper hello, executable-identity proof, restricted inspect completion, clean exit, and exact reap through the repository lab;
- supervised completion through the packaged CLI, wheel laboratory, and a binary built against the extracted crate, all using the exact extracted manifest and helper with no fallback; the general consumer includes a `.data/scripts` wheel that requires the prefix-read path.

The release workflow calls the same package and verification scripts before uploading any archive. Historical releases through Alpha.5 do not contain this helper; Alpha.6 is the first release whose Linux archive carries the contract.

## Nonclaims

The package contract does not activate a worker implicitly. `LinuxWorker::load_from_manifest` bounds and validates the fixed manifest, release version, helper target, bootstrap ABI, byte length, and lowercase SHA-256, selects only its sibling helper, and then applies the same sealed-executable authentication as `LinuxWorker::load`. Successful `apply_supervised` calls construct worker-backed `VerifiedArchive` state for inspect or materialize while keeping destination publication authority in the supervisor. `sealr --worker-manifest ABSOLUTE_PATH`, corpus execution in the wheel laboratory, and the extracted-package consumer all select that same boundary and fail closed without an in-process fallback. macOS and Windows containment remain separate future work.

The identity verifier cannot authenticate the release archive that contains it. Users authenticate the download with `SHA256SUMS` and GitHub build provenance first. The verifier then checks unsigned canonical evidence, including coherent rejection evidence. It does not execute codecs, reinterpret the live archive, reconstruct the live format-specific layout root, verify a signature, or turn the evidence into an attestation.
