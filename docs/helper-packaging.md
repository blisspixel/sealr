# Linux helper packaging contract

The native Linux release archive has one fixed production-helper boundary. The helper is present only in the `x86_64-unknown-linux-gnu` archive at `libexec/sealr/sealr-worker`. It is not a command, is never selected through `PATH`, and is absent from the macOS and Windows archives.

This contract packages the authenticated helper foundation for later runtime activation. It does not itself make the public library or CLI use the worker.

## Exact archive shape

The Linux archive contains exactly these seven files beneath its single versioned root:

```text
CHANGELOG.md
LICENSE
README.md
THIRD_PARTY_LICENSES.txt
sealr
libexec/sealr/sealr-worker
libexec/sealr/sealr-worker.manifest
```

The CLI and helper have mode `0755`. Documentation, licenses, and the manifest have mode `0644`; both `libexec` directories have mode `0755`. The macOS and Windows archives retain their exact five-file contracts and contain no `libexec` directory.

## Artifact identity

`sealr-worker.manifest` is BOM-free UTF-8 JSON with LF line endings and exactly these fields:

```json
{
  "schema": "sealr.worker-artifact.v1",
  "release_version": "0.1.0-alpha.5",
  "target": "x86_64-unknown-linux-musl",
  "bootstrap_abi": 1,
  "byte_len": 0,
  "sha256": "64 lowercase hexadecimal characters"
}
```

The example `byte_len` is schematic. Every real manifest binds the exact positive helper length and SHA-256. The enclosing release archive checksum and build-provenance attestation authenticate the helper and manifest transitively. At execution, the supervisor independently opens, hashes, seals, launches, and proves the running object before transferring archive authority, as specified in the [reduced-authority design](sandbox.md).

The helper is built as a static `x86_64-unknown-linux-musl` ELF and must have no program interpreter. The repository lab is a separate verification executable and is never included in a native release archive.

## License closure

The committed Linux `THIRD_PARTY_LICENSES.txt` is generated from an exact private dependency anchor containing the native CLI graph plus the production-only helper graph with default lab features disabled. The generator therefore includes helper runtime dependencies while excluding repository fault-lab dependencies. macOS and Windows continue to use the CLI-only target graph.

## Required verification

Required CI builds each native package with the same scripts used by the tag workflow, inspects entry names before extraction, rejects absolute paths, traversal, backslashes, duplicates, links, and extra files or directories, and extracts beneath a path containing spaces. It then checks the exact target license hash, CLI version and help, and Unix modes.

Linux additionally requires:

- exact manifest fields, release version, helper target, bootstrap ABI, length, and SHA-256;
- ELF64 x86-64 identity and absence of `PT_INTERP`;
- bounded refusal of direct invocation and `--help`;
- an authenticated extracted-helper hello, executable-identity proof, restricted inspect completion, clean exit, and exact reap through the repository lab.

The release workflow calls the same package and verification scripts before uploading any archive. The external Alpha.5 release remains historical and does not contain this helper; the contract applies to the next release candidate cut from a commit that includes it.

## Nonclaims

Packaging does not activate a public worker backend, change `Outcome`, construct a worker-backed `VerifiedArchive`, prove real-kernel restriction failure behavior, or provide a macOS or Windows containment claim. Those remain separate Alpha.6 gates.
