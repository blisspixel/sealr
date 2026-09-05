# External adopter pilot contract

Updated 2026-09-05.

> Status: verified technical baseline for the first external pilot. No external adopter has passed this contract. No separately maintained consumer has been selected, and no publishable pilot release has been assigned. Alpha.13 must not be retroactively published to crates.io because its immutable packaged README explicitly describes it as GitHub-only. Repository fixtures remain mechanism evidence only.

This document turns the roadmap's usefulness gate into one exact integration boundary. The machine-readable source is [`tests/package-contract/adopter-pilot.json`](../tests/package-contract/adopter-pilot.json), enforced by `scripts/verify_adopter_contract.ps1` in required CI. It pins the verified Alpha.13 mechanism baseline and the rules a new prerelease must satisfy before the external pilot starts. The [candidate surface inventory](candidate-surface.md) classifies the public identities this pilot may pin; it is not a freeze.

## Current evaluation source

The `sealr.external-adopter-pilot.v2` contract separates historical artifact
identities from the source currently under evaluation. Current evaluation pins
`sealr = "=0.1.0-alpha.15"` and matching Alpha.15 native companions. The copied
handoff manifest and workspace package version must agree with that requirement.
Alpha.15 remains GitHub-only and does not assign a registry pilot release.

Alpha.13 is historical reproduction evidence, not the recommended evaluation
release: Alpha.14 fixes incomplete Deflate stream admission. The historical
commit, source-package digest, and native archive digest below still describe
Alpha.13 exactly and must not be reassigned to a newer preview. These GitHub-only
prereleases may not be retroactively published to crates.io. The new-release gate
continues to require truthful tagged documentation and an agreed adopter scope.

## Adopter selection

The first pilot is one separately maintained publisher, registry, build backend, or installer with a Python wheel workflow on `x86_64-unknown-linux-gnu`. The maintainer must be able to make independent integration and release decisions, and the project's own CI must own the proof. A Sealr fork, copied example, or fixture maintained inside this repository does not qualify.

Agree the exact use case, Python version, installer version, resource budget, and failure policy before assigning a Sealr pilot prerelease. Scope drift after that assignment is a new contract, not an informal widening.

## Verified Alpha.13 baseline

The first pilot is intentionally limited to the strongest implemented path. The table below is the reproducible baseline used to negotiate that pilot, not a package to upload retroactively.

| Field | Exact baseline |
|---|---|
| Sealr release | `0.1.0-alpha.13` |
| Tag | `v0.1.0-alpha.13` |
| Tagged commit | `2fab2cfcd54dc065d02e25e74c3bfb227555ca90` |
| Rust source dependency | `sealr = "=0.1.0-alpha.13"` |
| Source registry | crates.io is allowlisted, but Alpha.13 is intentionally unpublished |
| Source package | Reproducibility evidence only: 553,812 bytes, SHA-256 `fb70684a71ec770bdf151176ef624244dd571de2c37bc7860e45db4c2607743e` |
| Package origin | Clean `v0.1.0-alpha.13` tag checkout, Cargo 1.98.0 |
| Native target | `x86_64-unknown-linux-gnu` |
| Native archive | `sealr-0.1.0-alpha.13-x86_64-unknown-linux-gnu.tar.gz` |
| Native archive identity | 3040308 bytes, SHA-256 `8f74d52566a275193261d82d3977e0b469b4c6c7d1a3f588f0b3a982a1f5892d` |
| Tested floor | Ubuntu 24.04 x86_64, glibc 2.39, Linux 6.8 or later |
| Supervised floor | Landlock ABI 3 plus the documented x86_64 seccomp filter |
| Worker manifest | `libexec/sealr/sealr-worker.manifest` |
| Evidence verifier | `sealr-identity-verifier` from the same authenticated native archive |
| Python adapter | PyPA installer 1.0.1, SHA-256 `011d045df8b954ced7dde3a7e42ae4418da40ecda7990f2d11d5ed7c146fd98b` |

The future pilot crate and native archive are separate artifacts with separate trust evidence. The crate supplies the public Rust API. The native archive supplies the authenticated worker and the separately implemented evidence verifier. Matching the version string is required but insufficient: the native archive must also pass its `SHA256SUMS` entry and GitHub build-provenance verification before either companion is trusted.

The verifier is implementation-independent from the Sealr crate. It is not supply-chain independence because it ships in the same native archive and release workflow.

## Semantic bundle

The Alpha.13 baseline fixes the exact interpretation, policy, consumer, and evidence lineages below. A new prerelease may retain them only if their definitions remain byte-for-byte unchanged.

| Claim | Identifier | SHA-256 or encoding |
|---|---|---|
| ZIP interpretation | `sealr.profile.zip.portable-utf8.v1` | `acee86158d481adff96da0277a470ba753d6208ede74bc48586bb0134db5152e` |
| Policy | `sealr:policy/default/v1` | `8298b205c981ed140a52ba555c0499712436969faf4ebc28d88d8d9e7024c340` |
| Wheel consumer | `sealr.consumer.python-wheel.v1` | `2fd5f81e38b6ad483fa0e998f665cc466a9bd9816382299f4a64a0202f4a91bb` under default `WheelLimits` |
| Specification snapshot | `pypa-wheel-core-metadata-2026-08-28` | Bound into the consumer digest |
| Canonical view | `sealr.view.v2` | RFC 8785 exact bytes |
| Canonical receipt | `sealr.receipt.v3` | RFC 8785 exact bytes |
| Handoff report | `sealr.pypa-wheel-source-example.v1` | Closed JSON result schema |
| Adapter | `pypa-installer-1.0.1-wheel-source` | Exact installer distribution and bridge |
| Target model | `pypa-installer-1.0.1-linux-posix` | Fresh roots, no bytecode, no overwrite |

Changing any profile, policy, limits, specification snapshot, schema, adapter, or target model creates a different pilot bundle. An adopter must not infer compatibility from the `0.1` package prefix.

## What this repository already proved

These proofs stay in Sealr CI. They do not satisfy the external usefulness gate.

| Proof | Owner today | Pilot requirement |
|---|---|---|
| Public-API-only copyable handoff against Cargo's extracted crate | Sealr repository | Repeat against a registry crate, without a path patch |
| Independent canonical evidence verification | Packaged verifier in the native archive | Same verifier, authenticated with the archive |
| Source deletion before the installer bridge | Copyable example and Poetry fixture | The adopter's integration and CI |
| Post-boundary `.whl` open denial | Host adapter and installer bridge in repository fixtures | The adopter's open hook or equivalent trace |
| Exact output and mode audit | Rust side of the copyable example | The adopter's trusted component |
| Poetry 2.4.2 private update seam | Repository-owned fixture | Out of scope unless that project is the selected adopter |

## Artifact acquisition gate

The Alpha.13 native archive is available and is sufficient to reproduce the repository mechanism. Follow the [release verification guide](release-verification.md) before extracting it. It is not the final pilot bundle unless the source acquisition contract is deliberately changed away from crates.io and reviewed as an exact immutable alternative.

The Alpha.13 source package mechanics are ready: the manifest, exact contents, MSRV, license, README, and extracted consumers pass required CI, and only `sealr` is allowlisted for crates.io. The clean tag package was reproduced twice with Cargo 1.98.0 as 553,812 bytes with SHA-256 `fb70684a71ec770bdf151176ef624244dd571de2c37bc7860e45db4c2607743e`.

Alpha.13 itself is not the upload candidate. Its immutable package README says the prerelease does not publish a crate to crates.io. Uploading it later would make the package's own documentation false and would create a registry artifact that cannot be overwritten. The exact digest above is baseline evidence, not publication authorization.

After an adopter and scope are agreed, prepare a new prerelease from protected `main`. That release must update the crate version, copied handoff pin, lockfile, changelog, release notes, workflow constants, machine pilot contract, and native worker and verifier artifacts together. Its tagged README must accurately describe the planned crates.io distribution. The GitHub release must be immutable and authenticated, and the source crate must be packaged and uploaded from the same clean tag. The [release process](releasing.md#publish-the-source-crate-for-the-pilot) defines the gates and readback.

The external pilot must use an ordinary immutable dependency resolution. It may not use:

- a local path dependency;
- a mutable branch;
- an unpublished workspace crate;
- any `__internal-*` feature;
- the wheel laboratory, CLI internals, or private semantic records.

After publication, the copied handoff must use the new exact version and generate a lockfile without a patch. That lockfile, its registry checksum, the authenticated native archive digest, the source package digest, and the release tag commit become pilot evidence. Required CI must then reject any drift between this document, the machine contract, and the selected release before downstream source transfer.

## Required downstream proof

The adopter's own CI must demonstrate all of the following through its real integration boundary.

1. Authenticate the native release archive before loading the worker manifest or verifier.
2. Reject a crate, worker manifest, helper, verifier, target, ABI, or feature-generation mismatch before source transfer.
3. Admit through `apply_supervised` under the fixed portable UTF-8 profile and default v1 policy.
4. Emit canonical view v2 and receipt v3 and require the packaged verifier to accept them against the observed wheel.
5. Keep the exact wheel artifact and install plan in Rust or an equivalently trusted component.
6. Delete the private source or revoke consumer access before the installer bridge starts.
7. Give Python only bounded verified blobs and the closed digest-bound manifest.
8. Install an open hook or equivalent trace that rejects every post-boundary wheel open.
9. Audit exact output paths, file kinds, content, and executable modes before accepting realization identity.
10. Keep archive denial, unsupported input, infrastructure failure, destination-effect failure, timeout, cancellation, and tamper failure distinguishable.

## Minimum negative matrix

| Mutation or failure | Required result |
|---|---|
| Native archive checksum or provenance mismatch | Stop before extraction or execution |
| Worker manifest release, target, ABI, length, or digest mismatch | Stop before source transfer |
| Helper feature-generation mismatch | Stop before source transfer |
| Canonical view, receipt, pair, or observed-source mutation | Independent verification failure |
| Raw or out-of-band manifest mutation | Stop before Python effects |
| Staged member content mutation | Stop before Python effects |
| Lying wheel `RECORD` | Wheel denial before install effects |
| Post-boundary `.whl` open | Immediate bridge failure |
| Missing, extra, linked, replaced, or mode-drifted output | Realization audit failure |
| Worker timeout, crash, or unclean exit | Infrastructure failure with no released partial member bytes |
| Existing destination or unsafe ancestor | Effect failure without overwrite |

Repository conformance already contains examples of these cases. The pilot passes only when the separately maintained project owns equivalent evidence in its own CI.

## Evidence to return to Sealr

The pilot report is a public, fill-in record. It should contain:

- the adopter repository and exact commit;
- the locked crate version and registry checksum;
- the native archive filename and SHA-256;
- the Sealr release tag commit;
- the supported operating-system, Python, installer, and target model;
- the corpus selection rule and byte-addressed artifact manifest;
- admitted, denied, unsupported, infrastructure-failure, and effect-failure counts;
- investigated rejection clusters;
- setup and public API friction;
- every requested semantic or schema change;
- the downstream no-reopen and negative-test results;
- explicit nonclaims.

No private wheel bytes, credentials, or sensitive paths belong in the report.

Suggested report skeleton:

```text
adopter:
  repository:
  commit:
sealr:
  crate_version:
  crate_checksum:
  native_archive:
  native_archive_sha256:
  tag_commit:
environment:
  os:
  python:
  installer:
  target_model:
corpus:
  selection_rule:
  artifact_manifest:
results:
  admitted:
  denied:
  unsupported:
  infrastructure_failure:
  effect_failure:
  investigated_rejection_clusters:
friction:
  setup:
  public_api:
  requested_changes:
proofs:
  no_reopen:
  negative_matrix:
nonclaims:
```

## Nonclaims

This contract does not claim production containment, malware detection, general Poetry support, crates.io publication of Alpha.13, or supply-chain independence of the packaged verifier.

## Exit decision

The external usefulness gate becomes green only when a separately maintained integration satisfies this contract and treats Sealr's capability and independently checked evidence as authoritative. A successful copied repository fixture, local path build, GitHub Action wrapper, or receipt followed by another unzip does not pass.

Pilot feedback then decides the candidate API and identity freeze. Any failure that exposes a product defect becomes a deterministic repository regression before the review surface freezes.
