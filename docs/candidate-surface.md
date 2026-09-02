# Candidate surface inventory

Updated 2026-09-02.

> Status: inventory, not a freeze. Required CI rejects drift between this page, [`tests/package-contract/candidate-surface.json`](../tests/package-contract/candidate-surface.json), the public profile, policy, identity, evidence, CLI, and package constants, crate features, and the [adopter pilot contract](adopter-pilot.md). Nothing here is frozen. Candidate stability follows adopter feedback.

The [near-term plan](near-term.md) asked for a classified inventory of the public surface before the freeze proposal. This page is that inventory. A later freeze document must name golden fixtures and a migration rule; this page does not.

Allowed classes:

| Class | Meaning |
|---|---|
| `candidate-stable-for-pilot` | The first external pilot may pin this identity. A semantic change needs a new identity before that pilot starts. |
| `preview` | Released and supported in this repository, but outside the first-pilot bundle. |
| `internal` | Not a supported runtime or public API. Hidden behind private features or research-only profiles. |
| `planned-for-replacement` | Visible today, but the freeze must not treat the current shape as the long-term contract. |

## Interpretation profiles

Every public profile constant in `crates/sealr/src/ir.rs` appears exactly once.

| Profile | Class |
|---|---|
| `sealr.profile.zip.portable-utf8.v1` | candidate-stable-for-pilot |
| `sealr.profile.zip.strict-ascii.v1` | preview |
| `sealr.profile.zip.strict-ascii.v2` | preview |
| `sealr.profile.zip64.strict-ascii.v1` | preview |
| `sealr.profile.tar.ustar-portable.v1` | preview |
| `sealr.profile.tar-gzip.ustar-portable.v1` | preview |
| `sealr.profile.tar.pax-portable.v1` | preview |
| `sealr.profile.tar.gnu-longname-portable.v1` | preview |
| `sealr.profile.tar-gzip.pax-portable.v1` | preview |
| `sealr.profile.tar-gzip.gnu-longname-portable.v1` | preview |
| `sealr.profile.tar-zstd.ustar-portable.v1` | preview |
| `sealr.profile.tar-xz.ustar-portable.v1` | preview |
| `sealr.profile.tar-bzip2.ustar-portable.v1` | preview |
| `sealr.profile.7z.copy-portable.v1` | preview |
| `sealr.profile.zip.wheel-utf8.v1` | internal |

The first pilot pins portable UTF-8 ZIP32, default policy v1, and the public wheel consumer. Other released profiles remain available in-process; the authenticated Linux worker still refuses non-ZIP32 selections without fallback.

## Policies

Every default policy constructor in `crates/sealr/src/policy.rs` appears exactly once.

| Policy | Class |
|---|---|
| `sealr:policy/default/v1` | candidate-stable-for-pilot |
| `sealr:policy/default/v2` | preview |
| `sealr:policy/default/v3` | preview |
| `sealr:policy/default/v4` | preview |
| `sealr:policy/default/v5` | preview |
| `sealr:policy/default/v6` | preview |
| `sealr:policy/default/v7` | preview |
| `sealr:policy/default/v8` | preview |
| `sealr:policy/default/v9` | preview |
| `sealr:policy/default/v10` | preview |
| `sealr:policy/default/v11` | preview |

Policy v1 authorizes ZIP32 only. Later defaults add later formats without changing the v1 bytes.

## Identities and encodings

Wheel consumer identities are in the first-pilot bundle. Tree encodings are released preview identities, not locks.

| Identity | Class |
|---|---|
| `sealr.consumer.python-wheel.v1` | candidate-stable-for-pilot |
| `sealr.wheel-consumer-profile.v1` | candidate-stable-for-pilot |
| `pypa-wheel-core-metadata-2026-08-28` | candidate-stable-for-pilot |
| `sealrWheelArtifactV1` | candidate-stable-for-pilot |
| `sealrWheelInstallPlanV1` | candidate-stable-for-pilot |
| `sealrWheelRealizationV1` | candidate-stable-for-pilot |
| `sealrTreeV1` | preview |
| `sealrTreeV2` | preview |
| `sealrTreeV3` | preview |
| `sealrTreeV4` | preview |
| `sealrTreeV5` | preview |
| `sealrTreeV6` | preview |
| `sealrTreeV7` | preview |
| `sealrTreeV8` | preview |
| `sealrTreeV9` | preview |
| `sealrTreeV10` | preview |
| `sealrTreeV11` | preview |
| `sealrTreeV12` | preview |

## Evidence schemas

The first pilot independently verifies canonical view v2 and receipt v3. The default declaration-order documents remain compatibility output.

| Schema | Class |
|---|---|
| `sealr.view.v2` | candidate-stable-for-pilot |
| `sealr.receipt.v3` | candidate-stable-for-pilot |
| `sealr.archive-ir.v1` | preview |
| `sealr.view.v1` | planned-for-replacement |
| `sealr.receipt.v2` | planned-for-replacement |

## Pilot operations

These public operations are the capability path the first adopter is expected to call. Additions may land before freeze. Removals or signature changes fail `crates/sealr/tests/api_surface.rs`.

- `apply`
- `apply_with_options`
- `Request` as the exhaustive `{ source, policy, dest }` struct
- `apply_supervised`
- `inspect_supervised`
- `LinuxWorker`
- `evaluate_wheel`
- `realize_identity`
- `VerifiedArchive::read_member`
- `VerifiedArchive::read_member_prefix`
- `Outcome::canonical_evidence`

The compile-time inventory of every supported public item remains [api-surface.md](api-surface.md). This page classifies that surface; it does not replace it.

## CLI machine output

The shipped CLI is a preview facade over the library. The first pilot's authority path is the public Rust API, not `sealr` as an installer.

| Contract | Value | Class |
|---|---|---|
| Admitted, complete, no effect failure | exit `0` | preview |
| Admission or verification did not complete | exit `2` | preview |
| Admitted, destination effect failed | exit `3` | preview |
| Operational or argument error | exit `1` | preview |

Canonical `--view`/`--receipt --canonical` files are the digested RFC 8785 bytes. Pretty stdout/stderr JSON is presentation.

## Distribution

| Contract | Value | Class |
|---|---|---|
| MSRV | `1.98` | candidate-stable-for-pilot |
| SemVer until 1.0 | prerelease; every breaking change in the changelog | preview |
| Publishable crate | `sealr` only | candidate-stable-for-pilot |
| Linux native archive | eight-file helper contract | candidate-stable-for-pilot |
| macOS and Windows native archives | six-file in-process contract | preview |
| Helper manifest schema | `sealr.worker-artifact.v1` | candidate-stable-for-pilot |
| Evidence verifier | `sealr-identity-verifier` | candidate-stable-for-pilot |

Linux native files:

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

## Internal features

These Cargo features are not a shipped API or a supported runtime activation surface:

- `__internal-fuzzing`
- `__internal-worker-lab`
- `__internal-lifecycle-lab`

The private semantic-record codec, worker protocol types, and wheel laboratory remain outside the public crate root.

## Planned for replacement

These names are visible today and must not be mistaken for the frozen contract:

| Surface | Id | Why it is not the freeze target |
|---|---|---|
| `Verdict` | `Verdict` | Compatibility adapter over the outcome axes |
| Default receipt schema v2 | `receipt.schema.v2-default-lineage` | Canonical receipt v3 is the digested lineage |
| Default view schema v1 | `view.schema.v1-default-lineage` | Canonical view v2 is the digested lineage |
| `Policy.atomic` | `Policy.atomic` | Historical durability selector name kept for digest stability |

## What would make this a freeze

All of the following, not any one of them:

1. One external adopter has returned the [pilot report](adopter-pilot.md#evidence-to-return-to-sealr).
2. Every adopter-requested semantic change has a new identity or an explicit documentation-only classification.
3. Golden compatibility fixtures exist for the candidate-stable identities.
4. A migration rule exists for every planned replacement.
5. The freeze document says so, and required CI pins that claim.

Until then, treat every class as an inventory label. Do not advertise a stable Sealr 1.0 surface from this page.
