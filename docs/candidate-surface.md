# Candidate surface inventory

Updated 2026-09-13.

> Status: inventory, not a freeze. Required CI rejects drift between this page, [`tests/package-contract/candidate-surface.json`](../tests/package-contract/candidate-surface.json), the public profile, policy, identity, evidence, CLI, and package constants, crate features, and the [optional adopter pilot contract](adopter-pilot.md). Nothing here is frozen. Candidate stability follows automated downstream evidence. External feedback adds cases whenever it arrives.

The [near-term plan](near-term.md) asked for a classified inventory of the public surface before the freeze proposal. This page is that inventory. All four planned replacements now have executable consumer migration rules. A later freeze still needs complete compatibility evidence for every advertised surface and an explicit versioning decision.

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

### Evidence consumer migration v1

`sealr.evidence-lineage-migration.v1` supplies the consumer migration contract for
`receipt.schema.v2-default-lineage` and `view.schema.v1-default-lineage`. Their
targets are `sealr.receipt.v3` and `sealr.view.v2`, respectively. The inventory
manifest records these two rows as `consumer-contract-tested`.
The remaining two replacement rules are described below and bound in the
[consumer migration manifest](../tests/package-contract/consumer-migrations.json).

An integrating caller selects `Outcome::canonical_evidence()` in Rust, or
`--canonical` when writing the CLI's `--view` and `--receipt` files. It gives the
exact emitted bytes and observed source to the packaged evidence verifier.
Legacy and mixed-lineage pairs fail closed. The caller must not sort, reserialize,
relabel, or fall back to legacy evidence after verification fails. Existing
default outputs, schemas, and their historical digest coverage remain unchanged.
This migration selects an existing emission path; it does not convert arbitrary
stored legacy documents into verified canonical evidence.

The fixture consumer is an inspection with no filesystem effect. It requires
successful evidence verification, the canonical schema pair, and `admitted`,
`complete`, and `not-requested` admission, verification, and effect statuses in
both documents. Verifier exit `0` alone means the evidence is coherent. A
coherent rejection remains a refused archive and authorizes no consumption.

The required [native package check](../scripts/verify_native_package.ps1) uses
the same packaged CLI and verifier for this exact matrix:

| Case | View schema | Receipt schema | Verifier exit | Consumer decision |
|---|---|---|---|---|
| `canonical-admitted` | `sealr.view.v2` | `sealr.receipt.v3` | `0` | `archive-admitted` |
| `legacy-pair` | `sealr.view.v1` | `sealr.receipt.v2` | `1` | `evidence-refused` |
| `legacy-view-canonical-receipt` | `sealr.view.v1` | `sealr.receipt.v3` | `1` | `evidence-refused` |
| `canonical-view-legacy-receipt` | `sealr.view.v2` | `sealr.receipt.v2` | `1` | `evidence-refused` |
| `canonical-rejected` | `sealr.view.v2` | `sealr.receipt.v3` | `0` | `archive-not-admitted` |

The input is the byte-pinned `gnu-tar-1.35` artifact in the
[existing producer corpus](../crates/sealr/tests/conformance/tar-producers-v1.json).
Flipping its first header byte supplies the rejected input. Legacy emission
comes from the same packaged CLI with `--canonical` omitted. Verification leaves
every input document byte-for-byte unchanged. The native check reuses its
existing canonical admission and rejection verification results, and the
candidate verifier binds the five cases and fixture identity to this inventory.

Existing [encoding tests](../crates/sealr/tests/evidence_encoding.rs) continue to
cover digest bytes, semantic parity, compatibility fields, and deterministic
rejection evidence. This matrix adds the consumer's lineage selection and
acceptance decision. It does not freeze the inventory, remove legacy output,
or establish that an admitted program is safe to execute.

### Verdict consumer migration v1

`sealr.verdict-consumer-migration.v1` replaces consumer decisions based on
`Verdict`, `rejected()`, or `wrote()` with independent capability and effect
decisions. The Deepr gate, PyPA handoff, and extracted-package consumer use this
path. `Outcome::verified_archive()` or `into_verified_archive()` supplies actual
member-read authority. Public status fields alone cannot construct that authority.

An inspection requires admitted and complete verification with no requested
effect. A consumer that requested materialization additionally requires a
committed effect before continuing. Missing sources, structural or CRC refusal,
and failed publication remain distinct outcomes. In particular, `Admitted` alone
does not imply complete verification or a usable capability.

The [packaged consumer](../tests/packaged-consumer/src/outcome_migration.rs)
executes six real operations: `inspected-capability`,
`committed-materialization`, `structural-denial`, `crc-denial`,
`effect-setup-failure`, and `source-unavailable`. It checks borrowed and owned
capability reads, destination bytes, denied consumption, and preservation of an
existing destination. The same matrix runs through the authenticated Linux
worker and as an ordinary in-process package test on supported native platforms.

The existing core `mutated_staged_content_never_publishes` regression supplies
separate evidence for a late failure after complete verification. It retains a
readable capability while the requested effect fails, legacy `Verdict` remains
rejected, and CLI exit remains `3`. A caller requiring committed writes stops;
the effect failure does not invalidate already established archive authority.
The consumer fixture does not manufacture this state by editing outcome fields
or exposing a public fault-injection feature.

Compatibility verdicts, helper methods, CLI exits, evidence fields, and semantic
identities retain their existing meaning. This migration removes their use as
the authority gate in these supported consumers; it does not remove the adapters.

### Named durability migration v1

`sealr.policy-durability-migration.v1` replaces direct Rust writes to
`Policy.atomic` with `Durability` selection on `Policy` or `PolicyDocument`.
Both expose `durability()`, `set_durability()`, and `with_durability()`.

| Named mode | Historical `atomic` | Receipt durability |
|---|---|---|
| `Durability::FlushOnly` | `false` | `flush-only` |
| `Durability::MemberSync` | `true` | `member-sync` |

The historical boolean remains the sole backing field. Existing policy JSON,
default digests, and worker records remain byte-compatible. JSON still uses
`atomic`; a second `durability` key is refused, including when both keys appear.
Validated policies remain immutable. Change the policy before validation so its
memoized digest describes the selected mode.

The [durability consumer tests](../crates/sealr/tests/durability_migration.rs)
compare all eleven policies in both modes against legacy byte encodings,
digests, and compiled controls. They also verify document validation, refusal
of a second JSON spelling, and real native publication and existing-destination
preservation in both modes. Required CI runs these package tests across the
supported native platforms.

Both modes stage privately and publish with no-replace semantics. `MemberSync`
additionally syncs completed member files. Neither mode syncs directories,
recovers abandoned stages, or establishes power-loss durability. A future mode
with different guarantees requires its own policy and migration contract.
Migration evidence does not retire compatibility fields or freeze the candidate.

## What would make this a freeze

All of the following, not any one of them:

1. An isolated consumer replays authenticated artifacts, source removal, no-reopen checks, and typed failures under the [near-term plan](near-term.md).
2. Every downstream-discovered semantic change has a new identity or an explicit documentation-only classification.
3. Golden compatibility fixtures exist for the candidate-stable identities.
4. A migration rule exists for every planned replacement.
5. The freeze document says so, and required CI pins that claim.

Until then, treat every class as an inventory label. Do not advertise a stable Sealr 1.0 surface from this page.
