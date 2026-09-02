# Near-term execution plan

Updated 2026-09-02.

> Status: active after `v0.1.0-alpha.13`. This page defines the work needed to turn Sealr's repository-owned wheel proof into one independently maintained adoption, then use that evidence to prepare a stable semantic surface. Completed preview work is indexed in the [milestone history](milestones.md).

The near-term objective is not another format. It is a consumer outside this repository that treats `VerifiedArchive` and independently checked canonical evidence as authoritative.

## Target outcome

The first external pilot should be deliberately narrow:

- one separately maintained wheel publisher, registry, build backend, or installer;
- one x86_64 Linux deployment model using the authenticated worker and packaged verifier;
- one exact prerelease of the public `sealr` crate;
- one source-removal boundary after admission;
- one reproducible downstream CI path proving that no ZIP parser reopens the source;
- one published compatibility and integration report with explicit nonclaims.

This scope exercises the strongest implemented boundary without claiming general package-manager, platform, format, or production support.

## Work package 1: make the adopter path ordinary

The copyable [PyPA `WheelSource` handoff](../crates/sealr/examples/pypa_installer_handoff/README.md) proves that the public pieces compose, but its local `patch.crates-io` flow is a repository packaging test. An external pilot needs an ordinary, versioned acquisition path.

The [external adopter pilot contract](adopter-pilot.md) now pins the verified Alpha.13 technical baseline, Linux native floor, worker ABI and feature generation, interpretation and policy identities, wheel consumer digest, evidence schemas, installer bridge, required negative matrix, and pilot report. Required CI verifies those declarations against their implementation sources. Alpha.13 must not be retroactively published because its immutable packaged README says it is GitHub-only. Adopter selection and a new, internally consistent pilot prerelease remain open.

1. Choose the pilot with a maintainer who can make independent integration and release decisions.
2. Agree on one exact use case, target platform, Python version, installer version, resource budget, and failure policy.
3. Once the scope is agreed, prepare a new prerelease whose tagged documentation truthfully names crates.io distribution. Publish its allowlisted `sealr` crate from the same clean tag as the matching authenticated native worker and verifier archive, then read both paths back. If a registry publication is not selected, document an equally exact source-package acquisition and verification flow that does not depend on a checkout or mutable branch.
4. Provide a short version-matching contract for the crate, worker manifest, verifier, canonical evidence lineage, and target platform.
5. Start from the packaged handoff, then remove repository fixture controls, private protocols, and path patches from the adopter-facing build.

Exit criteria:

- a clean machine can obtain and authenticate every required artifact;
- the downstream lockfile selects one exact Sealr prerelease;
- the integration uses no workspace crate, internal feature, private protocol, or repository script;
- version mismatch and missing worker support fail before source transfer or destination effects.

## Work package 2: prove authority transfer downstream

The adopter integration must preserve the boundary, not merely call Sealr before another unzip.

1. Admit the wheel through the supported portable UTF-8 profile and the authenticated Linux worker.
2. Emit canonical evidence and require the independent packaged verifier to accept it against the observed source.
3. Retain the exact wheel evaluation and install plan in Rust or an equivalently trusted component.
4. Remove or revoke access to the original wheel before the consumer phase begins.
5. Give the consumer only bounded verified member blobs and a closed digest-bound manifest. Do not give it the wheel path or wheel bytes.
6. Deny and trace `.whl` opens after the admission boundary.
7. Audit the realized output set, file kinds, executable modes, and content before accepting the realization identity.
8. Exercise admitted, denied, unsupported, infrastructure-failure, tamper, timeout, and cancellation paths.

Exit criteria:

- downstream CI succeeds after the source becomes unavailable;
- an open hook or equivalent process trace shows no post-admission source open;
- source, evidence, manifest, staged-member, output-set, and mode mutations all fail closed;
- the consumer reports archive denial separately from infrastructure and destination-effect failure;
- the integration documentation states its supported scope and residual risks.

## Work package 3: publish what the pilot teaches

External adoption matters because it can falsify repository assumptions. Capture that result before freezing the public surface.

1. Record setup time, required glue, public API friction, error-handling friction, artifact-delivery friction, and every requested unstable surface.
2. Publish the exact artifact set and a reproducible compatibility report without redistributing bytes whose terms do not allow it.
3. Classify each proposed change as documentation-only, additive API, breaking API, new profile, new schema, or deferred scope.
4. Add deterministic regressions for every reproducible Sealr defect.
5. Update the [API contract](api.md), [distribution contract](distribution-contract.md), and [usefulness test](usefulness.md) with the observed boundary and nonclaims.

Exit criteria:

- the adopter can update or reject a Sealr release intentionally;
- no integration requirement depends on undocumented repository knowledge;
- the roadmap can name the external proof precisely without overstating general compatibility.

## Parallel track A: targeted wheel compatibility

The current [v5 wheel inventory](wheel-compatibility-v5.md) contains 300 exact artifacts, 280 admissions, and 20 investigated denials. It observed no Unicode member paths, so simply increasing the same sample would not close the most relevant evidence gap.

Prioritize:

1. benign wheels with correctly flagged NFC Unicode member paths;
2. Store and Deflate members with exact data descriptors;
3. admitted `scripts`, `headers`, and `data` scheme cases across more producers;
4. producer and platform cohorts implicated by adopter failures;
5. exact rejection clusters near current resource and metadata limits.

Every added cohort needs byte-addressed acquisition metadata, a stated selection method, current profile and policy identities, separate artifact and finding counts, and individual investigation of material denial clusters. A compatibility need may create a new versioned profile. It may not silently widen an existing profile or the ZIP32 default.

## Parallel track B: candidate stability review

The [candidate surface inventory](candidate-surface.md) now classifies the public interpretation profiles, default policies, wheel and tree identities, evidence schemas, first-pilot operations, CLI exits, MSRV, native Linux archive layout, helper manifest, verifier, internal features, and planned replacements. It is an inventory, not a freeze.

Remaining freeze-prep work while the pilot runs:

- keep `crates/sealr/tests/api_surface.rs` and the compile-time public item list current as additive APIs land;
- record every adopter-requested change as additive, breaking, profile-versioned, schema-versioned, or documentation-only;
- attach golden compatibility fixtures and a migration rule to each `planned-for-replacement` surface before calling the inventory a freeze.

Candidate stability follows adopter feedback, not the other way around.

## Parallel track C: assurance and review readiness

Continue evidence that strengthens the current boundary:

1. accumulate the separate scheduled histories in the [assurance promotion ledger](assurance-promotion.md);
2. preserve bounded fuzzing, Kani, mutation, coverage, semantic shadow, native resource, and kernel-floor evidence with their existing nonclaims;
3. complete repeated hostile filesystem mutation stress on Linux, macOS, and Windows;
4. specify and test authenticated abandoned-stage recovery and explicit file, directory, publication, and power-loss durability levels;
5. refresh the [TCB report](tcb-report.md), including dependencies, platform `unsafe`, helper contents, and codec boundaries;
6. require TCB changes to be reviewed by someone other than their author, resolving the current single-maintainer review gap rather than waiving it;
7. draft an independent-review scope over the candidate-stable profiles, identities, materializer, worker, verifier, and package artifacts.

Commission the release-gating review only after the pilot-driven changes settle. Discovery reviews may happen earlier, but they do not satisfy the stable gate.

## Explicitly deferred

Until the external pilot and candidate review complete, do not prioritize:

- another container or wrapper profile;
- 7z LZMA/LZMA2 members or packed headers;
- ZIP methods 12, 93, or 95, or Deflate64;
- cpio, ar/deb, CAB, RPM, or RAR5;
- a broad language-binding matrix;
- a signing workflow presented as product completion;
- a TUI, hosted service, or general extraction frontend;
- performance work without a measured adopter bottleneck.

Research notes may continue, but they do not enter the shipped runtime or displace the active gates.

## Delivery sequence

| Order | Deliverable | Decision enabled |
|---|---|---|
| 1 | Exact adopter and bounded integration contract | Confirms the target and prevents scope drift |
| 2 | Ordinary authenticated artifact acquisition | Makes the pilot independent of the repository checkout |
| 3 | Downstream source-removal and no-reparse CI | Proves the core usefulness claim externally |
| 4 | Targeted compatibility and integration report | Identifies real profile, API, and documentation gaps |
| 5 | Candidate API, identity, evidence, and package freeze | Defines a stable reviewable surface |
| 6 | Lifecycle closure and accumulated assurance | Defines the evidence behind the stable claim |
| 7 | Independent security review and remediation | Tests the frozen claim before 1.0 |

The [roadmap](../ROADMAP.md) contains the stable gates and later sequence. The [vision](vision.md) explains the durable product direction. The [usefulness test](usefulness.md) remains the acceptance standard for the first three deliverables.
