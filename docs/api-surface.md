# Public API surface contract

> Status: the role-grouped inventory of the supported `sealr` crate surface, paired with its machine half: `crates/sealr/tests/api_surface.rs` imports every supported item by exact path and pins the core operation signatures through function-pointer coercions, so a removal, rename, or pinned-signature change fails compilation. Additions are permitted pre-freeze and land in both halves in the same change. The shape decisions behind this surface are recorded in the [API contract](api.md).

Everything supported flows through the crate root's re-exports plus the two public modules, `sealr::wheel` and `sealr::canonical_json`. Internal laboratories and fuzz bridges are `#[doc(hidden)]` behind private features and are not part of this contract.

| Group | Items |
|---|---|
| Operation | `apply`, `apply_with_options`, `Request` (permanently exhaustive: `source`, `policy`, `dest`), `Source`, `ApplyOptions`, `ArchiveSelection`, `Outcome`, `Verdict` |
| Evidence output | `View`, `Receipt`, `MemberView`, `SourceMeta`, `PolicyMeta`, `ToolMeta`, `EnvMeta`, `MaterializationMeta`, `WindowsMaterializationEvidence`, and the outcome axes: `AdmissionStatus`, `InterpretationStatus`, `VerificationStatus`, `EffectStatus`, `ViewCompleteness`, `StoppingPhase`, `SourceDigest`, `DigestHex` |
| Canonical lineage | `Outcome::canonical_evidence`, `CanonicalEvidence`, `sealr::canonical_json` (`jcs_bytes`, `CanonicalJsonError`, `CanonicalJsonErrorKind`, `MAX_CANONICAL_INTEGER`) |
| Findings | `Finding`, `FindingCode`, `Severity` |
| IR and per-format evidence | `ArchiveIR`, `IrMember`, `ByteRange`, the per-format `*Evidence`/`*Covering` records, the eight `*InterpretationProfile` selections, the per-profile `*_canonical_bytes`/`*_digest` function pairs, and the `*_SCHEMA` and profile-id constants |
| Identity | `content_root`, `layout_root`, the eleven `encode_*_layout` functions, `OutcomeIdentities`, `TreeRoot`, and the `TREE_ENCODING_*` ids |
| Policy | `Policy` (non-exhaustive; constructed through the versioned defaults or a validated document), `PolicyDocument`, `ValidatedPolicy`, `CompiledControls`, `ResourceBudget`, the `POLICY_FORMAT_*` constants, and the stable utilities `hex_sha256` and `ratio_exceeds` |
| Path jail | `jail_name`, `jail_relative`, `join_under_dest`, `JailedName`, and the two portable-name bound constants |
| Capability | `VerifiedArchive` (including `read_member` and `read_member_prefix`), `RetentionPlan`, `RetentionStatus`, `MemberReadError` and kind, `RetentionPlanError` and kind, and the three retention bound constants |
| Supervision | `apply_supervised`, `inspect_supervised`, `LinuxWorker`, `SupervisionError` and kind |
| Wheel consumer | `evaluate_wheel`, `realize_identity`, `WheelEvaluation`, `WheelLimits`, `WheelArtifactIR`, `WheelInstallPlan`, `InstallEntry`, `WheelIdentities`, `RealizedOutput`, `RealizationIdentityError` (accessors), `WheelFinding`, the filename and metadata records, the parse helpers, and the `CONSUMER_PROFILE_*`/encoding-id constants |
| Miscellaneous | `SnapshotKind` |

Discipline this surface already holds and the freeze will keep: non-exhaustive markers on output records; output records readable but not constructible where they carry authority (`WheelInstallPlan`, `VerifiedArchive` use private fields and accessors and block caller construction); input types built through constructors and builders; error types exposing accessors rather than public fields.

The extracted-package PyPA installer conformance proves one substantial downstream use of the supported surface without an internal feature or another workspace crate. The scheduled assurance lane now adds a compiler-accurate diff through SHA-256-authenticated `cargo-semver-checks` 0.49.0 against the self-contained package produced from the exact Alpha.11 commit. It augments these source and consumer contracts rather than replacing them. Seven item instances from the deliberate pre-freeze `Policy` and `RealizationIdentityError` shape changes are pinned warnings; the category cannot become promotable until a later release baseline removes that debt and starts a fresh ten-run history.
