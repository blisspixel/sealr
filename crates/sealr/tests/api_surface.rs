//! Compile-time pin of the supported public surface.
//!
//! Every supported public item is imported by exact path, and the core
//! operation signatures are pinned through function-pointer coercions, so
//! removing or renaming a supported item — or changing a pinned signature —
//! fails this test at compile time. Additions pass silently: the pre-freeze
//! contract permits additive growth, and an addition lands here in the same
//! change that introduces it. The role-grouped human half of this contract is
//! `docs/api-surface.md`.
#![allow(unused_imports)]
#![allow(clippy::no_effect_underscore_binding)]

use sealr::canonical_json::{
    jcs_bytes, CanonicalJsonError, CanonicalJsonErrorKind, MAX_CANONICAL_INTEGER,
};
use sealr::wheel::{
    evaluate_wheel, normalize_distribution, normalize_version, parse_wheel_filename,
    realize_identity, CoreMetadata, EntryPoint, EvaluationStage, ExecutableDisposition,
    InstallEntry, InstallScheme, InstallTransform, RealizationIdentityError, RealizedOutput,
    RecordBinding, WheelArtifactIR, WheelEvaluation, WheelFilename, WheelFinding, WheelHeaders,
    WheelIdentities, WheelInfrastructureErrorKind, WheelInstallPlan, WheelLimits, WheelMemberFacts,
    ARTIFACT_ENCODING_ID, CONSUMER_PROFILE_ID, CONSUMER_PROFILE_SCHEMA, PLAN_ENCODING_ID,
    REALIZATION_ENCODING_ID, SPEC_SNAPSHOT_ID,
};
use sealr::{
    apply, apply_supervised, apply_with_options, content_root, encode_sevenz_layout,
    encode_tar_bzip2_layout, encode_tar_gnu_longname_layout, encode_tar_gzip_gnu_longname_layout,
    encode_tar_gzip_layout, encode_tar_gzip_pax_layout, encode_tar_layout, encode_tar_pax_layout,
    encode_tar_xz_layout, encode_tar_zstd_layout, encode_zip64_layout, hex_sha256,
    inspect_supervised, jail_name, jail_relative, join_under_dest, layout_root, ratio_exceeds,
    AdmissionStatus, ApplyOptions, ArchiveFormat, ArchiveIR, ArchiveSelection, ByteRange,
    CanonicalEvidence, CompiledControls, DigestHex, EffectStatus, EnvMeta, Finding, FindingCode,
    InterpretationStatus, IrMember, JailedName, LinuxWorker, MaterializationMeta, MemberKind,
    MemberReadError, MemberReadErrorKind, MemberView, Outcome, Policy, PolicyDocument, PolicyMeta,
    Receipt, Request, ResourceBudget, RetentionPlan, RetentionPlanError, RetentionPlanErrorKind,
    RetentionStatus, SevenZInterpretationProfile, Severity, SnapshotKind, Source, SourceDigest,
    SourceMeta, StoppingPhase, SupervisionError, SupervisionErrorKind,
    TarBzip2InterpretationProfile, TarGnuLongNameInterpretationProfile,
    TarGzipInterpretationProfile, TarInterpretationProfile, TarPaxInterpretationProfile,
    TarXzInterpretationProfile, TarZstdInterpretationProfile, ToolMeta, TreeRoot, ValidatedPolicy,
    Verdict, VerificationStatus, VerifiedArchive, View, ViewCompleteness,
    WindowsMaterializationEvidence, ZipInterpretationProfile, MAX_RETENTION_PATHS,
    MAX_RETENTION_PATH_BYTES, MAX_RETENTION_TOTAL_PATH_BYTES, POLICY_FORMAT_SEVENZ_COPY,
    POLICY_FORMAT_TAR_BZIP2_USTAR, POLICY_FORMAT_TAR_GNU_LONGNAME,
    POLICY_FORMAT_TAR_GZIP_GNU_LONGNAME, POLICY_FORMAT_TAR_GZIP_PAX, POLICY_FORMAT_TAR_GZIP_USTAR,
    POLICY_FORMAT_TAR_PAX, POLICY_FORMAT_TAR_USTAR, POLICY_FORMAT_TAR_XZ_USTAR,
    POLICY_FORMAT_TAR_ZSTD_USTAR, POLICY_FORMAT_ZIP, POLICY_FORMAT_ZIP64,
    PORTABLE_NAME_MAX_COMPONENT_UTF16_UNITS, PORTABLE_NAME_MAX_COMPONENT_UTF8_BYTES,
    SEVENZ_COPY_PORTABLE_V1, TAR_BZIP2_USTAR_PORTABLE_V1, TAR_GNU_LONGNAME_PORTABLE_V1,
    TAR_GZIP_GNU_LONGNAME_PORTABLE_V1, TAR_GZIP_PAX_PORTABLE_V1, TAR_GZIP_USTAR_PORTABLE_V1,
    TAR_PAX_PORTABLE_V1, TAR_USTAR_PORTABLE_V1, TAR_XZ_USTAR_PORTABLE_V1,
    TAR_ZSTD_USTAR_PORTABLE_V1, TREE_ENCODING_ID, TREE_ENCODING_V10_ID, TREE_ENCODING_V11_ID,
    TREE_ENCODING_V12_ID, TREE_ENCODING_V2_ID, TREE_ENCODING_V3_ID, TREE_ENCODING_V4_ID,
    TREE_ENCODING_V5_ID, TREE_ENCODING_V6_ID, TREE_ENCODING_V7_ID, TREE_ENCODING_V8_ID,
    TREE_ENCODING_V9_ID, ZIP64_STRICT_ASCII_V1, ZIP_PORTABLE_UTF8_V1, ZIP_STRICT_ASCII_V1,
    ZIP_STRICT_ASCII_V2, ZIP_WHEEL_UTF8_V1,
};

#[test]
fn the_core_operation_signatures_are_pinned() {
    let _: fn(Request<'_>) -> Outcome = apply;
    let _: fn(Request<'_>, &ApplyOptions) -> Outcome = apply_with_options;
    let _: fn(&str, &VerifiedArchive, WheelLimits) -> WheelEvaluation = evaluate_wheel;
    let _: fn(
        &WheelInstallPlan,
        &str,
        &str,
        &[RealizedOutput],
    ) -> Result<String, RealizationIdentityError> = realize_identity;
    let _: fn(&serde_json::Value) -> Result<Vec<u8>, CanonicalJsonError> =
        jcs_bytes::<serde_json::Value>;
    let _: fn(&[u8]) -> String = hex_sha256;
    let _: fn(&ArchiveIR) -> TreeRoot = content_root;
    let _: fn(&ArchiveIR) -> TreeRoot = layout_root;
}

#[test]
fn the_frozen_request_shape_is_literally_constructible() {
    // The pre-freeze contract in docs/api.md: Request stays a permanently
    // exhaustive three-field struct. This literal is the contract.
    fn witness<'a>(source: Source<'a>, policy: &'a Policy) -> Request<'a> {
        Request {
            source,
            policy,
            dest: None,
        }
    }
    let policy = Policy::default_v1();
    let request = witness(
        Source::Bytes {
            path: None,
            data: b"",
        },
        &policy,
    );
    assert!(request.dest.is_none());
}
