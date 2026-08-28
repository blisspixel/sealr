//! `UntrustedArchive × Policy → (Materialization | Rejection) × Receipt × InspectableView`
//!
//! Ingest produces an immutable `SourceSnapshot`. Parsing and payload verification
//! use checked ranges over that snapshot; they do not reopen the caller path.

mod apply;
mod covering;
mod findings;
#[allow(dead_code)]
mod gzip;
mod identity;
mod interval;
mod ir;
mod jail;
mod materialize;
mod outcome;
mod policy;
mod quota;
mod ratio;
mod snapshot;
mod supervised;
mod tar;
mod verification;
#[cfg(any(target_os = "linux", feature = "__internal-worker-lab", test))]
#[allow(dead_code)]
mod worker_protocol;
// Private Alpha.6 semantic records back the supported Linux supervisor while
// their codec and types remain outside the public API.
#[allow(dead_code)]
mod semantic_record;
mod verified;
pub mod wheel;
mod zip;

/// Exercises the private semantic-record decoders from the separate fuzz
/// workspace without exposing their types through the supported API.
#[cfg(feature = "__internal-fuzzing")]
#[doc(hidden)]
pub fn __fuzz_semantic_records(input: &[u8]) {
    semantic_record::exercise_fuzz_input(input);
}

/// Exercises the bounded portable ustar parser and its public inspect path from
/// the separate fuzz workspace without exposing parser internals.
#[cfg(feature = "__internal-fuzzing")]
#[doc(hidden)]
pub fn __fuzz_tar_ustar_portable_v1(input: &[u8]) {
    tar::exercise_fuzz_input(input);
}

/// Exercises the bounded single-member gzip decoder and transform authority.
#[cfg(feature = "__internal-fuzzing")]
#[doc(hidden)]
pub fn __fuzz_gzip_rfc1952_single_member_v1(input: &[u8]) {
    gzip::exercise_fuzz_input(input);
}

/// Repository-only bridge used by the Linux worker conformance lab.
///
/// This module is absent unless the private `__internal-worker-lab` feature is
/// selected. It is not a supported runtime or public API surface.
#[cfg(feature = "__internal-worker-lab")]
#[doc(hidden)]
pub use semantic_record::worker_lab as __worker_lab;

/// Repository-only bridge from the authenticated helper binary to the generic
/// semantic worker adapter. It is not a supported public API surface.
#[cfg(feature = "__internal-worker-lab")]
#[doc(hidden)]
pub use semantic_record::worker_runtime as __worker_runtime;

/// Repository-only bridge for the authenticated Linux worker protocol.
///
/// The public supervisor and packaged helper share this implementation so the
/// frame, descriptor, sealed-blob, and helper-authentication invariants cannot
/// drift between their two crates.
#[cfg(feature = "__internal-worker-lab")]
#[doc(hidden)]
pub mod __worker_protocol {
    #[cfg(target_os = "linux")]
    pub use crate::worker_protocol::{HELPER_BOOTSTRAP_ABI, HELPER_FEATURE_ID};

    pub mod frame {
        pub use crate::worker_protocol::frame::*;
    }

    #[cfg(target_os = "linux")]
    pub mod helper {
        pub use crate::worker_protocol::helper::*;
    }

    #[cfg(target_os = "linux")]
    pub mod linux {
        pub use crate::worker_protocol::linux::*;
    }

    #[cfg(target_os = "linux")]
    pub mod sealed {
        pub use crate::worker_protocol::sealed::*;
    }
}

/// Repository-only bridge used by the native materialization lifecycle lab.
///
/// This module is absent unless the private `__internal-lifecycle-lab`
/// feature is selected. It is not a supported runtime or public API surface.
#[cfg(feature = "__internal-lifecycle-lab")]
#[doc(hidden)]
pub mod __materialization_lifecycle_lab {
    /// Plants a destination after staged-tree audit and immediately before
    /// native no-replace publication on the current thread.
    #[must_use]
    pub fn plant_destination_before_publication_for_current_thread() -> impl Drop {
        crate::materialize::plant_destination_before_publication_for_current_thread()
    }
}

pub use apply::{
    apply, apply_with_options, ApplyOptions, ArchiveSelection, EnvMeta, MemberView, Outcome,
    PolicyMeta, Receipt, Request, Source, SourceMeta, ToolMeta, Verdict, View,
};
pub use findings::{Finding, FindingCode, Severity};
pub use identity::{
    content_root, encode_tar_gzip_layout, encode_tar_layout, encode_zip64_layout, layout_root,
    OutcomeIdentities, TreeRoot, TREE_ENCODING_ID, TREE_ENCODING_V2_ID, TREE_ENCODING_V3_ID,
    TREE_ENCODING_V4_ID,
};
pub use ir::{
    tar_gzip_ustar_portable_v1_canonical_bytes, tar_gzip_ustar_portable_v1_digest,
    tar_ustar_portable_v1_canonical_bytes, tar_ustar_portable_v1_digest,
    zip64_strict_ascii_v1_canonical_bytes, zip64_strict_ascii_v1_digest,
    zip_portable_utf8_v1_canonical_bytes, zip_portable_utf8_v1_digest,
    zip_strict_ascii_v1_canonical_bytes, zip_strict_ascii_v1_digest,
    zip_strict_ascii_v2_canonical_bytes, zip_strict_ascii_v2_digest,
    zip_wheel_utf8_v1_canonical_bytes, zip_wheel_utf8_v1_digest, ArchiveCovering, ArchiveEvidence,
    ArchiveFormat, ArchiveIR, ByteRange, ExtraDisposition, ExtraFieldRecord, ExtraSite,
    GzipWrapperEvidence, IrMember, MemberContainerFacts, MemberEvidence, MemberKind,
    MemberSourceRanges, MemberVerification, NormalizationAction, TarArchiveCovering,
    TarGzipArchiveEvidence, TarGzipInterpretationProfile, TarInterpretationProfile,
    TarMemberEvidence, Zip64ArchiveCovering, Zip64DataDescriptorWidth, Zip64LocalValueShape,
    Zip64MemberEvidence, ZipInterpretationProfile, ZipMemberEvidence, ARCHIVE_IR_SCHEMA,
    TAR_ARCHIVE_IR_SCHEMA, TAR_GZIP_ARCHIVE_IR_SCHEMA, TAR_GZIP_USTAR_PORTABLE_V1,
    TAR_USTAR_PORTABLE_V1, ZIP64_ARCHIVE_IR_SCHEMA, ZIP64_STRICT_ASCII_V1, ZIP_PORTABLE_UTF8_V1,
    ZIP_STRICT_ASCII_V1, ZIP_STRICT_ASCII_V2, ZIP_WHEEL_UTF8_V1,
};
pub use jail::{
    jail_name, jail_relative, join_under_dest, JailedName, PORTABLE_NAME_MAX_COMPONENT_UTF16_UNITS,
    PORTABLE_NAME_MAX_COMPONENT_UTF8_BYTES,
};
pub use materialize::{MaterializationMeta, WindowsMaterializationEvidence};
pub use outcome::{
    AdmissionStatus, DigestHex, EffectStatus, InterpretationStatus, SourceDigest, StoppingPhase,
    VerificationStatus, ViewCompleteness,
};
pub use policy::{
    hex_sha256, ratio_exceeds, CompiledControls, Policy, ResourceBudget,
    POLICY_FORMAT_TAR_GZIP_USTAR, POLICY_FORMAT_TAR_USTAR, POLICY_FORMAT_ZIP, POLICY_FORMAT_ZIP64,
};
pub use snapshot::SnapshotKind;
pub use supervised::{
    apply_supervised, inspect_supervised, LinuxWorker, SupervisionError, SupervisionErrorKind,
};
pub use verified::{
    MemberReadError, MemberReadErrorKind, RetentionPlan, RetentionPlanError,
    RetentionPlanErrorKind, RetentionStatus, VerifiedArchive, MAX_RETENTION_PATHS,
    MAX_RETENTION_PATH_BYTES, MAX_RETENTION_TOTAL_PATH_BYTES,
};
