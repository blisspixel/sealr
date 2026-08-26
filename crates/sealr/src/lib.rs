//! `UntrustedArchive × Policy → (Materialization | Rejection) × Receipt × InspectableView`
//!
//! Ingest produces an immutable `SourceSnapshot`. Parsing and payload verification
//! use checked ranges over that snapshot; they do not reopen the caller path.

mod apply;
mod covering;
mod findings;
mod identity;
mod interval;
mod ir;
mod jail;
mod materialize;
mod outcome;
mod policy;
mod quota;
mod snapshot;
mod verification;
#[cfg(any(feature = "__internal-worker-lab", test))]
#[allow(dead_code)]
mod worker_protocol;
// Dormant Alpha.6 experiment. It is compiled and tested, but no shipped path
// can invoke it until the remaining authority and packaging gates close.
#[allow(dead_code)]
mod semantic_record;
mod verified;
mod zip;

/// Exercises the dormant semantic-record decoders from the separate fuzz
/// workspace without exposing their types or making them reachable by default.
#[cfg(feature = "__internal-fuzzing")]
#[doc(hidden)]
pub fn __fuzz_semantic_records(input: &[u8]) {
    semantic_record::exercise_fuzz_input(input);
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
    apply, apply_with_options, ApplyOptions, EnvMeta, MemberView, Outcome, PolicyMeta, Receipt,
    Request, Source, SourceMeta, ToolMeta, Verdict, View,
};
pub use findings::{Finding, FindingCode, Severity};
pub use identity::{content_root, layout_root, OutcomeIdentities, TreeRoot, TREE_ENCODING_ID};
pub use ir::{
    zip_strict_ascii_v1_canonical_bytes, zip_strict_ascii_v1_digest,
    zip_strict_ascii_v2_canonical_bytes, zip_strict_ascii_v2_digest, ArchiveCovering, ArchiveIR,
    ByteRange, ExtraDisposition, ExtraFieldRecord, ExtraSite, IrMember, MemberKind,
    MemberSourceRanges, MemberVerification, NormalizationAction, ZipInterpretationProfile,
    ARCHIVE_IR_SCHEMA, ZIP_STRICT_ASCII_V1, ZIP_STRICT_ASCII_V2,
};
pub use jail::{jail_name, jail_relative, join_under_dest, JailedName};
pub use materialize::{MaterializationMeta, WindowsMaterializationEvidence};
pub use outcome::{
    AdmissionStatus, DigestHex, EffectStatus, InterpretationStatus, SourceDigest, StoppingPhase,
    VerificationStatus, ViewCompleteness,
};
pub use policy::{hex_sha256, ratio_exceeds, CompiledControls, Policy, ResourceBudget};
pub use snapshot::SnapshotKind;
pub use verified::{
    MemberReadError, MemberReadErrorKind, RetentionPlan, RetentionPlanError,
    RetentionPlanErrorKind, RetentionStatus, VerifiedArchive, MAX_RETENTION_PATHS,
    MAX_RETENTION_PATH_BYTES, MAX_RETENTION_TOTAL_PATH_BYTES,
};
