//! `UntrustedArchive × Policy → (Materialization | Rejection) × Receipt × InspectableView`
//!
//! Ingest produces an immutable `SourceSnapshot`. Parse and payload reads use that
//! snapshot; they do not reopen the caller path.

mod apply;
mod covering;
mod findings;
mod identity;
mod ir;
mod jail;
mod materialize;
mod outcome;
mod policy;
mod snapshot;
mod zip;

pub use apply::{
    apply, EnvMeta, MemberView, Outcome, PolicyMeta, Receipt, Request, Source, SourceMeta,
    ToolMeta, Verdict, View,
};
pub use findings::{Finding, FindingCode, Severity};
pub use identity::{content_root, layout_root, OutcomeIdentities, TreeRoot, TREE_ENCODING_ID};
pub use ir::{
    zip_strict_ascii_v1_digest, ArchiveCovering, ArchiveIR, ByteRange, ExtraDisposition,
    ExtraFieldRecord, ExtraSite, IrMember, MemberKind, MemberSourceRanges, MemberVerification,
    NormalizationAction, ARCHIVE_IR_SCHEMA, ZIP_STRICT_ASCII_V1,
};
pub use jail::{jail_name, jail_relative, join_under_dest, JailedName};
pub use materialize::{MaterializationMeta, WindowsMaterializationEvidence};
pub use outcome::{
    AdmissionStatus, DigestHex, EffectStatus, InterpretationStatus, SourceDigest, StoppingPhase,
    VerificationStatus, ViewCompleteness,
};
pub use policy::{hex_sha256, ratio_exceeds, CompiledControls, Policy, ResourceBudget};
pub use snapshot::SnapshotKind;
