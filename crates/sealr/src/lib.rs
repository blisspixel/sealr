//! `UntrustedArchive × Policy → (Materialization | Rejection) × Receipt × InspectableView`
//!
//! Ingest produces an immutable [`SourceSnapshot`]. Parse and payload reads use that
//! snapshot; they do not reopen the caller path.

mod apply;
mod findings;
mod jail;
mod materialize;
mod outcome;
mod policy;
mod snapshot;
mod zip;

pub use apply::{apply, MemberView, Outcome, Receipt, Request, Source, Verdict, View};
pub use findings::{Finding, FindingCode, Severity};
pub use jail::{jail_relative, join_under_dest};
pub use materialize::{MaterializationMeta, WindowsMaterializationEvidence};
pub use outcome::{
    AdmissionStatus, EffectStatus, InterpretationStatus, SourceDigest, StoppingPhase,
    VerificationStatus, ViewCompleteness,
};
pub use policy::{hex_sha256, Policy};
pub use snapshot::{SnapshotKind, SourceSnapshot};
