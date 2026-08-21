//! `UntrustedArchive × Policy → (Materialization | Rejection) × Receipt × InspectableView`

mod apply;
mod findings;
mod jail;
mod materialize;
mod policy;
mod zip;

pub use apply::{apply, MemberView, Outcome, Receipt, Request, Source, Verdict, View};
pub use findings::{Finding, FindingCode, Severity};
pub use jail::{jail_relative, join_under_dest};
pub use materialize::{MaterializationMeta, WindowsMaterializationEvidence};
pub use policy::{hex_sha256, Policy};
