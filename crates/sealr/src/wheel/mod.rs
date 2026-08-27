//! Supported, bounded Python wheel consumer.
//!
//! The evaluator accepts only a completely verified [`crate::VerifiedArchive`]
//! interpreted under [`crate::ZipInterpretationProfile::PortableUtf8V1`]. It
//! reads semantic members through that capability and never receives a source
//! path or reparses ZIP structure.
//!
//! ```
//! use sealr::wheel::{
//!     evaluate_wheel, WheelEvaluation, WheelLimits, CONSUMER_PROFILE_ID,
//! };
//!
//! fn evaluate(archive: &sealr::VerifiedArchive) {
//!     let result = evaluate_wheel(
//!         "demo-1.0-py3-none-any.whl",
//!         archive,
//!         WheelLimits::default(),
//!     );
//!     if let WheelEvaluation::Admitted { artifact, plan, .. } = result {
//!         assert_eq!(artifact.consumer_profile, CONSUMER_PROFILE_ID);
//!         assert_eq!(plan.artifact_sha256().len(), 64);
//!     }
//! }
//! ```

mod evaluate;
mod identity;
mod model;
mod parse;

pub use evaluate::{evaluate_wheel, realize_identity};
pub use model::*;
pub use parse::{normalize_distribution, normalize_version, parse_wheel_filename};
