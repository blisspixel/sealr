//! Nonshipping Python wheel research consumer.
//!
//! This crate deliberately keeps wheel semantics out of Sealr's supported
//! archive API and native CLI. It consumes only [`sealr::VerifiedArchive`], so
//! semantic evaluation cannot reopen or independently parse the source ZIP.

mod evaluate;
mod identity;
mod model;
mod parse;

pub use evaluate::{evaluate_wheel, realize_identity};
pub use model::*;
pub use parse::{normalize_distribution, normalize_version, parse_wheel_filename};
