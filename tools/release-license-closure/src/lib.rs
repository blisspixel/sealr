//! Exact dependency anchor for the native release license bundles.
//!
//! This private crate deliberately has no code. Its normal dependency graph is
//! the union of the native CLI and independent evidence-verifier graphs on all
//! targets, plus the production-only helper graph on Linux.
