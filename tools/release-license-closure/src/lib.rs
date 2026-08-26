//! Exact dependency anchor for the Linux release license bundle.
//!
//! This private crate deliberately has no code. Its normal dependency graph is
//! the union of the native CLI and production-only Linux helper graphs. The
//! license generator uses it only for the Linux release target.
