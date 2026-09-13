//! Proof-only crate that compiles the exact production scalar kernels.

#![allow(dead_code)]

#[path = "../../../crates/sealr/src/interval.rs"]
mod interval;
#[path = "../../../crates/sealr/src/quota.rs"]
mod quota;
#[path = "../../../crates/sealr/src/ratio.rs"]
mod ratio;
