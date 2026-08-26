//! Shared authenticated Linux worker protocol primitives.

#[cfg(target_os = "linux")]
pub const HELPER_BOOTSTRAP_ABI: u64 = 1;
#[cfg(target_os = "linux")]
pub const HELPER_FEATURE_ID: u64 = 1;

pub mod frame;

#[cfg(target_os = "linux")]
pub mod helper;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub mod sealed;
