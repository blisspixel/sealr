//! Shared authenticated Linux worker protocol primitives.

pub mod frame;

#[cfg(target_os = "linux")]
pub mod helper;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub mod sealed;
