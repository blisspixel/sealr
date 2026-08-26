//! Fail-closed authenticated Linux worker execution.

use std::fmt;
use std::path::Path;

use crate::{ApplyOptions, Outcome, Policy, Source};

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub(crate) use linux::WorkerReadAuthority;

/// Stable category for failures of the supervised execution boundary.
///
/// Archive rejection and verification findings remain ordinary successful
/// [`Outcome`] values. These categories describe failures to establish or
/// complete the requested process-isolation boundary itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SupervisionErrorKind {
    IsolationUnavailable,
    HelperArtifact,
    Spawn,
    Authentication,
    RestrictionUnavailable,
    Protocol,
    TimedOut,
    WorkerExit,
    Reap,
    Source,
    IntegrityMismatch,
    Internal,
}

/// Failure to establish or complete a supervised worker operation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SupervisionError {
    kind: SupervisionErrorKind,
    detail: String,
}

impl SupervisionError {
    pub(crate) fn new(kind: SupervisionErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    /// Return the stable failure category.
    pub fn kind(&self) -> SupervisionErrorKind {
        self.kind
    }

    /// Return diagnostic detail that is not part of the compatibility contract.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn into_member_read_error(self, path: &str) -> crate::MemberReadError {
        use crate::MemberReadErrorKind;

        let kind = match self.kind {
            SupervisionErrorKind::IsolationUnavailable => MemberReadErrorKind::IsolationUnavailable,
            SupervisionErrorKind::TimedOut => MemberReadErrorKind::TimedOut,
            SupervisionErrorKind::Source => MemberReadErrorKind::SourceIo,
            SupervisionErrorKind::IntegrityMismatch => MemberReadErrorKind::IntegrityMismatch,
            SupervisionErrorKind::HelperArtifact
            | SupervisionErrorKind::Spawn
            | SupervisionErrorKind::Authentication
            | SupervisionErrorKind::RestrictionUnavailable
            | SupervisionErrorKind::Protocol
            | SupervisionErrorKind::WorkerExit
            | SupervisionErrorKind::Reap
            | SupervisionErrorKind::Internal => MemberReadErrorKind::WorkerFailed,
        };
        crate::MemberReadError::new(kind, path, self.detail)
    }
}

impl fmt::Display for SupervisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", kind_name(self.kind), self.detail)
    }
}

impl std::error::Error for SupervisionError {}

fn kind_name(kind: SupervisionErrorKind) -> &'static str {
    match kind {
        SupervisionErrorKind::IsolationUnavailable => "isolation unavailable",
        SupervisionErrorKind::HelperArtifact => "worker artifact rejected",
        SupervisionErrorKind::Spawn => "worker spawn failed",
        SupervisionErrorKind::Authentication => "worker authentication failed",
        SupervisionErrorKind::RestrictionUnavailable => "worker restriction setup failed",
        SupervisionErrorKind::Protocol => "worker protocol failed",
        SupervisionErrorKind::TimedOut => "worker timed out",
        SupervisionErrorKind::WorkerExit => "worker exited unsuccessfully",
        SupervisionErrorKind::Reap => "worker reap failed",
        SupervisionErrorKind::Source => "worker source failed",
        SupervisionErrorKind::IntegrityMismatch => "worker integrity check failed",
        SupervisionErrorKind::Internal => "supervisor invariant failed",
    }
}

/// Authenticated immutable Linux worker artifact.
///
/// Construction requires an explicit absolute path, exact byte length, and
/// SHA-256. The file is copied into a sealed executable object immediately, so
/// later operations neither consult `PATH` nor reopen the supplied pathname.
#[derive(Clone, Debug)]
pub struct LinuxWorker {
    #[cfg(target_os = "linux")]
    pub(crate) artifact: crate::worker_protocol::helper::HelperArtifact,
}

impl LinuxWorker {
    /// Authenticate and retain one exact helper artifact.
    pub fn load(
        path: &Path,
        expected_len: u64,
        expected_sha256: &str,
    ) -> Result<Self, SupervisionError> {
        #[cfg(target_os = "linux")]
        {
            let digest =
                crate::worker_protocol::helper::parse_digest(expected_sha256).map_err(|error| {
                    SupervisionError::new(SupervisionErrorKind::HelperArtifact, error.to_string())
                })?;
            let artifact =
                crate::worker_protocol::helper::HelperArtifact::load(path, expected_len, digest)
                    .map_err(|error| {
                        SupervisionError::new(
                            SupervisionErrorKind::HelperArtifact,
                            error.to_string(),
                        )
                    })?;
            Ok(Self { artifact })
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, expected_len, expected_sha256);
            Err(SupervisionError::new(
                SupervisionErrorKind::IsolationUnavailable,
                "authenticated worker execution is supported only on Linux",
            ))
        }
    }

    /// Return the authenticated helper digest as lowercase hexadecimal.
    pub fn digest_hex(&self) -> String {
        #[cfg(target_os = "linux")]
        {
            self.artifact.digest_hex()
        }
        #[cfg(not(target_os = "linux"))]
        {
            String::new()
        }
    }

    /// Return the exact authenticated helper length.
    pub fn len(&self) -> u64 {
        #[cfg(target_os = "linux")]
        {
            self.artifact.len()
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    }

    /// Return whether the authenticated helper has no bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Inspect one archive through an authenticated, reduced-authority Linux worker.
///
/// Planning retains one exact private-file snapshot. Payload verification runs
/// only after the helper proves `no_new_privs`, Landlock ABI 3 enforcement,
/// syscall filtering, and inherited-authority closure. Every non-retained
/// [`crate::VerifiedArchive::read_member`] call starts a fresh authenticated
/// worker. Infrastructure failure is returned as [`SupervisionError`]; there
/// is no in-process fallback.
pub fn inspect_supervised(
    source: Source<'_>,
    policy: &Policy,
    options: &ApplyOptions,
    worker: &LinuxWorker,
) -> Result<Outcome, SupervisionError> {
    #[cfg(target_os = "linux")]
    {
        linux::inspect(source, policy, options, worker)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (source, policy, options, worker);
        Err(SupervisionError::new(
            SupervisionErrorKind::IsolationUnavailable,
            "supervised archive inspection requires Linux",
        ))
    }
}
