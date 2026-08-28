//! Fail-closed authenticated Linux worker execution.

use std::fmt;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::path::Path;

#[cfg(target_os = "linux")]
use serde::Deserialize;

use crate::{ApplyOptions, ArchiveSelection, Outcome, Policy, Request, Source};

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
    Cleanup,
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
            | SupervisionErrorKind::Cleanup
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
        SupervisionErrorKind::Cleanup => "supervised cleanup failed",
        SupervisionErrorKind::Source => "worker source failed",
        SupervisionErrorKind::IntegrityMismatch => "worker integrity check failed",
        SupervisionErrorKind::Internal => "supervisor invariant failed",
    }
}

/// Apply one archive request through an authenticated, reduced-authority Linux
/// worker.
///
/// Planning and any destination setup remain in the supervisor. Payload
/// verification runs only after the helper proves `no_new_privs`, Landlock ABI
/// 3 enforcement, syscall filtering, and inherited-authority closure. A
/// materializing worker receives only the exact source, sealed plan, and a
/// cloned staging-directory capability. The supervisor alone audits and
/// publishes that stage after clean worker exit and reap.
///
/// Archive rejection, including destination setup or publication failure,
/// remains an ordinary [`Outcome`]. Failure to establish or complete the
/// requested isolation boundary is returned as [`SupervisionError`]. There is
/// no in-process fallback.
pub fn apply_supervised(
    request: Request<'_>,
    options: &ApplyOptions,
    worker: &LinuxWorker,
) -> Result<Outcome, SupervisionError> {
    let profile = supervised_zip_profile(options)?;
    #[cfg(target_os = "linux")]
    {
        linux::apply(request, options, profile, worker)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (request, options, profile, worker);
        Err(SupervisionError::new(
            SupervisionErrorKind::IsolationUnavailable,
            "supervised archive execution requires Linux",
        ))
    }
}

fn supervised_zip_profile(
    options: &ApplyOptions,
) -> Result<crate::ZipInterpretationProfile, SupervisionError> {
    match options.archive_selection() {
        ArchiveSelection::Zip(profile) if !profile.is_zip64() => Ok(profile),
        ArchiveSelection::Zip(_) => Err(SupervisionError::new(
            SupervisionErrorKind::IsolationUnavailable,
            "ZIP64 requires the not-yet-promoted semantic-record v3 worker contract",
        )),
        ArchiveSelection::TarGzipUstar(_) => Err(SupervisionError::new(
            SupervisionErrorKind::IsolationUnavailable,
            "gzip-wrapped TAR requires the not-yet-promoted semantic-record v3 worker contract",
        )),
        ArchiveSelection::TarUstar(_) => Err(SupervisionError::new(
            SupervisionErrorKind::IsolationUnavailable,
            "the authenticated worker contract currently supports ZIP profiles only",
        )),
        ArchiveSelection::TarPax(_) => Err(SupervisionError::new(
            SupervisionErrorKind::IsolationUnavailable,
            "restricted PAX TAR requires a future semantic-record worker contract",
        )),
        ArchiveSelection::TarGnuLongName(_) => Err(SupervisionError::new(
            SupervisionErrorKind::IsolationUnavailable,
            "restricted GNU long-name TAR requires a future semantic-record worker contract",
        )),
        ArchiveSelection::TarZstdUstar(_) => Err(SupervisionError::new(
            SupervisionErrorKind::IsolationUnavailable,
            "zstd-wrapped TAR requires a future semantic-record worker contract",
        )),
    }
}

#[cfg(test)]
mod selection_tests {
    use super::*;
    #[cfg(not(target_os = "linux"))]
    use crate::{Policy, Source};
    use crate::{
        TarGnuLongNameInterpretationProfile, TarGzipInterpretationProfile,
        TarInterpretationProfile, TarPaxInterpretationProfile, TarZstdInterpretationProfile,
    };

    #[test]
    fn worker_boundary_accepts_only_an_explicit_zip_selection() {
        assert_eq!(
            supervised_zip_profile(&ApplyOptions::new()).unwrap(),
            crate::ZipInterpretationProfile::StrictAsciiV1
        );
        let tar = ApplyOptions::new()
            .with_tar_interpretation_profile(TarInterpretationProfile::UstarPortableV1);
        let error = supervised_zip_profile(&tar).unwrap_err();
        assert_eq!(error.kind(), SupervisionErrorKind::IsolationUnavailable);
        assert!(error.to_string().contains("ZIP profiles only"));

        let zip64 = ApplyOptions::new()
            .with_interpretation_profile(crate::ZipInterpretationProfile::Zip64StrictAsciiV1);
        let error = supervised_zip_profile(&zip64).unwrap_err();
        assert_eq!(error.kind(), SupervisionErrorKind::IsolationUnavailable);
        assert!(error.to_string().contains("semantic-record v3"));

        let tar_pax = ApplyOptions::new()
            .with_tar_pax_interpretation_profile(TarPaxInterpretationProfile::PortableV1);
        let error = supervised_zip_profile(&tar_pax).unwrap_err();
        assert_eq!(error.kind(), SupervisionErrorKind::IsolationUnavailable);
        assert!(error.to_string().contains("PAX TAR"));

        let tar_gnu = ApplyOptions::new().with_tar_gnu_longname_interpretation_profile(
            TarGnuLongNameInterpretationProfile::PortableV1,
        );
        let error = supervised_zip_profile(&tar_gnu).unwrap_err();
        assert_eq!(error.kind(), SupervisionErrorKind::IsolationUnavailable);
        assert!(error.to_string().contains("GNU long-name TAR"));

        for profile in [
            TarGzipInterpretationProfile::UstarPortableV1,
            TarGzipInterpretationProfile::PaxPortableV1,
            TarGzipInterpretationProfile::GnuLongNamePortableV1,
        ] {
            let tar_gzip = ApplyOptions::new().with_tar_gzip_interpretation_profile(profile);
            let error = supervised_zip_profile(&tar_gzip).unwrap_err();
            assert_eq!(error.kind(), SupervisionErrorKind::IsolationUnavailable);
            assert!(error.to_string().contains("semantic-record v3"));
        }

        let tar_zstd = ApplyOptions::new()
            .with_tar_zstd_interpretation_profile(TarZstdInterpretationProfile::UstarPortableV1);
        let error = supervised_zip_profile(&tar_zstd).unwrap_err();
        assert_eq!(error.kind(), SupervisionErrorKind::IsolationUnavailable);
        assert!(error.to_string().contains("zstd-wrapped TAR"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn gzip_tar_refusal_precedes_a_missing_source_path() {
        let policy = Policy::default_v4();
        let missing = std::path::Path::new("definitely-missing-supervised-input.tar.gz");
        let request = Request {
            source: Source::Path(missing),
            policy: &policy,
            dest: None,
        };
        let options = ApplyOptions::new()
            .with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::UstarPortableV1);
        let error = apply_supervised(request, &options, &LinuxWorker {}).unwrap_err();
        assert_eq!(error.kind(), SupervisionErrorKind::IsolationUnavailable);
        assert!(error.to_string().contains("semantic-record v3"));
        assert!(!error.to_string().contains("source"));
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

    /// Authenticate and retain the helper bound by a packaged-worker manifest.
    ///
    /// The manifest path must be absolute and end in the fixed
    /// `sealr-worker.manifest` name. The bounded, exact-field manifest must
    /// describe this crate version, the production helper target, and the
    /// current bootstrap ABI. The helper is selected only as the sibling
    /// `sealr-worker` file and is then authenticated through [`Self::load`].
    /// Neither the manifest nor the helper is searched for through `PATH`.
    pub fn load_from_manifest(manifest_path: &Path) -> Result<Self, SupervisionError> {
        #[cfg(target_os = "linux")]
        {
            let identity = read_worker_manifest(manifest_path)?;
            Self::load(&identity.helper_path, identity.byte_len, &identity.sha256)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = manifest_path;
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

#[cfg(target_os = "linux")]
const WORKER_MANIFEST_NAME: &str = "sealr-worker.manifest";
#[cfg(target_os = "linux")]
const WORKER_HELPER_NAME: &str = "sealr-worker";
#[cfg(target_os = "linux")]
const WORKER_MANIFEST_SCHEMA: &str = "sealr.worker-artifact.v1";
#[cfg(target_os = "linux")]
const WORKER_HELPER_TARGET: &str = "x86_64-unknown-linux-musl";
#[cfg(target_os = "linux")]
const MAX_WORKER_MANIFEST_BYTES: u64 = 4 * 1024;
#[cfg(target_os = "linux")]
const MAX_WORKER_HELPER_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerManifest {
    schema: String,
    release_version: String,
    target: String,
    bootstrap_abi: u64,
    byte_len: u64,
    sha256: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct WorkerIdentity {
    helper_path: std::path::PathBuf,
    byte_len: u64,
    sha256: String,
}

#[cfg(target_os = "linux")]
fn read_worker_manifest(manifest_path: &Path) -> Result<WorkerIdentity, SupervisionError> {
    if !manifest_path.is_absolute() {
        return helper_artifact_error("worker manifest path must be absolute");
    }
    if manifest_path.file_name().and_then(|name| name.to_str()) != Some(WORKER_MANIFEST_NAME) {
        return helper_artifact_error(format!(
            "worker manifest must use the fixed {WORKER_MANIFEST_NAME} name"
        ));
    }

    let mut file = File::open(manifest_path).map_err(|error| {
        SupervisionError::new(
            SupervisionErrorKind::HelperArtifact,
            format!("worker manifest open failed: {error}"),
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        SupervisionError::new(
            SupervisionErrorKind::HelperArtifact,
            format!("worker manifest metadata failed: {error}"),
        )
    })?;
    if !metadata.is_file() {
        return helper_artifact_error("worker manifest is not a regular file");
    }
    if metadata.len() == 0 || metadata.len() > MAX_WORKER_MANIFEST_BYTES {
        return helper_artifact_error(format!(
            "worker manifest length must be in 1..={MAX_WORKER_MANIFEST_BYTES} bytes"
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_WORKER_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            SupervisionError::new(
                SupervisionErrorKind::HelperArtifact,
                format!("worker manifest read failed: {error}"),
            )
        })?;
    if bytes.len() as u64 != metadata.len() {
        return helper_artifact_error("worker manifest changed while it was read");
    }
    parse_worker_manifest(manifest_path, &bytes)
}

#[cfg(target_os = "linux")]
fn parse_worker_manifest(
    manifest_path: &Path,
    bytes: &[u8],
) -> Result<WorkerIdentity, SupervisionError> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf])
        || bytes.contains(&b'\r')
        || bytes.last() != Some(&b'\n')
    {
        return helper_artifact_error(
            "worker manifest must be BOM-free UTF-8 with LF line endings and a final newline",
        );
    }
    let manifest: WorkerManifest = serde_json::from_slice(bytes).map_err(|error| {
        SupervisionError::new(
            SupervisionErrorKind::HelperArtifact,
            format!("worker manifest JSON rejected: {error}"),
        )
    })?;
    if manifest.schema != WORKER_MANIFEST_SCHEMA {
        return helper_artifact_error("worker manifest schema is unsupported");
    }
    if manifest.release_version != env!("CARGO_PKG_VERSION") {
        return helper_artifact_error(format!(
            "worker manifest release version does not match {}",
            env!("CARGO_PKG_VERSION")
        ));
    }
    if manifest.target != WORKER_HELPER_TARGET || !cfg!(target_arch = "x86_64") {
        return helper_artifact_error(
            "worker manifest does not select the supported x86_64 Linux helper target",
        );
    }
    if manifest.bootstrap_abi != crate::worker_protocol::HELPER_BOOTSTRAP_ABI {
        return helper_artifact_error("worker manifest bootstrap ABI is unsupported");
    }
    if manifest.byte_len == 0 || manifest.byte_len > MAX_WORKER_HELPER_BYTES {
        return helper_artifact_error(format!(
            "worker manifest helper length must be in 1..={MAX_WORKER_HELPER_BYTES} bytes"
        ));
    }
    crate::worker_protocol::helper::parse_digest(&manifest.sha256).map_err(|error| {
        SupervisionError::new(SupervisionErrorKind::HelperArtifact, error.to_string())
    })?;
    if manifest
        .sha256
        .bytes()
        .any(|byte| byte.is_ascii_uppercase())
    {
        return helper_artifact_error("worker manifest SHA-256 must use lowercase hexadecimal");
    }
    let parent = manifest_path.parent().ok_or_else(|| {
        SupervisionError::new(
            SupervisionErrorKind::HelperArtifact,
            "worker manifest has no parent directory",
        )
    })?;
    Ok(WorkerIdentity {
        helper_path: parent.join(WORKER_HELPER_NAME),
        byte_len: manifest.byte_len,
        sha256: manifest.sha256,
    })
}

#[cfg(target_os = "linux")]
fn helper_artifact_error<T>(detail: impl Into<String>) -> Result<T, SupervisionError> {
    Err(SupervisionError::new(
        SupervisionErrorKind::HelperArtifact,
        detail,
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod manifest_tests {
    use super::*;

    fn manifest(extra: &str) -> Vec<u8> {
        format!(
            concat!(
                "{{\n",
                "  \"schema\": \"sealr.worker-artifact.v1\",\n",
                "  \"release_version\": \"{}\",\n",
                "  \"target\": \"x86_64-unknown-linux-musl\",\n",
                "  \"bootstrap_abi\": 1,\n",
                "  \"byte_len\": 17,\n",
                "  \"sha256\": \"{}\"{}\n",
                "}}\n"
            ),
            env!("CARGO_PKG_VERSION"),
            "01".repeat(32),
            extra
        )
        .into_bytes()
    }

    #[test]
    fn packaged_manifest_selects_only_its_fixed_sibling() {
        let path = Path::new("/opt/sealr/libexec/sealr/sealr-worker.manifest");
        let identity = parse_worker_manifest(path, &manifest("")).unwrap();
        assert_eq!(
            identity.helper_path,
            Path::new("/opt/sealr/libexec/sealr/sealr-worker")
        );
        assert_eq!(identity.byte_len, 17);
        assert_eq!(identity.sha256, "01".repeat(32));
    }

    #[test]
    fn packaged_manifest_rejects_unknown_fields_and_noncanonical_lines() {
        let path = Path::new("/opt/sealr/libexec/sealr/sealr-worker.manifest");
        let unknown = parse_worker_manifest(path, &manifest(",\n  \"extra\": true"))
            .expect_err("unknown fields must be rejected");
        assert_eq!(unknown.kind(), SupervisionErrorKind::HelperArtifact);

        let mut crlf = manifest("");
        crlf.insert(1, b'\r');
        assert!(parse_worker_manifest(path, &crlf).is_err());

        let mut no_newline = manifest("");
        no_newline.pop();
        assert!(parse_worker_manifest(path, &no_newline).is_err());
    }

    #[test]
    fn packaged_manifest_rejects_identity_drift() {
        let path = Path::new("/opt/sealr/libexec/sealr/sealr-worker.manifest");
        let wrong_version = String::from_utf8(manifest(""))
            .unwrap()
            .replace(env!("CARGO_PKG_VERSION"), "0.1.0-alpha.999");
        assert!(parse_worker_manifest(path, wrong_version.as_bytes()).is_err());

        let uppercase_digest = String::from_utf8(manifest(""))
            .unwrap()
            .replace(&"01".repeat(32), &"AB".repeat(32));
        assert!(parse_worker_manifest(path, uppercase_digest.as_bytes()).is_err());

        let zero_length = String::from_utf8(manifest(""))
            .unwrap()
            .replace("\"byte_len\": 17", "\"byte_len\": 0");
        assert!(parse_worker_manifest(path, zero_length.as_bytes()).is_err());
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
    apply_supervised(
        Request {
            source,
            policy,
            dest: None,
        },
        options,
        worker,
    )
}
