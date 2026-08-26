use std::fs::{self, File as StdFile};
use std::io::{self, BufRead, Write};
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir as CapDir, File as CapFile, OpenOptions as CapOpenOptions};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[cfg(any(test, feature = "__internal-worker-lab"))]
use std::cell::Cell;
#[cfg(test)]
use std::cell::RefCell;

use crate::findings::{Finding, FindingCode};
use crate::policy::ResourceBudget;
use crate::verification::{verify_payload, PayloadSpec};

#[cfg(target_os = "macos")]
mod apple;
#[cfg(windows)]
mod windows;

const SCHEMA: &str = "sealr.materialization.v2";
const BACKEND: &str = "cap-std-component-nofollow-v1";
const MEMBER_RESOLUTION: &str = "component-handles-nofollow";
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[cfg(test)]
enum InjectedStageMutation {
    Overwrite { relative: String, bytes: Vec<u8> },
    ExtraFile { relative: String, bytes: Vec<u8> },
}

#[cfg(any(test, feature = "__internal-worker-lab"))]
std::thread_local! {
    static INJECTED_CLEANUP_FAILURES: Cell<u32> = const { Cell::new(0) };
}

#[cfg(test)]
std::thread_local! {
    static AFTER_DIR_COMPONENT: RefCell<Option<(String, PathBuf)>> = const { RefCell::new(None) };
    static STAGE_MUTATION: RefCell<Option<InjectedStageMutation>> = const { RefCell::new(None) };
}

#[cfg(any(test, feature = "__internal-worker-lab"))]
pub(crate) struct CleanupFailureGuard {
    previous: u32,
}

#[cfg(any(test, feature = "__internal-worker-lab"))]
impl Drop for CleanupFailureGuard {
    fn drop(&mut self) {
        INJECTED_CLEANUP_FAILURES.with(|remaining| remaining.set(self.previous));
    }
}

#[cfg(any(test, feature = "__internal-worker-lab"))]
pub(crate) fn inject_cleanup_failures_for_current_thread(count: u32) -> CleanupFailureGuard {
    let previous = INJECTED_CLEANUP_FAILURES.with(|remaining| remaining.replace(count));
    CleanupFailureGuard { previous }
}

#[cfg(any(test, feature = "__internal-worker-lab"))]
fn injected_cleanup_failure() -> Option<io::Error> {
    INJECTED_CLEANUP_FAILURES.with(|remaining| {
        let count = remaining.get();
        if count == 0 {
            None
        } else {
            remaining.set(count - 1);
            Some(io::Error::other("injected staging cleanup failure"))
        }
    })
}

#[cfg(not(any(test, feature = "__internal-worker-lab")))]
fn injected_cleanup_failure() -> Option<io::Error> {
    None
}

#[cfg(test)]
pub(crate) struct DirComponentSeamGuard;

#[cfg(test)]
impl Drop for DirComponentSeamGuard {
    fn drop(&mut self) {
        AFTER_DIR_COMPONENT.with(|slot| slot.replace(None));
    }
}

#[cfg(test)]
pub(crate) fn inject_directory_component_replacement(
    component: impl Into<String>,
    outside: PathBuf,
) -> DirComponentSeamGuard {
    AFTER_DIR_COMPONENT.with(|slot| {
        slot.replace(Some((component.into(), outside)));
    });
    DirComponentSeamGuard
}

#[cfg(test)]
fn injected_after_directory_component(path: &Path) {
    AFTER_DIR_COMPONENT.with(|slot| {
        let slot = slot.borrow();
        let Some((name, outside)) = slot.as_ref() else {
            return;
        };
        if path.file_name().and_then(|value| value.to_str()) != Some(name.as_str()) {
            return;
        }
        let _ = fs::remove_dir_all(path);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let _ = std::os::unix::fs::symlink(outside, path);
        }
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("cmd")
                .args(["/d", "/c", "mklink", "/J"])
                .arg(path)
                .arg(outside)
                .status();
        }
    });
}

#[cfg(test)]
pub(crate) struct StageMutationGuard;

#[cfg(test)]
impl Drop for StageMutationGuard {
    fn drop(&mut self) {
        STAGE_MUTATION.with(|slot| slot.replace(None));
    }
}

#[cfg(test)]
pub(crate) fn inject_staged_content_overwrite(
    relative: impl Into<String>,
    bytes: Vec<u8>,
) -> StageMutationGuard {
    STAGE_MUTATION.with(|slot| {
        slot.replace(Some(InjectedStageMutation::Overwrite {
            relative: relative.into(),
            bytes,
        }));
    });
    StageMutationGuard
}

#[cfg(test)]
pub(crate) fn inject_staged_extra_file(
    relative: impl Into<String>,
    bytes: Vec<u8>,
) -> StageMutationGuard {
    STAGE_MUTATION.with(|slot| {
        slot.replace(Some(InjectedStageMutation::ExtraFile {
            relative: relative.into(),
            bytes,
        }));
    });
    StageMutationGuard
}

#[cfg(test)]
fn apply_injected_stage_mutation(stage: &Path) {
    STAGE_MUTATION.with(|slot| {
        let slot = slot.borrow();
        let Some(mutation) = slot.as_ref() else {
            return;
        };
        match mutation {
            InjectedStageMutation::Overwrite { relative, bytes } => {
                let _ = fs::write(stage.join(relative), bytes);
            }
            InjectedStageMutation::ExtraFile { relative, bytes } => {
                let _ = fs::write(stage.join(relative), bytes);
            }
        }
    });
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct MaterializationMeta {
    pub schema: &'static str,
    pub requested: bool,
    pub backend: &'static str,
    pub stage_mode: &'static str,
    pub stage_creation_primitive: &'static str,
    pub member_resolution: &'static str,
    pub durability: &'static str,
    pub publication_primitive: &'static str,
    pub outcome: &'static str,
    pub cleanup: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows: Option<WindowsMaterializationEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct WindowsMaterializationEvidence {
    pub storage_policy: &'static str,
    pub filesystem: Option<String>,
    pub device_scope: &'static str,
    pub persistent_acls: Option<bool>,
    pub read_only: Option<bool>,
    pub stage_acl_policy: &'static str,
    pub stage_acl: &'static str,
}

#[cfg(windows)]
fn initial_windows_evidence() -> Option<WindowsMaterializationEvidence> {
    Some(windows_evidence(
        windows::StorageObservation::not_observed(),
        "not-created",
    ))
}

#[cfg(not(windows))]
fn initial_windows_evidence() -> Option<WindowsMaterializationEvidence> {
    None
}

#[cfg(windows)]
fn windows_evidence(
    observation: windows::StorageObservation,
    stage_acl: &'static str,
) -> WindowsMaterializationEvidence {
    WindowsMaterializationEvidence {
        storage_policy: windows::STORAGE_POLICY,
        filesystem: observation.filesystem,
        device_scope: observation.device_scope,
        persistent_acls: observation.persistent_acls,
        read_only: observation.read_only,
        stage_acl_policy: windows::STAGE_ACL_POLICY,
        stage_acl,
    }
}

impl MaterializationMeta {
    pub(crate) fn not_started(requested: bool, atomic: bool) -> Self {
        if requested {
            Self {
                schema: SCHEMA,
                requested: true,
                backend: BACKEND,
                stage_mode: stage_mode(),
                stage_creation_primitive: stage_creation_primitive(),
                member_resolution: MEMBER_RESOLUTION,
                durability: durability(atomic),
                publication_primitive: publication_primitive(),
                outcome: "not-started",
                cleanup: "not-created",
                windows: initial_windows_evidence(),
            }
        } else {
            Self {
                schema: SCHEMA,
                requested: false,
                backend: "none",
                stage_mode: "none",
                stage_creation_primitive: "none",
                member_resolution: "none",
                durability: "none",
                publication_primitive: "none",
                outcome: "not-requested",
                cleanup: "not-applicable",
                windows: None,
            }
        }
    }

    pub(crate) fn setup_failed(
        atomic: bool,
        cleanup: &'static str,
        windows: Option<WindowsMaterializationEvidence>,
    ) -> Self {
        let mut report = Self::not_started(true, atomic);
        report.outcome = "setup-failed";
        report.cleanup = cleanup;
        report.windows = windows;
        report
    }
}

#[derive(Debug)]
pub(crate) struct MaterializationSetupError {
    findings: Vec<Finding>,
    cleanup: &'static str,
    windows: Option<Box<WindowsMaterializationEvidence>>,
}

impl MaterializationSetupError {
    fn before_stage(finding: Finding, windows: Option<WindowsMaterializationEvidence>) -> Self {
        Self {
            findings: vec![finding],
            cleanup: "not-created",
            windows: windows.map(Box::new),
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Vec<Finding>,
        &'static str,
        Option<WindowsMaterializationEvidence>,
    ) {
        (
            self.findings,
            self.cleanup,
            self.windows.map(|evidence| *evidence),
        )
    }

    fn after_stage(
        parent: &CapDir,
        root: CapDir,
        stage_name: &Path,
        windows: Option<WindowsMaterializationEvidence>,
        finding: Finding,
    ) -> Self {
        let mut findings = vec![finding];
        let cleanup = match root.remove_open_dir_all() {
            Ok(()) => "removed",
            Err(first_error) => match parent.remove_dir_all(stage_name) {
                Ok(()) => "removed",
                Err(final_error) => {
                    findings.push(Finding::error(
                        FindingCode::MaterializeCleanup,
                        format!(
                            "remove staging tree after setup failure: retained handle: \
                             {first_error}; parent-relative retry: {final_error}"
                        ),
                    ));
                    "failed"
                }
            },
        };
        Self {
            findings,
            cleanup,
            windows: windows.map(Box::new),
        }
    }

    fn after_stage_by_name(
        parent: &CapDir,
        stage_name: &Path,
        windows: Option<WindowsMaterializationEvidence>,
        finding: Finding,
    ) -> Self {
        let mut findings = vec![finding];
        let cleanup = match parent.remove_dir_all(stage_name) {
            Ok(()) => "removed",
            Err(first_error) => match parent.remove_dir_all(stage_name) {
                Ok(()) => "removed",
                Err(final_error) => {
                    findings.push(Finding::error(
                        FindingCode::MaterializeCleanup,
                        format!(
                            "remove staging tree after setup failure: first attempt: \
                             {first_error}; retry: {final_error}"
                        ),
                    ));
                    "failed"
                }
            },
        };
        Self {
            findings,
            cleanup,
            windows: windows.map(Box::new),
        }
    }
}

impl From<Finding> for MaterializationSetupError {
    fn from(finding: Finding) -> Self {
        Self {
            findings: vec![finding],
            cleanup: "not-created",
            windows: initial_windows_evidence().map(Box::new),
        }
    }
}

pub(crate) struct CapabilityMaterializer {
    parent: CapDir,
    #[cfg(test)]
    parent_path: PathBuf,
    root: Option<CapDir>,
    stage_name: PathBuf,
    final_name: PathBuf,
    atomic: bool,
    outcome: &'static str,
    cleanup: &'static str,
    windows: Option<WindowsMaterializationEvidence>,
}

/// The only stage authority needed by a plan-native archive writer.
///
/// This deliberately carries neither the destination parent nor the final
/// component name, so code using it cannot publish or remove the stage.
#[derive(Debug)]
pub(crate) struct StageWriteRoot {
    root: CapDir,
    #[cfg(test)]
    root_path: Option<PathBuf>,
}

impl StageWriteRoot {
    fn try_clone_from(root: &CapDir, _test_root_path: Option<PathBuf>) -> Result<Self, Finding> {
        let root = root.try_clone().map_err(|error| {
            Finding::error(
                FindingCode::MaterializeIo,
                format!("clone staging capability: {error}"),
            )
        })?;
        Ok(Self {
            root,
            #[cfg(test)]
            root_path: _test_root_path,
        })
    }

    #[cfg(feature = "__internal-worker-lab")]
    pub(crate) fn from_worker_file(file: StdFile) -> Result<Self, Finding> {
        let root = CapDir::from_std_file(file);
        ensure_stage_namespace_safe(&root)?;
        ensure_directory_handle_is_not_reparse(&root).map_err(|error| {
            Finding::error(
                FindingCode::MaterializeUnsafeComponent,
                format!("worker staging capability is a reparse point: {error}"),
            )
        })?;
        Ok(Self {
            root,
            #[cfg(test)]
            root_path: None,
        })
    }

    pub(crate) fn create_directory(&self, parts: &[String], member: &str) -> Result<(), Finding> {
        self.open_or_create_directories(parts)
            .map(|_| ())
            .map_err(|finding| finding.on(member))
    }

    pub(crate) fn create_file(&self, parts: &[String]) -> Result<CapFile, Finding> {
        let (leaf, parents) = parts.split_last().ok_or_else(|| {
            Finding::error(
                FindingCode::MaterializeIo,
                "canonical member has no path components",
            )
        })?;
        validate_component(leaf)?;
        let parent = self.open_or_create_directories(parents)?;
        let mut options = CapOpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        let file = parent
            .open_with(Path::new(leaf), &options)
            .map_err(|error| {
                Finding::error(
                    FindingCode::MaterializeUnsafeComponent,
                    format!("create member without following links: {error}"),
                )
            })?;
        ensure_file_handle_is_not_reparse(&file).map_err(|error| {
            Finding::error(
                FindingCode::MaterializeUnsafeComponent,
                format!("created member is a reparse point: {error}"),
            )
        })?;
        Ok(file)
    }

    fn open_or_create_directories(&self, parts: &[String]) -> Result<CapDir, Finding> {
        let mut current = self.root.try_clone().map_err(|error| {
            Finding::error(
                FindingCode::MaterializeIo,
                format!("clone staging capability: {error}"),
            )
        })?;
        #[cfg(test)]
        let mut relative = PathBuf::new();
        for part in parts {
            validate_component(part)?;
            let component = Path::new(part);
            match current.create_dir(component) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(Finding::error(
                        FindingCode::MaterializeIo,
                        format!("create directory component {part:?}: {error}"),
                    ));
                }
            }
            #[cfg(test)]
            if let Some(root_path) = &self.root_path {
                relative.push(part);
                injected_after_directory_component(&root_path.join(&relative));
            }
            current = current.open_dir_nofollow(component).map_err(|error| {
                Finding::error(
                    FindingCode::MaterializeUnsafeComponent,
                    format!("open directory component {part:?} without following links: {error}"),
                )
            })?;
            ensure_directory_handle_is_not_reparse(&current).map_err(|error| {
                Finding::error(
                    FindingCode::MaterializeUnsafeComponent,
                    format!("directory component {part:?} is a reparse point: {error}"),
                )
            })?;
        }
        Ok(current)
    }
}

#[derive(Debug)]
struct StageCreateError {
    error: io::Error,
    created: bool,
}

/// A randomly named directory whose namespace is private to the effective
/// principal and which is owned through retained directory capabilities.
///
/// Source snapshots use this for bounded spooling. Keeping the primitive here
/// ensures temporary archive bytes receive the same native ownership, mode,
/// ACL, reparse-point, and parent-filesystem checks as extraction staging.
pub(crate) struct PrivateDirectory {
    parent: CapDir,
    root: Option<CapDir>,
    name: PathBuf,
    #[cfg(test)]
    parent_path: PathBuf,
}

impl PrivateDirectory {
    pub(crate) fn create_in_system_temp(prefix: &str) -> io::Result<Self> {
        ensure_platform_supported().map_err(finding_as_io)?;
        if prefix.is_empty()
            || !prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private-directory prefix is not a safe filename fragment",
            ));
        }

        let parent_path = fs::canonicalize(std::env::temp_dir())?;
        let parent = CapDir::open_ambient_dir(&parent_path, ambient_authority())?;
        #[cfg(not(windows))]
        ensure_parent_namespace_safe(&parent).map_err(finding_as_io)?;
        #[cfg(windows)]
        windows::probe_supported_parent(&parent).map_err(|error| {
            io::Error::new(
                error.error.kind(),
                format!("unsupported private-spool parent: {}", error.error),
            )
        })?;

        for _ in 0..128 {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random)
                .map_err(|error| io::Error::other(format!("generate private name: {error}")))?;
            let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let name = PathBuf::from(format!("{prefix}{suffix}"));
            match create_stage(&parent, &name) {
                Ok(root) => {
                    if let Err(finding) = ensure_stage_namespace_safe(&root) {
                        let detail = finding.detail.clone();
                        let cleanup = root
                            .remove_open_dir_all()
                            .or_else(|_| parent.remove_dir_all(&name));
                        return Err(match cleanup {
                            Ok(()) => io::Error::new(io::ErrorKind::PermissionDenied, detail),
                            Err(error) => io::Error::other(format!(
                                "{detail}; private-directory cleanup also failed: {error}"
                            )),
                        });
                    }
                    if let Err(error) = ensure_directory_handle_is_not_reparse(&root) {
                        let cleanup = root
                            .remove_open_dir_all()
                            .or_else(|_| parent.remove_dir_all(&name));
                        return Err(match cleanup {
                            Ok(()) => error,
                            Err(cleanup_error) => io::Error::other(format!(
                                "private directory is a reparse point: {error}; cleanup also failed: {cleanup_error}"
                            )),
                        });
                    }
                    return Ok(Self {
                        parent,
                        root: Some(root),
                        name,
                        #[cfg(test)]
                        parent_path,
                    });
                }
                Err(error)
                    if !error.created && error.error.kind() == io::ErrorKind::AlreadyExists =>
                {
                    continue;
                }
                Err(error) if error.created => {
                    let cleanup = parent.remove_dir_all(&name);
                    return Err(match cleanup {
                        Ok(()) => error.error,
                        Err(cleanup_error) => io::Error::other(format!(
                            "open private-directory capability: {}; cleanup also failed: {cleanup_error}",
                            error.error
                        )),
                    });
                }
                Err(error) => return Err(error.error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique private directory",
        ))
    }

    pub(crate) fn root(&self) -> io::Result<&CapDir> {
        self.root
            .as_ref()
            .ok_or_else(|| io::Error::other("private-directory capability is unavailable"))
    }

    fn cleanup(&mut self) -> io::Result<()> {
        let Some(root) = self.root.take() else {
            return Ok(());
        };
        root.remove_open_dir_all()
            .or_else(|_| self.parent.remove_dir_all(&self.name))
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> PathBuf {
        self.parent_path.join(&self.name)
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn finding_as_io(finding: Finding) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, finding.detail)
}

impl CapabilityMaterializer {
    pub(crate) fn create(dest: &Path, atomic: bool) -> Result<Self, MaterializationSetupError> {
        ensure_platform_supported()?;
        let file_name = dest.file_name().ok_or_else(|| {
            Finding::error(
                FindingCode::MaterializeIo,
                "destination must name a directory below an existing root",
            )
        })?;
        let parent_input = dest
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent_path = fs::canonicalize(parent_input).map_err(|error| {
            Finding::error(
                FindingCode::MaterializeIo,
                format!("resolve existing destination parent: {error}"),
            )
        })?;
        let parent =
            CapDir::open_ambient_dir(&parent_path, ambient_authority()).map_err(|error| {
                Finding::error(
                    FindingCode::MaterializeIo,
                    format!("open destination parent capability: {error}"),
                )
            })?;
        #[cfg(not(windows))]
        ensure_parent_namespace_safe(&parent)?;
        #[cfg(windows)]
        let mut windows_report = match windows::probe_supported_parent(&parent) {
            Ok(observation) => Some(windows_evidence(observation, "not-created")),
            Err(error) => {
                let evidence = windows_evidence(error.observation, "not-created");
                return Err(MaterializationSetupError {
                    findings: vec![Finding::error(
                        FindingCode::MaterializeUnsupportedFilesystem,
                        format!("Windows destination parent is unsupported: {}", error.error),
                    )],
                    cleanup: "not-created",
                    windows: Some(Box::new(evidence)),
                });
            }
        };
        #[cfg(not(windows))]
        let windows_report = None;
        let final_name = PathBuf::from(file_name);
        if capability_path_exists(&parent, &final_name).map_err(|finding| {
            MaterializationSetupError::before_stage(finding, windows_report.clone())
        })? {
            return Err(MaterializationSetupError::before_stage(
                Finding::error(
                    FindingCode::MaterializeExists,
                    "destination already exists; replacement is not implemented",
                ),
                windows_report,
            ));
        }

        for _ in 0..128 {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(|error| {
                MaterializationSetupError::before_stage(
                    Finding::error(
                        FindingCode::MaterializeIo,
                        format!("generate staging name: {error}"),
                    ),
                    windows_report.clone(),
                )
            })?;
            let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let stage_name = PathBuf::from(format!(".sealr-stage-{suffix}"));
            match create_stage(&parent, &stage_name) {
                Ok(root) => {
                    if let Err(finding) = ensure_stage_namespace_safe(&root) {
                        #[cfg(windows)]
                        if let Some(evidence) = windows_report.as_mut() {
                            evidence.stage_acl = "verification-failed";
                        }
                        return Err(MaterializationSetupError::after_stage(
                            &parent,
                            root,
                            &stage_name,
                            windows_report,
                            finding,
                        ));
                    }
                    #[cfg(windows)]
                    if let Some(evidence) = windows_report.as_mut() {
                        evidence.stage_acl = "verified";
                    }
                    if let Err(error) = ensure_directory_handle_is_not_reparse(&root) {
                        return Err(MaterializationSetupError::after_stage(
                            &parent,
                            root,
                            &stage_name,
                            windows_report,
                            Finding::error(
                                FindingCode::MaterializeUnsafeComponent,
                                format!("staging directory is a reparse point: {error}"),
                            ),
                        ));
                    }
                    return Ok(Self {
                        parent,
                        #[cfg(test)]
                        parent_path,
                        root: Some(root),
                        stage_name,
                        final_name,
                        atomic,
                        outcome: "staged",
                        cleanup: "pending",
                        windows: windows_report,
                    });
                }
                Err(error)
                    if !error.created && error.error.kind() == io::ErrorKind::AlreadyExists =>
                {
                    continue;
                }
                Err(error) if error.created => {
                    return Err(MaterializationSetupError::after_stage_by_name(
                        &parent,
                        &stage_name,
                        windows_report,
                        Finding::error(
                            FindingCode::MaterializeIo,
                            format!(
                                "open staging capability without following links: {}",
                                error.error
                            ),
                        ),
                    ));
                }
                Err(error) => {
                    return Err(MaterializationSetupError::before_stage(
                        Finding::error(
                            FindingCode::MaterializeIo,
                            format!(
                                "create staging directory through capability: {}",
                                error.error
                            ),
                        ),
                        windows_report,
                    ));
                }
            }
        }
        Err(MaterializationSetupError::before_stage(
            Finding::error(
                FindingCode::MaterializeIo,
                "could not allocate a unique staging directory",
            ),
            windows_report,
        ))
    }

    pub(crate) fn create_directory(&self, parts: &[String], member: &str) -> Result<(), Finding> {
        self.stage_writer()?.create_directory(parts, member)
    }

    pub(crate) fn create_file(&self, parts: &[String]) -> Result<CapFile, Finding> {
        self.stage_writer()?.create_file(parts)
    }

    #[cfg(feature = "__internal-worker-lab")]
    pub(crate) fn try_clone_worker_file(&self) -> Result<StdFile, Finding> {
        #[cfg(target_os = "linux")]
        let file = rustix::fs::openat(
            self.root()?,
            ".",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(StdFile::from);
        #[cfg(not(target_os = "linux"))]
        let file = self.root()?.try_clone().map(CapDir::into_std_file);
        file.map_err(|error| {
            Finding::error(
                FindingCode::MaterializeIo,
                format!("clone worker staging capability: {error}"),
            )
        })
    }

    pub(crate) fn commit(&mut self) -> Result<(), Finding> {
        let root = self.root.as_ref().ok_or_else(|| {
            Finding::error(
                FindingCode::MaterializeCommit,
                "staging capability is unavailable during publication",
            )
        })?;
        ensure_stage_name_matches_root(&self.parent, root, &self.stage_name).map_err(|error| {
            Finding::error(
                FindingCode::MaterializeCommit,
                format!("staging name no longer identifies the audited root: {error}"),
            )
        })?;
        if let Err(error) = rename_noreplace(&self.parent, root, &self.stage_name, &self.final_name)
        {
            self.outcome = "publication-failed";
            return Err(if error.kind() == io::ErrorKind::AlreadyExists {
                Finding::error(
                    FindingCode::MaterializeExists,
                    "destination appeared while materializing",
                )
            } else {
                Finding::error(
                    FindingCode::MaterializeCommit,
                    format!("publish staging directory: {error}"),
                )
            });
        }
        drop(self.root.take());
        self.outcome = "committed";
        self.cleanup = "not-applicable-after-commit";
        Ok(())
    }

    pub(crate) fn abort(&mut self) -> Result<(), Finding> {
        if !matches!(self.cleanup, "pending" | "failed") {
            return Ok(());
        }
        let result = match injected_cleanup_failure() {
            Some(error) => Err(error),
            None => match self.root.take() {
                Some(root) => root.remove_open_dir_all(),
                None => self.parent.remove_dir_all(&self.stage_name),
            },
        };
        match result {
            Ok(()) => {
                if self.outcome == "staged" {
                    self.outcome = "aborted";
                }
                self.cleanup = "removed";
                Ok(())
            }
            Err(error) => {
                if self.outcome == "staged" {
                    self.outcome = "aborted";
                }
                self.cleanup = "failed";
                Err(Finding::error(
                    FindingCode::MaterializeCleanup,
                    format!("remove staging tree: {error}"),
                ))
            }
        }
    }

    pub(crate) fn report(&self) -> MaterializationMeta {
        MaterializationMeta {
            schema: SCHEMA,
            requested: true,
            backend: BACKEND,
            stage_mode: stage_mode(),
            stage_creation_primitive: stage_creation_primitive(),
            member_resolution: MEMBER_RESOLUTION,
            durability: durability(self.atomic),
            publication_primitive: publication_primitive(),
            outcome: self.outcome,
            cleanup: self.cleanup,
            windows: self.windows.clone(),
        }
    }

    fn root(&self) -> Result<&CapDir, Finding> {
        self.root.as_ref().ok_or_else(|| {
            Finding::error(
                FindingCode::MaterializeIo,
                "staging capability is unavailable",
            )
        })
    }

    fn stage_writer(&self) -> Result<StageWriteRoot, Finding> {
        #[cfg(test)]
        let test_root_path = Some(self.stage_path());
        #[cfg(not(test))]
        let test_root_path = None;
        StageWriteRoot::try_clone_from(self.root()?, test_root_path)
    }

    #[cfg(test)]
    fn open_or_create_directories(&self, parts: &[String]) -> Result<CapDir, Finding> {
        self.stage_writer()?.open_or_create_directories(parts)
    }

    fn open_existing_directories(&self, parts: &[String]) -> Result<CapDir, Finding> {
        let mut current = self.root()?.try_clone().map_err(|error| {
            Finding::error(
                FindingCode::MaterializeIo,
                format!("clone staging capability: {error}"),
            )
        })?;
        for part in parts {
            validate_component(part)?;
            current = current
                .open_dir_nofollow(Path::new(part))
                .map_err(|error| {
                    Finding::error(
                        FindingCode::MaterializeAudit,
                        format!("audit open directory {part:?}: {error}"),
                    )
                })?;
            ensure_directory_handle_is_not_reparse(&current).map_err(|error| {
                Finding::error(
                    FindingCode::MaterializeAudit,
                    format!("audited directory {part:?} is a reparse point: {error}"),
                )
            })?;
        }
        Ok(current)
    }

    pub(crate) fn audit_against(&self, ir: &crate::ir::ArchiveIR) -> Result<(), Finding> {
        use std::collections::BTreeSet;

        #[cfg(test)]
        apply_injected_stage_mutation(&self.stage_path());

        ensure_stage_namespace_safe(self.root()?).map_err(|finding| {
            Finding::error(
                FindingCode::MaterializeAudit,
                format!(
                    "staging root security drifted before audit: {}",
                    finding.detail
                ),
            )
        })?;
        ensure_stage_name_matches_root(&self.parent, self.root()?, &self.stage_name).map_err(
            |error| {
                Finding::error(
                    FindingCode::MaterializeAudit,
                    format!("staging name does not identify the retained root: {error}"),
                )
            },
        )?;

        let mut expected_dirs = BTreeSet::new();
        let mut expected_files = BTreeSet::new();
        for member in &ir.members {
            match member.kind {
                crate::ir::MemberKind::Directory => {
                    expected_dirs.insert(member.components.clone());
                    for index in 1..member.components.len() {
                        expected_dirs.insert(member.components[..index].to_vec());
                    }
                    self.open_existing_directories(&member.components)?;
                }
                crate::ir::MemberKind::File => {
                    expected_files.insert(member.components.clone());
                    for index in 1..member.components.len() {
                        expected_dirs.insert(member.components[..index].to_vec());
                    }
                    let Some(expected_sha) = member.content_sha256.as_deref() else {
                        return Err(Finding::error(
                            FindingCode::MaterializeAudit,
                            "file member is missing a content digest",
                        )
                        .on(&member.decoded_name));
                    };
                    let Some(expected_size) = member.actual_uncomp_size else {
                        return Err(Finding::error(
                            FindingCode::MaterializeAudit,
                            "file member is missing a verified size",
                        )
                        .on(&member.decoded_name));
                    };
                    let (leaf, parents) = member.components.split_last().ok_or_else(|| {
                        Finding::error(
                            FindingCode::MaterializeAudit,
                            "file member has no path components",
                        )
                        .on(&member.decoded_name)
                    })?;
                    let parent = self.open_existing_directories(parents)?;
                    let mut options = CapOpenOptions::new();
                    options.read(true).follow(FollowSymlinks::No);
                    let mut file =
                        parent
                            .open_with(Path::new(leaf), &options)
                            .map_err(|error| {
                                Finding::error(
                                    FindingCode::MaterializeAudit,
                                    format!("audit open file: {error}"),
                                )
                                .on(&member.decoded_name)
                            })?;
                    ensure_file_handle_is_not_reparse(&file).map_err(|error| {
                        Finding::error(
                            FindingCode::MaterializeAudit,
                            format!("audited file is a reparse point: {error}"),
                        )
                        .on(&member.decoded_name)
                    })?;
                    ensure_single_link(&file).map_err(|error| {
                        Finding::error(
                            FindingCode::MaterializeAudit,
                            format!("audited file link state is unsafe: {error}"),
                        )
                        .on(&member.decoded_name)
                    })?;
                    let (actual_size, actual_sha) = hash_staged_file(&mut file, expected_size)
                        .map_err(|error| {
                            Finding::error(
                                FindingCode::MaterializeAudit,
                                format!("audit read file: {error}"),
                            )
                            .on(&member.decoded_name)
                        })?;
                    if actual_size != expected_size {
                        return Err(Finding::error(
                            FindingCode::MaterializeAudit,
                            "staged size does not match the admitted IR",
                        )
                        .on(&member.decoded_name));
                    }
                    if actual_sha != expected_sha {
                        return Err(Finding::error(
                            FindingCode::MaterializeAudit,
                            "staged content does not match the admitted IR",
                        )
                        .on(&member.decoded_name));
                    }
                }
            }
        }

        let mut actual_dirs = BTreeSet::new();
        let mut actual_files = BTreeSet::new();
        collect_stage_tree(
            self.root()?,
            Vec::new(),
            &mut actual_dirs,
            &mut actual_files,
        )?;
        if actual_dirs != expected_dirs || actual_files != expected_files {
            return Err(Finding::error(
                FindingCode::MaterializeAudit,
                "staged tree paths do not match the admitted IR",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn stage_path(&self) -> PathBuf {
        self.parent_path.join(&self.stage_name)
    }
}

#[cfg(any(target_os = "android", target_os = "linux", target_os = "macos"))]
fn ensure_single_link(file: &CapFile) -> io::Result<()> {
    let metadata = rustix::fs::fstat(file)?;
    if metadata.st_nlink == 1 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("expected link count 1, observed {}", metadata.st_nlink),
        ))
    }
}

#[cfg(windows)]
fn ensure_single_link(_file: &CapFile) -> io::Result<()> {
    // The stable Rust Windows metadata surface does not expose link count.
    // Existing no-reparse, exact-tree, size, and digest checks remain active;
    // the Linux worker boundary adds the mandatory single-link check.
    Ok(())
}

#[cfg(not(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    windows
)))]
fn ensure_single_link(_file: &CapFile) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file link-count audit is unavailable on this platform",
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn ensure_stage_name_matches_root(parent: &CapDir, root: &CapDir, name: &Path) -> io::Result<()> {
    use cap_std::fs::MetadataExt;

    let named = parent.open_dir_nofollow(name)?;
    let named_metadata = named.dir_metadata()?;
    let root_metadata = root.dir_metadata()?;
    if named_metadata.dev() == root_metadata.dev() && named_metadata.ino() == root_metadata.ino() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stage device and inode identity changed",
        ))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn ensure_stage_name_matches_root(
    _parent: &CapDir,
    _root: &CapDir,
    _name: &Path,
) -> io::Result<()> {
    Ok(())
}

pub(crate) fn process_member_to_file(
    payload: impl BufRead,
    member: PayloadSpec,
    budget: ResourceBudget,
    remaining_total: u64,
    member_sync: bool,
    capture: Option<&mut Vec<u8>>,
    mut file: CapFile,
) -> Result<(u64, u32, [u8; 32]), Finding> {
    let result = {
        let mut writer = RetainingWriter {
            primary: &mut file,
            capture,
        };
        verify_payload(payload, member, budget, remaining_total, &mut writer)?
    };
    file.flush().map_err(|error| {
        Finding::error(FindingCode::MaterializeIo, format!("flush member: {error}"))
    })?;
    if member_sync {
        file.sync_all().map_err(|error| {
            Finding::error(FindingCode::MaterializeIo, format!("sync member: {error}"))
        })?;
    }
    Ok(result)
}

struct RetainingWriter<'a, W> {
    primary: &'a mut W,
    capture: Option<&'a mut Vec<u8>>,
}

impl<W: Write> Write for RetainingWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.primary.write(bytes)?;
        if let Some(capture) = self.capture.as_deref_mut() {
            capture.extend_from_slice(&bytes[..written]);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.primary.flush()
    }
}

fn hash_staged_file(file: &mut CapFile, expected_size: u64) -> io::Result<(u64, String)> {
    use std::io::Read;

    let mut size = 0_u64;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let remaining = expected_size.saturating_sub(size);
        let read_limit = remaining.saturating_add(1).min(buffer.len() as u64) as usize;
        let read = file.read(&mut buffer[..read_limit])?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("staged file size overflowed u64"))?;
        digest.update(&buffer[..read]);
        if size > expected_size {
            break;
        }
    }
    let hex = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((size, hex))
}

fn collect_stage_tree(
    dir: &CapDir,
    prefix: Vec<String>,
    dirs: &mut std::collections::BTreeSet<Vec<String>>,
    files: &mut std::collections::BTreeSet<Vec<String>>,
) -> Result<(), Finding> {
    let entries = dir.entries().map_err(|error| {
        Finding::error(
            FindingCode::MaterializeAudit,
            format!("audit list directory: {error}"),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            Finding::error(
                FindingCode::MaterializeAudit,
                format!("audit read directory entry: {error}"),
            )
        })?;
        let os_name = entry.file_name();
        let name = os_name.to_str().ok_or_else(|| {
            Finding::error(FindingCode::MaterializeAudit, "staged name is not UTF-8")
        })?;
        if name == "." || name == ".." {
            continue;
        }
        let metadata = dir.symlink_metadata(Path::new(name)).map_err(|error| {
            Finding::error(
                FindingCode::MaterializeAudit,
                format!("audit metadata for {name:?}: {error}"),
            )
        })?;
        if metadata_is_reparse(&metadata) {
            return Err(Finding::error(
                FindingCode::MaterializeAudit,
                format!("staged tree contains a reparse point at {name:?}"),
            ));
        }
        let mut path = prefix.clone();
        path.push(name.to_owned());
        if metadata.file_type().is_dir() {
            dirs.insert(path.clone());
            let child = dir.open_dir_nofollow(Path::new(name)).map_err(|error| {
                Finding::error(
                    FindingCode::MaterializeAudit,
                    format!("audit open staged directory {name:?}: {error}"),
                )
            })?;
            ensure_directory_handle_is_not_reparse(&child).map_err(|error| {
                Finding::error(
                    FindingCode::MaterializeAudit,
                    format!("audited directory {name:?} is a reparse point: {error}"),
                )
            })?;
            collect_stage_tree(&child, path, dirs, files)?;
        } else if metadata.file_type().is_file() {
            files.insert(path);
        } else {
            return Err(Finding::error(
                FindingCode::MaterializeAudit,
                format!("staged tree contains a non-file, non-directory entry at {name:?}"),
            ));
        }
    }
    Ok(())
}

fn metadata_is_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use cap_fs_ext::OsMetadataExt;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

impl Drop for CapabilityMaterializer {
    fn drop(&mut self) {
        if self.cleanup == "pending" {
            let _ = self.abort();
        }
    }
}

fn validate_component(component: &str) -> Result<(), Finding> {
    validate_component_io(component).map_err(|error| {
        Finding::error(
            FindingCode::MaterializeUnsafeComponent,
            format!("invalid canonical path component: {error}"),
        )
    })
}

fn validate_component_io(component: &str) -> io::Result<()> {
    let mut components = Path::new(component).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(value)), None) if value == component => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "component is not one normal relative name",
        )),
    }
}

fn capability_path_exists(dir: &CapDir, path: &Path) -> Result<bool, Finding> {
    match dir.symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Finding::error(
            FindingCode::MaterializeIo,
            format!("inspect destination: {error}"),
        )),
    }
}

fn durability(atomic: bool) -> &'static str {
    if atomic {
        "member-sync"
    } else {
        "flush-only"
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stage_mode() -> &'static str {
    "same-volume-random-128-mode-0700"
}

#[cfg(windows)]
fn stage_mode() -> &'static str {
    "same-volume-random-128-protected-token-user-dacl"
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn stage_mode() -> &'static str {
    "unsupported"
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stage_creation_primitive() -> &'static str {
    "mkdirat-mode-0700-openat-nofollow-safe-parent"
}

#[cfg(windows)]
fn stage_creation_primitive() -> &'static str {
    windows::STAGE_CREATION_PRIMITIVE
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn stage_creation_primitive() -> &'static str {
    "unsupported"
}

#[cfg(target_os = "linux")]
fn publication_primitive() -> &'static str {
    "renameat2-noreplace"
}

#[cfg(target_os = "macos")]
fn publication_primitive() -> &'static str {
    "renameatx-np-excl"
}

#[cfg(windows)]
fn publication_primitive() -> &'static str {
    windows::PUBLICATION_PRIMITIVE
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn publication_primitive() -> &'static str {
    "unsupported"
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn ensure_platform_supported() -> Result<(), Finding> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn ensure_platform_supported() -> Result<(), Finding> {
    Err(Finding::error(
        FindingCode::MaterializeUnsupported,
        "atomic no-replace materialization is unsupported on this platform",
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn create_stage(parent: &CapDir, name: &Path) -> Result<CapDir, StageCreateError> {
    use cap_std::fs::{DirBuilder, DirBuilderExt};

    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    parent
        .create_dir_with(name, &builder)
        .map_err(|error| StageCreateError {
            error,
            created: false,
        })?;
    parent
        .open_dir_nofollow(name)
        .map_err(|error| StageCreateError {
            error,
            created: true,
        })
}

#[cfg(windows)]
fn create_stage(parent: &CapDir, name: &Path) -> Result<CapDir, StageCreateError> {
    windows::create_stage(parent, name).map_err(|error| StageCreateError {
        error,
        created: false,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn create_stage(_parent: &CapDir, _name: &Path) -> Result<CapDir, StageCreateError> {
    Err(StageCreateError {
        error: io::Error::new(
            io::ErrorKind::Unsupported,
            "secure stage creation is unsupported",
        ),
        created: false,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn ensure_parent_namespace_safe(parent: &CapDir) -> Result<(), Finding> {
    use cap_std::fs::MetadataExt;

    let metadata = parent.dir_metadata().map_err(|_| {
        Finding::error(
            FindingCode::MaterializeUnsafeParent,
            "destination parent security metadata could not be read",
        )
    })?;
    let owner = metadata.uid();
    let effective_uid = rustix::process::geteuid().as_raw();
    let mode = metadata.mode();
    if owner != effective_uid && owner != 0 {
        return Err(Finding::error(
            FindingCode::MaterializeUnsafeParent,
            "destination parent is owned by an untrusted principal",
        ));
    }
    if !unix_parent_mode_is_safe(owner, effective_uid, mode) {
        return Err(Finding::error(
            FindingCode::MaterializeUnsafeParent,
            "destination parent permits cross-principal namespace mutation",
        ));
    }
    ensure_no_apple_extended_acl(parent, "destination parent")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unix_parent_mode_is_safe(owner: u32, effective_uid: u32, mode: u32) -> bool {
    let trusted_owner = owner == effective_uid || owner == 0;
    let externally_writable = mode & 0o022 != 0;
    let sticky = mode & 0o1000 != 0;
    trusted_owner && (!externally_writable || sticky)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn ensure_parent_namespace_safe(_parent: &CapDir) -> Result<(), Finding> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn ensure_stage_namespace_safe(root: &CapDir) -> Result<(), Finding> {
    use cap_std::fs::MetadataExt;

    let metadata = root.dir_metadata().map_err(|_| {
        Finding::error(
            FindingCode::MaterializeUnsafeParent,
            "staging directory security metadata could not be read",
        )
    })?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if metadata.uid() != effective_uid || metadata.mode() & 0o077 != 0 {
        return Err(Finding::error(
            FindingCode::MaterializeUnsafeParent,
            "staging directory ownership or permissions are unsafe",
        ));
    }
    ensure_no_apple_extended_acl(root, "staging directory")
}

#[cfg(windows)]
fn ensure_stage_namespace_safe(root: &CapDir) -> Result<(), Finding> {
    windows::ensure_private_stage_security(root).map_err(|error| {
        Finding::error(
            FindingCode::MaterializeUnsafeStage,
            format!("staging directory DACL verification failed: {error}"),
        )
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn ensure_stage_namespace_safe(_root: &CapDir) -> Result<(), Finding> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn ensure_no_apple_extended_acl(dir: &CapDir, label: &str) -> Result<(), Finding> {
    match apple::has_extended_acl(dir) {
        Ok(false) => Ok(()),
        Ok(true) => Err(Finding::error(
            FindingCode::MaterializeUnsafeParent,
            format!("{label} has an extended ACL"),
        )),
        Err(_) => Err(Finding::error(
            FindingCode::MaterializeUnsafeParent,
            format!("{label} ACL could not be proven absent"),
        )),
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn ensure_no_apple_extended_acl(_dir: &CapDir, _label: &str) -> Result<(), Finding> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rename_noreplace(parent: &CapDir, _root: &CapDir, from: &Path, to: &Path) -> io::Result<()> {
    Ok(rustix::fs::renameat_with(
        parent,
        from,
        parent,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )?)
}

#[cfg(windows)]
fn rename_noreplace(parent: &CapDir, root: &CapDir, _from: &Path, to: &Path) -> io::Result<()> {
    windows::rename_noreplace(parent, root, to)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn rename_noreplace(_parent: &CapDir, _root: &CapDir, _from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace publication is unsupported",
    ))
}

#[cfg(not(windows))]
fn ensure_directory_handle_is_not_reparse(_dir: &CapDir) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn ensure_directory_handle_is_not_reparse(dir: &CapDir) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;

    let metadata = dir.try_clone()?.into_std_file().metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reparse-point attribute is set",
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
pub(crate) fn ensure_file_handle_is_not_reparse(_file: &CapFile) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
pub(crate) fn ensure_file_handle_is_not_reparse(file: &CapFile) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;

    let metadata = file.try_clone()?.into_std().metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reparse-point attribute is set",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dest(label: &str) -> PathBuf {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        std::env::temp_dir().join(format!("sealr-materializer-{label}-{suffix}"))
    }

    #[test]
    fn missing_destination_parent_is_not_created() {
        let parent = temp_dest("missing-parent");
        let dest = parent.join("output");

        let error = match CapabilityMaterializer::create(&dest, false) {
            Ok(_) => panic!("materializer unexpectedly created a missing parent"),
            Err(error) => error,
        };
        let (findings, cleanup, _) = error.into_parts();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::MaterializeIo);
        assert_eq!(cleanup, "not-created");
        assert!(!parent.exists());
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_materialization_reports_never_serialize_windows_evidence() {
        let not_requested = MaterializationMeta::not_started(false, false);
        assert!(serde_json::to_value(not_requested)
            .unwrap()
            .get("windows")
            .is_none());

        let dest = temp_dest("non-windows-receipt");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        materializer.commit().unwrap();
        assert!(serde_json::to_value(materializer.report())
            .unwrap()
            .get("windows")
            .is_none());
        fs::remove_dir_all(&dest).unwrap();

        let missing_parent = temp_dest("non-windows-missing-parent");
        let error = match CapabilityMaterializer::create(&missing_parent.join("output"), false) {
            Ok(_) => panic!("missing parent unexpectedly accepted"),
            Err(error) => error,
        };
        let (_, cleanup, windows) = error.into_parts();
        let setup_failed = MaterializationMeta::setup_failed(false, cleanup, windows);
        assert!(serde_json::to_value(setup_failed)
            .unwrap()
            .get("windows")
            .is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn unix_parent_policy_requires_trusted_ownership_and_safe_mode() {
        let effective_uid = 1000;
        let cases = [
            (1000, 0o700, true),
            (0, 0o755, true),
            (1000, 0o770, false),
            (1000, 0o707, false),
            (0, 0o1777, true),
            (1000, 0o1777, true),
            (2000, 0o700, false),
            (2000, 0o1777, false),
        ];

        for (owner, mode, expected) in cases {
            assert_eq!(
                unix_parent_mode_is_safe(owner, effective_uid, mode),
                expected,
                "owner {owner}, mode {mode:o}"
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn rejects_nonsticky_shared_writable_parent_before_staging() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        for (label, mode) in [("group-writable", 0o770), ("other-writable", 0o707)] {
            let parent = temp_dest(label);
            fs::create_dir(&parent).unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(mode)).unwrap();
            let dest = parent.join("output");

            let error = match CapabilityMaterializer::create(&dest, false) {
                Ok(_) => panic!("unsafe parent unexpectedly accepted"),
                Err(error) => error,
            };
            let (findings, cleanup, _) = error.into_parts();

            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].code, FindingCode::MaterializeUnsafeParent);
            assert_eq!(cleanup, "not-created");
            assert!(!dest.exists());
            assert!(!fs::read_dir(&parent).unwrap().any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".sealr-stage-")));

            let owner = fs::metadata(&parent).unwrap().uid();
            assert_eq!(owner, rustix::process::geteuid().as_raw());
            fs::remove_dir(&parent).unwrap();
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn accepts_private_and_trusted_sticky_parents() {
        use std::os::unix::fs::PermissionsExt;

        for (label, mode) in [("private-parent", 0o700), ("sticky-parent", 0o1777)] {
            let parent = temp_dest(label);
            fs::create_dir(&parent).unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(mode)).unwrap();
            let dest = parent.join("output");

            let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
            let mut file = materializer
                .create_file(&["approved.txt".to_owned()])
                .unwrap();
            file.write_all(b"approved").unwrap();
            drop(file);
            materializer.commit().unwrap();

            assert_eq!(fs::read(dest.join("approved.txt")).unwrap(), b"approved");
            fs::remove_dir_all(&parent).unwrap();
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rejects_an_apple_extended_acl_before_staging() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let parent = temp_dest("apple-extended-acl");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let output = Command::new("chmod")
            .args([
                "+a",
                "everyone allow add_file,add_subdirectory,delete_child",
            ])
            .arg(&parent)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "add test ACL: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let dest = parent.join("output");
        let error = match CapabilityMaterializer::create(&dest, false) {
            Ok(_) => panic!("extended ACL unexpectedly accepted"),
            Err(error) => error,
        };
        let (findings, cleanup, _) = error.into_parts();
        assert_eq!(findings[0].code, FindingCode::MaterializeUnsafeParent);
        assert_eq!(cleanup, "not-created");
        assert!(!dest.exists());

        let output = Command::new("chmod")
            .arg("-N")
            .arg(&parent)
            .output()
            .unwrap();
        assert!(output.status.success());
        fs::remove_dir(&parent).unwrap();
    }

    #[test]
    fn creates_nested_members_through_component_handles() {
        let dest = temp_dest("nested");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        materializer
            .create_directory(&["empty".to_owned(), "nested".to_owned()], "empty/nested/")
            .unwrap();
        let mut file = materializer
            .create_file(&[
                "tree".to_owned(),
                "branch".to_owned(),
                "leaf.txt".to_owned(),
            ])
            .unwrap();
        file.write_all(b"leaf").unwrap();
        drop(file);
        materializer.commit().unwrap();

        assert_eq!(
            fs::read(dest.join("tree/branch/leaf.txt")).unwrap(),
            b"leaf"
        );
        assert!(dest.join("empty/nested").is_dir());
        let report = materializer.report();
        assert_eq!(report.schema, "sealr.materialization.v2");
        assert_eq!(report.outcome, "committed");
        assert_eq!(report.cleanup, "not-applicable-after-commit");
        #[cfg(target_os = "macos")]
        {
            assert_eq!(report.stage_creation_primitive, stage_creation_primitive());
            assert_eq!(report.publication_primitive, "renameatx-np-excl");
            assert!(report.windows.is_none());
        }
        fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn abort_removes_the_open_stage_and_reports_cleanup() {
        let dest = temp_dest("abort");
        let mut materializer = CapabilityMaterializer::create(&dest, true).unwrap();
        let stage_path = materializer.stage_path();
        let mut file = materializer
            .create_file(&["partial.txt".to_owned()])
            .unwrap();
        file.write_all(b"partial").unwrap();
        drop(file);

        materializer.abort().unwrap();

        assert!(!stage_path.exists());
        assert!(!dest.exists());
        assert_eq!(materializer.report().cleanup, "removed");
        assert_eq!(materializer.report().durability, "member-sync");
        assert_eq!(materializer.report().outcome, "aborted");
    }

    #[test]
    fn drop_does_not_change_a_final_cleanup_failure() {
        let parent = temp_dest("cleanup-final");
        fs::create_dir(&parent).unwrap();
        let dest = parent.join("output");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let stage_path = materializer.stage_path();
        materializer.cleanup = "failed";

        drop(materializer);

        assert!(stage_path.exists());
        assert!(!dest.exists());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn commit_preserves_a_destination_that_appears_after_staging() {
        let dest = temp_dest("appeared");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let mut file = materializer
            .create_file(&["inside.txt".to_owned()])
            .unwrap();
        file.write_all(b"staged").unwrap();
        drop(file);

        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("owner.txt"), b"existing").unwrap();
        let error = materializer.commit().unwrap_err();

        assert_eq!(error.code, FindingCode::MaterializeExists);
        assert_eq!(fs::read(dest.join("owner.txt")).unwrap(), b"existing");
        #[cfg(target_os = "macos")]
        {
            let report = materializer.report();
            assert_eq!(report.schema, "sealr.materialization.v2");
            assert_eq!(report.publication_primitive, "renameatx-np-excl");
            assert!(report.windows.is_none());
        }
        materializer.abort().unwrap();
        fs::remove_dir_all(dest).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn atomic_windows_stage_blocks_name_substitution_and_publishes_approved_tree() {
        const ERROR_SHARING_VIOLATION: i32 = 32;

        let dest = temp_dest("publication-substitution");
        let renamed = dest.with_extension("renamed-stage");
        let malicious = dest.with_extension("malicious-stage");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let stage = materializer.stage_path();
        let mut file = materializer
            .create_file(&["approved.txt".to_owned()])
            .unwrap();
        file.write_all(b"approved").unwrap();
        drop(file);

        fs::create_dir(&malicious).unwrap();
        fs::write(malicious.join("substituted.txt"), b"attacker-selected").unwrap();

        let rename_error = fs::rename(&stage, &renamed).unwrap_err();
        assert_eq!(rename_error.raw_os_error(), Some(ERROR_SHARING_VIOLATION));
        let remove_error = fs::remove_dir(&stage).unwrap_err();
        assert_eq!(remove_error.raw_os_error(), Some(ERROR_SHARING_VIOLATION));
        assert!(fs::rename(&malicious, &stage).is_err());

        materializer.commit().unwrap();

        assert_eq!(fs::read(dest.join("approved.txt")).unwrap(), b"approved");
        assert!(!dest.join("substituted.txt").exists());
        assert_eq!(
            materializer.report().stage_creation_primitive,
            windows::STAGE_CREATION_PRIMITIVE
        );
        assert_eq!(
            materializer.report().publication_primitive,
            windows::PUBLICATION_PRIMITIVE
        );

        fs::remove_dir_all(dest).unwrap();
        fs::remove_dir_all(malicious).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_stage_creation_is_exclusive() {
        let parent_path = temp_dest("exclusive-stage-parent");
        fs::create_dir(&parent_path).unwrap();
        let parent = CapDir::open_ambient_dir(&parent_path, ambient_authority()).unwrap();
        let existing_name = Path::new(".sealr-stage-existing-collision");
        fs::create_dir(parent_path.join(existing_name)).unwrap();
        let error = windows::create_stage(&parent, existing_name).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        fs::remove_dir(parent_path.join(existing_name)).unwrap();

        let name = Path::new(".sealr-stage-fixed-handle");
        let root = windows::create_stage(&parent, name).unwrap();
        let error = windows::create_stage(&parent, name).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);

        root.remove_open_dir_all().unwrap();
        drop(parent);
        fs::remove_dir(&parent_path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_stage_dacl_is_private_and_inherits_to_descendants() {
        use std::os::windows::io::AsRawHandle;

        let dest = temp_dest("private-stage-dacl");
        let mut materializer = CapabilityMaterializer::create(&dest, true).unwrap();
        let directory = materializer
            .open_or_create_directories(&["nested".to_owned()])
            .unwrap();
        let mut file = materializer
            .create_file(&["nested".to_owned(), "approved.txt".to_owned()])
            .unwrap();
        file.write_all(b"approved").unwrap();
        file.sync_all().unwrap();

        windows::ensure_private_descendant_security(directory.as_raw_handle(), true).unwrap();
        windows::ensure_private_descendant_security(file.as_raw_handle(), false).unwrap();

        let report = materializer.report();
        let serialized = serde_json::to_value(&report).unwrap();
        assert_eq!(serialized["schema"], "sealr.materialization.v2");
        assert_eq!(serialized["windows"]["stage_acl"], "verified");
        let evidence = report.windows.unwrap();
        assert_eq!(evidence.storage_policy, windows::STORAGE_POLICY);
        assert_eq!(evidence.filesystem.as_deref(), Some("NTFS"));
        assert_eq!(evidence.device_scope, "local");
        assert_eq!(evidence.persistent_acls, Some(true));
        assert_eq!(evidence.read_only, Some(false));
        assert_eq!(evidence.stage_acl_policy, windows::STAGE_ACL_POLICY);
        assert_eq!(evidence.stage_acl, "verified");

        drop(file);
        drop(directory);
        materializer.commit().unwrap();
        assert_eq!(
            fs::read(dest.join("nested/approved.txt")).unwrap(),
            b"approved"
        );
        fs::remove_dir_all(dest).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_stage_acl_verification_failure_cleans_up_and_reports_evidence() {
        let parent = temp_dest("acl-verification-failure-parent");
        fs::create_dir(&parent).unwrap();
        let dest = parent.join("output");
        let _guard = windows::inject_stage_security_failure();

        let error = match CapabilityMaterializer::create(&dest, false) {
            Ok(_) => panic!("injected stage ACL verification unexpectedly succeeded"),
            Err(error) => error,
        };
        let (findings, cleanup, evidence) = error.into_parts();

        assert_eq!(cleanup, "removed");
        assert!(findings
            .iter()
            .any(|finding| finding.code == FindingCode::MaterializeUnsafeStage));
        let report = MaterializationMeta::setup_failed(false, cleanup, evidence);
        let serialized = serde_json::to_value(&report).unwrap();
        assert_eq!(serialized["schema"], "sealr.materialization.v2");
        assert_eq!(serialized["windows"]["stage_acl"], "verification-failed");
        let evidence = report.windows.unwrap();
        assert_eq!(evidence.stage_acl, "verification-failed");
        assert!(parent.read_dir().unwrap().next().is_none());
        fs::remove_dir(parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_existing_destination_preserves_observed_storage_evidence() {
        let dest = temp_dest("existing-destination-evidence");
        fs::create_dir(&dest).unwrap();

        let error = match CapabilityMaterializer::create(&dest, false) {
            Ok(_) => panic!("existing destination unexpectedly accepted"),
            Err(error) => error,
        };
        let (findings, cleanup, evidence) = error.into_parts();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::MaterializeExists);
        assert_eq!(cleanup, "not-created");
        let report = MaterializationMeta::setup_failed(false, cleanup, evidence);
        let serialized = serde_json::to_value(&report).unwrap();
        assert_eq!(serialized["windows"]["stage_acl"], "not-created");
        let evidence = report.windows.unwrap();
        assert_eq!(evidence.filesystem.as_deref(), Some("NTFS"));
        assert_eq!(evidence.device_scope, "local");
        assert_eq!(evidence.persistent_acls, Some(true));
        assert_eq!(evidence.read_only, Some(false));
        assert_eq!(evidence.stage_acl, "not-created");

        fs::remove_dir(dest).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_publication_supports_non_bmp_destination_names() {
        let parent = temp_dest("unicode-parent");
        fs::create_dir(&parent).unwrap();
        let dest = parent.join("published-\u{10437}");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let mut file = materializer
            .create_file(&["approved.txt".to_owned()])
            .unwrap();
        file.write_all(b"approved").unwrap();
        drop(file);

        materializer.commit().unwrap();

        assert_eq!(fs::read(dest.join("approved.txt")).unwrap(), b"approved");
        drop(materializer);
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_publication_preserves_a_destination_file() {
        let dest = temp_dest("appeared-file");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let mut file = materializer
            .create_file(&["approved.txt".to_owned()])
            .unwrap();
        file.write_all(b"approved").unwrap();
        drop(file);
        fs::write(&dest, b"existing-file").unwrap();

        let error = materializer.commit().unwrap_err();

        assert_eq!(error.code, FindingCode::MaterializeExists);
        assert_eq!(fs::read(&dest).unwrap(), b"existing-file");
        materializer.abort().unwrap();
        fs::remove_file(dest).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn refuses_a_symlink_for_any_parent_component() {
        use std::os::unix::fs::symlink;

        let dest = temp_dest("symlink");
        let outside = temp_dest("outside");
        fs::create_dir(&outside).unwrap();
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        symlink(&outside, materializer.stage_path().join("escape")).unwrap();

        let result = materializer.create_file(&[
            "escape".to_owned(),
            "nested".to_owned(),
            "written.txt".to_owned(),
        ]);
        assert_eq!(
            result.unwrap_err().code,
            FindingCode::MaterializeUnsafeComponent
        );
        assert!(!outside.join("nested/written.txt").exists());

        materializer.abort().unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn refuses_a_windows_junction_for_any_parent_component() {
        use std::process::Command;

        let dest = temp_dest("junction");
        let outside = temp_dest("junction-outside");
        fs::create_dir(&outside).unwrap();
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let junction = materializer.stage_path().join("escape");
        let output = Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "create test junction: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let result = materializer.create_file(&[
            "escape".to_owned(),
            "nested".to_owned(),
            "written.txt".to_owned(),
        ]);
        assert_eq!(
            result.unwrap_err().code,
            FindingCode::MaterializeUnsafeComponent
        );
        assert!(!outside.join("nested/written.txt").exists());

        materializer.abort().unwrap();
        assert!(outside.read_dir().unwrap().next().is_none());
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn rejects_non_component_input_at_the_materializer_boundary() {
        let dest = temp_dest("invalid-component");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        assert!(materializer
            .create_file(&["nested/escape.txt".to_owned()])
            .is_err_and(|finding| finding.code == FindingCode::MaterializeUnsafeComponent));
        materializer.abort().unwrap();
    }

    #[test]
    fn refuses_a_regular_file_as_a_parent_component() {
        let dest = temp_dest("non-directory");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let mut parent = materializer.create_file(&["parent".to_owned()]).unwrap();
        parent.write_all(b"not a directory").unwrap();
        drop(parent);

        let error = materializer
            .create_file(&["parent".to_owned(), "child.txt".to_owned()])
            .unwrap_err();

        assert_eq!(error.code, FindingCode::MaterializeUnsafeComponent);
        materializer.abort().unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn refuses_a_symlink_as_the_final_component() {
        use std::os::unix::fs::symlink;

        let dest = temp_dest("leaf-symlink");
        let outside = temp_dest("leaf-outside");
        fs::write(&outside, b"outside").unwrap();
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        symlink(&outside, materializer.stage_path().join("leaf.txt")).unwrap();

        let error = materializer
            .create_file(&["leaf.txt".to_owned()])
            .unwrap_err();

        assert_eq!(error.code, FindingCode::MaterializeUnsafeComponent);
        assert_eq!(fs::read(&outside).unwrap(), b"outside");
        materializer.abort().unwrap();
        fs::remove_file(outside).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn unix_publication_preserves_a_destination_file() {
        let dest = temp_dest("appeared-file");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let mut file = materializer
            .create_file(&["approved.txt".to_owned()])
            .unwrap();
        file.write_all(b"approved").unwrap();
        drop(file);
        fs::write(&dest, b"existing-file").unwrap();

        let error = materializer.commit().unwrap_err();

        assert_eq!(error.code, FindingCode::MaterializeExists);
        assert_eq!(fs::read(&dest).unwrap(), b"existing-file");
        materializer.abort().unwrap();
        fs::remove_file(dest).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn refuses_a_destination_symlink_at_commit() {
        use std::os::unix::fs::symlink;

        let dest = temp_dest("dest-symlink-commit");
        let outside = temp_dest("dest-symlink-outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel.txt"), b"outside").unwrap();
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let mut file = materializer
            .create_file(&["approved.txt".to_owned()])
            .unwrap();
        file.write_all(b"approved").unwrap();
        drop(file);
        symlink(&outside, &dest).unwrap();

        let error = materializer.commit().unwrap_err();

        assert_eq!(error.code, FindingCode::MaterializeExists);
        assert_eq!(fs::read(outside.join("sentinel.txt")).unwrap(), b"outside");
        assert!(!outside.join("approved.txt").exists());
        materializer.abort().unwrap();
        fs::remove_file(&dest).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn refuses_a_destination_symlink_at_create() {
        use std::os::unix::fs::symlink;

        let dest = temp_dest("dest-symlink-create");
        let outside = temp_dest("dest-symlink-create-outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel.txt"), b"outside").unwrap();
        symlink(&outside, &dest).unwrap();

        let error = match CapabilityMaterializer::create(&dest, false) {
            Ok(_) => panic!("destination symlink unexpectedly accepted"),
            Err(error) => error,
        };
        let (findings, cleanup, _) = error.into_parts();
        assert_eq!(findings[0].code, FindingCode::MaterializeExists);
        assert_eq!(cleanup, "not-created");
        assert_eq!(fs::read(outside.join("sentinel.txt")).unwrap(), b"outside");
        fs::remove_file(&dest).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn refuses_a_directory_component_replaced_by_a_symlink() {
        use std::os::unix::fs::symlink;

        let dest = temp_dest("component-swap");
        let outside = temp_dest("component-swap-outside");
        fs::create_dir(&outside).unwrap();
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let mut first = materializer
            .create_file(&["tree".to_owned(), "a.txt".to_owned()])
            .unwrap();
        first.write_all(b"a").unwrap();
        drop(first);

        let tree = materializer.stage_path().join("tree");
        fs::remove_dir_all(&tree).unwrap();
        symlink(&outside, &tree).unwrap();

        let error = materializer
            .create_file(&["tree".to_owned(), "b.txt".to_owned()])
            .unwrap_err();
        assert_eq!(error.code, FindingCode::MaterializeUnsafeComponent);
        assert!(!outside.join("b.txt").exists());

        materializer.abort().unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn symlink_refusals_remain_stable_across_repeats() {
        for round in 0..32 {
            let dest = temp_dest(&format!("repeat-leaf-{round}"));
            let outside = temp_dest(&format!("repeat-leaf-outside-{round}"));
            fs::write(&outside, b"outside").unwrap();
            let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
            std::os::unix::fs::symlink(&outside, materializer.stage_path().join("leaf.txt"))
                .unwrap();
            let error = materializer
                .create_file(&["leaf.txt".to_owned()])
                .unwrap_err();
            assert_eq!(error.code, FindingCode::MaterializeUnsafeComponent);
            assert_eq!(fs::read(&outside).unwrap(), b"outside");
            materializer.abort().unwrap();
            fs::remove_file(outside).unwrap();
        }
    }

    #[cfg(windows)]
    #[test]
    fn refuses_a_destination_junction_at_commit() {
        use std::process::Command;

        let dest = temp_dest("dest-junction-commit");
        let outside = temp_dest("dest-junction-outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel.txt"), b"outside").unwrap();
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let mut file = materializer
            .create_file(&["approved.txt".to_owned()])
            .unwrap();
        file.write_all(b"approved").unwrap();
        drop(file);
        let output = Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&dest)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "create dest junction: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let error = materializer.commit().unwrap_err();
        assert_eq!(error.code, FindingCode::MaterializeExists);
        assert_eq!(fs::read(outside.join("sentinel.txt")).unwrap(), b"outside");
        assert!(!outside.join("approved.txt").exists());
        materializer.abort().unwrap();
        fs::remove_dir(&dest).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn refuses_a_destination_junction_at_create() {
        use std::process::Command;

        let dest = temp_dest("dest-junction-create");
        let outside = temp_dest("dest-junction-create-outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel.txt"), b"outside").unwrap();
        let output = Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&dest)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "create dest junction: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let error = match CapabilityMaterializer::create(&dest, false) {
            Ok(_) => panic!("destination junction unexpectedly accepted"),
            Err(error) => error,
        };
        let (findings, cleanup, _) = error.into_parts();
        assert_eq!(findings[0].code, FindingCode::MaterializeExists);
        assert_eq!(cleanup, "not-created");
        assert_eq!(fs::read(outside.join("sentinel.txt")).unwrap(), b"outside");
        fs::remove_dir(&dest).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn refuses_a_directory_component_replaced_by_a_junction() {
        use std::process::Command;

        let dest = temp_dest("component-swap-junction");
        let outside = temp_dest("component-swap-junction-outside");
        fs::create_dir(&outside).unwrap();
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let mut first = materializer
            .create_file(&["tree".to_owned(), "a.txt".to_owned()])
            .unwrap();
        first.write_all(b"a").unwrap();
        drop(first);

        let tree = materializer.stage_path().join("tree");
        fs::remove_dir_all(&tree).unwrap();
        let output = Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&tree)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "create component junction: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let error = materializer
            .create_file(&["tree".to_owned(), "b.txt".to_owned()])
            .unwrap_err();
        assert_eq!(error.code, FindingCode::MaterializeUnsafeComponent);
        assert!(!outside.join("b.txt").exists());
        materializer.abort().unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn refuses_a_windows_file_symlink_as_the_final_component() {
        use std::process::Command;

        let dest = temp_dest("leaf-reparse");
        let outside = temp_dest("leaf-reparse-outside");
        fs::write(&outside, b"outside").unwrap();
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let leaf = materializer.stage_path().join("leaf.txt");
        let output = Command::new("cmd")
            .args(["/d", "/c", "mklink"])
            .arg(&leaf)
            .arg(&outside)
            .output()
            .unwrap();
        if !output.status.success() {
            materializer.abort().unwrap();
            fs::remove_file(outside).unwrap();
            eprintln!(
                "skipping file-symlink leaf test; mklink needs privilege: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let error = materializer
            .create_file(&["leaf.txt".to_owned()])
            .unwrap_err();
        assert_eq!(error.code, FindingCode::MaterializeUnsafeComponent);
        assert_eq!(fs::read(&outside).unwrap(), b"outside");
        materializer.abort().unwrap();
        fs::remove_file(outside).unwrap();
    }

    fn verified_file(name: &str, components: &[&str], body: &[u8]) -> crate::ir::IrMember {
        let mut member = crate::ir::IrMember {
            raw_name_bytes: name.as_bytes().to_vec(),
            decoded_name: name.to_owned(),
            canonical_path: components.join("/"),
            components: components.iter().map(|part| (*part).to_owned()).collect(),
            kind: crate::ir::MemberKind::File,
            method: 0,
            flags: 0,
            declared_crc: 0,
            declared_comp_size: body.len() as u64,
            declared_uncomp_size: body.len() as u64,
            source_ranges: crate::ir::MemberSourceRanges {
                local_header: crate::ir::ByteRange { offset: 0, len: 30 },
                compressed_payload: crate::ir::ByteRange {
                    offset: 30,
                    len: body.len() as u64,
                },
                data_descriptor: None,
                central_header: crate::ir::ByteRange { offset: 0, len: 46 },
            },
            extra_fields: Vec::new(),
            actual_uncomp_size: None,
            actual_crc: None,
            content_sha256: None,
            verification: crate::ir::MemberVerification::Pending,
            normalization_actions: Vec::new(),
        };
        member.mark_file_verified(body.len() as u64, 0, crate::policy::hex_sha256(body));
        member
    }

    fn verified_directory(name: &str, components: &[&str]) -> crate::ir::IrMember {
        let mut member = verified_file(name, components, b"");
        member.kind = crate::ir::MemberKind::Directory;
        member.mark_directory_verified();
        member
    }

    #[test]
    fn audit_accepts_a_stage_that_matches_the_admitted_ir() {
        let dest = temp_dest("audit-match");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        materializer
            .create_directory(&["empty".to_owned()], "empty/")
            .unwrap();
        let mut file = materializer
            .create_file(&["tree".to_owned(), "leaf.txt".to_owned()])
            .unwrap();
        file.write_all(b"leaf").unwrap();
        drop(file);

        let ir = crate::ir::ArchiveIR::new(
            crate::outcome::SourceDigest::available("test"),
            vec![
                verified_directory("empty/", &["empty"]),
                verified_file("tree/leaf.txt", &["tree", "leaf.txt"], b"leaf"),
            ],
        );
        materializer.audit_against(&ir).expect("matching stage");
        materializer.commit().unwrap();
        assert_eq!(fs::read(dest.join("tree/leaf.txt")).unwrap(), b"leaf");
        assert!(dest.join("empty").is_dir());
        fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn audit_rejects_mutated_staged_content() {
        let dest = temp_dest("audit-mutate");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let mut file = materializer.create_file(&["hello.txt".to_owned()]).unwrap();
        file.write_all(b"hello").unwrap();
        drop(file);
        fs::write(materializer.stage_path().join("hello.txt"), b"HELLO").unwrap();

        let ir = crate::ir::ArchiveIR::new(
            crate::outcome::SourceDigest::available("test"),
            vec![verified_file("hello.txt", &["hello.txt"], b"hello")],
        );
        let error = materializer.audit_against(&ir).unwrap_err();
        assert_eq!(error.code, FindingCode::MaterializeAudit);
        materializer.abort().unwrap();
        assert!(!dest.exists());
    }

    #[test]
    fn audit_rejects_a_missing_staged_file() {
        let dest = temp_dest("audit-missing");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let mut file = materializer.create_file(&["hello.txt".to_owned()]).unwrap();
        file.write_all(b"hello").unwrap();
        drop(file);
        fs::remove_file(materializer.stage_path().join("hello.txt")).unwrap();

        let ir = crate::ir::ArchiveIR::new(
            crate::outcome::SourceDigest::available("test"),
            vec![verified_file("hello.txt", &["hello.txt"], b"hello")],
        );
        let error = materializer.audit_against(&ir).unwrap_err();
        assert_eq!(error.code, FindingCode::MaterializeAudit);
        materializer.abort().unwrap();
        assert!(!dest.exists());
    }

    #[test]
    fn audit_rejects_a_directory_where_a_file_was_authorized() {
        let dest = temp_dest("audit-wrong-kind");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        materializer
            .create_directory(&["hello.txt".to_owned()], "hello.txt/")
            .unwrap();

        let ir = crate::ir::ArchiveIR::new(
            crate::outcome::SourceDigest::available("test"),
            vec![verified_file("hello.txt", &["hello.txt"], b"hello")],
        );
        let error = materializer.audit_against(&ir).unwrap_err();
        assert_eq!(error.code, FindingCode::MaterializeAudit);
        materializer.abort().unwrap();
        assert!(!dest.exists());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn audit_rejects_stage_root_permission_drift() {
        use std::os::unix::fs::PermissionsExt;

        let dest = temp_dest("audit-root-mode");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        fs::set_permissions(materializer.stage_path(), fs::Permissions::from_mode(0o755)).unwrap();
        let ir =
            crate::ir::ArchiveIR::new(crate::outcome::SourceDigest::available("test"), Vec::new());
        let error = materializer.audit_against(&ir).unwrap_err();
        assert_eq!(error.code, FindingCode::MaterializeAudit);
        fs::set_permissions(materializer.stage_path(), fs::Permissions::from_mode(0o700)).unwrap();
        materializer.abort().unwrap();
        assert!(!dest.exists());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn commit_rejects_stage_name_substitution_after_audit() {
        use std::os::unix::fs::PermissionsExt;

        let dest = temp_dest("commit-stage-substitution");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let ir =
            crate::ir::ArchiveIR::new(crate::outcome::SourceDigest::available("test"), Vec::new());
        materializer.audit_against(&ir).unwrap();
        let stage_path = materializer.stage_path();
        let moved_path = stage_path.with_extension("moved");
        fs::rename(&stage_path, &moved_path).unwrap();
        fs::create_dir(&stage_path).unwrap();
        fs::set_permissions(&stage_path, fs::Permissions::from_mode(0o700)).unwrap();

        let error = materializer.commit().unwrap_err();
        assert_eq!(error.code, FindingCode::MaterializeCommit);
        assert!(error.detail.contains("audited root"));
        let _ = materializer.abort();
        if stage_path.exists() {
            fs::remove_dir_all(&stage_path).unwrap();
        }
        if moved_path.exists() {
            fs::remove_dir_all(&moved_path).unwrap();
        }
        assert!(!dest.exists());
    }

    #[test]
    fn audit_rejects_an_extra_staged_file() {
        let dest = temp_dest("audit-extra");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let mut file = materializer.create_file(&["hello.txt".to_owned()]).unwrap();
        file.write_all(b"hello").unwrap();
        drop(file);
        fs::write(materializer.stage_path().join("extra.txt"), b"nope").unwrap();

        let ir = crate::ir::ArchiveIR::new(
            crate::outcome::SourceDigest::available("test"),
            vec![verified_file("hello.txt", &["hello.txt"], b"hello")],
        );
        let error = materializer.audit_against(&ir).unwrap_err();
        assert_eq!(error.code, FindingCode::MaterializeAudit);
        materializer.abort().unwrap();
        assert!(!dest.exists());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn audit_rejects_expected_paths_that_share_a_hardlinked_inode() {
        let dest = temp_dest("audit-hardlink");
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let mut file = materializer.create_file(&["hello.txt".to_owned()]).unwrap();
        file.write_all(b"hello").unwrap();
        drop(file);
        fs::hard_link(
            materializer.stage_path().join("hello.txt"),
            materializer.stage_path().join("copy.txt"),
        )
        .unwrap();

        let ir = crate::ir::ArchiveIR::new(
            crate::outcome::SourceDigest::available("test"),
            vec![
                verified_file("hello.txt", &["hello.txt"], b"hello"),
                verified_file("copy.txt", &["copy.txt"], b"hello"),
            ],
        );
        let error = materializer.audit_against(&ir).unwrap_err();
        assert_eq!(error.code, FindingCode::MaterializeAudit);
        assert!(error.detail.contains("link count 1"));
        materializer.abort().unwrap();
        assert!(!dest.exists());
    }

    #[test]
    fn audit_rejects_a_staged_reparse_point() {
        let dest = temp_dest("audit-reparse");
        let outside = temp_dest("audit-reparse-outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel.txt"), b"outside").unwrap();
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let mut file = materializer.create_file(&["hello.txt".to_owned()]).unwrap();
        file.write_all(b"hello").unwrap();
        drop(file);
        let planted = materializer.stage_path().join("link");
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        std::os::unix::fs::symlink(&outside, &planted).unwrap();
        #[cfg(windows)]
        {
            let output = std::process::Command::new("cmd")
                .args(["/d", "/c", "mklink", "/J"])
                .arg(&planted)
                .arg(&outside)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "create audit junction: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let ir = crate::ir::ArchiveIR::new(
            crate::outcome::SourceDigest::available("test"),
            vec![verified_file("hello.txt", &["hello.txt"], b"hello")],
        );
        let error = materializer.audit_against(&ir).unwrap_err();
        assert_eq!(error.code, FindingCode::MaterializeAudit);
        assert_eq!(fs::read(outside.join("sentinel.txt")).unwrap(), b"outside");
        materializer.abort().unwrap();
        fs::remove_dir_all(outside).unwrap();
        assert!(!dest.exists());
    }

    #[test]
    fn refuses_an_intra_call_directory_component_replacement() {
        let dest = temp_dest("intra-call");
        let outside = temp_dest("intra-call-outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel.txt"), b"outside").unwrap();
        let mut materializer = CapabilityMaterializer::create(&dest, false).unwrap();
        let _guard = inject_directory_component_replacement("tree", outside.clone());
        let error = materializer
            .create_file(&["tree".to_owned(), "leaf.txt".to_owned()])
            .unwrap_err();
        assert_eq!(error.code, FindingCode::MaterializeUnsafeComponent);
        assert!(!outside.join("leaf.txt").exists());
        assert_eq!(fs::read(outside.join("sentinel.txt")).unwrap(), b"outside");
        materializer.abort().unwrap();
        fs::remove_dir_all(outside).unwrap();
    }
}
