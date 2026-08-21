use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir as CapDir, File as CapFile, OpenOptions as CapOpenOptions};
use serde::Serialize;

#[cfg(test)]
use std::cell::Cell;

use crate::findings::{Finding, FindingCode};

#[cfg(target_vendor = "apple")]
mod apple;
#[cfg(windows)]
mod windows;

const SCHEMA: &str = "sealr.materialization.v1";
const BACKEND: &str = "cap-std-component-nofollow-v1";
const MEMBER_RESOLUTION: &str = "component-handles-nofollow";
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[cfg(test)]
std::thread_local! {
    static INJECTED_CLEANUP_FAILURES: Cell<u32> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) struct CleanupFailureGuard {
    previous: u32,
}

#[cfg(test)]
impl Drop for CleanupFailureGuard {
    fn drop(&mut self) {
        INJECTED_CLEANUP_FAILURES.with(|remaining| remaining.set(self.previous));
    }
}

#[cfg(test)]
pub(crate) fn inject_cleanup_failures_for_current_thread(count: u32) -> CleanupFailureGuard {
    let previous = INJECTED_CLEANUP_FAILURES.with(|remaining| remaining.replace(count));
    CleanupFailureGuard { previous }
}

#[cfg(test)]
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

#[cfg(not(test))]
fn injected_cleanup_failure() -> Option<io::Error> {
    None
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
            }
        }
    }

    pub(crate) fn setup_failed(atomic: bool, cleanup: &'static str) -> Self {
        let mut report = Self::not_started(true, atomic);
        report.outcome = "setup-failed";
        report.cleanup = cleanup;
        report
    }
}

#[derive(Debug)]
pub(crate) struct MaterializationSetupError {
    findings: Vec<Finding>,
    cleanup: &'static str,
}

impl MaterializationSetupError {
    pub(crate) fn into_parts(self) -> (Vec<Finding>, &'static str) {
        (self.findings, self.cleanup)
    }

    fn after_stage(parent: &CapDir, stage_name: &Path, finding: Finding) -> Self {
        let mut findings = vec![finding];
        let cleanup = match parent.remove_dir_all(stage_name) {
            Ok(()) => "removed",
            Err(error) => {
                findings.push(Finding::error(
                    FindingCode::MaterializeCleanup,
                    format!("remove staging tree after setup failure: {error}"),
                ));
                "failed"
            }
        };
        Self { findings, cleanup }
    }
}

impl From<Finding> for MaterializationSetupError {
    fn from(finding: Finding) -> Self {
        Self {
            findings: vec![finding],
            cleanup: "not-created",
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
}

#[derive(Debug)]
struct StageCreateError {
    error: io::Error,
    created: bool,
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
        ensure_parent_namespace_safe(&parent)?;
        let final_name = PathBuf::from(file_name);
        if capability_path_exists(&parent, &final_name)? {
            return Err(Finding::error(
                FindingCode::MaterializeExists,
                "destination already exists; replacement is not implemented",
            )
            .into());
        }

        for _ in 0..128 {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(|error| {
                Finding::error(
                    FindingCode::MaterializeIo,
                    format!("generate staging name: {error}"),
                )
            })?;
            let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let stage_name = PathBuf::from(format!(".sealr-stage-{suffix}"));
            match create_stage(&parent, &stage_name) {
                Ok(root) => {
                    if let Err(finding) = ensure_stage_namespace_safe(&root) {
                        drop(root);
                        return Err(MaterializationSetupError::after_stage(
                            &parent,
                            &stage_name,
                            finding,
                        ));
                    }
                    if let Err(error) = ensure_directory_handle_is_not_reparse(&root) {
                        drop(root);
                        return Err(MaterializationSetupError::after_stage(
                            &parent,
                            &stage_name,
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
                    });
                }
                Err(error)
                    if !error.created && error.error.kind() == io::ErrorKind::AlreadyExists =>
                {
                    continue;
                }
                Err(error) if error.created => {
                    return Err(MaterializationSetupError::after_stage(
                        &parent,
                        &stage_name,
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
                    return Err(Finding::error(
                        FindingCode::MaterializeIo,
                        format!(
                            "create staging directory through capability: {}",
                            error.error
                        ),
                    )
                    .into());
                }
            }
        }
        Err(Finding::error(
            FindingCode::MaterializeIo,
            "could not allocate a unique staging directory",
        )
        .into())
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

    pub(crate) fn commit(&mut self) -> Result<(), Finding> {
        let root = self.root.as_ref().ok_or_else(|| {
            Finding::error(
                FindingCode::MaterializeCommit,
                "staging capability is unavailable during publication",
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

    fn open_or_create_directories(&self, parts: &[String]) -> Result<CapDir, Finding> {
        let mut current = self.root()?.try_clone().map_err(|error| {
            Finding::error(
                FindingCode::MaterializeIo,
                format!("clone staging capability: {error}"),
            )
        })?;
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

    #[cfg(test)]
    fn stage_path(&self) -> PathBuf {
        self.parent_path.join(&self.stage_name)
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

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn stage_mode() -> &'static str {
    "same-volume-random-128-mode-0700"
}

#[cfg(windows)]
fn stage_mode() -> &'static str {
    "same-volume-random-128-inherited-acl"
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
fn stage_mode() -> &'static str {
    "unsupported"
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn stage_creation_primitive() -> &'static str {
    "mkdirat-mode-0700-openat-nofollow-safe-parent"
}

#[cfg(windows)]
fn stage_creation_primitive() -> &'static str {
    windows::STAGE_CREATION_PRIMITIVE
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
fn stage_creation_primitive() -> &'static str {
    "unsupported"
}

#[cfg(target_os = "linux")]
fn publication_primitive() -> &'static str {
    "renameat2-noreplace"
}

#[cfg(target_vendor = "apple")]
fn publication_primitive() -> &'static str {
    "renameatx-np-excl"
}

#[cfg(windows)]
fn publication_primitive() -> &'static str {
    windows::PUBLICATION_PRIMITIVE
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
fn publication_primitive() -> &'static str {
    "unsupported"
}

#[cfg(any(target_os = "linux", target_vendor = "apple", windows))]
fn ensure_platform_supported() -> Result<(), Finding> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
fn ensure_platform_supported() -> Result<(), Finding> {
    Err(Finding::error(
        FindingCode::MaterializeUnsupported,
        "atomic no-replace materialization is unsupported on this platform",
    ))
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
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

#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
fn create_stage(_parent: &CapDir, _name: &Path) -> Result<CapDir, StageCreateError> {
    Err(StageCreateError {
        error: io::Error::new(
            io::ErrorKind::Unsupported,
            "secure stage creation is unsupported",
        ),
        created: false,
    })
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
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

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn unix_parent_mode_is_safe(owner: u32, effective_uid: u32, mode: u32) -> bool {
    let trusted_owner = owner == effective_uid || owner == 0;
    let externally_writable = mode & 0o022 != 0;
    let sticky = mode & 0o1000 != 0;
    trusted_owner && (!externally_writable || sticky)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn ensure_parent_namespace_safe(_parent: &CapDir) -> Result<(), Finding> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
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

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn ensure_stage_namespace_safe(_root: &CapDir) -> Result<(), Finding> {
    Ok(())
}

#[cfg(target_vendor = "apple")]
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

#[cfg(all(unix, not(target_vendor = "apple")))]
fn ensure_no_apple_extended_acl(_dir: &CapDir, _label: &str) -> Result<(), Finding> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
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

#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
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
fn ensure_file_handle_is_not_reparse(_file: &CapFile) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn ensure_file_handle_is_not_reparse(file: &CapFile) -> io::Result<()> {
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
        let (findings, cleanup) = error.into_parts();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::MaterializeIo);
        assert_eq!(cleanup, "not-created");
        assert!(!parent.exists());
    }

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
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

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
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
            let (findings, cleanup) = error.into_parts();

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

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
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

    #[cfg(target_vendor = "apple")]
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
        let (findings, cleanup) = error.into_parts();
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
        assert_eq!(materializer.report().outcome, "committed");
        assert_eq!(materializer.report().cleanup, "not-applicable-after-commit");
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

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
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

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
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
}
