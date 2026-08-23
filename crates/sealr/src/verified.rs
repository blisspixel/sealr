use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::BufReader;
use std::sync::Arc;

use crate::apply::process_member;
use crate::ir::{ArchiveIR, IrMember, MemberKind, MemberVerification};
use crate::jail::jail_name;
use crate::outcome::SourceDigest;
use crate::policy::ResourceBudget;
use crate::quota::QuotaState;
use crate::snapshot::SourceSnapshot;
use crate::zip;

/// Maximum number of distinct exact paths accepted by one retention plan.
pub const MAX_RETENTION_PATHS: usize = 64;
/// Maximum UTF-8 byte length of one retention path.
pub const MAX_RETENTION_PATH_BYTES: usize = 4_096;
/// Maximum aggregate UTF-8 byte length of all retention paths.
pub const MAX_RETENTION_TOTAL_PATH_BYTES: usize = 16_384;

/// Stable category for retention-plan construction failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetentionPlanErrorKind {
    TooManyPaths,
    PathTooLong,
    TotalPathBytesExceeded,
    NonCanonicalPath,
}

/// Failure returned while constructing a bounded retention plan.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetentionPlanError {
    kind: RetentionPlanErrorKind,
    path: String,
    detail: String,
}

impl RetentionPlanError {
    fn new(
        kind: RetentionPlanErrorKind,
        path: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            path: path.into(),
            detail: detail.into(),
        }
    }

    pub fn kind(&self) -> RetentionPlanErrorKind {
        self.kind
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for RetentionPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path, self.detail)
    }
}

impl std::error::Error for RetentionPlanError {}

/// Validated request to retain selected verified member bytes during the
/// original verification pass.
///
/// Paths are exact canonical archive paths. The two byte limits are separate
/// from archive-admission quotas and bound only the optional retained-byte
/// capability. Zero is a valid fail-closed limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionPlan {
    paths: BTreeSet<String>,
    path_bytes: usize,
    max_member_bytes: u64,
    max_total_bytes: u64,
}

impl RetentionPlan {
    /// Create an empty plan with caller-selected content ceilings.
    pub fn new(max_member_bytes: u64, max_total_bytes: u64) -> Self {
        Self {
            paths: BTreeSet::new(),
            path_bytes: 0,
            max_member_bytes,
            max_total_bytes,
        }
    }

    /// Validate and add one exact canonical path.
    ///
    /// Adding the same path again is idempotent.
    pub fn add_path(&mut self, path: impl Into<String>) -> Result<(), RetentionPlanError> {
        let path = path.into();
        if self.paths.contains(&path) {
            return Ok(());
        }
        if self.paths.len() >= MAX_RETENTION_PATHS {
            return Err(RetentionPlanError::new(
                RetentionPlanErrorKind::TooManyPaths,
                path,
                format!("retention plan supports at most {MAX_RETENTION_PATHS} paths"),
            ));
        }
        if path.len() > MAX_RETENTION_PATH_BYTES {
            return Err(RetentionPlanError::new(
                RetentionPlanErrorKind::PathTooLong,
                path,
                format!("retention path exceeds {MAX_RETENTION_PATH_BYTES} bytes"),
            ));
        }
        let next_path_bytes = self.path_bytes.checked_add(path.len()).ok_or_else(|| {
            RetentionPlanError::new(
                RetentionPlanErrorKind::TotalPathBytesExceeded,
                path.clone(),
                "retention path-byte counter overflowed",
            )
        })?;
        if next_path_bytes > MAX_RETENTION_TOTAL_PATH_BYTES {
            return Err(RetentionPlanError::new(
                RetentionPlanErrorKind::TotalPathBytesExceeded,
                path,
                format!("retention paths exceed {MAX_RETENTION_TOTAL_PATH_BYTES} total bytes"),
            ));
        }
        let jailed = jail_name(&path, u32::MAX).map_err(|finding| {
            RetentionPlanError::new(
                RetentionPlanErrorKind::NonCanonicalPath,
                path.clone(),
                format!("{}: {}", finding.code.as_str(), finding.detail),
            )
        })?;
        if !jailed.actions.is_empty() || jailed.components.join("/") != path {
            return Err(RetentionPlanError::new(
                RetentionPlanErrorKind::NonCanonicalPath,
                path,
                "retention path must already be in canonical form",
            ));
        }

        self.path_bytes = next_path_bytes;
        self.paths.insert(path);
        Ok(())
    }

    /// Validate and add one exact canonical path using builder style.
    pub fn with_path(mut self, path: impl Into<String>) -> Result<Self, RetentionPlanError> {
        self.add_path(path)?;
        Ok(self)
    }

    /// Iterate over requested paths in deterministic canonical-path order.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.paths.iter().map(String::as_str)
    }

    /// Maximum bytes that may be retained for one selected member.
    pub fn max_member_bytes(&self) -> u64 {
        self.max_member_bytes
    }

    /// Maximum aggregate bytes that may be retained across selected members.
    pub fn max_total_bytes(&self) -> u64 {
        self.max_total_bytes
    }
}

/// Result of one exact-path retention request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetentionStatus {
    NotRequested,
    Retained,
    NotFound,
    NotFile,
    MemberLimitExceeded,
    TotalLimitExceeded,
    PlatformLimit,
    AllocationFailed,
    IntegrityMismatch,
}

enum RetentionEntry {
    Selected { expected_size: u64 },
    Retained(Vec<u8>),
    NotFound,
    NotFile,
    MemberLimitExceeded,
    TotalLimitExceeded,
    PlatformLimit,
    AllocationFailed,
    IntegrityMismatch,
}

impl RetentionEntry {
    fn status(&self) -> RetentionStatus {
        match self {
            Self::Selected { .. } => RetentionStatus::IntegrityMismatch,
            Self::Retained(_) => RetentionStatus::Retained,
            Self::NotFound => RetentionStatus::NotFound,
            Self::NotFile => RetentionStatus::NotFile,
            Self::MemberLimitExceeded => RetentionStatus::MemberLimitExceeded,
            Self::TotalLimitExceeded => RetentionStatus::TotalLimitExceeded,
            Self::PlatformLimit => RetentionStatus::PlatformLimit,
            Self::AllocationFailed => RetentionStatus::AllocationFailed,
            Self::IntegrityMismatch => RetentionStatus::IntegrityMismatch,
        }
    }
}

pub(crate) struct RetentionBuild {
    entries: BTreeMap<String, RetentionEntry>,
}

impl RetentionBuild {
    pub(crate) fn plan(plan: Option<&RetentionPlan>, ir: &ArchiveIR) -> Self {
        let Some(plan) = plan else {
            return Self {
                entries: BTreeMap::new(),
            };
        };

        let members: BTreeMap<&str, &IrMember> = ir
            .members()
            .iter()
            .map(|member| (member.canonical_path.as_str(), member))
            .collect();
        let mut total = QuotaState::new(plan.max_total_bytes);
        let mut entries = BTreeMap::new();
        for path in &plan.paths {
            let entry = match members.get(path.as_str()) {
                None => RetentionEntry::NotFound,
                Some(member) if matches!(member.kind, MemberKind::Directory) => {
                    RetentionEntry::NotFile
                }
                Some(member) if member.declared_uncomp_size > plan.max_member_bytes => {
                    RetentionEntry::MemberLimitExceeded
                }
                Some(member) => match total.consume(member.declared_uncomp_size) {
                    Ok(_) => RetentionEntry::Selected {
                        expected_size: member.declared_uncomp_size,
                    },
                    Err(_) => RetentionEntry::TotalLimitExceeded,
                },
            };
            entries.insert(path.clone(), entry);
        }
        Self { entries }
    }

    pub(crate) fn begin_capture(&mut self, path: &str) -> Option<Vec<u8>> {
        let expected_size = match self.entries.get(path) {
            Some(RetentionEntry::Selected { expected_size }) => *expected_size,
            _ => return None,
        };
        let capacity = match usize::try_from(expected_size) {
            Ok(capacity) => capacity,
            Err(_) => {
                self.entries
                    .insert(path.to_string(), RetentionEntry::PlatformLimit);
                return None;
            }
        };
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(capacity).is_err() {
            self.entries
                .insert(path.to_string(), RetentionEntry::AllocationFailed);
            return None;
        }
        Some(bytes)
    }

    pub(crate) fn finish_capture(&mut self, path: &str, bytes: Option<Vec<u8>>) {
        let Some(bytes) = bytes else {
            return;
        };
        let expected_size = match self.entries.get(path) {
            Some(RetentionEntry::Selected { expected_size }) => *expected_size,
            _ => return,
        };
        let entry = if bytes.len() as u64 == expected_size {
            RetentionEntry::Retained(bytes)
        } else {
            RetentionEntry::IntegrityMismatch
        };
        self.entries.insert(path.to_string(), entry);
    }
}

/// Stable category for a bounded verified-member read failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemberReadErrorKind {
    NotFound,
    NotFile,
    LimitExceeded,
    PlatformLimit,
    AllocationFailed,
    SourceIo,
    IntegrityMismatch,
}

/// Failure returned by [`VerifiedArchive::read_member`].
///
/// The fields are private so diagnostic wording can improve without becoming
/// part of the compatibility contract. Consumers should branch on [`Self::kind`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemberReadError {
    kind: MemberReadErrorKind,
    path: String,
    detail: String,
}

impl MemberReadError {
    fn new(kind: MemberReadErrorKind, path: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind,
            path: path.into(),
            detail: detail.into(),
        }
    }

    pub fn kind(&self) -> MemberReadErrorKind {
        self.kind
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for MemberReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path, self.detail)
    }
}

impl std::error::Error for MemberReadError {}

struct VerifiedArchiveInner {
    snapshot: SourceSnapshot<'static>,
    ir: ArchiveIR,
    budget: ResourceBudget,
    members_by_path: BTreeMap<String, usize>,
    retention: BTreeMap<String, RetentionEntry>,
}

/// Opaque authority for one fully verified admitted archive.
///
/// Sealr is the only constructor. The capability retains the exact source
/// snapshot and the verified interpretation, so member reads do not reopen a
/// path or invoke another archive parser. Cloning this value shares the same
/// immutable capability rather than copying the archive.
///
/// ```
/// use sealr::{apply, Policy, Request, Source};
///
/// const EMPTY_ZIP: &[u8] = &[
///     0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/// ];
/// let policy = Policy::default_v1();
/// let outcome = apply(Request {
///     source: Source::Bytes { path: None, data: EMPTY_ZIP },
///     policy: &policy,
///     dest: None,
/// });
/// let verified = outcome.verified_archive().expect("empty ZIP is verified");
/// assert!(verified.members().is_empty());
/// ```
#[derive(Clone)]
#[must_use = "a verified archive is the authority for bounded member reads"]
pub struct VerifiedArchive {
    inner: Arc<VerifiedArchiveInner>,
}

impl VerifiedArchive {
    pub(crate) fn new(
        snapshot: SourceSnapshot<'_>,
        ir: ArchiveIR,
        budget: ResourceBudget,
        retention: RetentionBuild,
    ) -> Self {
        debug_assert!(ir
            .members()
            .iter()
            .all(|member| matches!(&member.verification, MemberVerification::Verified)));
        debug_assert_eq!(snapshot.digest(), ir.source_digest());

        let mut members_by_path = BTreeMap::new();
        for (index, member) in ir.members().iter().enumerate() {
            let previous = members_by_path.insert(member.canonical_path.clone(), index);
            debug_assert!(previous.is_none());
        }

        Self {
            inner: Arc::new(VerifiedArchiveInner {
                snapshot: snapshot.into_owned(),
                ir,
                budget,
                members_by_path,
                retention: retention.entries,
            }),
        }
    }

    pub fn archive_ir(&self) -> &ArchiveIR {
        &self.inner.ir
    }

    pub fn source_digest(&self) -> &SourceDigest {
        self.inner.ir.source_digest()
    }

    pub fn members(&self) -> &[IrMember] {
        self.inner.ir.members()
    }

    pub fn member(&self, canonical_path: &str) -> Option<&IrMember> {
        self.inner
            .members_by_path
            .get(canonical_path)
            .map(|index| &self.inner.ir.members()[*index])
    }

    /// Report whether an exact canonical path was requested and retained.
    pub fn retention_status(&self, canonical_path: &str) -> RetentionStatus {
        self.inner
            .retention
            .get(canonical_path)
            .map(RetentionEntry::status)
            .unwrap_or(RetentionStatus::NotRequested)
    }

    /// Borrow bytes captured during the original verification pass.
    ///
    /// `None` is returned when the path was not requested or its status is not
    /// [`RetentionStatus::Retained`]. Call [`Self::retention_status`] to
    /// distinguish those cases. This method does not reopen, parse, inflate,
    /// allocate, or hash.
    pub fn retained_member(&self, canonical_path: &str) -> Option<&[u8]> {
        match self.inner.retention.get(canonical_path) {
            Some(RetentionEntry::Retained(bytes)) => Some(bytes),
            _ => None,
        }
    }

    /// Total logical bytes retained for the requested exact paths.
    pub fn retained_bytes(&self) -> u64 {
        self.inner
            .retention
            .values()
            .filter_map(|entry| match entry {
                RetentionEntry::Retained(bytes) => Some(bytes.len() as u64),
                _ => None,
            })
            .sum()
    }

    /// Return verified member bytes after enforcing the caller's byte cap.
    ///
    /// The limit is checked against the previously measured size before memory
    /// is reserved. A member retained during the original verification pass is
    /// cloned after its retained size is checked. Otherwise, the read uses the
    /// recorded payload range and verifies size, CRC32, and SHA-256 again before
    /// any bytes reach the caller.
    pub fn read_member(
        &self,
        canonical_path: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, MemberReadError> {
        let member = self.member(canonical_path).ok_or_else(|| {
            MemberReadError::new(
                MemberReadErrorKind::NotFound,
                canonical_path,
                "verified member was not found",
            )
        })?;
        if matches!(member.kind, MemberKind::Directory) {
            return Err(MemberReadError::new(
                MemberReadErrorKind::NotFile,
                canonical_path,
                "verified member is a directory",
            ));
        }
        if !matches!(&member.verification, MemberVerification::Verified) {
            return Err(MemberReadError::new(
                MemberReadErrorKind::IntegrityMismatch,
                canonical_path,
                "capability contains a member that is not fully verified",
            ));
        }

        let expected_size = member.actual_uncomp_size.ok_or_else(|| {
            MemberReadError::new(
                MemberReadErrorKind::IntegrityMismatch,
                canonical_path,
                "verified member is missing its measured size",
            )
        })?;
        if expected_size > max_bytes {
            return Err(MemberReadError::new(
                MemberReadErrorKind::LimitExceeded,
                canonical_path,
                format!("verified size {expected_size} exceeds caller limit {max_bytes}"),
            ));
        }
        let capacity = usize::try_from(expected_size).map_err(|_| {
            MemberReadError::new(
                MemberReadErrorKind::PlatformLimit,
                canonical_path,
                format!("verified size {expected_size} does not fit this platform"),
            )
        })?;
        if let Some(retained) = self.retained_member(canonical_path) {
            if retained.len() as u64 != expected_size {
                return Err(MemberReadError::new(
                    MemberReadErrorKind::IntegrityMismatch,
                    canonical_path,
                    "retained member size disagrees with verified evidence",
                ));
            }
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(capacity).map_err(|error| {
                MemberReadError::new(
                    MemberReadErrorKind::AllocationFailed,
                    canonical_path,
                    format!("could not reserve {expected_size} bytes: {error}"),
                )
            })?;
            bytes.extend_from_slice(retained);
            return Ok(bytes);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(capacity).map_err(|error| {
            MemberReadError::new(
                MemberReadErrorKind::AllocationFailed,
                canonical_path,
                format!("could not reserve {expected_size} bytes: {error}"),
            )
        })?;

        let zip_member = member.as_zip_member();
        let payload = zip::payload_reader(&self.inner.snapshot, &zip_member)
            .map_err(|finding| member_read_error(canonical_path, &finding))?;
        let payload = BufReader::with_capacity(64 * 1024, payload);
        let (actual, crc, sha256) = process_member(
            payload,
            &zip_member,
            self.inner.budget,
            expected_size,
            &mut bytes,
        )
        .map_err(|finding| member_read_error(canonical_path, &finding))?;

        if actual != expected_size
            || Some(crc) != member.actual_crc
            || member.content_sha256.as_deref() != Some(sha256.as_str())
        {
            return Err(MemberReadError::new(
                MemberReadErrorKind::IntegrityMismatch,
                canonical_path,
                "member bytes disagree with the recorded verified evidence",
            ));
        }
        Ok(bytes)
    }
}

impl fmt::Debug for VerifiedArchive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedArchive")
            .field("source_digest", &self.source_digest())
            .field("member_count", &self.members().len())
            .field("retained_bytes", &self.retained_bytes())
            .finish_non_exhaustive()
    }
}

fn member_read_error(path: &str, finding: &crate::Finding) -> MemberReadError {
    let kind = if finding.code == crate::FindingCode::SourceIo {
        MemberReadErrorKind::SourceIo
    } else {
        MemberReadErrorKind::IntegrityMismatch
    };
    MemberReadError::new(
        kind,
        path,
        format!("{}: {}", finding.code.as_str(), finding.detail),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Cursor, Write};
    use std::path::PathBuf;

    use ::zip::write::SimpleFileOptions;
    use ::zip::{CompressionMethod, ZipWriter};

    use super::*;
    use crate::apply::{process_member_calls, reset_process_member_calls};
    use crate::{
        apply, apply_with_options, ApplyOptions, Finding, FindingCode, Policy, Request, Source,
    };

    #[test]
    fn verified_read_distinguishes_source_io_from_integrity_disagreement() {
        let source = Finding::error(FindingCode::SourceIo, "snapshot unavailable");
        let integrity = Finding::error(FindingCode::CrcMismatch, "content changed");

        assert_eq!(
            member_read_error("member.bin", &source).kind(),
            MemberReadErrorKind::SourceIo
        );
        assert_eq!(
            member_read_error("member.bin", &integrity).kind(),
            MemberReadErrorKind::IntegrityMismatch
        );
    }

    fn make_zip() -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            writer.start_file("metadata.txt", options).unwrap();
            writer.write_all(b"verified metadata").unwrap();
            writer.add_directory("empty/", options).unwrap();
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn make_single_file_zip(data: &[u8], method: CompressionMethod) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let options = SimpleFileOptions::default().compression_method(method);
            writer.start_file("member.bin", options).unwrap();
            writer.write_all(data).unwrap();
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn make_two_file_zip() -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            writer.start_file("z.txt", options).unwrap();
            writer.write_all(b"zulu!").unwrap();
            writer.start_file("a.txt", options).unwrap();
            writer.write_all(b"alpha").unwrap();
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn make_three_file_zip(a_size: u8, b_size: u8, c_size: u8) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            for (path, size, byte) in [
                ("c.bin", c_size, b'c'),
                ("a.bin", a_size, b'a'),
                ("b.bin", b_size, b'b'),
            ] {
                writer.start_file(path, options).unwrap();
                writer.write_all(&vec![byte; usize::from(size)]).unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn temp_path(label: &str) -> PathBuf {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        std::env::temp_dir().join(format!("sealr-{label}-{suffix}.zip"))
    }

    fn admitted(bytes: &[u8]) -> crate::Outcome {
        apply(Request {
            source: Source::Bytes {
                path: Some("fixture.zip"),
                data: bytes,
            },
            policy: &Policy::default_v1(),
            dest: None,
        })
    }

    fn admitted_with_retention(bytes: &[u8], plan: RetentionPlan) -> crate::Outcome {
        let policy = Policy::default_v1();
        let options = ApplyOptions::new().with_retention(plan);
        apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("fixture.zip"),
                    data: bytes,
                },
                policy: &policy,
                dest: None,
            },
            &options,
        )
    }

    #[test]
    fn retention_plan_requires_bounded_canonical_exact_paths() {
        let mut plan = RetentionPlan::new(32, 64);
        plan.add_path("metadata.txt").unwrap();
        plan.add_path("metadata.txt").unwrap();
        assert_eq!(plan.paths().collect::<Vec<_>>(), ["metadata.txt"]);

        let error = plan.add_path("./metadata.txt").unwrap_err();
        assert_eq!(error.kind(), RetentionPlanErrorKind::NonCanonicalPath);
        assert_eq!(error.path(), "./metadata.txt");

        let error = RetentionPlan::new(1, 1)
            .with_path("x".repeat(MAX_RETENTION_PATH_BYTES + 1))
            .unwrap_err();
        assert_eq!(error.kind(), RetentionPlanErrorKind::PathTooLong);

        let mut too_many = RetentionPlan::new(1, 1);
        for index in 0..MAX_RETENTION_PATHS {
            too_many.add_path(format!("path-{index}")).unwrap();
        }
        assert_eq!(
            too_many.add_path("one-too-many").unwrap_err().kind(),
            RetentionPlanErrorKind::TooManyPaths
        );

        let mut too_many_path_bytes = RetentionPlan::new(1, 1);
        for suffix in ['a', 'b', 'c', 'd'] {
            let mut path = "x".repeat(MAX_RETENTION_PATH_BYTES - 1);
            path.push(suffix);
            too_many_path_bytes.add_path(path).unwrap();
        }
        assert_eq!(
            too_many_path_bytes.add_path("overflow").unwrap_err().kind(),
            RetentionPlanErrorKind::TotalPathBytesExceeded
        );
    }

    #[test]
    fn retention_reports_missing_directory_and_member_limit_without_rejecting() {
        let bytes = make_zip();
        let plan = RetentionPlan::new(16, 64)
            .with_path("metadata.txt")
            .unwrap()
            .with_path("empty")
            .unwrap()
            .with_path("missing.txt")
            .unwrap();
        let outcome = admitted_with_retention(&bytes, plan);
        assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
        let archive = outcome.verified_archive().unwrap();

        assert_eq!(
            archive.retention_status("metadata.txt"),
            RetentionStatus::MemberLimitExceeded
        );
        assert_eq!(archive.retention_status("empty"), RetentionStatus::NotFile);
        assert_eq!(
            archive.retention_status("missing.txt"),
            RetentionStatus::NotFound
        );
        assert_eq!(
            archive.retention_status("not-requested.txt"),
            RetentionStatus::NotRequested
        );
        assert_eq!(archive.retained_bytes(), 0);
    }

    #[test]
    fn total_retention_selection_is_canonical_path_order_not_archive_order() {
        let bytes = make_two_file_zip();
        let plan = RetentionPlan::new(5, 5)
            .with_path("z.txt")
            .unwrap()
            .with_path("a.txt")
            .unwrap();
        let outcome = admitted_with_retention(&bytes, plan);
        let archive = outcome.verified_archive().unwrap();

        assert_eq!(archive.retained_member("a.txt"), Some(b"alpha".as_slice()));
        assert_eq!(
            archive.retention_status("z.txt"),
            RetentionStatus::TotalLimitExceeded
        );
        assert_eq!(archive.retained_bytes(), 5);
    }

    #[test]
    fn retention_selection_matches_independent_small_domain_oracle() {
        let mut checked_plans = 0_u64;
        for a_size in 0_u8..=4 {
            for b_size in 0_u8..=4 {
                for c_size in 0_u8..=4 {
                    let bytes = make_three_file_zip(a_size, b_size, c_size);
                    let outcome = admitted(&bytes);
                    let ir = outcome.archive_ir().expect("generated ZIP interpreted");

                    for member_limit in 0_u64..=4 {
                        for total_limit in 0_u64..=12 {
                            let plan = RetentionPlan::new(member_limit, total_limit)
                                .with_path("c.bin")
                                .unwrap()
                                .with_path("a.bin")
                                .unwrap()
                                .with_path("b.bin")
                                .unwrap();
                            let build = RetentionBuild::plan(Some(&plan), ir);
                            let mut used = 0_u64;
                            for (path, size) in [
                                ("a.bin", u64::from(a_size)),
                                ("b.bin", u64::from(b_size)),
                                ("c.bin", u64::from(c_size)),
                            ] {
                                let expected = if size > member_limit {
                                    RetentionStatus::MemberLimitExceeded
                                } else if used + size > total_limit {
                                    RetentionStatus::TotalLimitExceeded
                                } else {
                                    used += size;
                                    RetentionStatus::Retained
                                };
                                let actual = match build.entries.get(path).unwrap() {
                                    RetentionEntry::Selected { .. } => RetentionStatus::Retained,
                                    entry => entry.status(),
                                };
                                assert_eq!(
                                    actual, expected,
                                    "sizes=({a_size},{b_size},{c_size}), member={member_limit}, total={total_limit}, path={path}"
                                );
                            }
                            checked_plans += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(checked_plans, 8_125);
    }

    #[test]
    fn retention_capture_refuses_internal_size_disagreement() {
        let bytes = make_zip();
        let outcome = admitted(&bytes);
        let plan = RetentionPlan::new(17, 17)
            .with_path("metadata.txt")
            .unwrap();
        let mut build = RetentionBuild::plan(Some(&plan), outcome.archive_ir().unwrap());

        build.finish_capture("metadata.txt", Some(vec![0; 16]));
        assert!(matches!(
            build.entries.get("metadata.txt"),
            Some(RetentionEntry::IntegrityMismatch)
        ));
    }

    #[test]
    fn retained_reads_do_not_repeat_member_processing() {
        let bytes = make_two_file_zip();
        let plan = RetentionPlan::new(5, 5).with_path("a.txt").unwrap();
        reset_process_member_calls();
        let outcome = admitted_with_retention(&bytes, plan);
        assert_eq!(process_member_calls(), 2);
        let archive = outcome.verified_archive().unwrap();

        assert_eq!(archive.retained_member("a.txt"), Some(b"alpha".as_slice()));
        assert_eq!(archive.read_member("a.txt", 5).unwrap(), b"alpha");
        assert_eq!(archive.read_member("a.txt", 5).unwrap(), b"alpha");
        assert_eq!(process_member_calls(), 2);

        assert_eq!(archive.read_member("z.txt", 5).unwrap(), b"zulu!");
        assert_eq!(process_member_calls(), 3);
        assert_eq!(
            archive.read_member("a.txt", 4).unwrap_err().kind(),
            MemberReadErrorKind::LimitExceeded
        );
        assert_eq!(process_member_calls(), 3);
    }

    #[test]
    fn retention_does_not_change_admission_or_receipt_identity() {
        let bytes = make_zip();
        let baseline = admitted(&bytes);
        let plan = RetentionPlan::new(17, 17)
            .with_path("metadata.txt")
            .unwrap();
        let retained = admitted_with_retention(&bytes, plan);

        assert_eq!(
            serde_json::to_value(&baseline).unwrap(),
            serde_json::to_value(&retained).unwrap()
        );
        assert_eq!(
            retained
                .verified_archive()
                .unwrap()
                .retention_status("metadata.txt"),
            RetentionStatus::Retained
        );
    }

    #[test]
    fn materialization_and_retention_share_the_verification_pass() {
        let bytes = make_zip();
        let dest = temp_path("retained-materialization");
        let policy = Policy::default_v1();
        let plan = RetentionPlan::new(17, 17)
            .with_path("metadata.txt")
            .unwrap();
        let options = ApplyOptions::new().with_retention(plan);
        reset_process_member_calls();
        let outcome = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("fixture.zip"),
                    data: &bytes,
                },
                policy: &policy,
                dest: Some(&dest),
            },
            &options,
        );

        assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
        assert!(outcome.wrote());
        assert_eq!(process_member_calls(), 1);
        assert_eq!(
            fs::read(dest.join("metadata.txt")).unwrap(),
            b"verified metadata"
        );
        assert_eq!(
            outcome
                .verified_archive()
                .unwrap()
                .retained_member("metadata.txt"),
            Some(b"verified metadata".as_slice())
        );
        fs::remove_dir_all(dest).unwrap();
    }

    #[test]
    fn bounded_read_returns_revalidated_bytes() {
        let bytes = make_zip();
        let outcome = admitted(&bytes);
        let archive = outcome.verified_archive().expect("fully verified archive");

        assert_eq!(archive.members().len(), 2);
        assert_eq!(
            archive.read_member("metadata.txt", 17).unwrap(),
            b"verified metadata"
        );
        assert_eq!(
            archive.member("metadata.txt").unwrap().actual_uncomp_size,
            Some(17)
        );
        assert_eq!(
            archive.source_digest(),
            outcome.archive_ir().unwrap().source_digest()
        );
    }

    #[test]
    fn read_limit_is_enforced_before_returning_bytes() {
        let bytes = make_zip();
        let outcome = admitted(&bytes);
        let archive = outcome.verified_archive().unwrap();

        let error = archive.read_member("metadata.txt", 16).unwrap_err();
        assert_eq!(error.kind(), MemberReadErrorKind::LimitExceeded);
        assert_eq!(error.path(), "metadata.txt");
        assert!(error.detail().contains("17"));
    }

    #[test]
    fn absent_and_directory_members_are_distinct() {
        let bytes = make_zip();
        let outcome = admitted(&bytes);
        let archive = outcome.verified_archive().unwrap();

        assert_eq!(
            archive.read_member("missing.txt", 64).unwrap_err().kind(),
            MemberReadErrorKind::NotFound
        );
        assert_eq!(
            archive.read_member("empty", 64).unwrap_err().kind(),
            MemberReadErrorKind::NotFile
        );
    }

    #[test]
    fn borrowed_input_is_retained_after_the_caller_changes_it() {
        let mut bytes = make_zip();
        let outcome = admitted(&bytes);
        bytes.fill(0);

        assert_eq!(
            outcome
                .verified_archive()
                .unwrap()
                .read_member("metadata.txt", 17)
                .unwrap(),
            b"verified metadata"
        );
    }

    #[test]
    fn path_input_is_not_reopened_by_member_reads() {
        let bytes = make_zip();
        let path = temp_path("verified-path-retention");
        fs::write(&path, &bytes).unwrap();
        let policy = Policy::default_v1();
        let outcome = apply(Request {
            source: Source::Path(&path),
            policy: &policy,
            dest: None,
        });
        fs::remove_file(&path).unwrap();

        assert_eq!(
            outcome
                .verified_archive()
                .unwrap()
                .read_member("metadata.txt", 17)
                .unwrap(),
            b"verified metadata"
        );
    }

    #[test]
    fn verified_member_limit_matches_independent_small_domain_oracle() {
        for method in [CompressionMethod::Stored, CompressionMethod::Deflated] {
            for size in 0_u8..=64 {
                let data: Vec<u8> = (0..size).map(|value| value.wrapping_mul(37)).collect();
                let bytes = make_single_file_zip(&data, method);
                let outcome = admitted(&bytes);
                let archive = outcome.verified_archive().expect("generated ZIP admitted");

                for limit in 0_u64..=64 {
                    let result = archive.read_member("member.bin", limit);
                    if limit < u64::from(size) {
                        assert_eq!(
                            result.unwrap_err().kind(),
                            MemberReadErrorKind::LimitExceeded,
                            "method {method:?}, size {size}, limit {limit}"
                        );
                    } else {
                        assert_eq!(
                            result.unwrap(),
                            data,
                            "method {method:?}, size {size}, limit {limit}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn capability_clone_shares_the_same_authority() {
        let bytes = make_zip();
        let outcome = admitted(&bytes);
        let first = outcome.verified_archive().unwrap().clone();
        let second = first.clone();

        assert!(Arc::ptr_eq(&first.inner, &second.inner));
    }
}
