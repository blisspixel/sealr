use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use crate::apply::process_member;
use crate::ir::{ArchiveIR, IrMember, MemberKind, MemberVerification};
use crate::outcome::SourceDigest;
use crate::policy::ResourceBudget;
use crate::snapshot::SourceSnapshot;
use crate::zip;

/// Stable category for a bounded verified-member read failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemberReadErrorKind {
    NotFound,
    NotFile,
    LimitExceeded,
    PlatformLimit,
    AllocationFailed,
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
    pub(crate) fn new(snapshot: SourceSnapshot<'_>, ir: ArchiveIR, budget: ResourceBudget) -> Self {
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

    /// Return a fully revalidated member after enforcing the caller's byte cap.
    ///
    /// The limit is checked against the previously measured size before memory
    /// is reserved. The read then uses the recorded payload range and verifies
    /// size, CRC32, and SHA-256 again before any bytes reach the caller.
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
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(capacity).map_err(|error| {
            MemberReadError::new(
                MemberReadErrorKind::AllocationFailed,
                canonical_path,
                format!("could not reserve {expected_size} bytes: {error}"),
            )
        })?;

        let zip_member = member.as_zip_member();
        let payload = zip::payload(&self.inner.snapshot, &zip_member)
            .map_err(|finding| integrity_error(canonical_path, &finding))?;
        let (actual, crc, sha256) = process_member(
            payload,
            &zip_member,
            self.inner.budget,
            expected_size,
            &mut bytes,
        )
        .map_err(|finding| integrity_error(canonical_path, &finding))?;

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
            .finish_non_exhaustive()
    }
}

fn integrity_error(path: &str, finding: &crate::Finding) -> MemberReadError {
    MemberReadError::new(
        MemberReadErrorKind::IntegrityMismatch,
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
    use crate::{apply, Policy, Request, Source};

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
