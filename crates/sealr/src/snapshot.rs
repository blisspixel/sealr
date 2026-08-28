use std::borrow::Cow;
use std::error::Error;
use std::fmt;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

#[cfg(any(target_os = "linux", feature = "__internal-worker-lab"))]
use std::io::{Seek, SeekFrom};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::OpenOptions as CapOpenOptions;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::findings::{Finding, FindingCode};
use crate::ir::ByteRange;
use crate::materialize::{ensure_file_handle_is_not_reparse, PrivateDirectory};
use crate::outcome::SourceDigest;
use crate::policy::hex_sha256;

const COPY_BUFFER_BYTES: usize = 64 * 1024;
const SPOOL_FILE_NAME: &str = "archive.snapshot";

#[derive(Debug, PartialEq, Eq)]
struct OpenedSourceState {
    len: u64,
    platform: PlatformSourceState,
}

#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
struct PlatformSourceState {
    device: u64,
    inode: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
struct PlatformSourceState {
    attributes: u32,
    creation_time: u64,
    last_write_time: u64,
}

#[cfg(not(any(unix, windows)))]
#[derive(Debug, PartialEq, Eq)]
struct PlatformSourceState {
    modified: Option<std::time::SystemTime>,
}

/// How this invocation holds the exact archive bytes.
///
/// Every available backend implements the same checked, read-only random-access
/// contract. Path inputs are copied once into a Sealr-owned private file. Byte
/// inputs stay in memory and are either caller-borrowed or process-owned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SnapshotKind {
    MemoryOwned,
    MemoryBorrowed,
    PrivateFile,
    Unavailable,
}

enum SnapshotBacking<'a> {
    Memory(Cow<'a, [u8]>),
    PrivateFile(PrivateFileSnapshot),
}

struct PrivateFileSnapshot {
    // Drop the reader before attempting to remove its private directory.
    file: Option<File>,
    directory: Option<PrivateDirectory>,
}

impl Drop for PrivateFileSnapshot {
    fn drop(&mut self) {
        drop(self.file.take());
        drop(self.directory.take());
    }
}

impl fmt::Debug for PrivateFileSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateFileSnapshot")
            .field("reader_available", &self.file.is_some())
            .finish_non_exhaustive()
    }
}

/// Immutable archive bytes for one `apply()` invocation.
///
/// The digest is SHA-256 of exactly the bytes in this object. Parsing,
/// verification, materialization, and later `VerifiedArchive` reads use this
/// object and never reopen the caller path.
pub struct SourceSnapshot<'a> {
    path: Option<String>,
    backing: SnapshotBacking<'a>,
    len: u64,
    digest: SourceDigest,
}

/// Stable identifier for one immutable byte domain in an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SnapshotDomainId(u16);

impl SnapshotDomainId {
    pub(crate) const ORIGINAL: Self = Self(0);
}

/// One exact range resolved against a named immutable snapshot domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DomainRange {
    pub(crate) domain: SnapshotDomainId,
    pub(crate) range: ByteRange,
}

impl DomainRange {
    pub(crate) fn original(range: ByteRange) -> Self {
        Self {
            domain: SnapshotDomainId::ORIGINAL,
            range,
        }
    }
}

/// Immutable snapshot domains retained by one ready or verified authority.
///
/// Raw ZIP and TAR currently contain exactly the original domain. Derived
/// domains are reserved for bounded, identity-bound wrapper transformations.
pub(crate) struct SnapshotSet<'a> {
    domains: Vec<SourceSnapshot<'a>>,
}

impl fmt::Debug for SnapshotSet<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotSet")
            .field("domain_count", &self.domains.len())
            .field("original", &self.original())
            .finish()
    }
}

impl<'a> SnapshotSet<'a> {
    pub(crate) fn from_original(snapshot: SourceSnapshot<'a>) -> Self {
        Self {
            domains: vec![snapshot],
        }
    }

    pub(crate) fn original(&self) -> &SourceSnapshot<'a> {
        &self.domains[0]
    }

    pub(crate) fn len(&self) -> usize {
        self.domains.len()
    }

    pub(crate) fn domain(&self, id: SnapshotDomainId) -> Option<&SourceSnapshot<'a>> {
        self.domains.get(usize::from(id.0))
    }

    /// Create and retain one bounded derived domain and its complete identity
    /// record as a single operation.
    ///
    /// The supplied reader must implement the decoder selected by `profile`.
    /// This method independently hashes the exact immutable input range and
    /// bounds the derived output before reserving and appending both objects.
    /// A returned error therefore leaves both collections unchanged.
    #[allow(dead_code)]
    pub(crate) fn append_derived_from_reader(
        &mut self,
        transforms: &mut TransformGraph,
        profile: TransformProfile,
        input: DomainRange,
        output: impl Read,
        max_output_bytes: u64,
    ) -> Result<SnapshotDomainId, Finding> {
        let (output_domain, input_sha256) = self.prepare_transform(transforms, profile, input)?;
        let snapshot = SourceSnapshot::private_derived_from_reader(output, max_output_bytes)?;
        self.append_prepared_transform(
            transforms,
            profile,
            input,
            input_sha256,
            output_domain,
            snapshot,
        )
    }

    /// Atomically retain an already bounded and verified private transform
    /// output. Format adapters use this after a decoder has validated framing,
    /// checksums, and exact input consumption while constructing the snapshot.
    #[allow(dead_code)]
    pub(crate) fn append_derived_snapshot(
        &mut self,
        transforms: &mut TransformGraph,
        profile: TransformProfile,
        input: DomainRange,
        snapshot: SourceSnapshot<'a>,
    ) -> Result<SnapshotDomainId, Finding> {
        let (output_domain, input_sha256) = self.prepare_transform(transforms, profile, input)?;
        self.append_prepared_transform(
            transforms,
            profile,
            input,
            input_sha256,
            output_domain,
            snapshot,
        )
    }

    fn prepare_transform(
        &self,
        transforms: &TransformGraph,
        profile: TransformProfile,
        input: DomainRange,
    ) -> Result<(SnapshotDomainId, String), Finding> {
        if !profile.validates() {
            return Err(Finding::error(
                FindingCode::CoveringInconsistent,
                "derived snapshot uses an invalid transformation profile identity",
            ));
        }
        if !transforms.validates(self) {
            return Err(Finding::error(
                FindingCode::CoveringInconsistent,
                "existing transformation graph does not match the retained snapshots",
            ));
        }

        let id = u16::try_from(self.domains.len()).map_err(|_| {
            Finding::error(
                FindingCode::QuotaArchive,
                "snapshot domain count exceeds the u16 identity space",
            )
        })?;
        let output_domain = SnapshotDomainId(id);
        if usize::from(input.domain.0) >= usize::from(id) {
            return Err(Finding::error(
                FindingCode::CoveringInconsistent,
                "transformation input must precede its output domain",
            ));
        }
        let input_sha256 = self.range_sha256(input)?;
        Ok((output_domain, input_sha256))
    }

    fn append_prepared_transform(
        &mut self,
        transforms: &mut TransformGraph,
        profile: TransformProfile,
        input: DomainRange,
        input_sha256: String,
        output_domain: SnapshotDomainId,
        snapshot: SourceSnapshot<'a>,
    ) -> Result<SnapshotDomainId, Finding> {
        if snapshot.kind() != SnapshotKind::PrivateFile || snapshot.path.is_some() {
            return Err(Finding::error(
                FindingCode::CoveringInconsistent,
                "derived snapshot must be a private pathless file",
            ));
        }
        let output_len = snapshot.len();
        let output_sha256 = snapshot
            .digest()
            .sha256()
            .ok_or_else(|| {
                Finding::error(
                    FindingCode::CoveringInconsistent,
                    "derived snapshot digest is unavailable",
                )
            })?
            .to_owned();

        // Both reservations happen before either append. Vec::push cannot
        // allocate after these succeed, so every error path is all-or-nothing.
        self.domains.try_reserve_exact(1).map_err(|error| {
            Finding::error(
                FindingCode::SourceIo,
                format!("could not reserve a derived snapshot domain: {error}"),
            )
        })?;
        transforms.records.try_reserve_exact(1).map_err(|error| {
            Finding::error(
                FindingCode::SourceIo,
                format!("could not reserve a transformation record: {error}"),
            )
        })?;

        let record = TransformRecord {
            profile,
            profile_id: profile.id(),
            profile_sha256: profile.digest().to_owned(),
            decoder_parameters_sha256: profile.decoder_parameters_digest().to_owned(),
            input,
            input_sha256,
            output_domain,
            output_len,
            output_sha256,
        };
        self.domains.push(snapshot);
        transforms.records.push(record);
        Ok(output_domain)
    }

    pub(crate) fn reader(
        &self,
        source: DomainRange,
    ) -> Result<SnapshotRangeReader<'_, 'a>, Finding> {
        let index = usize::from(source.domain.0);
        let snapshot = self.domains.get(index).ok_or_else(|| {
            Finding::error(
                FindingCode::CoveringInconsistent,
                "payload references an unavailable snapshot domain",
            )
        })?;
        snapshot.reader(source.range.offset, source.range.len)
    }

    fn range_sha256(&self, source: DomainRange) -> Result<String, Finding> {
        let mut reader = self.reader(source)?;
        let (len, sha256) = copy_bounded(&mut reader, &mut io::sink(), source.range.len)?;
        if len != source.range.len {
            return Err(Finding::error(
                FindingCode::SourceIo,
                format!(
                    "snapshot range read {len} bytes; expected {}",
                    source.range.len
                ),
            ));
        }
        Ok(sha256)
    }

    pub(crate) fn into_owned(self) -> SnapshotSet<'static> {
        SnapshotSet {
            domains: self
                .domains
                .into_iter()
                .map(SourceSnapshot::into_owned)
                .collect(),
        }
    }
}

/// Closed registry of deterministic, bounded decoder configurations.
///
/// New profiles require a source change, a pinned canonical definition, and a
/// pinned canonical decoder-parameter encoding. Archive bytes cannot introduce
/// or select an unregistered transformation definition.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransformProfile {
    GzipRfc1952SingleMemberV1,
    #[cfg(test)]
    TestIdentityV1,
    #[cfg(test)]
    TestReverseV1,
}

impl TransformProfile {
    pub(crate) const fn id(self) -> &'static str {
        match self {
            Self::GzipRfc1952SingleMemberV1 => "sealr.transform.gzip.rfc1952-single-member.v1",
            #[cfg(test)]
            Self::TestIdentityV1 => "sealr.transform.test.identity.v1",
            #[cfg(test)]
            Self::TestReverseV1 => "sealr.transform.test.reverse.v1",
        }
    }

    pub(crate) const fn definition(self) -> &'static [u8] {
        match self {
            Self::GzipRfc1952SingleMemberV1 => b"algorithm=rfc1952-gzip;members=exactly-one;reserved-flags=zero;extra-fields=exact-subfield-framing-si2-nonzero;trailing-data=forbidden;header-crc=verify-when-present;data-crc32=verify;isize=verify;payload=rfc1951-deflate;output=bounded",
            #[cfg(test)]
            Self::TestIdentityV1 => b"algorithm=test-identity;version=1",
            #[cfg(test)]
            Self::TestReverseV1 => b"algorithm=test-reverse;version=1",
        }
    }

    pub(crate) const fn digest(self) -> &'static str {
        match self {
            Self::GzipRfc1952SingleMemberV1 => {
                "f01a542c9009aed6d669843234b81dcf0e80b176e507913f8aeaf968ce59577d"
            }
            #[cfg(test)]
            Self::TestIdentityV1 => {
                "dcae4d8d85fa913574e0cf81b205fdccb2ccb6ecc6119b0c2b402fb1cb9ed000"
            }
            #[cfg(test)]
            Self::TestReverseV1 => {
                "a19ea13ab92508a1a557e90b06f0ca6437842a07d880395bc53861d46cdfed5d"
            }
        }
    }

    pub(crate) const fn decoder_parameters(self) -> &'static [u8] {
        match self {
            Self::GzipRfc1952SingleMemberV1 => b"rfc1951-window-bits=15;preset-dictionary=none",
            #[cfg(test)]
            Self::TestIdentityV1 => b"mode=identity;window=none",
            #[cfg(test)]
            Self::TestReverseV1 => b"mode=reverse;window=none",
        }
    }

    pub(crate) const fn decoder_parameters_digest(self) -> &'static str {
        match self {
            Self::GzipRfc1952SingleMemberV1 => {
                "c835627b01c4b54041c627319fab4d5af294a203ac26fbe91cadb6d1f17cd5e1"
            }
            #[cfg(test)]
            Self::TestIdentityV1 => {
                "c0a95e3707203775cc0b39778d398583f2bfa475166799077f7e9c8c3277e3c8"
            }
            #[cfg(test)]
            Self::TestReverseV1 => {
                "d0c414c4963a57cdde85cb38f0cba572fb7f3ca9a34f9f5632a75b3cab5d3214"
            }
        }
    }

    fn validates(self) -> bool {
        is_transform_profile_id(self.id())
            && !self.definition().is_empty()
            && is_sha256_hex(self.digest())
            && transform_profile_sha256(self.id(), self.definition()).as_deref()
                == Some(self.digest())
            && is_sha256_hex(self.decoder_parameters_digest())
            && hex_sha256(self.decoder_parameters()) == self.decoder_parameters_digest()
    }
}

/// One identity-bound transformation from an existing range to a new domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransformRecord {
    pub(crate) profile: TransformProfile,
    pub(crate) profile_id: &'static str,
    pub(crate) profile_sha256: String,
    pub(crate) decoder_parameters_sha256: String,
    pub(crate) input: DomainRange,
    pub(crate) input_sha256: String,
    pub(crate) output_domain: SnapshotDomainId,
    pub(crate) output_len: u64,
    pub(crate) output_sha256: String,
}

/// Topologically ordered transformations that produced derived domains.
#[derive(Debug, Default)]
pub(crate) struct TransformGraph {
    records: Vec<TransformRecord>,
}

impl TransformGraph {
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    #[allow(dead_code)]
    pub(crate) fn records(&self) -> &[TransformRecord] {
        &self.records
    }

    pub(crate) fn validates(&self, snapshots: &SnapshotSet<'_>) -> bool {
        if self.records.len().checked_add(1) != Some(snapshots.len()) {
            return false;
        }
        self.records.iter().enumerate().all(|(index, record)| {
            let Some(output_index) = index.checked_add(1) else {
                return false;
            };
            let Ok(output_number) = u16::try_from(output_index) else {
                return false;
            };
            if !record.profile.validates()
                || record.profile_id != record.profile.id()
                || !is_sha256_hex(&record.profile_sha256)
                || record.profile_sha256 != record.profile.digest()
                || !is_sha256_hex(&record.decoder_parameters_sha256)
                || record.decoder_parameters_sha256 != record.profile.decoder_parameters_digest()
                || !is_sha256_hex(&record.input_sha256)
                || record.output_domain != SnapshotDomainId(output_number)
                || usize::from(record.input.domain.0) >= usize::from(output_number)
            {
                return false;
            }
            let Ok(input_sha256) = snapshots.range_sha256(record.input) else {
                return false;
            };
            if input_sha256 != record.input_sha256 {
                return false;
            }
            let Some(output) = snapshots.domain(record.output_domain) else {
                return false;
            };
            output.len() == record.output_len
                && output.digest().sha256() == Some(record.output_sha256.as_str())
                && is_sha256_hex(&record.output_sha256)
        })
    }
}

fn is_transform_profile_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}

fn transform_profile_sha256(id: &str, definition: &[u8]) -> Option<String> {
    let id_len = u64::try_from(id.len()).ok()?;
    let definition_len = u64::try_from(definition.len()).ok()?;
    let mut digest = Sha256::new();
    digest.update(b"sealr.transform-profile.v1\0");
    digest.update(id_len.to_be_bytes());
    digest.update(id.as_bytes());
    digest.update(definition_len.to_be_bytes());
    digest.update(definition);
    Some(
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct TestReadFailure {
    start: u64,
    end: u64,
    armed: bool,
}

#[cfg(test)]
thread_local! {
    static TEST_READ_FAILURE: std::cell::RefCell<Option<TestReadFailure>> = const { std::cell::RefCell::new(None) };
    static TEST_READ_RANGES: std::cell::RefCell<Vec<(u64, u64)>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
#[must_use]
pub(crate) struct TestReadFailureGuard {
    previous: Option<TestReadFailure>,
}

#[cfg(test)]
impl Drop for TestReadFailureGuard {
    fn drop(&mut self) {
        TEST_READ_FAILURE.with(|failure| *failure.borrow_mut() = self.previous.take());
    }
}

#[cfg(test)]
pub(crate) fn inject_read_failure(start: u64, len: u64) -> TestReadFailureGuard {
    let end = start
        .checked_add(len)
        .expect("test snapshot failure range must not overflow");
    let previous = TEST_READ_FAILURE.with(|failure| {
        failure.borrow_mut().replace(TestReadFailure {
            start,
            end,
            armed: false,
        })
    });
    TestReadFailureGuard { previous }
}

#[cfg(test)]
pub(crate) fn arm_test_read_failure() {
    TEST_READ_FAILURE.with(|failure| {
        if let Some(failure) = failure.borrow_mut().as_mut() {
            failure.armed = true;
        }
    });
}

#[cfg(test)]
pub(crate) fn test_read_failure_is_armed() -> bool {
    TEST_READ_FAILURE.with(|failure| {
        failure
            .borrow()
            .as_ref()
            .is_some_and(|failure| failure.armed)
    })
}

#[cfg(test)]
pub(crate) fn reset_test_read_ranges() {
    TEST_READ_RANGES.with(|ranges| ranges.borrow_mut().clear());
}

#[cfg(test)]
pub(crate) fn test_read_ranges() -> Vec<(u64, u64)> {
    TEST_READ_RANGES.with(|ranges| ranges.borrow().clone())
}

#[cfg(test)]
fn injected_read_failure(offset: u64, len: u64) -> bool {
    let Some(end) = offset.checked_add(len) else {
        return false;
    };
    TEST_READ_FAILURE.with(|failure| {
        let mut failure = failure.borrow_mut();
        let should_fail = failure
            .as_ref()
            .is_some_and(|failure| failure.armed && offset < failure.end && end > failure.start);
        if should_fail {
            failure.as_mut().unwrap().armed = false;
        }
        should_fail
    })
}

impl fmt::Debug for SourceSnapshot<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceSnapshot")
            .field("path", &self.path)
            .field("kind", &self.kind())
            .field("len", &self.len)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl<'a> SourceSnapshot<'a> {
    #[cfg(test)]
    pub fn owned(path: Option<String>, bytes: Vec<u8>) -> Self {
        let len = bytes.len() as u64;
        let digest = SourceDigest::available(hex_sha256(&bytes));
        Self {
            path,
            backing: SnapshotBacking::Memory(Cow::Owned(bytes)),
            len,
            digest,
        }
    }

    pub fn borrowed(path: Option<String>, bytes: &'a [u8]) -> Self {
        let len = bytes.len() as u64;
        let digest = SourceDigest::available(hex_sha256(bytes));
        Self {
            path,
            backing: SnapshotBacking::Memory(Cow::Borrowed(bytes)),
            len,
            digest,
        }
    }

    #[cfg(any(target_os = "linux", feature = "__internal-worker-lab"))]
    pub(crate) fn from_worker_file(
        mut file: File,
        path: Option<String>,
        expected_len: u64,
        max_archive_bytes: u64,
    ) -> Result<SourceSnapshot<'static>, Finding> {
        let metadata = file.metadata().map_err(|error| {
            Finding::error(
                FindingCode::SourceIo,
                format!("read worker source metadata: {error}"),
            )
        })?;
        if !metadata.is_file() {
            return Err(Finding::error(
                FindingCode::SourceIo,
                "worker source descriptor is not a regular file",
            ));
        }
        if metadata.len() != expected_len {
            return Err(Finding::error(
                FindingCode::SourceIo,
                format!(
                    "worker source length is {}; expected {expected_len}",
                    metadata.len()
                ),
            ));
        }
        file.seek(SeekFrom::Start(0)).map_err(|error| {
            Finding::error(
                FindingCode::SourceIo,
                format!("seek worker source before hashing: {error}"),
            )
        })?;
        let (len, sha256) = copy_bounded(&mut file, &mut io::sink(), max_archive_bytes)?;
        if len != expected_len {
            return Err(Finding::error(
                FindingCode::SourceIo,
                format!("worker source read {len} bytes; expected {expected_len}"),
            ));
        }
        file.seek(SeekFrom::Start(0)).map_err(|error| {
            Finding::error(
                FindingCode::SourceIo,
                format!("rewind worker source after hashing: {error}"),
            )
        })?;
        Ok(SourceSnapshot {
            path,
            backing: SnapshotBacking::PrivateFile(PrivateFileSnapshot {
                file: Some(file),
                directory: None,
            }),
            len,
            digest: SourceDigest::available(sha256),
        })
    }

    /// Open a path once and copy its exact, bounded contents into a private
    /// file before any archive interpretation begins.
    pub(crate) fn private_file_from_path(
        source_path: &Path,
        path: Option<String>,
        max_archive_bytes: u64,
    ) -> Result<Self, Finding> {
        let source = open_source_for_snapshot(source_path).map_err(|error| {
            Finding::error(FindingCode::SourceIo, format!("open source: {error}"))
        })?;
        Self::private_file_from_opened(source, path, max_archive_bytes, || {})
    }

    /// Copy caller-owned bytes into the same private, unlinked file backend
    /// used for path snapshots before transferring read authority to a worker.
    #[cfg(target_os = "linux")]
    pub(crate) fn private_file_from_bytes(
        path: Option<String>,
        bytes: &[u8],
        max_archive_bytes: u64,
    ) -> Result<Self, Finding> {
        let expected_len = bytes.len() as u64;
        Self::private_file_from_reader(path, bytes, expected_len, max_archive_bytes)
    }

    fn private_file_from_opened(
        mut source: File,
        path: Option<String>,
        max_archive_bytes: u64,
        after_copy: impl FnOnce(),
    ) -> Result<Self, Finding> {
        let before = source.metadata().map_err(|error| {
            Finding::error(
                FindingCode::SourceIo,
                format!("read opened-source metadata: {error}"),
            )
        })?;
        if !before.is_file() {
            return Err(Finding::error(
                FindingCode::SourceIo,
                "opened source is not a regular file",
            ));
        }
        let before = opened_source_state(&before);
        let expected_len = before.len;
        if expected_len > max_archive_bytes {
            return Err(Finding::error(
                FindingCode::QuotaArchive,
                format!("archive is {expected_len} bytes; cap is {max_archive_bytes}"),
            ));
        }

        let snapshot =
            Self::private_file_from_reader(path, &mut source, expected_len, max_archive_bytes)?;
        after_copy();
        let after = source.metadata().map_err(|error| {
            Finding::error(
                FindingCode::SourceIo,
                format!("recheck opened-source metadata: {error}"),
            )
        })?;
        if !after.is_file() || opened_source_state(&after) != before {
            return Err(Finding::error(
                FindingCode::SourceIo,
                "opened source changed while the private snapshot was being copied",
            ));
        }
        Ok(snapshot)
    }

    fn private_file_from_reader(
        path: Option<String>,
        source: impl Read,
        expected_len: u64,
        max_archive_bytes: u64,
    ) -> Result<Self, Finding> {
        Self::private_file_from_bounded_reader(path, source, Some(expected_len), max_archive_bytes)
    }

    #[allow(dead_code)]
    pub(crate) fn private_derived_from_reader(
        source: impl Read,
        max_output_bytes: u64,
    ) -> Result<SourceSnapshot<'static>, Finding> {
        Self::private_file_from_bounded_reader(None, source, None, max_output_bytes)
            .map(SourceSnapshot::into_owned)
    }

    fn private_file_from_bounded_reader(
        path: Option<String>,
        mut source: impl Read,
        expected_len: Option<u64>,
        max_archive_bytes: u64,
    ) -> Result<Self, Finding> {
        let directory =
            PrivateDirectory::create_in_system_temp(".sealr-source-").map_err(|error| {
                Finding::error(
                    FindingCode::SourceIo,
                    format!("create private source directory: {error}"),
                )
            })?;
        let root = directory.root().map_err(|error| {
            Finding::error(
                FindingCode::SourceIo,
                format!("access private source directory: {error}"),
            )
        })?;
        let mut write_options = CapOpenOptions::new();
        write_options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        let mut writer = root
            .open_with(Path::new(SPOOL_FILE_NAME), &write_options)
            .map_err(|error| {
                Finding::error(
                    FindingCode::SourceIo,
                    format!("create private source file: {error}"),
                )
            })?;
        ensure_file_handle_is_not_reparse(&writer).map_err(|error| {
            Finding::error(
                FindingCode::SourceIo,
                format!("private source file is a reparse point: {error}"),
            )
        })?;

        let (len, sha256) = copy_bounded(&mut source, &mut writer, max_archive_bytes)?;
        if let Some(expected_len) = expected_len {
            if len != expected_len {
                return Err(Finding::error(
                    FindingCode::SourceIo,
                    format!(
                        "opened source length changed while copying: expected {expected_len}, read {len}"
                    ),
                ));
            }
        }
        writer.flush().map_err(|error| {
            Finding::error(
                FindingCode::SourceIo,
                format!("flush private source file: {error}"),
            )
        })?;
        let written_len = writer
            .metadata()
            .map_err(|error| {
                Finding::error(
                    FindingCode::SourceIo,
                    format!("inspect private source file: {error}"),
                )
            })?
            .len();
        if written_len != len {
            return Err(Finding::error(
                FindingCode::SourceIo,
                format!("private source length is {written_len}; copied length is {len}"),
            ));
        }
        drop(writer);

        let mut read_options = CapOpenOptions::new();
        read_options.read(true).follow(FollowSymlinks::No);
        let reader = root
            .open_with(Path::new(SPOOL_FILE_NAME), &read_options)
            .map_err(|error| {
                Finding::error(
                    FindingCode::SourceIo,
                    format!("open private source file read-only: {error}"),
                )
            })?;
        ensure_file_handle_is_not_reparse(&reader).map_err(|error| {
            Finding::error(
                FindingCode::SourceIo,
                format!("private source reader is a reparse point: {error}"),
            )
        })?;
        let metadata = reader.metadata().map_err(|error| {
            Finding::error(
                FindingCode::SourceIo,
                format!("inspect private source reader: {error}"),
            )
        })?;
        if !metadata.is_file() || metadata.len() != len {
            return Err(Finding::error(
                FindingCode::SourceIo,
                "private source reader does not identify the exact regular file that was copied",
            ));
        }
        root.remove_file(Path::new(SPOOL_FILE_NAME))
            .map_err(|error| {
                Finding::error(
                    FindingCode::SourceIo,
                    format!("remove private source filename after opening: {error}"),
                )
            })?;

        Ok(Self {
            path,
            backing: SnapshotBacking::PrivateFile(PrivateFileSnapshot {
                file: Some(reader.into_std()),
                directory: Some(directory),
            }),
            len,
            digest: SourceDigest::available(sha256),
        })
    }

    #[cfg(test)]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn path_owned(&self) -> Option<String> {
        self.path.clone()
    }

    #[cfg(test)]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.backing {
            SnapshotBacking::Memory(bytes) => Some(bytes),
            SnapshotBacking::PrivateFile(_) => None,
        }
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[cfg(test)]
    fn spool_path(&self) -> Option<std::path::PathBuf> {
        match &self.backing {
            SnapshotBacking::PrivateFile(snapshot) => {
                snapshot.directory.as_ref().map(PrivateDirectory::path)
            }
            SnapshotBacking::Memory(_) => None,
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn digest(&self) -> &SourceDigest {
        &self.digest
    }

    /// Duplicate the exact read-only private-file authority for a worker.
    #[cfg(target_os = "linux")]
    pub(crate) fn try_clone_worker_file(&self) -> Result<File, Finding> {
        match &self.backing {
            SnapshotBacking::PrivateFile(snapshot) => snapshot
                .file
                .as_ref()
                .ok_or_else(|| {
                    Finding::error(
                        FindingCode::SourceIo,
                        "private source reader is unavailable",
                    )
                })?
                .try_clone()
                .map_err(|error| {
                    Finding::error(
                        FindingCode::SourceIo,
                        format!("clone private source authority: {error}"),
                    )
                }),
            SnapshotBacking::Memory(_) => Err(Finding::error(
                FindingCode::SourceIo,
                "worker source authority requires a private-file snapshot",
            )),
        }
    }

    pub fn kind(&self) -> SnapshotKind {
        match &self.backing {
            SnapshotBacking::Memory(Cow::Owned(_)) => SnapshotKind::MemoryOwned,
            SnapshotBacking::Memory(Cow::Borrowed(_)) => SnapshotKind::MemoryBorrowed,
            SnapshotBacking::PrivateFile(_) => SnapshotKind::PrivateFile,
        }
    }

    /// Convert this invocation snapshot into process-owned storage. A private
    /// file and owned memory move without copying; borrowed bytes are copied.
    pub(crate) fn into_owned(self) -> SourceSnapshot<'static> {
        let backing = match self.backing {
            SnapshotBacking::Memory(bytes) => {
                SnapshotBacking::Memory(Cow::Owned(bytes.into_owned()))
            }
            SnapshotBacking::PrivateFile(file) => SnapshotBacking::PrivateFile(file),
        };
        SourceSnapshot {
            path: self.path,
            backing,
            len: self.len,
            digest: self.digest,
        }
    }

    /// Copy one exact checked range into a caller-owned buffer.
    pub(crate) fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Finding> {
        let len = u64::try_from(output.len()).map_err(|_| {
            Finding::error(
                FindingCode::ZipDiffC4Offset,
                "read buffer length does not fit u64",
            )
        })?;
        self.checked_range(offset, len)?;
        #[cfg(test)]
        TEST_READ_RANGES.with(|ranges| ranges.borrow_mut().push((offset, len)));
        #[cfg(test)]
        if injected_read_failure(offset, len) {
            return Err(Finding::error(
                FindingCode::SourceIo,
                format!("injected snapshot read failure at offset {offset}"),
            ));
        }
        match &self.backing {
            SnapshotBacking::Memory(bytes) => {
                let start = usize::try_from(offset).map_err(|_| {
                    Finding::error(
                        FindingCode::ZipDiffC4Offset,
                        "range offset does not fit this platform",
                    )
                })?;
                let end = start.checked_add(output.len()).ok_or_else(|| {
                    Finding::error(FindingCode::ZipDiffC4Offset, "range end overflows")
                })?;
                let source = bytes.get(start..end).ok_or_else(|| {
                    Finding::error(FindingCode::ZipDiffC4Offset, "range extends past snapshot")
                })?;
                output.copy_from_slice(source);
                Ok(())
            }
            SnapshotBacking::PrivateFile(snapshot) => {
                let file = snapshot.file.as_ref().ok_or_else(|| {
                    Finding::error(
                        FindingCode::SourceIo,
                        "private source reader is unavailable",
                    )
                })?;
                read_file_exact_at(file, offset, output)
            }
        }
    }

    /// Copy one exact checked range into a bounded owned buffer.
    pub(crate) fn read_vec(&self, offset: u64, len: u64) -> Result<Vec<u8>, Finding> {
        self.checked_range(offset, len)?;
        let length = usize::try_from(len).map_err(|_| {
            Finding::error(
                FindingCode::ZipDiffC4Offset,
                "range length does not fit this platform",
            )
        })?;
        let mut output = Vec::new();
        output.try_reserve_exact(length).map_err(|error| {
            Finding::error(
                FindingCode::SourceIo,
                format!("could not reserve {len} snapshot bytes: {error}"),
            )
        })?;
        output.resize(length, 0);
        self.read_exact_at(offset, &mut output)?;
        Ok(output)
    }

    /// Open a checked reader limited to one exact snapshot range.
    pub(crate) fn reader(
        &self,
        offset: u64,
        len: u64,
    ) -> Result<SnapshotRangeReader<'_, 'a>, Finding> {
        self.checked_range(offset, len)?;
        Ok(SnapshotRangeReader {
            snapshot: self,
            offset,
            remaining: len,
        })
    }

    fn checked_range(&self, offset: u64, len: u64) -> Result<(), Finding> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| Finding::error(FindingCode::ZipDiffC4Offset, "range end overflows"))?;
        if end > self.len {
            return Err(Finding::error(
                FindingCode::ZipDiffC4Offset,
                "range extends past snapshot",
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
fn open_source_for_snapshot(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};

    OpenOptions::new()
        .read(true)
        // A writer that is already open causes this open to fail, and a new
        // writer cannot open until this handle closes. Delete sharing is safe:
        // later reads use this exact handle, never the caller's path.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(path)
}

#[cfg(not(windows))]
fn open_source_for_snapshot(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(unix)]
fn opened_source_state(metadata: &Metadata) -> OpenedSourceState {
    use std::os::unix::fs::MetadataExt;

    OpenedSourceState {
        len: metadata.len(),
        platform: PlatformSourceState {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        },
    }
}

#[cfg(windows)]
fn opened_source_state(metadata: &Metadata) -> OpenedSourceState {
    use std::os::windows::fs::MetadataExt;

    OpenedSourceState {
        len: metadata.len(),
        platform: PlatformSourceState {
            attributes: metadata.file_attributes(),
            creation_time: metadata.creation_time(),
            last_write_time: metadata.last_write_time(),
        },
    }
}

#[cfg(not(any(unix, windows)))]
fn opened_source_state(metadata: &Metadata) -> OpenedSourceState {
    OpenedSourceState {
        len: metadata.len(),
        platform: PlatformSourceState {
            modified: metadata.modified().ok(),
        },
    }
}

fn copy_bounded(
    source: &mut impl Read,
    destination: &mut impl Write,
    max_archive_bytes: u64,
) -> Result<(u64, String), Finding> {
    let mut len = 0_u64;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let remaining_plus_one = max_archive_bytes.saturating_sub(len).saturating_add(1);
        let read_limit = usize::try_from(remaining_plus_one.min(buffer.len() as u64))
            .expect("copy buffer length fits usize");
        let read = loop {
            match source.read(&mut buffer[..read_limit]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result,
            }
        }
        .map_err(|error| {
            finding_from_io(&error).unwrap_or_else(|| {
                Finding::error(FindingCode::SourceIo, format!("read source: {error}"))
            })
        })?;
        if read == 0 {
            break;
        }
        let next = len.checked_add(read as u64).ok_or_else(|| {
            Finding::error(FindingCode::QuotaArchive, "archive length overflowed u64")
        })?;
        if next > max_archive_bytes {
            return Err(Finding::error(
                FindingCode::QuotaArchive,
                format!("archive grew beyond the input cap of {max_archive_bytes} bytes"),
            ));
        }
        destination.write_all(&buffer[..read]).map_err(|error| {
            Finding::error(
                FindingCode::SourceIo,
                format!("write private source file: {error}"),
            )
        })?;
        digest.update(&buffer[..read]);
        len = next;
    }
    let sha256 = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((len, sha256))
}

#[cfg(unix)]
fn read_file_at(file: &File, output: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;

    file.read_at(output, offset)
}

#[cfg(windows)]
fn read_file_at(file: &File, output: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;

    file.seek_read(output, offset)
}

#[cfg(not(any(unix, windows)))]
fn read_file_at(file: &File, output: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::io::{Seek, SeekFrom};

    let mut shared = file;
    shared.seek(SeekFrom::Start(offset))?;
    shared.read(output)
}

fn read_file_exact_at(file: &File, mut offset: u64, mut output: &mut [u8]) -> Result<(), Finding> {
    while !output.is_empty() {
        let read = match read_file_at(file, output, offset) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Finding::error(
                    FindingCode::SourceIo,
                    format!("read private source at offset {offset}: {error}"),
                ));
            }
            Ok(0) => {
                return Err(Finding::error(
                    FindingCode::SourceIo,
                    format!("private source ended unexpectedly at offset {offset}"),
                ));
            }
            Ok(read) => read,
        };
        offset = offset.checked_add(read as u64).ok_or_else(|| {
            Finding::error(
                FindingCode::SourceIo,
                "private source read offset overflowed u64",
            )
        })?;
        output = &mut output[read..];
    }
    Ok(())
}

#[derive(Debug)]
struct SnapshotReadError(Finding);

impl fmt::Display for SnapshotReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.0.code.as_str(), self.0.detail)
    }
}

impl Error for SnapshotReadError {}

pub(crate) fn finding_from_io(error: &io::Error) -> Option<Finding> {
    let mut current: Option<&(dyn Error + 'static)> =
        error.get_ref().map(|inner| inner as &(dyn Error + 'static));
    while let Some(candidate) = current {
        if let Some(snapshot) = candidate.downcast_ref::<SnapshotReadError>() {
            return Some(snapshot.0.clone());
        }
        current = candidate.source();
    }
    None
}

pub(crate) fn as_io_error(finding: Finding) -> io::Error {
    let kind = if finding.code == FindingCode::SourceIo {
        io::ErrorKind::Other
    } else {
        io::ErrorKind::UnexpectedEof
    };
    io::Error::new(kind, SnapshotReadError(finding))
}

/// Read-only cursor over one checked half-open snapshot range.
#[derive(Debug)]
pub(crate) struct SnapshotRangeReader<'s, 'a> {
    snapshot: &'s SourceSnapshot<'a>,
    offset: u64,
    remaining: u64,
}

impl Read for SnapshotRangeReader<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        let output_len = u64::try_from(output.len()).unwrap_or(u64::MAX);
        let count = self.remaining.min(output_len);
        let count = usize::try_from(count).expect("read count is bounded by the output buffer");
        let count_u64 =
            u64::try_from(count).expect("read count already originated from a u64 value");
        self.snapshot
            .read_exact_at(self.offset, &mut output[..count])
            .map_err(as_io_error)?;
        self.offset = self
            .offset
            .checked_add(count_u64)
            .expect("validated snapshot range cannot overflow");
        self.remaining -= count_u64;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const IDENTITY_PROFILE: TransformProfile = TransformProfile::TestIdentityV1;
    const REVERSE_PROFILE: TransformProfile = TransformProfile::TestReverseV1;
    const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn one_transform() -> (SnapshotSet<'static>, TransformGraph) {
        let original = b"xxwrappedyy";
        let output = b"decoded archive";
        let mut snapshots = SnapshotSet::from_original(SourceSnapshot::borrowed(None, original));
        let mut graph = TransformGraph::empty();
        let domain = snapshots
            .append_derived_from_reader(
                &mut graph,
                IDENTITY_PROFILE,
                DomainRange::original(ByteRange { offset: 2, len: 7 }),
                Cursor::new(output),
                output.len() as u64,
            )
            .unwrap();
        assert_eq!(domain, SnapshotDomainId(1));
        (snapshots, graph)
    }

    struct InterruptedThenData {
        interrupted: bool,
        inner: Cursor<Vec<u8>>,
        largest_request: usize,
        max_read: usize,
    }

    struct StructuredFailure(Finding);

    impl Read for StructuredFailure {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(as_io_error(self.0.clone()))
        }
    }

    impl Read for InterruptedThenData {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.largest_request = self.largest_request.max(output.len());
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::new(io::ErrorKind::Interrupted, "try again"));
            }
            let limit = output.len().min(self.max_read);
            self.inner.read(&mut output[..limit])
        }
    }

    struct InterruptedWriter {
        interrupted: bool,
        bytes: Vec<u8>,
    }

    impl Write for InterruptedWriter {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::new(io::ErrorKind::Interrupted, "try again"));
            }
            self.bytes.extend_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn borrowed_snapshot_does_not_copy_and_hashes_the_caller_bytes() {
        let data = b"PK\x03\x04hello";
        let snapshot = SourceSnapshot::borrowed(Some("t.zip".into()), data);
        assert_eq!(snapshot.kind(), SnapshotKind::MemoryBorrowed);
        assert_eq!(snapshot.path(), Some("t.zip"));
        assert!(!snapshot.is_empty());
        assert_eq!(snapshot.as_bytes().unwrap().as_ptr(), data.as_ptr());
        assert_eq!(snapshot.len(), data.len() as u64);
        let digest = hex_sha256(data);
        assert_eq!(snapshot.digest().sha256(), Some(digest.as_str()));
    }

    #[test]
    fn owned_snapshot_isolates_path_bytes() {
        let data = b"owned-archive".to_vec();
        let snapshot = SourceSnapshot::owned(Some("p.zip".into()), data.clone());
        assert_eq!(snapshot.kind(), SnapshotKind::MemoryOwned);
        assert_eq!(snapshot.as_bytes().unwrap(), data.as_slice());
        let digest = hex_sha256(&data);
        assert_eq!(snapshot.digest().sha256(), Some(digest.as_str()));
    }

    #[test]
    fn range_rejects_past_end_without_panic() {
        let snapshot = SourceSnapshot::borrowed(None, b"abcd");
        let finding = snapshot.read_vec(2, 8).unwrap_err();
        assert_eq!(finding.code, FindingCode::ZipDiffC4Offset);
        assert_eq!(snapshot.read_vec(1, 2).unwrap(), b"bc");
        assert_eq!(snapshot.read_vec(4, 0).unwrap(), b"");
    }

    #[test]
    fn exact_reads_and_range_reader_share_checked_u64_bounds() {
        let snapshot = SourceSnapshot::borrowed(None, b"abcdefgh");
        let mut exact = [0_u8; 3];
        snapshot.read_exact_at(2, &mut exact).unwrap();
        assert_eq!(&exact, b"cde");
        assert_eq!(snapshot.read_vec(4, 4).unwrap(), b"efgh");

        let mut reader = snapshot.reader(1, 5).unwrap();
        let mut streamed = Vec::new();
        reader.read_to_end(&mut streamed).unwrap();
        assert_eq!(streamed, b"bcdef");

        assert_eq!(
            snapshot.reader(7, 2).unwrap_err().code,
            FindingCode::ZipDiffC4Offset
        );
        assert_eq!(
            snapshot.read_vec(u64::MAX, 1).unwrap_err().code,
            FindingCode::ZipDiffC4Offset
        );
        assert_eq!(
            snapshot.read_vec(0, u64::MAX).unwrap_err().code,
            FindingCode::ZipDiffC4Offset
        );
    }

    #[test]
    fn into_owned_preserves_bytes_path_and_digest() {
        let data = b"borrowed-archive";
        let snapshot = SourceSnapshot::borrowed(Some("input.zip".into()), data);
        let digest = snapshot.digest().clone();
        let owned = snapshot.into_owned();

        assert_eq!(owned.kind(), SnapshotKind::MemoryOwned);
        assert_eq!(owned.path(), Some("input.zip"));
        assert_eq!(owned.as_bytes().unwrap(), data);
        assert_eq!(owned.digest(), &digest);
    }

    #[test]
    fn snapshot_set_resolves_only_declared_domains_and_owns_borrowed_input() {
        let data = b"original-domain";
        let snapshots = SnapshotSet::from_original(SourceSnapshot::borrowed(None, data));
        assert_eq!(snapshots.len(), 1);
        assert!(TransformGraph::empty().is_empty());

        let mut reader = snapshots
            .reader(DomainRange::original(ByteRange { offset: 2, len: 6 }))
            .unwrap();
        let mut selected = Vec::new();
        reader.read_to_end(&mut selected).unwrap();
        assert_eq!(selected, b"iginal");

        let unavailable = snapshots
            .reader(DomainRange {
                domain: SnapshotDomainId(1),
                range: ByteRange { offset: 0, len: 0 },
            })
            .unwrap_err();
        assert_eq!(unavailable.code, FindingCode::CoveringInconsistent);

        let owned = snapshots.into_owned();
        assert_eq!(owned.original().kind(), SnapshotKind::MemoryOwned);
        assert_eq!(owned.original().as_bytes().unwrap(), data);
    }

    #[test]
    fn derived_transform_chain_binds_exact_inputs_profiles_parameters_and_outputs() {
        assert!(IDENTITY_PROFILE.validates());
        assert!(REVERSE_PROFILE.validates());
        let gzip_profile = TransformProfile::GzipRfc1952SingleMemberV1;
        assert!(gzip_profile.validates());
        assert_eq!(
            transform_profile_sha256(gzip_profile.id(), gzip_profile.definition()).as_deref(),
            Some(gzip_profile.digest())
        );
        assert_eq!(
            hex_sha256(gzip_profile.decoder_parameters()),
            gzip_profile.decoder_parameters_digest()
        );

        let (mut snapshots, mut graph) = one_transform();
        let second_output = b"inner archive";
        let second_domain = snapshots
            .append_derived_from_reader(
                &mut graph,
                REVERSE_PROFILE,
                DomainRange {
                    domain: SnapshotDomainId(1),
                    range: ByteRange { offset: 2, len: 7 },
                },
                Cursor::new(second_output),
                second_output.len() as u64,
            )
            .unwrap();

        assert_eq!(second_domain, SnapshotDomainId(2));
        assert_eq!(snapshots.len(), 3);
        assert_eq!(graph.records.len(), 2);
        assert!(graph.validates(&snapshots));
        assert_eq!(
            snapshots.domain(SnapshotDomainId(1)).unwrap().kind(),
            SnapshotKind::PrivateFile
        );
        assert_eq!(graph.records[0].input_sha256, hex_sha256(b"wrapped"));
        assert_eq!(graph.records[0].profile_id, IDENTITY_PROFILE.id());
        assert_eq!(graph.records[0].profile_sha256, IDENTITY_PROFILE.digest());
        assert_eq!(
            graph.records[0].decoder_parameters_sha256,
            IDENTITY_PROFILE.decoder_parameters_digest()
        );
        assert_eq!(graph.records[1].input_sha256, hex_sha256(b"coded a"));
        assert_eq!(graph.records[1].output_sha256, hex_sha256(second_output));
    }

    #[test]
    fn transform_graph_rejects_tampered_input_profile_parameters_and_output() {
        let (mut snapshots, mut graph) = one_transform();

        let input_sha256 = graph.records[0].input_sha256.clone();
        graph.records[0].input_sha256 = ZERO_SHA256.into();
        assert!(!graph.validates(&snapshots));
        graph.records[0].input_sha256 = input_sha256;

        let profile = graph.records[0].profile;
        graph.records[0].profile = REVERSE_PROFILE;
        assert!(!graph.validates(&snapshots));
        graph.records[0].profile = profile;

        let profile_id = graph.records[0].profile_id;
        graph.records[0].profile_id = "sealr.transform.test.changed.v1";
        assert!(!graph.validates(&snapshots));
        graph.records[0].profile_id = profile_id;

        let profile_sha256 = graph.records[0].profile_sha256.clone();
        graph.records[0].profile_sha256 = ZERO_SHA256.into();
        assert!(!graph.validates(&snapshots));
        graph.records[0].profile_sha256 = profile_sha256;

        let parameters_sha256 = graph.records[0].decoder_parameters_sha256.clone();
        graph.records[0].decoder_parameters_sha256 = ZERO_SHA256.into();
        assert!(!graph.validates(&snapshots));
        graph.records[0].decoder_parameters_sha256 = parameters_sha256;

        let output_len = graph.records[0].output_len;
        graph.records[0].output_len = output_len + 1;
        assert!(!graph.validates(&snapshots));
        graph.records[0].output_len = output_len;
        let output_sha256 = graph.records[0].output_sha256.clone();
        graph.records[0].output_sha256 = ZERO_SHA256.into();
        assert!(!graph.validates(&snapshots));
        graph.records[0].output_sha256 = output_sha256;

        let retained_digest = snapshots.domains[1].digest.clone();
        snapshots.domains[1].digest = SourceDigest::available(ZERO_SHA256);
        assert!(!graph.validates(&snapshots));
        snapshots.domains[1].digest = retained_digest;
        assert!(graph.validates(&snapshots));
    }

    #[test]
    fn transform_graph_rejects_self_forward_and_unavailable_references() {
        let (mut snapshots, mut graph) = one_transform();
        let second_output = b"second";
        snapshots
            .append_derived_from_reader(
                &mut graph,
                REVERSE_PROFILE,
                DomainRange {
                    domain: SnapshotDomainId(1),
                    range: ByteRange { offset: 0, len: 7 },
                },
                Cursor::new(second_output),
                second_output.len() as u64,
            )
            .unwrap();
        assert!(graph.validates(&snapshots));

        graph.records[0].input.domain = SnapshotDomainId(1);
        assert!(!graph.validates(&snapshots));
        graph.records[0].input.domain = SnapshotDomainId(2);
        assert!(!graph.validates(&snapshots));
        graph.records[0].input.domain = SnapshotDomainId(99);
        assert!(!graph.validates(&snapshots));
        graph.records[0].input = DomainRange::original(ByteRange { offset: 2, len: 7 });

        graph.records[1].input.domain = SnapshotDomainId(2);
        assert!(!graph.validates(&snapshots));
        graph.records[1].input.domain = SnapshotDomainId(99);
        assert!(!graph.validates(&snapshots));
        graph.records[1].input.domain = SnapshotDomainId(1);

        graph.records[0].input.range = ByteRange {
            offset: u64::MAX,
            len: 1,
        };
        assert!(!graph.validates(&snapshots));
        graph.records[0].input = DomainRange::original(ByteRange { offset: 2, len: 7 });
        graph.records[0].output_domain = SnapshotDomainId(99);
        assert!(!graph.validates(&snapshots));
    }

    #[test]
    fn derived_transform_cap_failure_is_all_or_nothing_and_reads_cap_plus_one() {
        let original = b"wrapped";
        let output = b"four";
        let mut snapshots = SnapshotSet::from_original(SourceSnapshot::borrowed(None, original));
        let mut graph = TransformGraph::empty();
        let mut reader = InterruptedThenData {
            interrupted: false,
            inner: Cursor::new(output.to_vec()),
            largest_request: 0,
            max_read: output.len(),
        };

        let error = snapshots
            .append_derived_from_reader(
                &mut graph,
                IDENTITY_PROFILE,
                DomainRange::original(ByteRange {
                    offset: 0,
                    len: original.len() as u64,
                }),
                &mut reader,
                output.len() as u64 - 1,
            )
            .unwrap_err();

        assert_eq!(error.code, FindingCode::QuotaArchive);
        assert_eq!(reader.largest_request, output.len());
        assert_eq!(snapshots.len(), 1);
        assert_eq!(graph.records.len(), 0);
        assert!(graph.validates(&snapshots));

        snapshots
            .append_derived_from_reader(
                &mut graph,
                IDENTITY_PROFILE,
                DomainRange::original(ByteRange {
                    offset: 0,
                    len: original.len() as u64,
                }),
                Cursor::new(output),
                output.len() as u64,
            )
            .unwrap();
        assert!(graph.validates(&snapshots));
        graph.records[0].decoder_parameters_sha256 = ZERO_SHA256.into();
        let domain_count = snapshots.len();
        let record_count = graph.records.len();
        let invalid = snapshots
            .append_derived_from_reader(
                &mut graph,
                REVERSE_PROFILE,
                DomainRange {
                    domain: SnapshotDomainId(1),
                    range: ByteRange { offset: 0, len: 1 },
                },
                Cursor::new(output),
                output.len() as u64,
            )
            .unwrap_err();
        assert_eq!(invalid.code, FindingCode::CoveringInconsistent);
        assert_eq!(snapshots.len(), domain_count);
        assert_eq!(graph.records.len(), record_count);
    }

    #[test]
    fn prepared_private_transform_appends_atomically_and_rejects_memory_output() {
        let original = b"wrapped";
        let output = b"decoded";
        let mut snapshots = SnapshotSet::from_original(SourceSnapshot::borrowed(None, original));
        let mut graph = TransformGraph::empty();
        let private =
            SourceSnapshot::private_derived_from_reader(Cursor::new(output), output.len() as u64)
                .unwrap();

        let domain = snapshots
            .append_derived_snapshot(
                &mut graph,
                IDENTITY_PROFILE,
                DomainRange::original(ByteRange {
                    offset: 0,
                    len: original.len() as u64,
                }),
                private,
            )
            .unwrap();

        assert_eq!(domain, SnapshotDomainId(1));
        assert!(graph.validates(&snapshots));

        let memory = SourceSnapshot::owned(None, b"not private".to_vec());
        let error = snapshots
            .append_derived_snapshot(
                &mut graph,
                REVERSE_PROFILE,
                DomainRange {
                    domain,
                    range: ByteRange {
                        offset: 0,
                        len: output.len() as u64,
                    },
                },
                memory,
            )
            .unwrap_err();
        assert_eq!(error.code, FindingCode::CoveringInconsistent);
        assert_eq!(snapshots.len(), 2);
        assert_eq!(graph.records().len(), 1);
        assert!(graph.validates(&snapshots));
    }

    #[test]
    fn private_file_snapshot_has_random_access_and_removes_its_directory() {
        let data = b"private snapshot bytes".repeat(4096);
        let snapshot = SourceSnapshot::private_file_from_reader(
            Some("input.zip".into()),
            Cursor::new(&data),
            data.len() as u64,
            data.len() as u64,
        )
        .unwrap();
        assert_eq!(snapshot.kind(), SnapshotKind::PrivateFile);
        assert!(snapshot.as_bytes().is_none());
        assert_eq!(snapshot.read_vec(7, 31).unwrap(), data[7..38]);
        let SnapshotBacking::PrivateFile(private) = &snapshot.backing else {
            unreachable!("snapshot kind was checked above");
        };
        let mut reader = private.file.as_ref().unwrap();
        assert!(reader.write_all(b"mutation").is_err());
        let directory = snapshot.spool_path().unwrap();
        assert!(directory.is_dir());
        assert!(!directory.join(SPOOL_FILE_NAME).exists());
        drop(snapshot);
        assert!(!directory.exists());
    }

    #[test]
    fn private_copy_retries_interruption_and_never_requests_more_than_64_kib() {
        let data = vec![0x5a; COPY_BUFFER_BYTES * 3 + 17];
        let mut source = InterruptedThenData {
            interrupted: false,
            inner: Cursor::new(data.clone()),
            largest_request: 0,
            max_read: 17,
        };
        let snapshot = SourceSnapshot::private_file_from_reader(
            None,
            &mut source,
            data.len() as u64,
            data.len() as u64,
        )
        .unwrap();
        assert_eq!(source.largest_request, COPY_BUFFER_BYTES);
        assert_eq!(snapshot.read_vec(0, data.len() as u64).unwrap(), data);
    }

    #[test]
    fn bounded_copy_retries_an_interrupted_private_file_write() {
        let data = b"write interruption must not create a partial snapshot";
        let mut writer = InterruptedWriter {
            interrupted: false,
            bytes: Vec::new(),
        };

        let (len, digest) =
            copy_bounded(&mut Cursor::new(data), &mut writer, data.len() as u64).unwrap();

        assert!(writer.interrupted);
        assert_eq!(writer.bytes, data);
        assert_eq!(len, data.len() as u64);
        assert_eq!(digest, hex_sha256(data));
    }

    #[test]
    fn retained_source_handle_ignores_caller_path_replacement() {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let directory = std::env::temp_dir().join(format!("sealr-source-replace-{suffix}"));
        std::fs::create_dir(&directory).unwrap();
        let source_path = directory.join("input.zip");
        let moved_path = directory.join("opened.zip");
        let original = b"original opened bytes";
        std::fs::write(&source_path, original).unwrap();
        let mut opened = File::open(&source_path).unwrap();
        std::fs::rename(&source_path, &moved_path).unwrap();
        std::fs::write(&source_path, b"replacement path bytes").unwrap();

        let snapshot = SourceSnapshot::private_file_from_reader(
            Some(source_path.display().to_string()),
            &mut opened,
            original.len() as u64,
            original.len() as u64,
        )
        .unwrap();

        assert_eq!(snapshot.read_vec(0, snapshot.len()).unwrap(), original);
        drop(snapshot);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_path_copy_rejects_same_length_in_place_mutation() {
        use std::io::{Seek, SeekFrom};

        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let directory = std::env::temp_dir().join(format!("sealr-source-mutate-{suffix}"));
        std::fs::create_dir(&directory).unwrap();
        let source_path = directory.join("input.zip");
        let original = vec![0x11; COPY_BUFFER_BYTES * 2];
        std::fs::write(&source_path, &original).unwrap();
        let source = open_source_for_snapshot(&source_path).unwrap();

        let error = SourceSnapshot::private_file_from_opened(
            source,
            Some(source_path.display().to_string()),
            original.len() as u64,
            || {
                let mut writer = OpenOptions::new().write(true).open(&source_path).unwrap();
                writer
                    .seek(SeekFrom::Start(COPY_BUFFER_BYTES as u64))
                    .unwrap();
                writer.write_all(&vec![0x22; COPY_BUFFER_BYTES]).unwrap();
                writer.flush().unwrap();
            },
        )
        .unwrap_err();

        assert_eq!(error.code, FindingCode::SourceIo);
        assert_eq!(
            error.detail,
            "opened source changed while the private snapshot was being copied"
        );
        assert_eq!(
            std::fs::metadata(&source_path).unwrap().len(),
            original.len() as u64
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn private_path_copy_rejects_an_existing_writer() {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let directory = std::env::temp_dir().join(format!("sealr-source-writer-{suffix}"));
        std::fs::create_dir(&directory).unwrap();
        let source_path = directory.join("input.zip");
        std::fs::write(&source_path, b"stable bytes").unwrap();
        let writer = OpenOptions::new().write(true).open(&source_path).unwrap();

        let error = SourceSnapshot::private_file_from_path(
            &source_path,
            Some(source_path.display().to_string()),
            1024,
        )
        .unwrap_err();

        assert_eq!(error.code, FindingCode::SourceIo);
        assert!(error.detail.starts_with("open source:"));
        drop(writer);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn private_copy_rejects_truncation_and_growth_without_a_digest() {
        let truncated =
            SourceSnapshot::private_file_from_reader(None, Cursor::new(b"short"), 10, 10)
                .unwrap_err();
        assert_eq!(truncated.code, FindingCode::SourceIo);

        let over_cap =
            SourceSnapshot::private_file_from_reader(None, Cursor::new(b"too long"), 8, 7)
                .unwrap_err();
        assert_eq!(over_cap.code, FindingCode::QuotaArchive);
    }

    #[test]
    fn snapshot_kind_json_is_stable() {
        assert_eq!(
            serde_json::to_value(SnapshotKind::MemoryOwned).unwrap(),
            serde_json::json!("memory-owned")
        );
        assert_eq!(
            serde_json::to_value(SnapshotKind::MemoryBorrowed).unwrap(),
            serde_json::json!("memory-borrowed")
        );
        assert_eq!(
            serde_json::to_value(SnapshotKind::PrivateFile).unwrap(),
            serde_json::json!("private-file")
        );
        assert_eq!(
            serde_json::to_value(SnapshotKind::Unavailable).unwrap(),
            serde_json::json!("unavailable")
        );
    }

    #[test]
    fn snapshot_io_error_round_trips_the_structured_finding() {
        let finding = Finding::error(FindingCode::SourceIo, "read failed at offset 41");
        let error = as_io_error(finding.clone());
        assert_eq!(finding_from_io(&error), Some(finding));
    }

    #[test]
    fn bounded_private_copy_preserves_a_structured_transform_finding() {
        let finding = Finding::error(
            FindingCode::CodecDeflateInvalidStream,
            "invalid transform stream",
        );

        let error =
            SourceSnapshot::private_derived_from_reader(StructuredFailure(finding.clone()), 1024)
                .unwrap_err();

        assert_eq!(error, finding);
    }
}
