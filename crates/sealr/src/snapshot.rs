use std::borrow::Cow;
use std::io::{self, Read};

use serde::Serialize;

use crate::findings::{Finding, FindingCode};
use crate::outcome::SourceDigest;
use crate::policy::hex_sha256;

/// How this invocation holds the exact archive bytes.
///
/// Current memory backends expose checked random access. File-backed and
/// content-addressed backends come later and must preserve the same property:
/// parse, verify, and materialize observe one immutable byte object whose
/// digest was recorded at ingest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SnapshotKind {
    MemoryOwned,
    MemoryBorrowed,
    Unavailable,
}

/// Immutable archive bytes for one `apply()` invocation.
///
/// Path inputs become process-owned after a bounded read. Caller-borrowed
/// slices stay borrowed for the call. The digest is SHA-256 of exactly these
/// bytes; later reads must not observe a different version.
#[derive(Clone, Debug)]
pub struct SourceSnapshot<'a> {
    path: Option<String>,
    bytes: Cow<'a, [u8]>,
    digest: SourceDigest,
}

impl<'a> SourceSnapshot<'a> {
    pub fn owned(path: Option<String>, bytes: Vec<u8>) -> Self {
        let digest = SourceDigest::available(hex_sha256(&bytes));
        Self {
            path,
            bytes: Cow::Owned(bytes),
            digest,
        }
    }

    pub fn borrowed(path: Option<String>, bytes: &'a [u8]) -> Self {
        let digest = SourceDigest::available(hex_sha256(bytes));
        Self {
            path,
            bytes: Cow::Borrowed(bytes),
            digest,
        }
    }

    #[cfg(test)]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn path_owned(&self) -> Option<String> {
        self.path.clone()
    }

    #[cfg(test)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn digest(&self) -> &SourceDigest {
        &self.digest
    }

    pub fn kind(&self) -> SnapshotKind {
        match self.bytes {
            Cow::Owned(_) => SnapshotKind::MemoryOwned,
            Cow::Borrowed(_) => SnapshotKind::MemoryBorrowed,
        }
    }

    /// Convert this invocation snapshot into process-owned bytes without
    /// copying an already owned path input.
    pub(crate) fn into_owned(self) -> SourceSnapshot<'static> {
        SourceSnapshot {
            path: self.path,
            bytes: Cow::Owned(self.bytes.into_owned()),
            digest: self.digest,
        }
    }

    /// Checked random-access read over the recorded bytes.
    pub fn range(&self, offset: u64, len: u64) -> Result<&[u8], Finding> {
        let (start, end) = self.checked_range(offset, len)?;
        self.bytes.get(start..end).ok_or_else(|| {
            Finding::error(FindingCode::ZipDiffC4Offset, "range extends past snapshot")
        })
    }

    /// Copy one exact checked range into a caller-owned buffer.
    pub(crate) fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Finding> {
        let len = u64::try_from(output.len()).map_err(|_| {
            Finding::error(
                FindingCode::ZipDiffC4Offset,
                "read buffer length does not fit u64",
            )
        })?;
        output.copy_from_slice(self.range(offset, len)?);
        Ok(())
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

    fn checked_range(&self, offset: u64, len: u64) -> Result<(usize, usize), Finding> {
        let start = usize::try_from(offset).map_err(|_| {
            Finding::error(
                FindingCode::ZipDiffC4Offset,
                "range offset does not fit this platform",
            )
        })?;
        let length = usize::try_from(len).map_err(|_| {
            Finding::error(
                FindingCode::ZipDiffC4Offset,
                "range length does not fit this platform",
            )
        })?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| Finding::error(FindingCode::ZipDiffC4Offset, "range end overflows"))?;
        if end > self.bytes.len() {
            return Err(Finding::error(
                FindingCode::ZipDiffC4Offset,
                "range extends past snapshot",
            ));
        }
        Ok((start, end))
    }
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
            .map_err(|finding| io::Error::new(io::ErrorKind::UnexpectedEof, finding.detail))?;
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

    #[test]
    fn borrowed_snapshot_does_not_copy_and_hashes_the_caller_bytes() {
        let data = b"PK\x03\x04hello";
        let snapshot = SourceSnapshot::borrowed(Some("t.zip".into()), data);
        assert_eq!(snapshot.kind(), SnapshotKind::MemoryBorrowed);
        assert_eq!(snapshot.path(), Some("t.zip"));
        assert!(!snapshot.is_empty());
        assert_eq!(snapshot.as_bytes().as_ptr(), data.as_ptr());
        assert_eq!(snapshot.len(), data.len() as u64);
        let digest = hex_sha256(data);
        assert_eq!(snapshot.digest().sha256(), Some(digest.as_str()));
    }

    #[test]
    fn owned_snapshot_isolates_path_bytes() {
        let data = b"owned-archive".to_vec();
        let snapshot = SourceSnapshot::owned(Some("p.zip".into()), data.clone());
        assert_eq!(snapshot.kind(), SnapshotKind::MemoryOwned);
        assert_eq!(snapshot.as_bytes(), data.as_slice());
        let digest = hex_sha256(&data);
        assert_eq!(snapshot.digest().sha256(), Some(digest.as_str()));
    }

    #[test]
    fn range_rejects_past_end_without_panic() {
        let snapshot = SourceSnapshot::borrowed(None, b"abcd");
        let finding = snapshot.range(2, 8).unwrap_err();
        assert_eq!(finding.code, FindingCode::ZipDiffC4Offset);
        assert_eq!(snapshot.range(1, 2).unwrap(), b"bc");
        assert_eq!(snapshot.range(4, 0).unwrap(), b"");
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
        assert_eq!(owned.as_bytes(), data);
        assert_eq!(owned.digest(), &digest);
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
            serde_json::to_value(SnapshotKind::Unavailable).unwrap(),
            serde_json::json!("unavailable")
        );
    }
}
