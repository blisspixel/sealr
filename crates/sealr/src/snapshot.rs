use std::borrow::Cow;

use serde::Serialize;

use crate::findings::{Finding, FindingCode};
use crate::outcome::SourceDigest;
use crate::policy::hex_sha256;

/// How this invocation holds the exact archive bytes.
///
/// Bounded random-access and content-addressed snapshots come later. They must
/// preserve the same property: parse, verify, and materialize observe one
/// immutable byte object whose digest was recorded at ingest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
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

    #[allow(dead_code)]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn path_owned(&self) -> Option<String> {
        self.path.clone()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[allow(dead_code)]
    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    #[allow(dead_code)]
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

    /// Checked random-access read over the recorded bytes.
    pub fn range(&self, offset: u64, len: u64) -> Result<&[u8], Finding> {
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
        self.bytes.get(start..end).ok_or_else(|| {
            Finding::error(FindingCode::ZipDiffC4Offset, "range extends past snapshot")
        })
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
