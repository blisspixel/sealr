//! Codec-free covering checker.
//!
//! This is a range oracle over a claimed `ArchiveIR`. It does not search for an
//! EOCD, inflate payloads, or jail names. If it re-parsed ZIP, it would be a
//! second parser.

use crate::findings::{Finding, FindingCode};
use crate::ir::{ArchiveIR, ByteRange};
use crate::snapshot::SourceSnapshot;

const LFH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const CDH_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];

/// Check that `ir.covering` is a labeled partition of `snapshot` with the
/// claimed member header signatures at the recorded offsets.
pub fn audit_covering(snapshot: &SourceSnapshot<'_>, ir: &ArchiveIR) -> Result<(), Finding> {
    let digest = snapshot.digest();
    if ir.source_digest != *digest {
        return Err(inconsistent("source digest does not match the snapshot"));
    }

    let covering = &ir.covering;
    if covering.local_records.offset != 0 {
        return Err(inconsistent("local-record covering must start at offset 0"));
    }
    if covering.eocd.len != 22 {
        return Err(inconsistent("EOCD covering length must be 22"));
    }
    if covering.local_records.end() != covering.central_directory.offset {
        return Err(inconsistent(
            "local records do not abut the central directory",
        ));
    }
    if covering.central_directory.end() != covering.eocd.offset {
        return Err(inconsistent("central directory does not abut the EOCD"));
    }
    if covering.eocd.end() != covering.comment.offset {
        return Err(inconsistent("EOCD does not abut its comment"));
    }
    if covering.comment.end() != snapshot.len() {
        return Err(inconsistent(
            "covering comment end is not the snapshot length",
        ));
    }

    let _ = checked_end(covering.local_records, "local-record covering")?;
    let _ = checked_end(covering.central_directory, "central-directory covering")?;
    let _ = checked_end(covering.eocd, "EOCD covering")?;
    let _ = checked_end(covering.comment, "comment covering")?;

    let eocd = snapshot
        .range(covering.eocd.offset, covering.eocd.len)
        .map_err(|_| inconsistent("claimed EOCD range is outside the snapshot"))?;
    if eocd[0..4] != EOCD_SIG {
        return Err(inconsistent(
            "claimed EOCD offset does not hold an EOCD signature",
        ));
    }
    let this_disk = le_u16(eocd, 4);
    let cd_disk = le_u16(eocd, 6);
    let this_count = le_u16(eocd, 8);
    let total_count = le_u16(eocd, 10);
    let cd_size = u64::from(le_u32(eocd, 12));
    let cd_offset = u64::from(le_u32(eocd, 16));
    let comment_len = u64::from(le_u16(eocd, 20));
    if this_disk != 0 || cd_disk != 0 {
        return Err(inconsistent("EOCD names a spanned archive"));
    }
    if this_count != total_count {
        return Err(inconsistent(
            "EOCD this-disk count does not match total count",
        ));
    }
    if u64::from(total_count) != ir.members.len() as u64 {
        return Err(inconsistent(
            "EOCD entry count does not match the IR member list",
        ));
    }
    if cd_offset != covering.central_directory.offset {
        return Err(inconsistent(
            "EOCD central-directory offset does not match the covering",
        ));
    }
    if cd_size != covering.central_directory.len {
        return Err(inconsistent(
            "EOCD central-directory size does not match the covering",
        ));
    }
    if comment_len != covering.comment.len {
        return Err(inconsistent(
            "EOCD comment length does not match the covering",
        ));
    }

    let mut local_ranges: Vec<(u64, u64)> = Vec::new();
    let mut central_ranges: Vec<(u64, u64)> = Vec::new();
    for member in &ir.members {
        for (range, label) in [
            (member.source_ranges.local_header, "local header"),
            (
                member.source_ranges.compressed_payload,
                "compressed payload",
            ),
            (member.source_ranges.central_header, "central header"),
        ] {
            let _ =
                checked_end(range, label).map_err(|finding| finding.on(&member.decoded_name))?;
        }
        if let Some(descriptor) = member.source_ranges.data_descriptor {
            let _ = checked_end(descriptor, "data descriptor")
                .map_err(|finding| finding.on(&member.decoded_name))?;
        }
        if member.source_ranges.local_header.len < 30 {
            return Err(
                inconsistent("local header is shorter than 30 bytes").on(&member.decoded_name)
            );
        }
        if member.source_ranges.central_header.len < 46 {
            return Err(
                inconsistent("central header is shorter than 46 bytes").on(&member.decoded_name)
            );
        }
        let lfh = snapshot
            .range(member.source_ranges.local_header.offset, 4)
            .map_err(|_| {
                inconsistent("claimed LFH range is outside the snapshot").on(&member.decoded_name)
            })?;
        if lfh != LFH_SIG {
            return Err(
                inconsistent("claimed LFH offset does not hold a local-header signature")
                    .on(&member.decoded_name),
            );
        }
        let cdh = snapshot
            .range(member.source_ranges.central_header.offset, 4)
            .map_err(|_| {
                inconsistent("claimed CDH range is outside the snapshot").on(&member.decoded_name)
            })?;
        if cdh != CDH_SIG {
            return Err(inconsistent(
                "claimed CDH offset does not hold a central-directory signature",
            )
            .on(&member.decoded_name));
        }
        if !contains_range(
            covering.central_directory,
            member.source_ranges.central_header,
        ) {
            return Err(
                inconsistent("central header is outside the CD covering").on(&member.decoded_name)
            );
        }
        if member.source_ranges.local_header.end() != member.source_ranges.compressed_payload.offset
        {
            return Err(
                inconsistent("local header does not abut its payload").on(&member.decoded_name)
            );
        }
        if let Some(descriptor) = member.source_ranges.data_descriptor {
            if member.source_ranges.compressed_payload.end() != descriptor.offset {
                return Err(inconsistent("payload does not abut its data descriptor")
                    .on(&member.decoded_name));
            }
        }
        let local_start = member.source_ranges.local_header.offset;
        let local_end = member.source_ranges.record_end();
        if local_start >= local_end {
            return Err(inconsistent("empty local record range").on(&member.decoded_name));
        }
        let local_len = local_end.checked_sub(local_start).ok_or_else(|| {
            inconsistent("local record length underflow").on(&member.decoded_name)
        })?;
        let local_record = ByteRange {
            offset: local_start,
            len: local_len,
        };
        if !contains_range(covering.local_records, local_record) {
            return Err(
                inconsistent("local record is outside the local covering").on(&member.decoded_name)
            );
        }
        if !contains_range(local_record, member.source_ranges.compressed_payload) {
            return Err(
                inconsistent("payload range is outside its local record").on(&member.decoded_name)
            );
        }
        if let Some(descriptor) = member.source_ranges.data_descriptor {
            if !contains_range(local_record, descriptor) {
                return Err(inconsistent("data descriptor is outside its local record")
                    .on(&member.decoded_name));
            }
        }
        local_ranges.push((local_start, local_end));
        central_ranges.push((
            member.source_ranges.central_header.offset,
            member.source_ranges.central_header.end(),
        ));
    }

    local_ranges.sort_by_key(|range| range.0);
    central_ranges.sort_by_key(|range| range.0);
    if local_ranges.is_empty() {
        if covering.local_records.len != 0 {
            return Err(inconsistent(
                "empty member list has a nonempty local covering",
            ));
        }
        if covering.central_directory.len != 0 {
            return Err(inconsistent(
                "empty member list has a nonempty central covering",
            ));
        }
        return Ok(());
    }
    if local_ranges[0].0 != covering.local_records.offset {
        return Err(inconsistent(
            "first local record does not start the local covering",
        ));
    }
    for window in local_ranges.windows(2) {
        if window[0].1 != window[1].0 {
            return Err(inconsistent(
                "local records do not form a partition of the covering",
            ));
        }
    }
    if local_ranges.last().expect("nonempty").1 != covering.local_records.end() {
        return Err(inconsistent(
            "last local record does not end the local covering",
        ));
    }
    if central_ranges[0].0 != covering.central_directory.offset {
        return Err(inconsistent(
            "first central header does not start the CD covering",
        ));
    }
    for window in central_ranges.windows(2) {
        if window[0].1 != window[1].0 {
            return Err(inconsistent(
                "central headers do not form a partition of the covering",
            ));
        }
    }
    if central_ranges.last().expect("nonempty").1 != covering.central_directory.end() {
        return Err(inconsistent(
            "last central header does not end the CD covering",
        ));
    }
    Ok(())
}

fn contains_range(outer: ByteRange, inner: ByteRange) -> bool {
    inner.offset >= outer.offset && inner.end() <= outer.end()
}

fn checked_end(range: ByteRange, what: &str) -> Result<u64, Finding> {
    range
        .offset
        .checked_add(range.len)
        .ok_or_else(|| inconsistent(&format!("{what} overflow")))
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn inconsistent(detail: &str) -> Finding {
    Finding::error(FindingCode::CoveringInconsistent, detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::{apply, Request, Source};
    use crate::findings::Finding;
    use crate::ir::ArchiveIR;
    use crate::policy::Policy;
    use std::io::{Cursor, Write};

    fn make_zip() -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ::zip::ZipWriter::new(&mut cursor);
            let options = ::zip::write::SimpleFileOptions::default()
                .compression_method(::zip::CompressionMethod::Stored);
            writer.start_file("hello.txt", options).unwrap();
            writer.write_all(b"hello").unwrap();
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    #[test]
    fn admitted_inspect_covering_matches_the_snapshot() {
        let bytes = make_zip();
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("cover.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });
        assert!(!out.rejected(), "{:?}", out.view.findings);
        let ir = out.archive_ir.as_ref().unwrap();
        let snapshot = crate::snapshot::SourceSnapshot::borrowed(None, &bytes);
        audit_covering(&snapshot, ir).expect("covering should certify the snapshot");
    }

    #[test]
    fn covering_rejects_a_snapshot_that_is_not_the_source() {
        let bytes = make_zip();
        let ir = admitted_ir(&bytes);
        let mut other = bytes.clone();
        other[0] ^= 0xff;
        let snapshot = crate::snapshot::SourceSnapshot::borrowed(None, &other);
        let error = audit_covering(&snapshot, &ir).unwrap_err();
        assert_eq!(error.code, FindingCode::CoveringInconsistent);
    }

    fn admitted_ir(bytes: &[u8]) -> ArchiveIR {
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("cover.zip"),
                data: bytes,
            },
            policy: &policy,
            dest: None,
        });
        assert!(!out.rejected(), "{:?}", out.view.findings);
        out.archive_ir.expect("admitted inspect has IR")
    }

    fn covering_error(bytes: &[u8], ir: &ArchiveIR) -> Finding {
        let snapshot = crate::snapshot::SourceSnapshot::borrowed(None, bytes);
        audit_covering(&snapshot, ir).expect_err("mutated covering must fail")
    }

    #[test]
    fn covering_rejects_mutated_interval_claims() {
        let bytes = make_zip();
        let original = admitted_ir(&bytes);

        let mut ir = original.clone();
        ir.covering.comment.len = ir.covering.comment.len.saturating_add(1);
        assert_eq!(
            covering_error(&bytes, &ir).code,
            FindingCode::CoveringInconsistent
        );

        let mut ir = original.clone();
        ir.covering.eocd.len = 23;
        assert_eq!(
            covering_error(&bytes, &ir).code,
            FindingCode::CoveringInconsistent
        );

        let mut ir = original.clone();
        ir.members[0].source_ranges.local_header.offset =
            ir.members[0].source_ranges.central_header.offset;
        assert_eq!(
            covering_error(&bytes, &ir).code,
            FindingCode::CoveringInconsistent
        );

        let mut ir = original.clone();
        ir.members[0].source_ranges.compressed_payload.len = ir.members[0]
            .source_ranges
            .compressed_payload
            .len
            .saturating_add(1);
        assert_eq!(
            covering_error(&bytes, &ir).code,
            FindingCode::CoveringInconsistent
        );

        let mut ir = original.clone();
        ir.members[0].source_ranges.central_header.len = 45;
        assert_eq!(
            covering_error(&bytes, &ir).code,
            FindingCode::CoveringInconsistent
        );

        let mut ir = original.clone();
        ir.members.clear();
        assert_eq!(
            covering_error(&bytes, &ir).code,
            FindingCode::CoveringInconsistent
        );

        let mut ir = original.clone();
        ir.covering.eocd.offset = u64::MAX;
        assert_eq!(
            covering_error(&bytes, &ir).code,
            FindingCode::CoveringInconsistent
        );

        let mut ir = original;
        ir.members[0].source_ranges.local_header.offset = u64::MAX;
        assert_eq!(
            covering_error(&bytes, &ir).code,
            FindingCode::CoveringInconsistent
        );
    }

    #[test]
    fn empty_archive_covering_is_an_empty_partition() {
        let bytes = {
            let mut cursor = Cursor::new(Vec::new());
            {
                let writer = ::zip::ZipWriter::new(&mut cursor);
                writer.finish().unwrap();
            }
            cursor.into_inner()
        };
        let ir = admitted_ir(&bytes);
        assert!(ir.members.is_empty());
        assert_eq!(ir.covering.local_records.len, 0);
        assert_eq!(ir.covering.central_directory.len, 0);
        let snapshot = crate::snapshot::SourceSnapshot::borrowed(None, &bytes);
        audit_covering(&snapshot, &ir).expect("empty covering should certify the snapshot");
    }
}
