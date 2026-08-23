//! Codec-free covering checker.
//!
//! This is a range oracle over a claimed `ArchiveIR`. It does not search for an
//! EOCD, inflate payloads, or jail names. If it re-parsed ZIP, it would be a
//! second parser.

use crate::findings::{Finding, FindingCode};
use crate::interval::{CheckedInterval, IntervalError};
use crate::ir::{ArchiveIR, ByteRange};
use crate::snapshot::SourceSnapshot;

const LFH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const CDH_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoveringAuditError<'member> {
    Inconsistent {
        detail: &'static str,
        member: Option<&'member str>,
    },
    AllocationFailed,
}

impl<'member> CoveringAuditError<'member> {
    fn on(self, member: &'member str) -> Self {
        match self {
            Self::Inconsistent { detail, .. } => Self::Inconsistent {
                detail,
                member: Some(member),
            },
            Self::AllocationFailed => Self::AllocationFailed,
        }
    }

    fn into_finding(self) -> Finding {
        match self {
            Self::Inconsistent { detail, member } => {
                let finding = Finding::error(FindingCode::CoveringInconsistent, detail);
                match member {
                    Some(member) => finding.on(member),
                    None => finding,
                }
            }
            Self::AllocationFailed => panic!("bounded covering audit allocation failed"),
        }
    }
}

/// Check that `ir.covering` is a labeled partition of `snapshot` with the
/// claimed member header signatures at the recorded offsets.
pub(crate) fn audit_covering(snapshot: &SourceSnapshot<'_>, ir: &ArchiveIR) -> Result<(), Finding> {
    audit_covering_fallible(snapshot, ir).map_err(CoveringAuditError::into_finding)
}

pub(crate) fn audit_covering_fallible<'member>(
    snapshot: &SourceSnapshot<'_>,
    ir: &'member ArchiveIR,
) -> Result<(), CoveringAuditError<'member>> {
    let digest = snapshot.digest();
    if ir.source_digest != *digest {
        return Err(inconsistent("source digest does not match the snapshot"));
    }

    let covering = &ir.covering;
    let local_cover = checked_interval(covering.local_records, "local-record covering overflow")?;
    let central_cover = checked_interval(
        covering.central_directory,
        "central-directory covering overflow",
    )?;
    let eocd_cover = checked_interval(covering.eocd, "EOCD covering overflow")?;
    let comment_cover = checked_interval(covering.comment, "comment covering overflow")?;

    if local_cover.start() != 0 {
        return Err(inconsistent("local-record covering must start at offset 0"));
    }
    if covering.eocd.len != 22 {
        return Err(inconsistent("EOCD covering length must be 22"));
    }
    if local_cover.end() != central_cover.start() {
        return Err(inconsistent(
            "local records do not abut the central directory",
        ));
    }
    if central_cover.end() != eocd_cover.start() {
        return Err(inconsistent("central directory does not abut the EOCD"));
    }
    if eocd_cover.end() != comment_cover.start() {
        return Err(inconsistent("EOCD does not abut its comment"));
    }
    if comment_cover.end() != snapshot.len() {
        return Err(inconsistent(
            "covering comment end is not the snapshot length",
        ));
    }

    let mut eocd = [0_u8; 22];
    snapshot
        .read_exact_at(covering.eocd.offset, &mut eocd)
        .map_err(|_| inconsistent("claimed EOCD range is outside the snapshot"))?;
    if eocd[0..4] != EOCD_SIG {
        return Err(inconsistent(
            "claimed EOCD offset does not hold an EOCD signature",
        ));
    }
    let this_disk = le_u16(&eocd, 4);
    let cd_disk = le_u16(&eocd, 6);
    let this_count = le_u16(&eocd, 8);
    let total_count = le_u16(&eocd, 10);
    let cd_size = u64::from(le_u32(&eocd, 12));
    let cd_offset = u64::from(le_u32(&eocd, 16));
    let comment_len = u64::from(le_u16(&eocd, 20));
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

    let mut local_ranges = Vec::new();
    local_ranges
        .try_reserve_exact(ir.members.len())
        .map_err(|_| CoveringAuditError::AllocationFailed)?;
    let mut central_ranges = Vec::new();
    central_ranges
        .try_reserve_exact(ir.members.len())
        .map_err(|_| CoveringAuditError::AllocationFailed)?;
    for member in &ir.members {
        let local_header =
            checked_interval(member.source_ranges.local_header, "local header overflow")
                .map_err(|finding| finding.on(&member.decoded_name))?;
        let payload = checked_interval(
            member.source_ranges.compressed_payload,
            "compressed payload overflow",
        )
        .map_err(|finding| finding.on(&member.decoded_name))?;
        let central_header = checked_interval(
            member.source_ranges.central_header,
            "central header overflow",
        )
        .map_err(|finding| finding.on(&member.decoded_name))?;
        let descriptor = member
            .source_ranges
            .data_descriptor
            .map(|range| checked_interval(range, "data descriptor overflow"))
            .transpose()
            .map_err(|finding| finding.on(&member.decoded_name))?;

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
        let mut lfh = [0_u8; 4];
        snapshot
            .read_exact_at(member.source_ranges.local_header.offset, &mut lfh)
            .map_err(|_| {
                inconsistent("claimed LFH range is outside the snapshot").on(&member.decoded_name)
            })?;
        if lfh != LFH_SIG {
            return Err(
                inconsistent("claimed LFH offset does not hold a local-header signature")
                    .on(&member.decoded_name),
            );
        }
        let mut cdh = [0_u8; 4];
        snapshot
            .read_exact_at(member.source_ranges.central_header.offset, &mut cdh)
            .map_err(|_| {
                inconsistent("claimed CDH range is outside the snapshot").on(&member.decoded_name)
            })?;
        if cdh != CDH_SIG {
            return Err(inconsistent(
                "claimed CDH offset does not hold a central-directory signature",
            )
            .on(&member.decoded_name));
        }
        if !central_cover.contains(central_header) {
            return Err(
                inconsistent("central header is outside the CD covering").on(&member.decoded_name)
            );
        }
        if local_header.end() != payload.start() {
            return Err(
                inconsistent("local header does not abut its payload").on(&member.decoded_name)
            );
        }
        if let Some(descriptor) = descriptor {
            if payload.end() != descriptor.start() {
                return Err(inconsistent("payload does not abut its data descriptor")
                    .on(&member.decoded_name));
            }
        }
        let local_end = descriptor.map_or_else(|| payload.end(), CheckedInterval::end);
        let local_record = CheckedInterval::from_bounds(local_header.start(), local_end)
            .map_err(|_| inconsistent("local record length underflow").on(&member.decoded_name))?;
        if local_record.is_empty() {
            return Err(inconsistent("empty local record range").on(&member.decoded_name));
        }
        if !local_cover.contains(local_record) {
            return Err(
                inconsistent("local record is outside the local covering").on(&member.decoded_name)
            );
        }
        if !local_record.contains(payload) {
            return Err(
                inconsistent("payload range is outside its local record").on(&member.decoded_name)
            );
        }
        if let Some(descriptor) = descriptor {
            if !local_record.contains(descriptor) {
                return Err(inconsistent("data descriptor is outside its local record")
                    .on(&member.decoded_name));
            }
        }
        local_ranges.push(local_record);
        central_ranges.push(central_header);
    }

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
    local_ranges.sort_unstable_by_key(|interval| interval.start());
    validate_ordered_partition(
        local_cover,
        &local_ranges,
        "first local record does not start the local covering",
        "last local record does not end the local covering",
        "local records do not form a partition of the covering",
    )?;
    central_ranges.sort_unstable_by_key(|interval| interval.start());
    validate_ordered_partition(
        central_cover,
        &central_ranges,
        "first central header does not start the CD covering",
        "last central header does not end the CD covering",
        "central headers do not form a partition of the covering",
    )?;
    Ok(())
}

fn validate_ordered_partition<'member>(
    outer: CheckedInterval,
    parts: &[CheckedInterval],
    first_gap: &'static str,
    last_gap: &'static str,
    invalid: &'static str,
) -> Result<(), CoveringAuditError<'member>> {
    if parts.is_empty() {
        return if outer.is_empty() {
            Ok(())
        } else {
            Err(inconsistent(invalid))
        };
    }
    if parts
        .iter()
        .any(|part| part.is_empty() || !outer.contains(*part))
    {
        return Err(inconsistent(invalid));
    }
    if parts[0].start() != outer.start() {
        return Err(inconsistent(first_gap));
    }
    if parts
        .windows(2)
        .any(|window| window[0].end() != window[1].start())
    {
        return Err(inconsistent(invalid));
    }
    if parts[parts.len() - 1].end() != outer.end() {
        return Err(inconsistent(last_gap));
    }
    Ok(())
}

fn checked_interval<'member>(
    range: ByteRange,
    overflow_detail: &'static str,
) -> Result<CheckedInterval, CoveringAuditError<'member>> {
    CheckedInterval::from_offset_len(range.offset, range.len).map_err(|error| match error {
        IntervalError::EndOverflow => inconsistent(overflow_detail),
        IntervalError::Reversed => unreachable!("offset-plus-length cannot produce reversal"),
    })
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

fn inconsistent(detail: &'static str) -> CoveringAuditError<'static> {
    CoveringAuditError::Inconsistent {
        detail,
        member: None,
    }
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
        let ir = out.archive_ir().unwrap();
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
        out.archive_ir().cloned().expect("admitted inspect has IR")
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

    #[test]
    #[should_panic(expected = "bounded covering audit allocation failed")]
    fn compatibility_error_conversion_does_not_forge_archive_evidence() {
        let _ = CoveringAuditError::AllocationFailed.into_finding();
    }
}
