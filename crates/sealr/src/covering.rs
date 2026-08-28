//! Codec-free covering checker.
//!
//! This is a range oracle over a claimed `ArchiveIR`. It does not search for an
//! EOCD, inflate payloads, or jail names. If it re-parsed ZIP, it would be a
//! second parser.

use crc32fast::Hasher as Crc;

use crate::findings::{Finding, FindingCode};
use crate::interval::{CheckedInterval, IntervalError};
use crate::ir::{
    ArchiveFormat, ArchiveIR, ByteRange, ExtraDisposition, ExtraSite, GnuLongNamePathSource,
    GzipWrapperEvidence, MemberKind, PaxExtensionEvidence, PaxExtensionKind, PaxKeyword,
    PaxValueSource, Zip64DataDescriptorWidth, Zip64LocalValueShape,
};
use crate::policy::hex_sha256;
use crate::snapshot::SourceSnapshot;

const LFH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const CDH_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const ZIP64_EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
const ZIP64_LOCATOR_SIG: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
const DATA_DESCRIPTOR_SIG: [u8; 4] = [0x50, 0x4b, 0x07, 0x08];
const GZIP_FLAG_HEADER_CRC: u8 = 1 << 1;
const GZIP_FLAG_EXTRA: u8 = 1 << 2;
const GZIP_FLAG_NAME: u8 = 1 << 3;
const GZIP_FLAG_COMMENT: u8 = 1 << 4;
const GZIP_FLAG_RESERVED: u8 = 0b1110_0000;
const TAR_BLOCK_LEN: u64 = 512;
const PAX_MAX_EXTENSION_BYTES: u64 = 64 * 1024;
const PAX_MAX_EXTENSIONS: usize = 1024;
const PAX_MAX_RECORD_LENGTH_DIGITS: usize = 20;
const PAX_MAX_KEYWORD_BYTES: usize = 16;
const PAX_MAX_EFFECTIVE_PATH_BYTES: usize = 8191;
const GNU_MAX_CARRIERS: usize = 1024;
const GNU_MAX_PATH_BYTES: usize = 8191;

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
            Self::AllocationFailed => Finding::error(
                FindingCode::CoveringInconsistent,
                "bounded covering audit could not reserve scratch space",
            ),
        }
    }
}

/// Check that the ZIP covering is a labeled partition of `snapshot` with the
/// claimed member header signatures at the recorded offsets.
pub(crate) fn audit_covering(snapshot: &SourceSnapshot<'_>, ir: &ArchiveIR) -> Result<(), Finding> {
    audit_covering_fallible(snapshot, ir).map_err(CoveringAuditError::into_finding)
}

/// Independently check strict ZIP64 archive and member evidence without
/// invoking the structural parser or a payload codec.
pub(crate) fn audit_zip64_covering(
    snapshot: &SourceSnapshot<'_>,
    ir: &ArchiveIR,
) -> Result<(), Finding> {
    let fail = |detail: &'static str| Finding::error(FindingCode::CoveringInconsistent, detail);
    if ir.format() != ArchiveFormat::Zip64 {
        return Err(fail("ZIP64 covering audit received a non-ZIP64 IR"));
    }
    if ir.source_digest != *snapshot.digest() {
        return Err(fail("source digest does not match the snapshot"));
    }
    let covering = ir
        .zip64_covering()
        .ok_or_else(|| fail("ZIP64 IR has no ZIP64 covering"))?;
    let local_cover = checked_interval(covering.local_records, "local-record covering overflow")
        .map_err(CoveringAuditError::into_finding)?;
    let central_cover = checked_interval(
        covering.central_directory,
        "central-directory covering overflow",
    )
    .map_err(CoveringAuditError::into_finding)?;
    let eocd_end = checked_range_end(covering.eocd, "EOCD covering overflow")?;
    let comment_end = checked_range_end(covering.comment, "comment covering overflow")?;
    if covering.local_records.offset != 0
        || local_cover.end() != central_cover.start()
        || covering.eocd.len != 22
        || eocd_end != covering.comment.offset
        || comment_end != snapshot.len()
    {
        return Err(fail(
            "ZIP64 top-level ranges do not exactly partition the snapshot",
        ));
    }

    let pair = match (covering.zip64_eocd, covering.zip64_locator) {
        (None, None) => None,
        (Some(record), Some(locator)) => Some((record, locator)),
        _ => return Err(fail("ZIP64 end-record evidence is only partially present")),
    };
    let expected_after_cd = pair.map_or(covering.eocd.offset, |(record, _)| record.offset);
    if central_cover.end() != expected_after_cd {
        return Err(fail(
            "ZIP64 central directory does not abut the next end record",
        ));
    }

    let mut eocd = [0_u8; 22];
    snapshot
        .read_exact_at(covering.eocd.offset, &mut eocd)
        .map_err(|_| fail("claimed ZIP64 classic EOCD is outside the snapshot"))?;
    if eocd[0..4] != EOCD_SIG || le_u16(&eocd, 4) != 0 || le_u16(&eocd, 6) != 0 {
        return Err(fail("claimed ZIP64 classic EOCD is invalid or spanned"));
    }
    if u64::from(le_u16(&eocd, 20)) != covering.comment.len {
        return Err(fail(
            "ZIP64 EOCD comment length does not match the covering",
        ));
    }
    let classic_count_disk = le_u16(&eocd, 8);
    let classic_count_total = le_u16(&eocd, 10);
    let classic_cd_size = le_u32(&eocd, 12);
    let classic_cd_offset = le_u32(&eocd, 16);
    let resolved_count = ir.members.len() as u64;
    let mut zip64_end_version_needed = None;

    if let Some((record_range, locator_range)) = pair {
        if record_range.len != 56
            || locator_range.len != 20
            || checked_range_end(record_range, "ZIP64 EOCD range overflow")? != locator_range.offset
            || checked_range_end(locator_range, "ZIP64 locator range overflow")?
                != covering.eocd.offset
        {
            return Err(fail("ZIP64 end pair does not have fixed adjacent geometry"));
        }
        let mut record = [0_u8; 56];
        let mut locator = [0_u8; 20];
        snapshot
            .read_exact_at(record_range.offset, &mut record)
            .map_err(|_| fail("claimed ZIP64 EOCD is outside the snapshot"))?;
        snapshot
            .read_exact_at(locator_range.offset, &mut locator)
            .map_err(|_| fail("claimed ZIP64 locator is outside the snapshot"))?;
        if record[0..4] != ZIP64_EOCD_SIG
            || le_u64(&record, 4) != 44
            || le_u32(&record, 16) != 0
            || le_u32(&record, 20) != 0
            || le_u64(&record, 24) != resolved_count
            || le_u64(&record, 32) != resolved_count
            || le_u64(&record, 40) != covering.central_directory.len
            || le_u64(&record, 48) != covering.central_directory.offset
        {
            return Err(fail("ZIP64 EOCD disagrees with the represented archive"));
        }
        zip64_end_version_needed = Some(le_u16(&record, 14));
        if locator[0..4] != ZIP64_LOCATOR_SIG
            || le_u32(&locator, 4) != 0
            || le_u64(&locator, 8) != record_range.offset
            || le_u32(&locator, 16) != 1
        {
            return Err(fail("ZIP64 locator disagrees with the represented archive"));
        }
        let has_sentinel = classic_count_disk == u16::MAX
            || classic_count_total == u16::MAX
            || classic_cd_size == u32::MAX
            || classic_cd_offset == u32::MAX;
        if !has_sentinel
            || !canonical_end_u16(classic_count_disk, resolved_count)
            || !canonical_end_u16(classic_count_total, resolved_count)
            || !canonical_end_u32(classic_cd_size, covering.central_directory.len)
            || !canonical_end_u32(classic_cd_offset, covering.central_directory.offset)
        {
            return Err(fail(
                "classic EOCD is not canonical for the ZIP64 end record",
            ));
        }
    } else if u64::from(classic_count_disk) != resolved_count
        || u64::from(classic_count_total) != resolved_count
        || u64::from(classic_cd_size) != covering.central_directory.len
        || u64::from(classic_cd_offset) != covering.central_directory.offset
    {
        return Err(fail(
            "classic EOCD disagrees with member-only ZIP64 evidence",
        ));
    }

    let mut local_ranges = Vec::new();
    local_ranges
        .try_reserve_exact(ir.members.len())
        .map_err(|_| fail("ZIP64 covering audit could not reserve local ranges"))?;
    let mut central_ranges = Vec::new();
    central_ranges
        .try_reserve_exact(ir.members.len())
        .map_err(|_| fail("ZIP64 covering audit could not reserve central ranges"))?;
    for member in &ir.members {
        let zip64 = member
            .zip64_evidence()
            .ok_or_else(|| fail("ZIP64 member lacks ZIP64 evidence").on(&member.decoded_name))?;
        let zip = &zip64.zip;
        let ranges = &zip.source_ranges;
        let local_header = checked_interval(ranges.local_header, "ZIP64 local header overflow")
            .map_err(CoveringAuditError::into_finding)?;
        let payload = checked_interval(ranges.compressed_payload, "ZIP64 payload overflow")
            .map_err(CoveringAuditError::into_finding)?;
        let central_header = checked_interval(ranges.central_header, "ZIP64 CDH overflow")
            .map_err(CoveringAuditError::into_finding)?;
        let descriptor = ranges
            .data_descriptor
            .map(|range| checked_interval(range, "ZIP64 descriptor overflow"))
            .transpose()
            .map_err(CoveringAuditError::into_finding)?;
        if ranges.local_header.len < 30 || ranges.central_header.len < 46 {
            return Err(
                fail("ZIP64 member header range is shorter than its fixed header")
                    .on(&member.decoded_name),
            );
        }
        let mut local = [0_u8; 30];
        let mut central = [0_u8; 46];
        snapshot
            .read_exact_at(ranges.local_header.offset, &mut local)
            .map_err(|_| fail("claimed ZIP64 LFH is outside the snapshot"))?;
        snapshot
            .read_exact_at(ranges.central_header.offset, &mut central)
            .map_err(|_| fail("claimed ZIP64 CDH is outside the snapshot"))?;
        if local[0..4] != LFH_SIG || central[0..4] != CDH_SIG {
            return Err(
                fail("claimed ZIP64 member header signature is invalid").on(&member.decoded_name)
            );
        }
        let local_name_len = u64::from(le_u16(&local, 26));
        let local_extra_len = u64::from(le_u16(&local, 28));
        let central_name_len = u64::from(le_u16(&central, 28));
        let central_extra_len = u64::from(le_u16(&central, 30));
        let central_comment_len = u64::from(le_u16(&central, 32));
        if ranges.local_header.len != 30 + local_name_len + local_extra_len
            || ranges.central_header.len
                != 46 + central_name_len + central_extra_len + central_comment_len
            || local_header.end() != payload.start()
            || ranges.compressed_payload.len != zip.declared_comp_size
            || !local_cover.contains(local_header)
            || !central_cover.contains(central_header)
        {
            return Err(
                fail("ZIP64 member ranges disagree with encoded header lengths")
                    .on(&member.decoded_name),
            );
        }
        if le_u16(&local, 4) != zip64.local_version_needed
            || le_u16(&central, 6) != zip64.central_version_needed
        {
            return Err(
                fail("ZIP64 member version evidence disagrees with the source")
                    .on(&member.decoded_name),
            );
        }
        let central_legacy_mask = u8::from(le_u32(&central, 24) == u32::MAX)
            | (u8::from(le_u32(&central, 20) == u32::MAX) << 1)
            | (u8::from(le_u32(&central, 42) == u32::MAX) << 2);
        let local_legacy_mask = u8::from(le_u32(&local, 22) == u32::MAX)
            | (u8::from(le_u32(&local, 18) == u32::MAX) << 1);
        if central_legacy_mask != zip64.central_legacy_sentinel_mask
            || local_legacy_mask != zip64.local_legacy_sentinel_mask
        {
            return Err(
                fail("ZIP64 legacy sentinel evidence disagrees with the source")
                    .on(&member.decoded_name),
            );
        }
        audit_zip64_common_member(snapshot, member, &local, &central, pair.is_some())?;
        audit_zip64_extras(snapshot, member, &local, &central)?;
        audit_zip64_descriptor(snapshot, member)?;

        let local_end = descriptor.map_or_else(|| payload.end(), CheckedInterval::end);
        if descriptor.is_some_and(|value| payload.end() != value.start()) {
            return Err(fail("ZIP64 payload does not abut its descriptor").on(&member.decoded_name));
        }
        local_ranges.push(
            CheckedInterval::from_bounds(local_header.start(), local_end)
                .map_err(|_| fail("ZIP64 local record range underflows"))?,
        );
        central_ranges.push(central_header);
    }

    if let Some(version_needed) = zip64_end_version_needed {
        let maximum_member_version = ir
            .members
            .iter()
            .filter_map(|member| member.zip64_evidence())
            .map(|evidence| evidence.central_version_needed)
            .max()
            .unwrap_or(0);
        if version_needed != 45
            && (maximum_member_version == 0 || version_needed != maximum_member_version)
        {
            return Err(fail(
                "ZIP64 EOCD extraction version is neither 4.5 nor the maximum member version",
            ));
        }
    }

    local_ranges.sort_unstable_by_key(|interval| interval.start());
    central_ranges.sort_unstable_by_key(|interval| interval.start());
    validate_ordered_partition(
        local_cover,
        &local_ranges,
        "first ZIP64 local record does not start the covering",
        "last ZIP64 local record does not end the covering",
        "ZIP64 local records do not partition the covering",
    )
    .map_err(CoveringAuditError::into_finding)?;
    validate_ordered_partition(
        central_cover,
        &central_ranges,
        "first ZIP64 central header does not start the covering",
        "last ZIP64 central header does not end the covering",
        "ZIP64 central headers do not partition the covering",
    )
    .map_err(CoveringAuditError::into_finding)?;
    Ok(())
}

fn audit_zip64_common_member(
    snapshot: &SourceSnapshot<'_>,
    member: &crate::ir::IrMember,
    local: &[u8; 30],
    central: &[u8; 46],
    has_global_end_pair: bool,
) -> Result<(), Finding> {
    let fail = |detail: &'static str| {
        Finding::error(FindingCode::CoveringInconsistent, detail).on(&member.decoded_name)
    };
    let zip64 = member
        .zip64_evidence()
        .ok_or_else(|| fail("ZIP64 member lacks ZIP64 evidence"))?;
    let zip = &zip64.zip;
    let local_flags = le_u16(local, 6);
    let central_flags = le_u16(central, 8);
    let local_method = le_u16(local, 8);
    let central_method = le_u16(central, 10);
    if local_flags != zip.flags
        || central_flags != zip.flags
        || local_method != zip.method
        || central_method != zip.method
        || !matches!(zip.flags, 0 | 0x0008)
        || !matches!(zip.method, 0 | 8)
    {
        return Err(fail(
            "ZIP64 common method or flag evidence disagrees with the source",
        ));
    }
    if le_u32(central, 16) != zip.declared_crc
        || le_u16(central, 34) != 0
        || (le_u16(central, 4) >> 8) as u8 != zip.creator_system
        || le_u32(central, 38) != zip.external_attributes
    {
        return Err(fail(
            "ZIP64 common central-directory evidence disagrees with the source",
        ));
    }

    let local_name_offset = zip
        .source_ranges
        .local_header
        .offset
        .checked_add(30)
        .ok_or_else(|| fail("ZIP64 local name offset overflows"))?;
    let central_name_offset = zip
        .source_ranges
        .central_header
        .offset
        .checked_add(46)
        .ok_or_else(|| fail("ZIP64 central name offset overflows"))?;
    let local_name = snapshot
        .read_vec(local_name_offset, u64::from(le_u16(local, 26)))
        .map_err(|_| fail("ZIP64 local name is outside the snapshot"))?;
    let central_name = snapshot
        .read_vec(central_name_offset, u64::from(le_u16(central, 28)))
        .map_err(|_| fail("ZIP64 central name is outside the snapshot"))?;
    if local_name != member.raw_name_bytes
        || central_name != member.raw_name_bytes
        || !member.raw_name_bytes.is_ascii()
        || member.decoded_name.as_bytes() != member.raw_name_bytes
    {
        return Err(fail("ZIP64 member name evidence disagrees with the source"));
    }
    let source_is_directory = member.raw_name_bytes.ends_with(b"/");
    if source_is_directory != matches!(member.kind, MemberKind::Directory) {
        return Err(fail("ZIP64 member kind disagrees with its source name"));
    }
    let dos_directory = zip.external_attributes & 0x10 != 0;
    let unix_kind = (zip.external_attributes >> 16) & 0xf000;
    let attribute_is_directory = dos_directory || unix_kind == 0x4000;
    let attribute_is_regular = unix_kind == 0x8000;
    let attribute_is_special = unix_kind != 0 && unix_kind != 0x4000 && unix_kind != 0x8000;
    if attribute_is_special
        || (attribute_is_directory && attribute_is_regular)
        || (attribute_is_directory != source_is_directory
            && (attribute_is_directory || attribute_is_regular))
        || (source_is_directory
            && (zip.declared_comp_size != 0
                || member.declared_uncomp_size != 0
                || zip.method != 0
                || zip.declared_crc != 0))
    {
        return Err(fail(
            "ZIP64 directory metadata disagrees with the admitted member kind",
        ));
    }

    let local_crc = le_u32(local, 14);
    let local_comp = le_u32(local, 18);
    let local_uncomp = le_u32(local, 22);
    let uses_descriptor = zip.flags & 0x0008 != 0;
    if (!uses_descriptor && local_crc != zip.declared_crc)
        || (uses_descriptor && local_crc != 0 && local_crc != zip.declared_crc)
    {
        return Err(fail("ZIP64 local CRC evidence disagrees with the source"));
    }
    match zip64.local_value_shape {
        Zip64LocalValueShape::Absent => {
            let sizes_match = if uses_descriptor {
                (local_comp == 0 || u64::from(local_comp) == zip.declared_comp_size)
                    && (local_uncomp == 0 || u64::from(local_uncomp) == member.declared_uncomp_size)
            } else {
                u64::from(local_comp) == zip.declared_comp_size
                    && u64::from(local_uncomp) == member.declared_uncomp_size
            };
            if zip64.local_zip64_extra.is_some() || !sizes_match {
                return Err(fail(
                    "ZIP64 absent local values disagree with legacy size fields",
                ));
            }
        }
        Zip64LocalValueShape::Exact => {
            let forced = local_uncomp == u32::MAX && local_comp == u32::MAX;
            let canonical = canonical_member_u32(local_uncomp, member.declared_uncomp_size)
                && canonical_member_u32(local_comp, zip.declared_comp_size);
            if zip64.local_zip64_extra.is_none() || (!forced && !canonical) {
                return Err(fail(
                    "ZIP64 exact local values disagree with legacy size fields",
                ));
            }
        }
        Zip64LocalValueShape::StreamingZeros => {
            if !uses_descriptor
                || zip64.local_zip64_extra.is_none()
                || local_uncomp != u32::MAX
                || local_comp != u32::MAX
            {
                return Err(fail(
                    "ZIP64 zero streaming values disagree with legacy placeholders",
                ));
            }
        }
        Zip64LocalValueShape::StreamingMaxima => {
            if !uses_descriptor
                || zip64.local_zip64_extra.is_none()
                || local_uncomp != 0
                || local_comp != 0
            {
                return Err(fail(
                    "ZIP64 maximum streaming values disagree with legacy placeholders",
                ));
            }
        }
    }

    if zip64.local_zip64_extra.is_some() && zip64.local_version_needed < 45 {
        return Err(fail("ZIP64 local extra requires extraction version 4.5"));
    }
    let central_legacy_comp = le_u32(central, 20);
    let central_legacy_uncomp = le_u32(central, 24);
    let central_legacy_offset = le_u32(central, 42);
    let standard_offset_only = zip64.central_presence_mask == 0b100
        && u64::from(central_legacy_uncomp) == member.declared_uncomp_size
        && u64::from(central_legacy_comp) == zip.declared_comp_size
        && matches!(
            (zip.method, zip64.central_version_needed),
            (0, 10) | (8, 20)
        );
    let go_offset_only = zip64.central_presence_mask == 0b111
        && central_legacy_uncomp == u32::MAX
        && central_legacy_comp == u32::MAX
        && zip64.central_version_needed == 20
        && matches!(zip.method, 0 | 8);
    let offset_only = has_global_end_pair
        && (standard_offset_only || go_offset_only)
        && central_legacy_offset == u32::MAX
        && member.declared_uncomp_size < u64::from(u32::MAX)
        && zip.declared_comp_size < u64::from(u32::MAX)
        && zip.source_ranges.local_header.offset >= u64::from(u32::MAX);
    if zip64.central_zip64_extra.is_some() && zip64.central_version_needed < 45 && !offset_only {
        return Err(fail(
            "ZIP64 central evidence has no admitted low-version offset-only shape",
        ));
    }
    let expected_descriptor_width = uses_descriptor.then_some(
        if zip64.local_zip64_extra.is_some()
            || zip.declared_comp_size >= u64::from(u32::MAX)
            || member.declared_uncomp_size >= u64::from(u32::MAX)
        {
            Zip64DataDescriptorWidth::Zip64
        } else {
            Zip64DataDescriptorWidth::Zip32
        },
    );
    if zip64.descriptor_width != expected_descriptor_width {
        return Err(fail(
            "ZIP64 descriptor-width evidence is not canonical for the member",
        ));
    }
    Ok(())
}

fn canonical_member_u32(legacy: u32, resolved: u64) -> bool {
    if resolved < u64::from(u32::MAX) {
        u64::from(legacy) == resolved
    } else {
        legacy == u32::MAX
    }
}

/// Independently check the exact RFC 1952 wrapper partition and recorded
/// fixed fields without invoking a compression codec.
pub(crate) fn audit_gzip_wrapper_covering(
    snapshot: &SourceSnapshot<'_>,
    evidence: &GzipWrapperEvidence,
) -> Result<(), Finding> {
    let fail = |detail: &'static str| Finding::error(FindingCode::CoveringInconsistent, detail);
    let header_end = checked_range_end(evidence.header, "gzip header range overflow")?;
    let payload_end = checked_range_end(
        evidence.compressed_payload,
        "gzip compressed payload range overflow",
    )?;
    let trailer_end = checked_range_end(evidence.trailer, "gzip trailer range overflow")?;
    if evidence.header.offset != 0
        || evidence.header.len < 10
        || evidence.compressed_payload.offset != header_end
        || evidence.trailer.offset != payload_end
        || evidence.trailer.len != 8
        || trailer_end != snapshot.len()
    {
        return Err(fail(
            "gzip ranges do not exactly partition the original snapshot",
        ));
    }

    let mut fixed = [0_u8; 10];
    snapshot
        .read_exact_at(0, &mut fixed)
        .map_err(|_| fail("gzip fixed header is outside the original snapshot"))?;
    if fixed[..3] != [0x1f, 0x8b, 8]
        || fixed[3] & GZIP_FLAG_RESERVED != 0
        || fixed[3] != evidence.flags
        || le_u32(&fixed, 4) != evidence.modification_time
        || fixed[8] != evidence.extra_flags
        || fixed[9] != evidence.operating_system
    {
        return Err(fail("gzip fixed header disagrees with wrapper evidence"));
    }

    let mut cursor = 10_u64;
    if evidence.flags & GZIP_FLAG_EXTRA != 0 {
        let extra = evidence
            .extra
            .ok_or_else(|| fail("gzip FEXTRA flag has no range evidence"))?;
        if extra.offset != cursor || extra.len < 2 {
            return Err(fail("gzip FEXTRA range is not canonical"));
        }
        let mut xlen = [0_u8; 2];
        snapshot
            .read_exact_at(cursor, &mut xlen)
            .map_err(|_| fail("gzip FEXTRA XLEN is outside the original snapshot"))?;
        if u64::from(u16::from_le_bytes(xlen)) + 2 != extra.len {
            return Err(fail("gzip FEXTRA XLEN disagrees with its range"));
        }
        let extra_end = checked_range_end(extra, "gzip FEXTRA range overflow")?;
        let mut subfield_cursor = cursor + 2;
        let mut count = 0_u32;
        let mut seen = [0_u64; 1024];
        while subfield_cursor < extra_end {
            if extra_end - subfield_cursor < 4 {
                return Err(fail("gzip FEXTRA has an incomplete subfield header"));
            }
            let mut subfield = [0_u8; 4];
            snapshot
                .read_exact_at(subfield_cursor, &mut subfield)
                .map_err(|_| fail("gzip FEXTRA subfield header is outside the snapshot"))?;
            if subfield[1] == 0 {
                return Err(fail("gzip FEXTRA subfield uses reserved SI2 zero"));
            }
            let id = u16::from_le_bytes([subfield[0], subfield[1]]);
            let word = usize::from(id / 64);
            let bit = u32::from(id % 64);
            if seen[word] & (1_u64 << bit) != 0 {
                return Err(fail("gzip FEXTRA repeats a subfield ID"));
            }
            seen[word] |= 1_u64 << bit;
            let subfield_end = subfield_cursor
                .checked_add(4)
                .and_then(|value| {
                    value.checked_add(u64::from(u16::from_le_bytes([subfield[2], subfield[3]])))
                })
                .ok_or_else(|| fail("gzip FEXTRA subfield range overflow"))?;
            if subfield_end > extra_end {
                return Err(fail("gzip FEXTRA subfield exceeds XLEN"));
            }
            count = count
                .checked_add(1)
                .ok_or_else(|| fail("gzip FEXTRA subfield count overflow"))?;
            subfield_cursor = subfield_end;
        }
        if count != evidence.extra_subfield_count {
            return Err(fail("gzip FEXTRA subfield count disagrees with evidence"));
        }
        cursor = extra_end;
    } else if evidence.extra.is_some() || evidence.extra_subfield_count != 0 {
        return Err(fail("gzip FEXTRA evidence is present without its flag"));
    }

    cursor = audit_gzip_c_string(
        snapshot,
        cursor,
        header_end,
        evidence.flags & GZIP_FLAG_NAME != 0,
        evidence.original_name,
        "gzip FNAME evidence is inconsistent",
    )?;
    cursor = audit_gzip_c_string(
        snapshot,
        cursor,
        header_end,
        evidence.flags & GZIP_FLAG_COMMENT != 0,
        evidence.comment,
        "gzip FCOMMENT evidence is inconsistent",
    )?;

    if evidence.flags & GZIP_FLAG_HEADER_CRC != 0 {
        let range = evidence
            .header_crc16
            .ok_or_else(|| fail("gzip FHCRC flag has no range evidence"))?;
        if range.offset != cursor || range.len != 2 {
            return Err(fail("gzip FHCRC range is not canonical"));
        }
        let header_bytes = snapshot
            .read_vec(0, cursor)
            .map_err(|_| fail("gzip header bytes are outside the original snapshot"))?;
        let mut actual = Crc::new();
        actual.update(&header_bytes);
        let actual = actual.finalize() as u16;
        let mut declared = [0_u8; 2];
        snapshot
            .read_exact_at(cursor, &mut declared)
            .map_err(|_| fail("gzip FHCRC is outside the original snapshot"))?;
        if u16::from_le_bytes(declared) != actual {
            return Err(fail("gzip FHCRC disagrees with the original header"));
        }
        cursor += 2;
    } else if evidence.header_crc16.is_some() {
        return Err(fail("gzip FHCRC evidence is present without its flag"));
    }
    if cursor != header_end {
        return Err(fail(
            "gzip optional fields do not exactly fill the header range",
        ));
    }

    let mut trailer = [0_u8; 8];
    snapshot
        .read_exact_at(evidence.trailer.offset, &mut trailer)
        .map_err(|_| fail("gzip trailer is outside the original snapshot"))?;
    if le_u32(&trailer, 0) != evidence.declared_crc32
        || le_u32(&trailer, 4) != evidence.declared_isize
        || evidence.declared_isize != gzip_isize(evidence.derived_output_len)
        || evidence.derived_output_sha256.len() != 64
        || !evidence
            .derived_output_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(fail(
            "gzip trailer or derived-output evidence is inconsistent",
        ));
    }
    Ok(())
}

fn gzip_isize(len: u64) -> u32 {
    u32::try_from(len % (u64::from(u32::MAX) + 1)).expect("gzip ISIZE modulo always fits u32")
}

fn audit_gzip_c_string(
    snapshot: &SourceSnapshot<'_>,
    cursor: u64,
    header_end: u64,
    flagged: bool,
    range: Option<ByteRange>,
    detail: &'static str,
) -> Result<u64, Finding> {
    let fail = || Finding::error(FindingCode::CoveringInconsistent, detail);
    if !flagged {
        return if range.is_none() {
            Ok(cursor)
        } else {
            Err(fail())
        };
    }
    let range = range.ok_or_else(fail)?;
    let end = checked_range_end(range, detail)?;
    if range.offset != cursor || range.len == 0 || end > header_end {
        return Err(fail());
    }
    let bytes = snapshot
        .read_vec(range.offset, range.len)
        .map_err(|_| fail())?;
    if bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
        return Err(fail());
    }
    Ok(end)
}

/// Independently check a portable-ustar IR's source partition and recorded
/// member ranges without interpreting names, numeric fields, or payloads.
pub(crate) fn audit_tar_covering(
    snapshot: &SourceSnapshot<'_>,
    ir: &ArchiveIR,
) -> Result<(), Finding> {
    let fail = |detail: &'static str| Finding::error(FindingCode::CoveringInconsistent, detail);
    if !matches!(
        ir.format(),
        ArchiveFormat::TarUstar | ArchiveFormat::TarGzipUstar
    ) {
        return Err(fail("TAR covering audit received a non-TAR IR"));
    }
    match ir.format() {
        ArchiveFormat::TarUstar if ir.source_digest != *snapshot.digest() => {
            return Err(fail("source digest does not match the TAR snapshot"));
        }
        ArchiveFormat::TarGzipUstar => {
            let gzip = ir
                .gzip_evidence()
                .ok_or_else(|| fail("gzip-wrapped TAR IR has no wrapper evidence"))?;
            if gzip.derived_output_len != snapshot.len()
                || snapshot.digest().sha256() != Some(gzip.derived_output_sha256.as_str())
            {
                return Err(fail("derived TAR identity does not match its snapshot"));
            }
        }
        _ => {}
    }
    let covering = ir
        .tar_covering()
        .ok_or_else(|| fail("TAR IR has no TAR covering"))?;
    let member_end = checked_range_end(covering.member_records, "member covering overflow")?;
    let terminator_end = checked_range_end(covering.terminator, "terminator overflow")?;
    let trailing_end = checked_range_end(covering.trailing_zeros, "trailing range overflow")?;
    if covering.member_records.offset != 0
        || covering.terminator.offset != member_end
        || covering.terminator.len != 1024
        || covering.trailing_zeros.offset != terminator_end
        || trailing_end != snapshot.len()
    {
        return Err(fail("TAR covering does not exactly partition the snapshot"));
    }

    let mut expected_header = 0_u64;
    for member in &ir.members {
        if member.format() != ir.format() {
            return Err(
                fail("TAR member evidence variant does not match the archive format")
                    .on(&member.decoded_name),
            );
        }
        let evidence = member.tar_evidence().ok_or_else(|| {
            fail("TAR member lacks format-specific evidence").on(&member.decoded_name)
        })?;
        let header_end = checked_range_end(evidence.header, "TAR header overflow")?;
        let payload_end = checked_range_end(evidence.payload, "TAR payload overflow")?;
        let padding_end = checked_range_end(evidence.padding, "TAR padding overflow")?;
        let expected_padding = (512 - (evidence.payload.len % 512)) % 512;
        if evidence.header.offset != expected_header
            || evidence.header.len != 512
            || evidence.payload.offset != header_end
            || evidence.payload.len != member.declared_uncomp_size
            || evidence.padding.offset != payload_end
            || evidence.padding.len != expected_padding
            || !padding_end.is_multiple_of(512)
            || padding_end > member_end
        {
            return Err(
                fail("TAR member ranges do not form one aligned record").on(&member.decoded_name)
            );
        }
        let mut header = [0_u8; 512];
        snapshot
            .read_exact_at(evidence.header.offset, &mut header)
            .map_err(|_| {
                fail("claimed TAR header is outside the snapshot").on(&member.decoded_name)
            })?;
        if hex_sha256(&header) != evidence.header_sha256 {
            return Err(
                fail("TAR header digest does not match the snapshot").on(&member.decoded_name)
            );
        }
        audit_zero_range(
            snapshot,
            evidence.padding,
            "claimed TAR member padding contains nonzero bytes",
        )
        .map_err(|finding| finding.on(&member.decoded_name))?;
        expected_header = padding_end;
    }
    if expected_header != member_end {
        return Err(fail("TAR member records do not fill their covering"));
    }
    let mut terminator = [1_u8; 1024];
    snapshot
        .read_exact_at(covering.terminator.offset, &mut terminator)
        .map_err(|_| fail("claimed TAR terminator is outside the snapshot"))?;
    if terminator.iter().any(|byte| *byte != 0) {
        return Err(fail("claimed TAR terminator contains nonzero bytes"));
    }
    audit_zero_range(
        snapshot,
        covering.trailing_zeros,
        "claimed TAR trailing record padding contains nonzero bytes",
    )?;
    Ok(())
}

/// Independently check the exact physical partition and PAX override replay
/// for the closed portable PAX profile.
pub(crate) fn audit_tar_pax_covering(
    snapshot: &SourceSnapshot<'_>,
    ir: &ArchiveIR,
) -> Result<(), Finding> {
    let fail = |detail: &'static str| Finding::error(FindingCode::CoveringInconsistent, detail);
    if !matches!(
        ir.format(),
        ArchiveFormat::TarPax | ArchiveFormat::TarGzipPax
    ) {
        return Err(fail("PAX covering audit received a non-PAX IR"));
    }
    match ir.format() {
        ArchiveFormat::TarPax if ir.source_digest != *snapshot.digest() => {
            return Err(fail("source digest does not match the PAX snapshot"));
        }
        ArchiveFormat::TarGzipPax => {
            let gzip = ir
                .gzip_evidence()
                .ok_or_else(|| fail("gzip-wrapped PAX IR has no wrapper evidence"))?;
            if gzip.derived_output_len != snapshot.len()
                || snapshot.digest().sha256() != Some(gzip.derived_output_sha256.as_str())
            {
                return Err(fail("derived PAX identity does not match its snapshot"));
            }
        }
        _ => {}
    }
    let archive = ir
        .tar_pax_evidence()
        .ok_or_else(|| fail("PAX IR has no PAX archive evidence"))?;
    if archive.extensions.len() > PAX_MAX_EXTENSIONS
        || u32::try_from(archive.extensions.len()).is_err()
    {
        return Err(fail(
            "PAX extension evidence exceeds the closed profile cap",
        ));
    }

    let member_end = checked_range_end(
        archive.tar.member_records,
        "PAX member-record covering overflow",
    )?;
    let terminator_end = checked_range_end(archive.tar.terminator, "PAX terminator overflow")?;
    let trailing_end = checked_range_end(
        archive.tar.trailing_zeros,
        "PAX trailing-zero range overflow",
    )?;
    if archive.tar.member_records.offset != 0
        || archive.tar.terminator.offset != member_end
        || archive.tar.terminator.len != TAR_BLOCK_LEN * 2
        || archive.tar.trailing_zeros.offset != terminator_end
        || trailing_end != snapshot.len()
        || !snapshot.len().is_multiple_of(TAR_BLOCK_LEN)
    {
        return Err(fail(
            "PAX top-level ranges do not exactly partition the snapshot",
        ));
    }

    let mut cursor = 0_u64;
    let mut extension_index = 0_usize;
    let mut member_index = 0_usize;
    let mut globals = PaxAuditOverrides::default();
    let mut pending_local: Option<PaxAuditOverrides> = None;
    while cursor < member_end {
        let next_extension = archive.extensions.get(extension_index);
        let next_member = ir.members.get(member_index);
        let extension_here = next_extension.is_some_and(|value| value.header.offset == cursor);
        let member_here = next_member.is_some_and(|value| {
            value
                .tar_pax_evidence()
                .is_some_and(|evidence| evidence.tar.header.offset == cursor)
        });
        match (extension_here, member_here) {
            (true, false) => {
                if pending_local.is_some() {
                    return Err(fail(
                        "local PAX extension is not followed immediately by a member",
                    ));
                }
                let extension = next_extension.expect("extension presence was checked");
                cursor = audit_one_pax_extension(snapshot, extension, cursor, member_end)?;
                let update = PaxAuditOverrides::from_extension(extension, extension_index)?;
                match extension.kind {
                    PaxExtensionKind::Global => globals.update_from(update),
                    PaxExtensionKind::Local => pending_local = Some(update),
                }
                extension_index = extension_index
                    .checked_add(1)
                    .ok_or_else(|| fail("PAX extension index overflowed usize"))?;
            }
            (false, true) => {
                let member = next_member.expect("member presence was checked");
                cursor = audit_one_pax_member(
                    snapshot,
                    member,
                    &archive.extensions,
                    &globals,
                    pending_local.as_ref(),
                    cursor,
                    member_end,
                )?;
                pending_local = None;
                member_index = member_index
                    .checked_add(1)
                    .ok_or_else(|| fail("PAX member index overflowed usize"))?;
            }
            (true, true) => {
                return Err(fail(
                    "PAX extension and member evidence claim the same header block",
                ));
            }
            (false, false) => {
                return Err(fail(
                    "PAX extension and member records do not form a source-ordered partition",
                ));
            }
        }
    }
    if cursor != member_end
        || extension_index != archive.extensions.len()
        || member_index != ir.members.len()
    {
        return Err(fail(
            "PAX extension and member records do not fill their covering",
        ));
    }
    if pending_local.is_some() {
        return Err(fail("local PAX extension has no following member"));
    }

    audit_zero_range(
        snapshot,
        archive.tar.terminator,
        "claimed PAX terminator contains nonzero bytes",
    )?;
    audit_zero_range(
        snapshot,
        archive.tar.trailing_zeros,
        "claimed PAX trailing record padding contains nonzero bytes",
    )?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct PaxAuditOverrides {
    path: Option<PaxValueSource>,
    size: Option<PaxValueSource>,
}

impl PaxAuditOverrides {
    fn from_extension(
        extension: &PaxExtensionEvidence,
        extension_index: usize,
    ) -> Result<Self, Finding> {
        let fail = |detail: &'static str| Finding::error(FindingCode::CoveringInconsistent, detail);
        let extension_index = u32::try_from(extension_index)
            .map_err(|_| fail("PAX extension index does not fit u32"))?;
        let mut state = Self::default();
        for (record_index, record) in extension.records.iter().enumerate() {
            let record_index = u32::try_from(record_index)
                .map_err(|_| fail("PAX record index does not fit u32"))?;
            let source = match extension.kind {
                PaxExtensionKind::Global => PaxValueSource::Global {
                    extension_index,
                    record_index,
                },
                PaxExtensionKind::Local => PaxValueSource::Local {
                    extension_index,
                    record_index,
                },
            };
            match record.keyword {
                PaxKeyword::Path => state.path = Some(source),
                PaxKeyword::Size => state.size = Some(source),
            }
        }
        Ok(state)
    }

    fn update_from(&mut self, update: Self) {
        if update.path.is_some() {
            self.path = update.path;
        }
        if update.size.is_some() {
            self.size = update.size;
        }
    }
}

fn audit_one_pax_extension(
    snapshot: &SourceSnapshot<'_>,
    extension: &PaxExtensionEvidence,
    expected_header: u64,
    covering_end: u64,
) -> Result<u64, Finding> {
    let fail = |detail: &'static str| Finding::error(FindingCode::CoveringInconsistent, detail);
    let header_end = checked_range_end(extension.header, "PAX extension header overflow")?;
    let payload_end = checked_range_end(extension.payload, "PAX extension payload overflow")?;
    let padding_end = checked_range_end(extension.padding, "PAX extension padding overflow")?;
    let expected_padding =
        (TAR_BLOCK_LEN - (extension.payload.len % TAR_BLOCK_LEN)) % TAR_BLOCK_LEN;
    if extension.header.offset != expected_header
        || extension.header.len != TAR_BLOCK_LEN
        || extension.payload.offset != header_end
        || extension.payload.len > PAX_MAX_EXTENSION_BYTES
        || extension.padding.offset != payload_end
        || extension.padding.len != expected_padding
        || !padding_end.is_multiple_of(TAR_BLOCK_LEN)
        || padding_end > covering_end
    {
        return Err(fail("PAX extension ranges do not form one aligned record"));
    }

    let mut header = [0_u8; TAR_BLOCK_LEN as usize];
    snapshot
        .read_exact_at(extension.header.offset, &mut header)
        .map_err(|_| fail("claimed PAX extension header is outside the snapshot"))?;
    let facts = audit_pax_header(&header)?;
    let expected_typeflag = match extension.kind {
        PaxExtensionKind::Global => b'g',
        PaxExtensionKind::Local => b'x',
    };
    if facts.typeflag != expected_typeflag
        || facts.size != extension.payload.len
        || facts.mode != extension.mode
        || facts.mtime != extension.mtime
        || facts.checksum != extension.header_checksum
        || !pax_header_name_matches(&header, &extension.raw_name_bytes)
        || hex_sha256(&header) != extension.header_sha256
    {
        return Err(fail(
            "PAX extension header evidence disagrees with the snapshot",
        ));
    }

    let payload = snapshot
        .read_vec(extension.payload.offset, extension.payload.len)
        .map_err(|_| fail("claimed PAX extension payload is outside the snapshot"))?;
    if hex_sha256(&payload) != extension.payload_sha256 {
        return Err(fail(
            "PAX extension payload digest disagrees with the snapshot",
        ));
    }
    audit_pax_records(&payload, extension.payload.offset, &extension.records)?;
    audit_zero_range(
        snapshot,
        extension.padding,
        "claimed PAX extension padding contains nonzero bytes",
    )?;
    Ok(padding_end)
}

fn audit_one_pax_member(
    snapshot: &SourceSnapshot<'_>,
    member: &crate::ir::IrMember,
    extensions: &[PaxExtensionEvidence],
    globals: &PaxAuditOverrides,
    local: Option<&PaxAuditOverrides>,
    expected_header: u64,
    covering_end: u64,
) -> Result<u64, Finding> {
    let fail = |detail: &'static str| {
        Finding::error(FindingCode::CoveringInconsistent, detail).on(&member.decoded_name)
    };
    if !matches!(
        member.format(),
        ArchiveFormat::TarPax | ArchiveFormat::TarGzipPax
    ) {
        return Err(fail(
            "PAX member evidence variant does not match the archive format",
        ));
    }
    let evidence = member
        .tar_pax_evidence()
        .ok_or_else(|| fail("PAX member lacks PAX-specific evidence"))?;
    let tar = &evidence.tar;
    let header_end = checked_range_end(tar.header, "PAX member header overflow")?;
    let payload_end = checked_range_end(tar.payload, "PAX member payload overflow")?;
    let padding_end = checked_range_end(tar.padding, "PAX member padding overflow")?;
    let expected_padding = (TAR_BLOCK_LEN - (tar.payload.len % TAR_BLOCK_LEN)) % TAR_BLOCK_LEN;
    if tar.header.offset != expected_header
        || tar.header.len != TAR_BLOCK_LEN
        || tar.payload.offset != header_end
        || tar.payload.len != member.declared_uncomp_size
        || tar.padding.offset != payload_end
        || tar.padding.len != expected_padding
        || !padding_end.is_multiple_of(TAR_BLOCK_LEN)
        || padding_end > covering_end
    {
        return Err(fail("PAX member ranges do not form one aligned record"));
    }

    let mut header = [0_u8; TAR_BLOCK_LEN as usize];
    snapshot
        .read_exact_at(tar.header.offset, &mut header)
        .map_err(|_| fail("claimed PAX member header is outside the snapshot"))?;
    let facts = audit_pax_header(&header).map_err(|finding| finding.on(&member.decoded_name))?;
    let source_is_directory = facts.typeflag == b'5';
    if !matches!(facts.typeflag, 0 | b'0' | b'5')
        || source_is_directory != matches!(member.kind, MemberKind::Directory)
        || (source_is_directory && member.declared_uncomp_size != 0)
        || facts.size != evidence.base_size
        || facts.mode != tar.mode
        || facts.mtime != tar.mtime
        || facts.checksum != tar.header_checksum
        || !pax_header_name_matches(&header, &evidence.base_name_bytes)
        || hex_sha256(&header) != tar.header_sha256
    {
        return Err(fail(
            "PAX member header evidence disagrees with the snapshot",
        ));
    }

    let expected_path_source = local
        .and_then(|state| state.path)
        .or(globals.path)
        .unwrap_or(PaxValueSource::Ustar);
    let expected_size_source = local
        .and_then(|state| state.size)
        .or(globals.size)
        .unwrap_or(PaxValueSource::Ustar);
    if evidence.path_source != expected_path_source || evidence.size_source != expected_size_source
    {
        return Err(fail(
            "PAX member override source evidence disagrees with replayed state",
        ));
    }

    let effective_name = match expected_path_source {
        PaxValueSource::Ustar => evidence.base_name_bytes.as_slice(),
        source => pax_source_record(extensions, source, PaxKeyword::Path)
            .ok_or_else(|| fail("PAX path source does not reference its replayed record"))?
            .raw_value_bytes
            .as_slice(),
    };
    let effective_size = match expected_size_source {
        PaxValueSource::Ustar => evidence.base_size,
        source => pax_source_record(extensions, source, PaxKeyword::Size)
            .and_then(|record| record.parsed_size)
            .ok_or_else(|| fail("PAX size source does not reference its replayed record"))?,
    };
    if effective_name.is_empty()
        || effective_name.len() > PAX_MAX_EFFECTIVE_PATH_BYTES
        || effective_name.contains(&0)
        || std::str::from_utf8(effective_name).is_err()
        || member.raw_name_bytes != effective_name
        || member.decoded_name.as_bytes() != effective_name
        || member.declared_uncomp_size != effective_size
    {
        return Err(fail(
            "PAX member effective name or size disagrees with replayed state",
        ));
    }

    audit_zero_range(
        snapshot,
        tar.padding,
        "claimed PAX member padding contains nonzero bytes",
    )
    .map_err(|finding| finding.on(&member.decoded_name))?;
    Ok(padding_end)
}

fn pax_source_record(
    extensions: &[PaxExtensionEvidence],
    source: PaxValueSource,
    keyword: PaxKeyword,
) -> Option<&crate::ir::PaxRecordEvidence> {
    let (extension_index, record_index, expected_kind) = match source {
        PaxValueSource::Ustar => return None,
        PaxValueSource::Global {
            extension_index,
            record_index,
        } => (extension_index, record_index, PaxExtensionKind::Global),
        PaxValueSource::Local {
            extension_index,
            record_index,
        } => (extension_index, record_index, PaxExtensionKind::Local),
    };
    let extension = extensions.get(usize::try_from(extension_index).ok()?)?;
    if extension.kind != expected_kind {
        return None;
    }
    let record = extension.records.get(usize::try_from(record_index).ok()?)?;
    (record.keyword == keyword).then_some(record)
}

fn audit_pax_records(
    payload: &[u8],
    payload_offset: u64,
    records: &[crate::ir::PaxRecordEvidence],
) -> Result<(), Finding> {
    let fail = |detail: &'static str| Finding::error(FindingCode::CoveringInconsistent, detail);
    if records.is_empty() || records.len() > 2 {
        return Err(fail(
            "PAX extension does not contain exactly one or two records",
        ));
    }
    let mut cursor = 0_usize;
    let mut record_index = 0_usize;
    let mut saw_path = false;
    let mut saw_size = false;
    while cursor < payload.len() {
        let evidence = records
            .get(record_index)
            .ok_or_else(|| fail("PAX payload contains more records than its evidence"))?;
        let record_start = cursor;
        while cursor < payload.len() && payload[cursor].is_ascii_digit() {
            cursor = cursor
                .checked_add(1)
                .ok_or_else(|| fail("PAX record length scan overflowed usize"))?;
            if cursor - record_start > PAX_MAX_RECORD_LENGTH_DIGITS {
                return Err(fail("PAX record length exceeds the closed digit cap"));
            }
        }
        if cursor == record_start || cursor == payload.len() || payload[cursor] != b' ' {
            return Err(fail("PAX record lacks its canonical length delimiter"));
        }
        let length_digits = &payload[record_start..cursor];
        if length_digits.len() > 1 && length_digits[0] == b'0' {
            return Err(fail("PAX record length has a leading zero"));
        }
        let record_len_u64 = parse_pax_decimal(length_digits)
            .ok_or_else(|| fail("PAX record length overflowed u64"))?;
        let record_len = usize::try_from(record_len_u64)
            .map_err(|_| fail("PAX record length does not fit usize"))?;
        let record_end = record_start
            .checked_add(record_len)
            .ok_or_else(|| fail("PAX record end overflowed usize"))?;
        if record_len == 0 || record_end > payload.len() || payload[record_end - 1] != b'\n' {
            return Err(fail("PAX record length or terminator is inconsistent"));
        }

        cursor = cursor
            .checked_add(1)
            .ok_or_else(|| fail("PAX record body offset overflowed usize"))?;
        if cursor >= record_end - 1 {
            return Err(fail("PAX record has an empty key/value body"));
        }
        let body = &payload[cursor..record_end - 1];
        let equals = body
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| fail("PAX record lacks its keyword delimiter"))?;
        if equals == 0 || equals > PAX_MAX_KEYWORD_BYTES {
            return Err(fail("PAX record keyword is outside the closed profile"));
        }
        let keyword_bytes = &body[..equals];
        let value = &body[equals + 1..];
        let value_start = cursor
            .checked_add(equals + 1)
            .ok_or_else(|| fail("PAX value offset overflowed usize"))?;
        let keyword = match keyword_bytes {
            b"path" if !saw_path => {
                saw_path = true;
                if value.is_empty()
                    || value.len() > PAX_MAX_EFFECTIVE_PATH_BYTES
                    || value.contains(&0)
                    || std::str::from_utf8(value).is_err()
                {
                    return Err(fail("PAX path value is outside the closed profile"));
                }
                if evidence.parsed_size.is_some() {
                    return Err(fail("PAX path record carries parsed size evidence"));
                }
                PaxKeyword::Path
            }
            b"size" if !saw_size => {
                saw_size = true;
                if value.is_empty()
                    || value.len() > PAX_MAX_RECORD_LENGTH_DIGITS
                    || !value.iter().all(u8::is_ascii_digit)
                    || (value.len() > 1 && value[0] == b'0')
                {
                    return Err(fail("PAX size value is not canonical unsigned decimal"));
                }
                let parsed = parse_pax_decimal(value)
                    .ok_or_else(|| fail("PAX size value overflowed u64"))?;
                if evidence.parsed_size != Some(parsed) {
                    return Err(fail(
                        "PAX parsed size evidence disagrees with its raw value",
                    ));
                }
                PaxKeyword::Size
            }
            b"path" | b"size" => return Err(fail("PAX extension repeats a keyword")),
            _ => return Err(fail("PAX record keyword is outside the closed profile")),
        };

        let absolute_record = payload_offset
            .checked_add(
                u64::try_from(record_start)
                    .map_err(|_| fail("PAX relative record offset does not fit u64"))?,
            )
            .ok_or_else(|| fail("PAX absolute record offset overflowed u64"))?;
        let absolute_value = payload_offset
            .checked_add(
                u64::try_from(value_start)
                    .map_err(|_| fail("PAX relative value offset does not fit u64"))?,
            )
            .ok_or_else(|| fail("PAX absolute value offset overflowed u64"))?;
        if evidence.record
            != (ByteRange {
                offset: absolute_record,
                len: record_len_u64,
            })
            || evidence.value
                != (ByteRange {
                    offset: absolute_value,
                    len: u64::try_from(value.len())
                        .map_err(|_| fail("PAX value length does not fit u64"))?,
                })
            || evidence.keyword != keyword
            || evidence.raw_value_bytes != value
        {
            return Err(fail(
                "PAX record evidence disagrees with exact source bytes",
            ));
        }
        cursor = record_end;
        record_index = record_index
            .checked_add(1)
            .ok_or_else(|| fail("PAX record index overflowed usize"))?;
    }
    if record_index != records.len() {
        return Err(fail(
            "PAX record evidence does not exactly consume the payload",
        ));
    }
    Ok(())
}

/// Independently reparse and replay the exact old-GNU long-name source.
///
/// This deliberately does not invoke the structural parser or share its
/// header helpers. Readiness requires agreement between these two authorities.
pub(crate) fn audit_tar_gnu_longname_covering(
    snapshot: &SourceSnapshot<'_>,
    ir: &ArchiveIR,
) -> Result<(), Finding> {
    let fail = |detail: &'static str| Finding::error(FindingCode::CoveringInconsistent, detail);
    if !matches!(
        ir.format(),
        ArchiveFormat::TarGnuLongName | ArchiveFormat::TarGzipGnuLongName
    ) {
        return Err(fail("GNU TAR covering audit received a non-GNU IR"));
    }
    match ir.format() {
        ArchiveFormat::TarGnuLongName if ir.source_digest != *snapshot.digest() => {
            return Err(fail("source digest does not match the GNU TAR snapshot"));
        }
        ArchiveFormat::TarGzipGnuLongName => {
            let gzip = ir
                .gzip_evidence()
                .ok_or_else(|| fail("gzip-wrapped GNU TAR IR has no wrapper evidence"))?;
            if gzip.derived_output_len != snapshot.len()
                || snapshot.digest().sha256() != Some(gzip.derived_output_sha256.as_str())
            {
                return Err(fail("derived GNU TAR identity does not match its snapshot"));
            }
        }
        _ => {}
    }
    let archive = ir
        .tar_gnu_longname_evidence()
        .ok_or_else(|| fail("GNU TAR IR has no GNU archive evidence"))?;
    if archive.carriers.len() > GNU_MAX_CARRIERS {
        return Err(fail("GNU carrier evidence exceeds the closed profile cap"));
    }

    let covering = &archive.tar;
    let member_end = checked_range_end(covering.member_records, "GNU member covering overflow")?;
    let terminator_end = checked_range_end(covering.terminator, "GNU terminator overflow")?;
    let trailing_end = checked_range_end(covering.trailing_zeros, "GNU trailing range overflow")?;
    if covering.member_records.offset != 0
        || covering.terminator.offset != member_end
        || covering.terminator.len != TAR_BLOCK_LEN * 2
        || covering.trailing_zeros.offset != terminator_end
        || trailing_end != snapshot.len()
    {
        return Err(fail(
            "GNU TAR covering does not exactly partition the snapshot",
        ));
    }

    let mut cursor = 0_u64;
    let mut carrier_index = 0_usize;
    let mut member_index = 0_usize;
    let mut pending: Option<u32> = None;
    while cursor < member_end {
        let header_end = cursor
            .checked_add(TAR_BLOCK_LEN)
            .ok_or_else(|| fail("GNU header end overflowed"))?;
        if header_end > member_end {
            return Err(fail("GNU header crosses the member-record covering"));
        }
        let mut header = [0_u8; TAR_BLOCK_LEN as usize];
        snapshot
            .read_exact_at(cursor, &mut header)
            .map_err(|_| fail("GNU header is outside the snapshot"))?;
        let facts = audit_gnu_header(&header)?;
        let padded_size = facts
            .size
            .checked_add((TAR_BLOCK_LEN - facts.size % TAR_BLOCK_LEN) % TAR_BLOCK_LEN)
            .ok_or_else(|| fail("GNU record alignment overflowed"))?;
        let payload_end = header_end
            .checked_add(facts.size)
            .ok_or_else(|| fail("GNU payload end overflowed"))?;
        let record_end = header_end
            .checked_add(padded_size)
            .ok_or_else(|| fail("GNU record end overflowed"))?;
        if record_end > member_end {
            return Err(fail("GNU record crosses the member-record covering"));
        }

        if facts.typeflag == b'L' {
            if pending.is_some() {
                return Err(fail("GNU long-name carriers are chained"));
            }
            if facts.size < 2 || facts.size > (GNU_MAX_PATH_BYTES as u64 + 1) {
                return Err(fail("GNU carrier payload is outside the closed bound"));
            }
            let carrier = archive
                .carriers
                .get(carrier_index)
                .ok_or_else(|| fail("GNU source has an unrecorded carrier"))?;
            let padding_len = padded_size - facts.size;
            let path_len = facts.size - 1;
            if carrier.header
                != (ByteRange {
                    offset: cursor,
                    len: TAR_BLOCK_LEN,
                })
                || carrier.payload
                    != (ByteRange {
                        offset: header_end,
                        len: facts.size,
                    })
                || carrier.path
                    != (ByteRange {
                        offset: header_end,
                        len: path_len,
                    })
                || carrier.padding
                    != (ByteRange {
                        offset: payload_end,
                        len: padding_len,
                    })
                || carrier.raw_name_bytes != facts.name
                || carrier.mode != facts.mode
                || carrier.mtime != facts.mtime
                || carrier.header_checksum != facts.checksum
                || carrier.header_sha256 != hex_sha256(&header)
            {
                return Err(fail("GNU carrier evidence disagrees with its header"));
            }
            let payload = snapshot
                .read_vec(header_end, facts.size)
                .map_err(|_| fail("GNU carrier payload is outside the snapshot"))?;
            let path = &payload[..payload.len() - 1];
            if payload.last() != Some(&0)
                || path.contains(&0)
                || std::str::from_utf8(path).is_err()
                || carrier.path_bytes != path
                || carrier.payload_sha256 != hex_sha256(&payload)
            {
                return Err(fail("GNU carrier payload evidence or final NUL disagrees"));
            }
            audit_zero_range(
                snapshot,
                carrier.padding,
                "GNU carrier padding contains nonzero bytes",
            )?;
            let index = u32::try_from(carrier_index)
                .map_err(|_| fail("GNU carrier index does not fit u32"))?;
            pending = Some(index);
            carrier_index += 1;
        } else {
            let member = ir
                .members
                .get(member_index)
                .ok_or_else(|| fail("GNU source has an unrecorded ordinary member"))?;
            if !matches!(
                member.format(),
                ArchiveFormat::TarGnuLongName | ArchiveFormat::TarGzipGnuLongName
            ) {
                return Err(fail("GNU member evidence carries the wrong format"));
            }
            let evidence = member
                .tar_gnu_longname_evidence()
                .ok_or_else(|| fail("GNU member lacks format-specific evidence"))?;
            let expected_kind = if facts.typeflag == b'5' {
                MemberKind::Directory
            } else {
                MemberKind::File
            };
            let padding_len = padded_size - facts.size;
            if member.kind != expected_kind
                || member.declared_uncomp_size != facts.size
                || evidence.base_name_bytes != facts.name
                || evidence.tar.header
                    != (ByteRange {
                        offset: cursor,
                        len: TAR_BLOCK_LEN,
                    })
                || evidence.tar.payload
                    != (ByteRange {
                        offset: header_end,
                        len: facts.size,
                    })
                || evidence.tar.padding
                    != (ByteRange {
                        offset: payload_end,
                        len: padding_len,
                    })
                || evidence.tar.mode != facts.mode
                || evidence.tar.mtime != facts.mtime
                || evidence.tar.header_checksum != facts.checksum
                || evidence.tar.header_sha256 != hex_sha256(&header)
            {
                return Err(
                    fail("GNU ordinary-member evidence disagrees with its header")
                        .on(&member.decoded_name),
                );
            }

            let expected_effective = match pending.take() {
                Some(index) => {
                    if evidence.path_source
                        != (GnuLongNamePathSource::Carrier {
                            carrier_index: index,
                        })
                    {
                        return Err(fail("GNU member carrier provenance is stale or missing")
                            .on(&member.decoded_name));
                    }
                    archive
                        .carriers
                        .get(index as usize)
                        .map(|carrier| carrier.path_bytes.as_slice())
                        .ok_or_else(|| fail("GNU member carrier provenance is out of range"))?
                }
                None => {
                    if evidence.path_source != GnuLongNamePathSource::Header
                        || std::str::from_utf8(&facts.name).is_err()
                    {
                        return Err(fail("GNU header-name provenance is inconsistent")
                            .on(&member.decoded_name));
                    }
                    facts.name.as_slice()
                }
            };
            if member.raw_name_bytes != expected_effective
                || member.decoded_name.as_bytes() != expected_effective
                || member.components.join("/") != member.canonical_path
            {
                return Err(fail("GNU effective pathname evidence is inconsistent")
                    .on(&member.decoded_name));
            }
            let strip_actions = member
                .normalization_actions
                .iter()
                .filter(|action| {
                    matches!(
                        action,
                        crate::ir::NormalizationAction::StripDirectoryTrailingSlash
                    )
                })
                .count();
            if member.kind == MemberKind::Directory {
                let expected_canonical = member.decoded_name.strip_suffix('/');
                match expected_canonical {
                    Some(path)
                        if strip_actions == 1
                            && member.canonical_path.as_bytes() == path.as_bytes() => {}
                    None if strip_actions == 0
                        && member.canonical_path.as_bytes() == member.decoded_name.as_bytes() => {}
                    _ => {
                        return Err(fail("GNU directory slash normalization is inconsistent")
                            .on(&member.decoded_name));
                    }
                }
            } else if strip_actions != 0 {
                return Err(fail("GNU file has directory-only normalization evidence")
                    .on(&member.decoded_name));
            }
            audit_zero_range(
                snapshot,
                evidence.tar.padding,
                "GNU member padding contains nonzero bytes",
            )
            .map_err(|finding| finding.on(&member.decoded_name))?;
            member_index += 1;
        }
        cursor = record_end;
    }

    if pending.is_some()
        || carrier_index != archive.carriers.len()
        || member_index != ir.members.len()
        || cursor != member_end
    {
        return Err(fail(
            "GNU state or evidence tables do not exactly consume the source",
        ));
    }
    let mut terminator = [1_u8; (TAR_BLOCK_LEN * 2) as usize];
    snapshot
        .read_exact_at(covering.terminator.offset, &mut terminator)
        .map_err(|_| fail("GNU terminator is outside the snapshot"))?;
    if terminator.iter().any(|byte| *byte != 0) {
        return Err(fail("GNU terminator contains nonzero bytes"));
    }
    audit_zero_range(
        snapshot,
        covering.trailing_zeros,
        "GNU trailing record padding contains nonzero bytes",
    )?;
    Ok(())
}

#[derive(Clone, Debug)]
struct GnuHeaderFacts {
    name: Vec<u8>,
    typeflag: u8,
    size: u64,
    mode: u32,
    mtime: u64,
    checksum: u32,
}

fn audit_gnu_header(header: &[u8; TAR_BLOCK_LEN as usize]) -> Result<GnuHeaderFacts, Finding> {
    let fail = |detail: &'static str| Finding::error(FindingCode::CoveringInconsistent, detail);
    if &header[257..265] != b"ustar  \0"
        || header[157..257].iter().any(|byte| *byte != 0)
        || header[345..].iter().any(|byte| *byte != 0)
        || !pax_owner_field_is_canonical(&header[265..297])
        || !pax_owner_field_is_canonical(&header[297..329])
    {
        return Err(fail("GNU header is outside exact old-GNU framing"));
    }
    let checksum_field = &header[148..156];
    if !checksum_field[..6]
        .iter()
        .all(|byte| matches!(byte, b'0'..=b'7'))
        || checksum_field[6] != 0
        || checksum_field[7] != b' '
    {
        return Err(fail("GNU header checksum field is not canonical"));
    }
    let checksum = parse_pax_octal_digits(&checksum_field[..6])
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| fail("GNU header checksum overflows u32"))?;
    let actual_checksum = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u32::from(b' ')
            } else {
                u32::from(*byte)
            }
        })
        .sum::<u32>();
    if checksum != actual_checksum {
        return Err(fail("GNU header checksum disagrees with its bytes"));
    }
    let mode_u64 = parse_pax_octal(&header[100..108])
        .ok_or_else(|| fail("GNU header mode is not canonical octal"))?;
    if mode_u64 > 0o7777
        || parse_pax_octal(&header[108..116]).is_none()
        || parse_pax_octal(&header[116..124]).is_none()
        || !pax_device_field_is_zero(&header[329..337])
        || !pax_device_field_is_zero(&header[337..345])
    {
        return Err(fail(
            "GNU header identity fields are outside the closed profile",
        ));
    }
    let size = parse_pax_octal(&header[124..136])
        .ok_or_else(|| fail("GNU header size is not canonical octal"))?;
    let mtime = parse_pax_octal(&header[136..148])
        .ok_or_else(|| fail("GNU header mtime is not canonical octal"))?;
    let typeflag = header[156];
    if !matches!(typeflag, 0 | b'0' | b'5' | b'L') {
        return Err(fail("GNU header type is outside the closed profile"));
    }
    if typeflag == b'5' && size != 0 {
        return Err(fail("GNU directory has a nonzero size"));
    }
    let name = pax_text_field(&header[..100], false)
        .ok_or_else(|| fail("GNU header name is not closed structural text"))?
        .to_vec();
    Ok(GnuHeaderFacts {
        name,
        typeflag,
        size,
        mode: u32::try_from(mode_u64).expect("portable GNU mode fits u32"),
        mtime,
        checksum,
    })
}

#[derive(Clone, Copy, Debug)]
struct PaxHeaderFacts {
    typeflag: u8,
    size: u64,
    mode: u32,
    mtime: u64,
    checksum: u32,
}

fn audit_pax_header(header: &[u8; TAR_BLOCK_LEN as usize]) -> Result<PaxHeaderFacts, Finding> {
    let fail = |detail: &'static str| Finding::error(FindingCode::CoveringInconsistent, detail);
    if &header[257..263] != b"ustar\0"
        || &header[263..265] != b"00"
        || header[500..].iter().any(|byte| *byte != 0)
        || header[157..257].iter().any(|byte| *byte != 0)
        || !pax_owner_field_is_canonical(&header[265..297])
        || !pax_owner_field_is_canonical(&header[297..329])
    {
        return Err(fail("PAX header is outside exact POSIX ustar framing"));
    }
    let checksum_field = &header[148..156];
    if !checksum_field[..6]
        .iter()
        .all(|byte| matches!(byte, b'0'..=b'7'))
        || checksum_field[6] != 0
        || checksum_field[7] != b' '
    {
        return Err(fail("PAX header checksum field is not canonical"));
    }
    let checksum = parse_pax_octal_digits(&checksum_field[..6])
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| fail("PAX header checksum overflows u32"))?;
    let actual_checksum = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u32::from(b' ')
            } else {
                u32::from(*byte)
            }
        })
        .sum::<u32>();
    if checksum != actual_checksum {
        return Err(fail("PAX header checksum disagrees with its bytes"));
    }

    let mode_u64 = parse_pax_octal(&header[100..108])
        .ok_or_else(|| fail("PAX header mode is not canonical octal"))?;
    if mode_u64 > 0o7777
        || parse_pax_octal(&header[108..116]).is_none()
        || parse_pax_octal(&header[116..124]).is_none()
    {
        return Err(fail(
            "PAX header identity fields are outside the closed profile",
        ));
    }
    let size = parse_pax_octal(&header[124..136])
        .ok_or_else(|| fail("PAX header size is not canonical octal"))?;
    if header[156] == b'5' && size != 0 {
        return Err(fail("PAX directory has a nonzero underlying size"));
    }
    let mtime = parse_pax_octal(&header[136..148])
        .ok_or_else(|| fail("PAX header mtime is not canonical octal"))?;
    if !pax_device_field_is_zero(&header[329..337]) || !pax_device_field_is_zero(&header[337..345])
    {
        return Err(fail("PAX header device fields are not canonical zero"));
    }
    Ok(PaxHeaderFacts {
        typeflag: header[156],
        size,
        mode: u32::try_from(mode_u64).expect("portable PAX mode fits u32"),
        mtime,
        checksum,
    })
}

fn pax_header_name_matches(header: &[u8; TAR_BLOCK_LEN as usize], expected: &[u8]) -> bool {
    let Some(name) = pax_text_field(&header[0..100], false) else {
        return false;
    };
    let Some(prefix) = pax_text_field(&header[345..500], true) else {
        return false;
    };
    let expected_len = prefix
        .len()
        .checked_add(usize::from(!prefix.is_empty()))
        .and_then(|value| value.checked_add(name.len()));
    if expected_len != Some(expected.len()) {
        return false;
    }
    if prefix.is_empty() {
        expected == name
    } else {
        expected.starts_with(prefix)
            && expected.get(prefix.len()) == Some(&b'/')
            && expected.get(prefix.len() + 1..) == Some(name)
    }
}

fn pax_text_field(field: &[u8], empty_allowed: bool) -> Option<&[u8]> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) || (!empty_allowed && end == 0) {
        None
    } else {
        Some(&field[..end])
    }
}

fn pax_owner_field_is_canonical(field: &[u8]) -> bool {
    let Some(end) = field.iter().position(|byte| *byte == 0) else {
        return false;
    };
    field[end..].iter().all(|byte| *byte == 0)
        && field[..end].iter().all(|byte| matches!(byte, b' '..=b'~'))
}

fn pax_device_field_is_zero(field: &[u8]) -> bool {
    field.iter().all(|byte| *byte == 0) || parse_pax_octal(field) == Some(0)
}

fn parse_pax_octal(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return None;
    }
    let end = field.iter().position(|byte| !matches!(byte, b'0'..=b'7'))?;
    if end == 0 || field[end..].iter().any(|byte| !matches!(byte, 0 | b' ')) {
        return None;
    }
    parse_pax_octal_digits(&field[..end])
}

fn parse_pax_octal_digits(digits: &[u8]) -> Option<u64> {
    digits.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(8)
            .and_then(|value| value.checked_add(u64::from(byte.checked_sub(b'0')?)))
    })
}

fn parse_pax_decimal(digits: &[u8]) -> Option<u64> {
    digits.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte.checked_sub(b'0')?)))
    })
}

fn audit_zip64_extras(
    snapshot: &SourceSnapshot<'_>,
    member: &crate::ir::IrMember,
    local: &[u8; 30],
    central: &[u8; 46],
) -> Result<(), Finding> {
    let fail = |detail: &'static str| {
        Finding::error(FindingCode::CoveringInconsistent, detail).on(&member.decoded_name)
    };
    let zip64 = member
        .zip64_evidence()
        .ok_or_else(|| fail("ZIP64 member lacks ZIP64 evidence"))?;
    let zip = &zip64.zip;
    for field in &zip.extra_fields {
        let header_end = checked_range_end(
            field.header_range,
            "ZIP64 extra-field header range overflows",
        )
        .map_err(|_| fail("ZIP64 extra-field header range overflows"))?;
        if field.id != 0x0001
            || field.disposition != ExtraDisposition::Semantic
            || field.header_range.len != 4
            || header_end != field.data_range.offset
        {
            return Err(fail(
                "ZIP64 extra-field evidence is not the closed semantic language",
            ));
        }
    }
    for (site, expected) in [
        (ExtraSite::Local, zip64.local_zip64_extra),
        (ExtraSite::Central, zip64.central_zip64_extra),
    ] {
        let mut matching = zip.extra_fields.iter().filter(|field| field.site == site);
        let actual = matching.next().map(|field| field.data_range);
        if matching.next().is_some() || actual != expected {
            return Err(fail("ZIP64 site-specific extra evidence is inconsistent"));
        }
        if let Some(data_range) = expected {
            let header_offset = data_range
                .offset
                .checked_sub(4)
                .ok_or_else(|| fail("ZIP64 extra header offset underflows"))?;
            let mut header = [0_u8; 4];
            snapshot
                .read_exact_at(header_offset, &mut header)
                .map_err(|_| fail("ZIP64 extra header is outside the snapshot"))?;
            if le_u16(&header, 0) != 0x0001 || u64::from(le_u16(&header, 2)) != data_range.len {
                return Err(fail("ZIP64 extra header disagrees with its evidence"));
            }
        }
    }

    let local_extra_start = zip
        .source_ranges
        .local_header
        .offset
        .checked_add(30 + u64::from(le_u16(local, 26)))
        .ok_or_else(|| fail("ZIP64 local extra offset overflows"))?;
    let local_extra_end = local_extra_start
        .checked_add(u64::from(le_u16(local, 28)))
        .ok_or_else(|| fail("ZIP64 local extra range overflows"))?;
    let central_extra_start = zip
        .source_ranges
        .central_header
        .offset
        .checked_add(46 + u64::from(le_u16(central, 28)))
        .ok_or_else(|| fail("ZIP64 central extra offset overflows"))?;
    let central_extra_end = central_extra_start
        .checked_add(u64::from(le_u16(central, 30)))
        .ok_or_else(|| fail("ZIP64 central extra range overflows"))?;
    for (range, start, end) in [
        (zip64.local_zip64_extra, local_extra_start, local_extra_end),
        (
            zip64.central_zip64_extra,
            central_extra_start,
            central_extra_end,
        ),
    ] {
        if let Some(range) = range {
            let header_start = range
                .offset
                .checked_sub(4)
                .ok_or_else(|| fail("ZIP64 extra range underflows"))?;
            let range_end = checked_range_end(range, "ZIP64 extra data range overflows")
                .map_err(|_| fail("ZIP64 extra data range overflows"))?;
            if header_start != start || range_end != end {
                return Err(fail(
                    "ZIP64 extra does not exactly fill its header extra area",
                ));
            }
        } else if start != end {
            return Err(fail("unrepresented ZIP64 header extra bytes remain"));
        }
    }

    match zip64.local_zip64_extra {
        None => {
            if zip64.local_value_shape != Zip64LocalValueShape::Absent {
                return Err(fail(
                    "absent local ZIP64 extra has a non-absent value shape",
                ));
            }
        }
        Some(range) => {
            if range.len != 16 || zip64.local_value_shape == Zip64LocalValueShape::Absent {
                return Err(fail("local ZIP64 extra has an invalid semantic shape"));
            }
            let data = snapshot
                .read_vec(range.offset, range.len)
                .map_err(|_| fail("local ZIP64 extra is outside the snapshot"))?;
            let values = [le_u64(&data, 0), le_u64(&data, 8)];
            let expected = [member.declared_uncomp_size, zip.declared_comp_size];
            let valid = match zip64.local_value_shape {
                Zip64LocalValueShape::Absent => false,
                Zip64LocalValueShape::Exact => values == expected,
                Zip64LocalValueShape::StreamingZeros => values == [0, 0],
                Zip64LocalValueShape::StreamingMaxima => values == [u64::MAX, u64::MAX],
            };
            if !valid {
                return Err(fail("local ZIP64 value shape disagrees with the source"));
            }
        }
    }

    match zip64.central_zip64_extra {
        None => {
            if zip64.central_presence_mask != 0 || zip64.central_legacy_sentinel_mask != 0 {
                return Err(fail("absent central ZIP64 extra has semantic fields"));
            }
            if u64::from(le_u32(central, 24)) != member.declared_uncomp_size
                || u64::from(le_u32(central, 20)) != zip.declared_comp_size
                || u64::from(le_u32(central, 42)) != zip.source_ranges.local_header.offset
            {
                return Err(fail(
                    "central legacy values disagree with resolved ZIP64 evidence",
                ));
            }
        }
        Some(range) => {
            let mask = zip64.central_presence_mask;
            if mask == 0 || mask > 0b111 || range.len != u64::from(mask.count_ones()) * 8 {
                return Err(fail(
                    "central ZIP64 presence mask disagrees with its data length",
                ));
            }
            if mask & zip64.central_legacy_sentinel_mask != zip64.central_legacy_sentinel_mask {
                return Err(fail("central ZIP64 presence mask omits a legacy sentinel"));
            }
            let data = snapshot
                .read_vec(range.offset, range.len)
                .map_err(|_| fail("central ZIP64 extra is outside the snapshot"))?;
            let legacy = [
                le_u32(central, 24),
                le_u32(central, 20),
                le_u32(central, 42),
            ];
            let resolved = [
                member.declared_uncomp_size,
                zip.declared_comp_size,
                zip.source_ranges.local_header.offset,
            ];
            let required_mask = legacy
                .iter()
                .enumerate()
                .fold(0_u8, |required, (index, value)| {
                    required | (u8::from(*value == u32::MAX) << index)
                });
            let mut matching_masks = 0_u8;
            let mut unique_mask = 0_u8;
            for candidate in 1_u8..8 {
                if candidate.count_ones() != mask.count_ones()
                    || candidate & required_mask != required_mask
                {
                    continue;
                }
                let mut candidate_values = legacy.map(u64::from);
                let mut cursor = 0_usize;
                let mut valid = true;
                for index in 0..3 {
                    if candidate & (1 << index) == 0 {
                        continue;
                    }
                    let value = le_u64(&data, cursor);
                    cursor += 8;
                    if legacy[index] == u32::MAX {
                        candidate_values[index] = value;
                    } else if value != u64::from(legacy[index]) {
                        valid = false;
                        break;
                    }
                }
                if valid && candidate_values == resolved {
                    matching_masks = matching_masks.saturating_add(1);
                    unique_mask = candidate;
                }
            }
            if matching_masks != 1 || unique_mask != mask {
                return Err(fail(
                    "central ZIP64 values do not have one evidence-selected interpretation",
                ));
            }
        }
    }
    Ok(())
}

fn audit_zip64_descriptor(
    snapshot: &SourceSnapshot<'_>,
    member: &crate::ir::IrMember,
) -> Result<(), Finding> {
    let fail = |detail: &'static str| {
        Finding::error(FindingCode::CoveringInconsistent, detail).on(&member.decoded_name)
    };
    let zip64 = member
        .zip64_evidence()
        .ok_or_else(|| fail("ZIP64 member lacks ZIP64 evidence"))?;
    let zip = &zip64.zip;
    match (zip64.descriptor_width, zip.source_ranges.data_descriptor) {
        (None, None) if zip.flags & 0x0008 == 0 => Ok(()),
        (Some(width), Some(range)) if zip.flags & 0x0008 != 0 => {
            let expected_len = match width {
                Zip64DataDescriptorWidth::Zip32 => 16,
                Zip64DataDescriptorWidth::Zip64 => 24,
            };
            if range.len != expected_len {
                return Err(fail("ZIP64 descriptor range has the wrong width"));
            }
            let data = snapshot
                .read_vec(range.offset, range.len)
                .map_err(|_| fail("ZIP64 descriptor is outside the snapshot"))?;
            if data[0..4] != DATA_DESCRIPTOR_SIG || le_u32(&data, 4) != zip.declared_crc {
                return Err(fail(
                    "ZIP64 descriptor signature or CRC disagrees with evidence",
                ));
            }
            let (compressed, uncompressed) = match width {
                Zip64DataDescriptorWidth::Zip32 => {
                    (u64::from(le_u32(&data, 8)), u64::from(le_u32(&data, 12)))
                }
                Zip64DataDescriptorWidth::Zip64 => (le_u64(&data, 8), le_u64(&data, 16)),
            };
            if compressed != zip.declared_comp_size || uncompressed != member.declared_uncomp_size {
                return Err(fail("ZIP64 descriptor sizes disagree with evidence"));
            }
            Ok(())
        }
        _ => Err(fail("ZIP64 descriptor evidence disagrees with flag bit 3")),
    }
}

fn canonical_end_u16(legacy: u16, resolved: u64) -> bool {
    if resolved < u64::from(u16::MAX) {
        u64::from(legacy) == resolved || legacy == u16::MAX
    } else {
        legacy == u16::MAX
    }
}

fn canonical_end_u32(legacy: u32, resolved: u64) -> bool {
    if resolved < u64::from(u32::MAX) {
        u64::from(legacy) == resolved || legacy == u32::MAX
    } else {
        legacy == u32::MAX
    }
}

fn audit_zero_range(
    snapshot: &SourceSnapshot<'_>,
    range: ByteRange,
    detail: &'static str,
) -> Result<(), Finding> {
    let end = checked_range_end(range, "zero-padding range overflow")?;
    if end > snapshot.len() {
        return Err(Finding::error(
            FindingCode::CoveringInconsistent,
            "zero-padding range extends beyond the snapshot",
        ));
    }
    let mut offset = range.offset;
    let mut buffer = [0_u8; 8 * 1024];
    while offset != end {
        let remaining = end - offset;
        let len = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded covering zero-scan length fits usize");
        snapshot.read_exact_at(offset, &mut buffer[..len])?;
        if buffer[..len].iter().any(|byte| *byte != 0) {
            return Err(Finding::error(FindingCode::CoveringInconsistent, detail));
        }
        offset += len as u64;
    }
    Ok(())
}

fn checked_range_end(range: ByteRange, detail: &'static str) -> Result<u64, Finding> {
    range
        .offset
        .checked_add(range.len)
        .ok_or_else(|| Finding::error(FindingCode::CoveringInconsistent, detail))
}

pub(crate) fn audit_covering_fallible<'member>(
    snapshot: &SourceSnapshot<'_>,
    ir: &'member ArchiveIR,
) -> Result<(), CoveringAuditError<'member>> {
    let digest = snapshot.digest();
    if ir.source_digest != *digest {
        return Err(inconsistent("source digest does not match the snapshot"));
    }

    let covering = ir
        .zip_covering()
        .ok_or_else(|| inconsistent("ZIP covering audit received a non-ZIP IR"))?;
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
        let evidence = member.zip_evidence().ok_or_else(|| {
            inconsistent("ZIP member lacks ZIP evidence").on(&member.decoded_name)
        })?;
        let source_ranges = &evidence.source_ranges;
        let local_header = checked_interval(source_ranges.local_header, "local header overflow")
            .map_err(|finding| finding.on(&member.decoded_name))?;
        let payload = checked_interval(
            source_ranges.compressed_payload,
            "compressed payload overflow",
        )
        .map_err(|finding| finding.on(&member.decoded_name))?;
        let central_header =
            checked_interval(source_ranges.central_header, "central header overflow")
                .map_err(|finding| finding.on(&member.decoded_name))?;
        let descriptor = source_ranges
            .data_descriptor
            .map(|range| checked_interval(range, "data descriptor overflow"))
            .transpose()
            .map_err(|finding| finding.on(&member.decoded_name))?;

        if source_ranges.local_header.len < 30 {
            return Err(
                inconsistent("local header is shorter than 30 bytes").on(&member.decoded_name)
            );
        }
        if source_ranges.central_header.len < 46 {
            return Err(
                inconsistent("central header is shorter than 46 bytes").on(&member.decoded_name)
            );
        }
        let mut lfh = [0_u8; 4];
        snapshot
            .read_exact_at(source_ranges.local_header.offset, &mut lfh)
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
            .read_exact_at(source_ranges.central_header.offset, &mut cdh)
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

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
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
    use crate::apply::{apply, apply_with_options, ApplyOptions, Request, Source};
    use crate::findings::Finding;
    use crate::ir::{
        ArchiveEvidence, ArchiveIR, GnuLongNamePathSource, MemberEvidence, PaxValueSource,
        TarGnuLongNameInterpretationProfile, TarInterpretationProfile, TarMemberEvidence,
        TarPaxInterpretationProfile, Zip64MemberEvidence, ZipInterpretationProfile,
        ZipMemberEvidence,
    };
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

    fn make_tar() -> Vec<u8> {
        fn octal(field: &mut [u8], value: u64) {
            field.fill(b'0');
            let value = format!("{value:o}");
            let end = field.len() - 1;
            field[end - value.len()..end].copy_from_slice(value.as_bytes());
            field[end] = 0;
        }
        let mut header = [0_u8; 512];
        header[..9].copy_from_slice(b"hello.txt");
        octal(&mut header[100..108], 0o644);
        octal(&mut header[108..116], 0);
        octal(&mut header[116..124], 0);
        octal(&mut header[124..136], 5);
        octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        octal(&mut header[329..337], 0);
        octal(&mut header[337..345], 0);
        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
        header[154] = 0;
        header[155] = b' ';
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(b"hello");
        bytes.resize(1024, 0);
        bytes.resize(2048, 0);
        bytes
    }

    fn make_pax_tar() -> Vec<u8> {
        fn octal(field: &mut [u8], value: u64) {
            field.fill(b'0');
            let value = format!("{value:o}");
            let end = field.len() - 1;
            field[end - value.len()..end].copy_from_slice(value.as_bytes());
            field[end] = 0;
        }

        fn header(name: &[u8], size: u64, typeflag: u8) -> [u8; 512] {
            let mut header = [0_u8; 512];
            header[..name.len()].copy_from_slice(name);
            octal(&mut header[100..108], 0o644);
            octal(&mut header[108..116], 0);
            octal(&mut header[116..124], 0);
            octal(&mut header[124..136], size);
            octal(&mut header[136..148], 0);
            header[148..156].fill(b' ');
            header[156] = typeflag;
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            octal(&mut header[329..337], 0);
            octal(&mut header[337..345], 0);
            let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
            header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
            header[154] = 0;
            header[155] = b' ';
            header
        }

        fn record(keyword: &str, value: &str) -> Vec<u8> {
            let suffix = format!(" {keyword}={value}\n");
            let mut length = suffix.len() + 1;
            loop {
                let exact = suffix.len() + length.to_string().len();
                if exact == length {
                    return format!("{length}{suffix}").into_bytes();
                }
                length = exact;
            }
        }

        fn append_record(bytes: &mut Vec<u8>, header_bytes: [u8; 512], payload: &[u8]) {
            bytes.extend_from_slice(&header_bytes);
            bytes.extend_from_slice(payload);
            let padded = payload.len().next_multiple_of(512);
            bytes.resize(bytes.len() + padded - payload.len(), 0);
        }

        let mut bytes = Vec::new();
        let mut global = record("path", "global.txt");
        global.extend_from_slice(&record("size", "4"));
        append_record(
            &mut bytes,
            header(b"GlobalHead", global.len() as u64, b'g'),
            &global,
        );
        append_record(&mut bytes, header(b"base-one", 1, b'0'), b"ABCD");

        let mut local = record("path", "local.txt");
        local.extend_from_slice(&record("size", "3"));
        append_record(
            &mut bytes,
            header(b"LocalHead", local.len() as u64, b'x'),
            &local,
        );
        append_record(&mut bytes, header(b"base-two", 2, b'0'), b"XYZ");
        bytes.resize(bytes.len() + 1024, 0);
        bytes
    }

    fn make_gnu_longname_tar() -> Vec<u8> {
        fn octal(field: &mut [u8], value: u64) {
            field.fill(b'0');
            let value = format!("{value:o}");
            let end = field.len() - 1;
            field[end - value.len()..end].copy_from_slice(value.as_bytes());
            field[end] = 0;
        }

        fn header(name: &[u8], size: u64, typeflag: u8) -> [u8; 512] {
            let mut header = [0_u8; 512];
            header[..name.len()].copy_from_slice(name);
            octal(&mut header[100..108], 0o644);
            octal(&mut header[108..116], 0);
            octal(&mut header[116..124], 0);
            octal(&mut header[124..136], size);
            octal(&mut header[136..148], 0);
            header[148..156].fill(b' ');
            header[156] = typeflag;
            header[257..265].copy_from_slice(b"ustar  \0");
            let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
            header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
            header[154] = 0;
            header[155] = b' ';
            header
        }

        fn append_record(bytes: &mut Vec<u8>, header: [u8; 512], payload: &[u8]) {
            bytes.extend_from_slice(&header);
            bytes.extend_from_slice(payload);
            bytes.resize(bytes.len().next_multiple_of(512), 0);
        }

        let path = format!("mission/{}/status.txt", "segment".repeat(15));
        let mut carrier_payload = path.as_bytes().to_vec();
        carrier_payload.push(0);
        let mut bytes = Vec::new();
        append_record(
            &mut bytes,
            header(b"producer-carrier", carrier_payload.len() as u64, b'L'),
            &carrier_payload,
        );
        append_record(&mut bytes, header(b"opaque-base", 4, b'0'), b"mars");
        bytes.resize(bytes.len() + 1024, 0);
        bytes
    }

    fn make_zip64() -> Vec<u8> {
        let hex = concat!(
            "504b03042d0000000800000021000b5704bbffffffffffffffff01001400",
            "6101001000100000000000000005000000000000007374440500504b0102",
            "2d002d0000000800000021000b5704bb0500000010000000010000000000",
            "00000000000080010000000061504b050600000000010001002f00000038",
            "0000000000",
        );
        let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs
            .iter()
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ASCII"), 16)
                    .expect("fixture hex is valid")
            })
            .collect()
    }

    #[test]
    fn gzip_covering_audit_independently_rejects_duplicate_extra_ids() {
        let mut bytes = vec![0x1f, 0x8b, 8, GZIP_FLAG_EXTRA, 0, 0, 0, 0, 0, 255];
        bytes.extend_from_slice(&8_u16.to_le_bytes());
        bytes.extend_from_slice(b"SL\0\0SL\0\0");
        bytes.push(0);
        bytes.extend_from_slice(&[0; 8]);
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        let evidence = GzipWrapperEvidence {
            flags: GZIP_FLAG_EXTRA,
            modification_time: 0,
            extra_flags: 0,
            operating_system: 255,
            header: ByteRange { offset: 0, len: 20 },
            extra: Some(ByteRange {
                offset: 10,
                len: 10,
            }),
            extra_subfield_count: 2,
            original_name: None,
            comment: None,
            header_crc16: None,
            compressed_payload: ByteRange { offset: 20, len: 1 },
            trailer: ByteRange { offset: 21, len: 8 },
            declared_crc32: 0,
            declared_isize: 0,
            derived_output_len: 0,
            derived_output_sha256: "0".repeat(64),
        };
        assert_eq!(
            audit_gzip_wrapper_covering(&snapshot, &evidence)
                .unwrap_err()
                .code,
            FindingCode::CoveringInconsistent
        );
    }

    fn admitted_tar_ir(bytes: &[u8]) -> ArchiveIR {
        let policy = Policy::default_v2();
        let options = ApplyOptions::new()
            .with_tar_interpretation_profile(TarInterpretationProfile::UstarPortableV1);
        let outcome = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("cover.tar"),
                    data: bytes,
                },
                policy: &policy,
                dest: None,
            },
            &options,
        );
        assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
        outcome.archive_ir().cloned().unwrap()
    }

    fn admitted_pax_ir(bytes: &[u8]) -> ArchiveIR {
        let policy = Policy::default_v5();
        let options = ApplyOptions::new()
            .with_tar_pax_interpretation_profile(TarPaxInterpretationProfile::PortableV1);
        let outcome = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("cover-pax.tar"),
                    data: bytes,
                },
                policy: &policy,
                dest: None,
            },
            &options,
        );
        assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
        outcome.archive_ir().cloned().expect("admitted PAX IR")
    }

    fn admitted_gnu_ir(bytes: &[u8]) -> ArchiveIR {
        let policy = Policy::default_v6();
        let options = ApplyOptions::new().with_tar_gnu_longname_interpretation_profile(
            TarGnuLongNameInterpretationProfile::PortableV1,
        );
        let outcome = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("cover-gnu.tar"),
                    data: bytes,
                },
                policy: &policy,
                dest: None,
            },
            &options,
        );
        assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
        outcome
            .archive_ir()
            .cloned()
            .expect("admitted GNU long-name IR")
    }

    fn tar_covering_mut(ir: &mut ArchiveIR) -> &mut crate::ir::TarArchiveCovering {
        match &mut ir.evidence {
            ArchiveEvidence::Tar(covering) => covering,
            ArchiveEvidence::TarPax(evidence) => &mut evidence.tar,
            ArchiveEvidence::TarGnuLongName(evidence) => &mut evidence.tar,
            ArchiveEvidence::TarGzipPax(evidence) => &mut evidence.pax.tar,
            ArchiveEvidence::TarGzipGnuLongName(evidence) => &mut evidence.gnu.tar,
            ArchiveEvidence::Zip(_) | ArchiveEvidence::Zip64(_) | ArchiveEvidence::TarGzip(_) => {
                panic!("expected TAR evidence")
            }
        }
    }

    fn zip_covering_mut(ir: &mut ArchiveIR) -> &mut crate::ir::ArchiveCovering {
        match &mut ir.evidence {
            ArchiveEvidence::Zip(covering) => covering,
            ArchiveEvidence::Zip64(_)
            | ArchiveEvidence::Tar(_)
            | ArchiveEvidence::TarGzip(_)
            | ArchiveEvidence::TarPax(_)
            | ArchiveEvidence::TarGnuLongName(_)
            | ArchiveEvidence::TarGzipPax(_)
            | ArchiveEvidence::TarGzipGnuLongName(_) => {
                panic!("expected ZIP evidence")
            }
        }
    }

    fn zip64_covering_mut(ir: &mut ArchiveIR) -> &mut crate::ir::Zip64ArchiveCovering {
        match &mut ir.evidence {
            ArchiveEvidence::Zip64(covering) => covering,
            ArchiveEvidence::Zip(_)
            | ArchiveEvidence::Tar(_)
            | ArchiveEvidence::TarGzip(_)
            | ArchiveEvidence::TarPax(_)
            | ArchiveEvidence::TarGnuLongName(_)
            | ArchiveEvidence::TarGzipPax(_)
            | ArchiveEvidence::TarGzipGnuLongName(_) => {
                panic!("expected ZIP64 evidence")
            }
        }
    }

    fn tar_member_mut(ir: &mut ArchiveIR, index: usize) -> &mut TarMemberEvidence {
        match &mut ir.members[index].evidence {
            MemberEvidence::Tar(evidence) => evidence,
            MemberEvidence::TarPax(evidence) | MemberEvidence::TarGzipPax(evidence) => {
                &mut evidence.tar
            }
            MemberEvidence::TarGnuLongName(evidence)
            | MemberEvidence::TarGzipGnuLongName(evidence) => &mut evidence.tar,
            MemberEvidence::Zip(_) | MemberEvidence::Zip64(_) | MemberEvidence::TarGzip(_) => {
                panic!("expected TAR member evidence")
            }
        }
    }

    fn pax_archive_mut(ir: &mut ArchiveIR) -> &mut crate::ir::TarPaxArchiveEvidence {
        match &mut ir.evidence {
            ArchiveEvidence::TarPax(evidence) => evidence,
            ArchiveEvidence::TarGzipPax(evidence) => &mut evidence.pax,
            ArchiveEvidence::Zip(_)
            | ArchiveEvidence::Zip64(_)
            | ArchiveEvidence::Tar(_)
            | ArchiveEvidence::TarGzip(_)
            | ArchiveEvidence::TarGnuLongName(_)
            | ArchiveEvidence::TarGzipGnuLongName(_) => panic!("expected PAX archive evidence"),
        }
    }

    fn pax_member_mut(ir: &mut ArchiveIR, index: usize) -> &mut crate::ir::TarPaxMemberEvidence {
        match &mut ir.members[index].evidence {
            MemberEvidence::TarPax(evidence) | MemberEvidence::TarGzipPax(evidence) => evidence,
            MemberEvidence::Zip(_)
            | MemberEvidence::Zip64(_)
            | MemberEvidence::Tar(_)
            | MemberEvidence::TarGzip(_)
            | MemberEvidence::TarGnuLongName(_)
            | MemberEvidence::TarGzipGnuLongName(_) => panic!("expected PAX member evidence"),
        }
    }

    fn gnu_archive_mut(ir: &mut ArchiveIR) -> &mut crate::ir::TarGnuLongNameArchiveEvidence {
        match &mut ir.evidence {
            ArchiveEvidence::TarGnuLongName(evidence) => evidence,
            ArchiveEvidence::TarGzipGnuLongName(evidence) => &mut evidence.gnu,
            ArchiveEvidence::Zip(_)
            | ArchiveEvidence::Zip64(_)
            | ArchiveEvidence::Tar(_)
            | ArchiveEvidence::TarGzip(_)
            | ArchiveEvidence::TarPax(_)
            | ArchiveEvidence::TarGzipPax(_) => panic!("expected GNU long-name archive evidence"),
        }
    }

    fn gnu_member_mut(
        ir: &mut ArchiveIR,
        index: usize,
    ) -> &mut crate::ir::TarGnuLongNameMemberEvidence {
        match &mut ir.members[index].evidence {
            MemberEvidence::TarGnuLongName(evidence)
            | MemberEvidence::TarGzipGnuLongName(evidence) => evidence,
            MemberEvidence::Zip(_)
            | MemberEvidence::Zip64(_)
            | MemberEvidence::Tar(_)
            | MemberEvidence::TarGzip(_)
            | MemberEvidence::TarPax(_)
            | MemberEvidence::TarGzipPax(_) => panic!("expected GNU long-name member evidence"),
        }
    }

    fn zip_member_mut(ir: &mut ArchiveIR, index: usize) -> &mut ZipMemberEvidence {
        match &mut ir.members[index].evidence {
            MemberEvidence::Zip(evidence) => evidence,
            MemberEvidence::Zip64(_)
            | MemberEvidence::Tar(_)
            | MemberEvidence::TarGzip(_)
            | MemberEvidence::TarPax(_)
            | MemberEvidence::TarGnuLongName(_)
            | MemberEvidence::TarGzipPax(_)
            | MemberEvidence::TarGzipGnuLongName(_) => {
                panic!("expected ZIP member evidence")
            }
        }
    }

    fn zip64_member_mut(ir: &mut ArchiveIR, index: usize) -> &mut Zip64MemberEvidence {
        match &mut ir.members[index].evidence {
            MemberEvidence::Zip64(evidence) => evidence,
            MemberEvidence::Zip(_)
            | MemberEvidence::Tar(_)
            | MemberEvidence::TarGzip(_)
            | MemberEvidence::TarPax(_)
            | MemberEvidence::TarGnuLongName(_)
            | MemberEvidence::TarGzipPax(_)
            | MemberEvidence::TarGzipGnuLongName(_) => {
                panic!("expected ZIP64 member evidence")
            }
        }
    }

    fn admitted_zip64_ir(bytes: &[u8]) -> ArchiveIR {
        let policy = Policy::default_v3();
        let options = ApplyOptions::new()
            .with_interpretation_profile(ZipInterpretationProfile::Zip64StrictAsciiV1);
        let outcome = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("cover-zip64.zip"),
                    data: bytes,
                },
                policy: &policy,
                dest: None,
            },
            &options,
        );
        assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
        outcome.archive_ir().cloned().expect("admitted ZIP64 IR")
    }

    #[test]
    fn zip64_covering_oracle_rejects_native_evidence_drift() {
        let bytes = make_zip64();
        let original = admitted_zip64_ir(&bytes);
        let snapshot = crate::snapshot::SourceSnapshot::borrowed(None, &bytes);
        audit_zip64_covering(&snapshot, &original).expect("source-derived ZIP64 evidence audits");

        macro_rules! rejects {
            ($ir:ident, $edit:block) => {{
                let mut $ir = original.clone();
                $edit
                let snapshot = crate::snapshot::SourceSnapshot::borrowed(None, &bytes);
                assert_eq!(
                    audit_zip64_covering(&snapshot, &$ir).unwrap_err().code,
                    FindingCode::CoveringInconsistent
                );
            }};
        }

        rejects!(ir, {
            zip64_covering_mut(&mut ir).eocd.len = 23;
        });
        rejects!(ir, {
            zip64_covering_mut(&mut ir).zip64_eocd = Some(ByteRange { offset: 0, len: 56 });
        });
        rejects!(ir, {
            zip64_covering_mut(&mut ir).central_directory.len += 1;
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0).zip.method ^= 8;
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0).zip.flags = 0x0008;
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0).zip.declared_crc ^= 1;
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0).zip.creator_system ^= 1;
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0).zip.external_attributes ^= 1;
        });
        rejects!(ir, {
            ir.members[0].raw_name_bytes[0] = b'b';
        });
        rejects!(ir, {
            ir.members[0].kind = MemberKind::Directory;
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0).local_version_needed = 20;
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0).central_version_needed = 20;
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0).central_presence_mask = 1;
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0).central_legacy_sentinel_mask = 1;
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0).local_legacy_sentinel_mask = 0;
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0).local_value_shape = Zip64LocalValueShape::StreamingZeros;
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0).local_zip64_extra = None;
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0).central_zip64_extra =
                zip64_member_mut(&mut ir, 0).local_zip64_extra;
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0).descriptor_width = Some(Zip64DataDescriptorWidth::Zip32);
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0)
                .zip
                .source_ranges
                .local_header
                .len = u64::MAX;
        });
        rejects!(ir, {
            zip64_member_mut(&mut ir, 0).zip.extra_fields[0]
                .header_range
                .len = u64::MAX;
        });
    }

    #[test]
    fn tar_covering_oracle_rejects_each_evidence_layer_drift() {
        let bytes = make_tar();
        let original = admitted_tar_ir(&bytes);
        let audit = |ir: &ArchiveIR| {
            let snapshot = crate::snapshot::SourceSnapshot::borrowed(None, &bytes);
            assert_eq!(
                audit_tar_covering(&snapshot, ir).unwrap_err().code,
                FindingCode::CoveringInconsistent
            );
        };

        let snapshot = crate::snapshot::SourceSnapshot::borrowed(None, &bytes);
        audit_tar_covering(&snapshot, &original).unwrap();

        let mut covering = original.clone();
        tar_covering_mut(&mut covering).trailing_zeros.len = 1;
        audit(&covering);

        let mut evidence = original.clone();
        tar_member_mut(&mut evidence, 0).header.offset = 1;
        audit(&evidence);

        let mut digest = original;
        tar_member_mut(&mut digest, 0).header_sha256 = "0".repeat(64);
        audit(&digest);

        let original = admitted_tar_ir(&bytes);
        let mut nonzero_padding = bytes.clone();
        nonzero_padding[517] = 1;
        let padding_snapshot = crate::snapshot::SourceSnapshot::borrowed(None, &nonzero_padding);
        let mut padding_ir = original.clone();
        padding_ir.source_digest = padding_snapshot.digest().to_owned();
        assert_eq!(
            audit_tar_covering(&padding_snapshot, &padding_ir)
                .unwrap_err()
                .code,
            FindingCode::CoveringInconsistent
        );

        let mut trailing_bytes = bytes;
        trailing_bytes.resize(2560, 0);
        let mut trailing_ir = admitted_tar_ir(&trailing_bytes);
        trailing_bytes[2048] = 1;
        let trailing_snapshot = crate::snapshot::SourceSnapshot::borrowed(None, &trailing_bytes);
        trailing_ir.source_digest = trailing_snapshot.digest().to_owned();
        assert_eq!(
            audit_tar_covering(&trailing_snapshot, &trailing_ir)
                .unwrap_err()
                .code,
            FindingCode::CoveringInconsistent
        );
    }

    #[test]
    fn pax_covering_oracle_replays_state_and_rejects_each_evidence_layer_drift() {
        let bytes = make_pax_tar();
        let original = admitted_pax_ir(&bytes);
        let snapshot = crate::snapshot::SourceSnapshot::borrowed(None, &bytes);
        audit_tar_pax_covering(&snapshot, &original).expect("source-derived PAX evidence audits");
        assert_eq!(original.pax_extensions().unwrap().len(), 2);
        assert_eq!(original.members.len(), 2);

        let audit = |ir: &ArchiveIR| {
            let snapshot = crate::snapshot::SourceSnapshot::borrowed(None, &bytes);
            assert_eq!(
                audit_tar_pax_covering(&snapshot, ir).unwrap_err().code,
                FindingCode::CoveringInconsistent
            );
        };

        let mut ir = original.clone();
        pax_archive_mut(&mut ir).tar.terminator.len = 512;
        audit(&ir);

        let mut ir = original.clone();
        pax_archive_mut(&mut ir).extensions.swap(0, 1);
        audit(&ir);

        let mut ir = original.clone();
        pax_archive_mut(&mut ir).extensions[0].header_sha256 = "0".repeat(64);
        audit(&ir);

        let mut ir = original.clone();
        pax_archive_mut(&mut ir).extensions[0].payload_sha256 = "0".repeat(64);
        audit(&ir);

        let mut ir = original.clone();
        pax_archive_mut(&mut ir).extensions[0].records[0]
            .record
            .offset += 1;
        audit(&ir);

        let mut ir = original.clone();
        pax_archive_mut(&mut ir).extensions[0].records[0].raw_value_bytes[0] ^= 1;
        audit(&ir);

        let mut ir = original.clone();
        pax_archive_mut(&mut ir).extensions[0].records[1].parsed_size = Some(5);
        audit(&ir);

        let mut ir = original.clone();
        pax_member_mut(&mut ir, 0).path_source = PaxValueSource::Ustar;
        audit(&ir);

        let mut ir = original.clone();
        pax_member_mut(&mut ir, 1).size_source = PaxValueSource::Global {
            extension_index: 0,
            record_index: 1,
        };
        audit(&ir);

        let mut ir = original.clone();
        pax_member_mut(&mut ir, 0).base_name_bytes[0] ^= 1;
        audit(&ir);

        let mut ir = original.clone();
        ir.members[0].raw_name_bytes[0] ^= 1;
        audit(&ir);

        let mut ir = original;
        pax_member_mut(&mut ir, 1).tar.padding.len += 1;
        audit(&ir);
    }

    #[test]
    fn gnu_covering_oracle_replays_state_and_rejects_each_evidence_layer_drift() {
        let bytes = make_gnu_longname_tar();
        let original = admitted_gnu_ir(&bytes);
        let snapshot = crate::snapshot::SourceSnapshot::borrowed(None, &bytes);
        audit_tar_gnu_longname_covering(&snapshot, &original)
            .expect("source-derived GNU long-name evidence audits");
        assert_eq!(original.gnu_longname_carriers().unwrap().len(), 1);
        assert_eq!(original.members.len(), 1);

        let audit = |ir: &ArchiveIR| {
            let snapshot = crate::snapshot::SourceSnapshot::borrowed(None, &bytes);
            assert_eq!(
                audit_tar_gnu_longname_covering(&snapshot, ir)
                    .unwrap_err()
                    .code,
                FindingCode::CoveringInconsistent
            );
        };

        macro_rules! rejects {
            ($ir:ident, $edit:block) => {{
                let mut $ir = original.clone();
                $edit
                audit(&$ir);
            }};
        }

        rejects!(ir, {
            gnu_archive_mut(&mut ir).tar.terminator.len = 512;
        });
        rejects!(ir, {
            gnu_archive_mut(&mut ir).carriers[0].header.offset += 1;
        });
        rejects!(ir, {
            gnu_archive_mut(&mut ir).carriers[0].payload.len -= 1;
        });
        rejects!(ir, {
            gnu_archive_mut(&mut ir).carriers[0].path.len -= 1;
        });
        rejects!(ir, {
            gnu_archive_mut(&mut ir).carriers[0].padding.offset += 1;
        });
        rejects!(ir, {
            gnu_archive_mut(&mut ir).carriers[0].raw_name_bytes[0] ^= 1;
        });
        rejects!(ir, {
            gnu_archive_mut(&mut ir).carriers[0].path_bytes[0] ^= 1;
        });
        rejects!(ir, {
            gnu_archive_mut(&mut ir).carriers[0].mode ^= 1;
        });
        rejects!(ir, {
            gnu_archive_mut(&mut ir).carriers[0].mtime += 1;
        });
        rejects!(ir, {
            gnu_archive_mut(&mut ir).carriers[0].header_checksum ^= 1;
        });
        rejects!(ir, {
            gnu_archive_mut(&mut ir).carriers[0].header_sha256 = "0".repeat(64);
        });
        rejects!(ir, {
            gnu_archive_mut(&mut ir).carriers[0].payload_sha256 = "0".repeat(64);
        });
        rejects!(ir, {
            gnu_archive_mut(&mut ir).carriers.clear();
        });
        rejects!(ir, {
            gnu_member_mut(&mut ir, 0).base_name_bytes[0] ^= 1;
        });
        rejects!(ir, {
            gnu_member_mut(&mut ir, 0).path_source = GnuLongNamePathSource::Header;
        });
        rejects!(ir, {
            gnu_member_mut(&mut ir, 0).path_source =
                GnuLongNamePathSource::Carrier { carrier_index: 1 };
        });
        rejects!(ir, {
            gnu_member_mut(&mut ir, 0).tar.header.offset += 1;
        });
        rejects!(ir, {
            gnu_member_mut(&mut ir, 0).tar.payload.len += 1;
        });
        rejects!(ir, {
            gnu_member_mut(&mut ir, 0).tar.header_sha256 = "0".repeat(64);
        });
        rejects!(ir, {
            ir.members[0].raw_name_bytes[0] ^= 1;
        });
        rejects!(ir, {
            ir.members[0].kind = MemberKind::Directory;
        });
        rejects!(ir, {
            ir.members[0].canonical_path.push('x');
        });
    }

    #[test]
    fn pax_covering_header_enforces_underlying_directory_size() {
        fn header(size: u64, typeflag: u8) -> [u8; 512] {
            fn octal(field: &mut [u8], value: u64) {
                field.fill(b'0');
                let value = format!("{value:o}");
                let end = field.len() - 1;
                field[end - value.len()..end].copy_from_slice(value.as_bytes());
                field[end] = 0;
            }

            let mut header = [0_u8; 512];
            header[..3].copy_from_slice(b"dir");
            octal(&mut header[100..108], 0o755);
            octal(&mut header[108..116], 0);
            octal(&mut header[116..124], 0);
            octal(&mut header[124..136], size);
            octal(&mut header[136..148], 0);
            header[148..156].fill(b' ');
            header[156] = typeflag;
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            octal(&mut header[329..337], 0);
            octal(&mut header[337..345], 0);
            let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
            header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
            header[154] = 0;
            header[155] = b' ';
            header
        }

        let error = audit_pax_header(&header(1, b'5')).unwrap_err();
        assert_eq!(error.code, FindingCode::CoveringInconsistent);
        assert!(error
            .detail
            .contains("PAX directory has a nonzero underlying size"));
        audit_pax_header(&header(0, b'5')).expect("zero-size directory remains canonical");
        audit_pax_header(&header(1, b'0')).expect("nonzero regular file remains canonical");
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
        let covering = zip_covering_mut(&mut ir);
        covering.comment.len = covering.comment.len.saturating_add(1);
        assert_eq!(
            covering_error(&bytes, &ir).code,
            FindingCode::CoveringInconsistent
        );

        let mut ir = original.clone();
        zip_covering_mut(&mut ir).eocd.len = 23;
        assert_eq!(
            covering_error(&bytes, &ir).code,
            FindingCode::CoveringInconsistent
        );

        let mut ir = original.clone();
        let central_offset = zip_member_mut(&mut ir, 0)
            .source_ranges
            .central_header
            .offset;
        zip_member_mut(&mut ir, 0).source_ranges.local_header.offset = central_offset;
        assert_eq!(
            covering_error(&bytes, &ir).code,
            FindingCode::CoveringInconsistent
        );

        let mut ir = original.clone();
        let member = zip_member_mut(&mut ir, 0);
        member.source_ranges.compressed_payload.len = member
            .source_ranges
            .compressed_payload
            .len
            .saturating_add(1);
        assert_eq!(
            covering_error(&bytes, &ir).code,
            FindingCode::CoveringInconsistent
        );

        let mut ir = original.clone();
        zip_member_mut(&mut ir, 0).source_ranges.central_header.len = 45;
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
        zip_covering_mut(&mut ir).eocd.offset = u64::MAX;
        assert_eq!(
            covering_error(&bytes, &ir).code,
            FindingCode::CoveringInconsistent
        );

        let mut ir = original;
        zip_member_mut(&mut ir, 0).source_ranges.local_header.offset = u64::MAX;
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
        let covering = ir.zip_covering().unwrap();
        assert_eq!(covering.local_records.len, 0);
        assert_eq!(covering.central_directory.len, 0);
        let snapshot = crate::snapshot::SourceSnapshot::borrowed(None, &bytes);
        audit_covering(&snapshot, &ir).expect("empty covering should certify the snapshot");
    }

    #[test]
    fn ordered_partition_matches_bounded_bitmap_oracle() {
        let candidates: Vec<CheckedInterval> = (0..=5)
            .flat_map(|start| {
                (start..=5).map(move |end| CheckedInterval::from_bounds(start, end).unwrap())
            })
            .collect();
        let mut case_count = 0;

        for outer_start in 0..=5 {
            for outer_end in outer_start..=5 {
                let outer = CheckedInterval::from_bounds(outer_start, outer_end).unwrap();
                let mut parts = Vec::new();
                for part_count in 0..=3 {
                    compare_all_ordered_part_lists(
                        outer,
                        &candidates,
                        &mut parts,
                        part_count,
                        &mut case_count,
                    );
                }
            }
        }

        assert_eq!(case_count, 204_204);
    }

    fn compare_all_ordered_part_lists(
        outer: CheckedInterval,
        candidates: &[CheckedInterval],
        parts: &mut Vec<CheckedInterval>,
        remaining: usize,
        case_count: &mut usize,
    ) {
        if remaining == 0 {
            let expected = covering_bitmap_partition_oracle(outer, parts);
            let mut ordered = parts.clone();
            ordered.sort_unstable_by_key(|interval| interval.start());
            let actual = validate_ordered_partition(
                outer,
                &ordered,
                "first gap",
                "last gap",
                "invalid partition",
            )
            .is_ok();
            assert_eq!(actual, expected, "outer={outer:?}, parts={parts:?}");
            *case_count += 1;
            return;
        }

        for &candidate in candidates {
            parts.push(candidate);
            compare_all_ordered_part_lists(outer, candidates, parts, remaining - 1, case_count);
            parts.pop();
        }
    }

    fn covering_bitmap_partition_oracle(outer: CheckedInterval, parts: &[CheckedInterval]) -> bool {
        if outer.is_empty() {
            return parts.is_empty();
        }
        if parts.is_empty() || parts.iter().any(|part| part.is_empty()) {
            return false;
        }

        let mut counts = vec![0_u8; (outer.end() - outer.start()) as usize];
        for part in parts {
            if part.start() < outer.start() || part.end() > outer.end() {
                return false;
            }
            for position in part.start()..part.end() {
                let index = (position - outer.start()) as usize;
                counts[index] = counts[index].saturating_add(1);
            }
        }
        counts.into_iter().all(|count| count == 1)
    }

    #[test]
    fn compatibility_error_conversion_fails_closed_without_panicking() {
        let finding = CoveringAuditError::AllocationFailed.into_finding();
        assert_eq!(finding.code, FindingCode::CoveringInconsistent);
        assert_eq!(finding.severity, crate::findings::Severity::Error);
        assert_eq!(finding.member, None);
        assert_eq!(
            finding.detail,
            "bounded covering audit could not reserve scratch space"
        );
    }
}
