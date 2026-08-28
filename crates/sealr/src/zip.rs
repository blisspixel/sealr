//! CD-first ZIP reader. One interpretation. Disagreement is a finding.

use crate::findings::{Finding, FindingCode};
use crate::interval::{exact_partition, CheckedInterval, IntervalError, PartitionError};
use crate::ir::{
    is_denied_extra_id, ByteRange, ExtraDisposition, ExtraFieldRecord, ExtraSite, IrMember,
    MemberSourceRanges, ZipInterpretationProfile,
};
use crate::snapshot::SourceSnapshot;
use std::collections::BTreeSet;
use std::io::Read;

const EOCD_SIG: u32 = 0x0605_4b50;
const CDH_SIG: u32 = 0x0201_4b50;
const LFH_SIG: u32 = 0x0403_4b50;
const DATA_DESCRIPTOR_SIG: u32 = 0x0807_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
const EOCD_MIN: usize = 22;

const ZIP64_EXTRA_ID: u16 = 0x0001;
const ZIP64_U32_SENTINEL: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Zip64CentralValues {
    uncompressed_size: u64,
    compressed_size: u64,
    local_header_offset: u64,
    presence_mask: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Zip64ExtraResolutionError {
    InvalidLength,
    MissingRequiredValue,
    Ambiguous,
    ValueMismatch,
    NoncanonicalLegacyValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum DataDescriptorWidth {
    Zip32,
    Zip64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ClassicEndFields {
    entries_on_disk: u16,
    total_entries: u16,
    central_directory_size: u32,
    central_directory_offset: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResolvedEndRecords {
    total_entries: u64,
    central_directory_size: u64,
    central_directory_offset: u64,
    zip64_eocd: Option<ByteRange>,
    zip64_locator: Option<ByteRange>,
}

fn canonical_legacy_u16(legacy: u16, resolved: u64) -> bool {
    if resolved < u64::from(u16::MAX) {
        u64::from(legacy) == resolved
    } else {
        legacy == u16::MAX
    }
}

fn canonical_legacy_u32(legacy: u32, resolved: u64) -> bool {
    if resolved < u64::from(u32::MAX) {
        u64::from(legacy) == resolved
    } else {
        legacy == u32::MAX
    }
}

/// Resolves the optional ZIP64 end pair immediately before a classic EOCD.
/// The first profile permits only the fixed 56-byte record and 20-byte
/// locator, both single-disk and exactly adjacent.
#[allow(dead_code)]
fn resolve_zip64_end_records(
    snapshot: &SourceSnapshot<'_>,
    eocd_offset: u64,
    classic: ClassicEndFields,
) -> Result<ResolvedEndRecords, Finding> {
    if classic.entries_on_disk != classic.total_entries {
        return Err(Finding::error(
            FindingCode::ZipDiffC3Count,
            "classic EOCD per-disk and total entry counts disagree",
        ));
    }
    let has_sentinel = classic.entries_on_disk == u16::MAX
        || classic.total_entries == u16::MAX
        || classic.central_directory_size == u32::MAX
        || classic.central_directory_offset == u32::MAX;
    let Some(locator_offset) = eocd_offset.checked_sub(20) else {
        if has_sentinel {
            return Err(Finding::error(
                FindingCode::ZipDiffC5Zip64,
                "ZIP64 legacy sentinel has no locator",
            ));
        }
        return Ok(ResolvedEndRecords {
            total_entries: u64::from(classic.total_entries),
            central_directory_size: u64::from(classic.central_directory_size),
            central_directory_offset: u64::from(classic.central_directory_offset),
            zip64_eocd: None,
            zip64_locator: None,
        });
    };
    let mut locator = [0_u8; 20];
    snapshot.read_exact_at(locator_offset, &mut locator)?;
    if u32::from_le_bytes(locator[0..4].try_into().unwrap()) != ZIP64_LOCATOR_SIG {
        if has_sentinel {
            return Err(Finding::error(
                FindingCode::ZipDiffC5Zip64,
                "ZIP64 legacy sentinel has no locator",
            ));
        }
        return Ok(ResolvedEndRecords {
            total_entries: u64::from(classic.total_entries),
            central_directory_size: u64::from(classic.central_directory_size),
            central_directory_offset: u64::from(classic.central_directory_offset),
            zip64_eocd: None,
            zip64_locator: None,
        });
    }

    let locator_disk = u32::from_le_bytes(locator[4..8].try_into().unwrap());
    let zip64_eocd_offset = u64::from_le_bytes(locator[8..16].try_into().unwrap());
    let total_disks = u32::from_le_bytes(locator[16..20].try_into().unwrap());
    if locator_disk != 0 || total_disks != 1 {
        return Err(Finding::error(
            FindingCode::ZipDiffC3Count,
            "ZIP64 locator describes a spanned archive",
        ));
    }
    if zip64_eocd_offset.checked_add(56) != Some(locator_offset) {
        return Err(Finding::error(
            FindingCode::ZipDiffC4Offset,
            "ZIP64 EOCD does not exactly abut its locator",
        ));
    }

    let mut record = [0_u8; 56];
    snapshot
        .read_exact_at(zip64_eocd_offset, &mut record)
        .map_err(|_| Finding::error(FindingCode::ZipDiffC4Offset, "ZIP64 EOCD extends past EOF"))?;
    if u32::from_le_bytes(record[0..4].try_into().unwrap()) != ZIP64_EOCD_SIG {
        return Err(Finding::error(
            FindingCode::ZipDiffC5Zip64,
            "ZIP64 locator does not point to a ZIP64 EOCD",
        ));
    }
    if u64::from_le_bytes(record[4..12].try_into().unwrap()) != 44 {
        return Err(Finding::error(
            FindingCode::ZipDiffC5Zip64,
            "ZIP64 EOCD extensible sector is denied",
        ));
    }
    let version_needed = u16::from_le_bytes(record[14..16].try_into().unwrap());
    if version_needed < 45 {
        return Err(Finding::error(
            FindingCode::ZipDiffC5Zip64,
            "ZIP64 EOCD requires extraction version 4.5 or later",
        ));
    }
    let this_disk = u32::from_le_bytes(record[16..20].try_into().unwrap());
    let central_directory_disk = u32::from_le_bytes(record[20..24].try_into().unwrap());
    if this_disk != 0 || central_directory_disk != 0 {
        return Err(Finding::error(
            FindingCode::ZipDiffC3Count,
            "ZIP64 EOCD describes a spanned archive",
        ));
    }
    let entries_on_disk = u64::from_le_bytes(record[24..32].try_into().unwrap());
    let total_entries = u64::from_le_bytes(record[32..40].try_into().unwrap());
    if entries_on_disk != total_entries {
        return Err(Finding::error(
            FindingCode::ZipDiffC3Count,
            "ZIP64 per-disk and total entry counts disagree",
        ));
    }
    let central_directory_size = u64::from_le_bytes(record[40..48].try_into().unwrap());
    let central_directory_offset = u64::from_le_bytes(record[48..56].try_into().unwrap());
    if central_directory_offset.checked_add(central_directory_size) != Some(zip64_eocd_offset) {
        return Err(Finding::error(
            FindingCode::ZipDiffC4Offset,
            "ZIP64 central-directory geometry does not land on the ZIP64 EOCD",
        ));
    }
    if !canonical_legacy_u16(classic.entries_on_disk, entries_on_disk)
        || !canonical_legacy_u16(classic.total_entries, total_entries)
        || !canonical_legacy_u32(classic.central_directory_size, central_directory_size)
        || !canonical_legacy_u32(classic.central_directory_offset, central_directory_offset)
    {
        return Err(Finding::error(
            FindingCode::ZipDiffC5Zip64,
            "classic EOCD and ZIP64 EOCD values are not canonically identical",
        ));
    }

    Ok(ResolvedEndRecords {
        total_entries,
        central_directory_size,
        central_directory_offset,
        zip64_eocd: Some(ByteRange {
            offset: zip64_eocd_offset,
            len: 56,
        }),
        zip64_locator: Some(ByteRange {
            offset: locator_offset,
            len: 20,
        }),
    })
}

/// Resolves the sentinel-driven ZIP64 values in a central-directory extra.
///
/// APPNOTE fixes the logical field order but major writers sometimes include
/// exact redundant in-range values. There are only eight possible presence
/// masks for the three supported fields, so enumerate them and require one
/// complete interpretation instead of shifting fields heuristically.
#[allow(dead_code)]
fn resolve_zip64_central_values(
    data: &[u8],
    legacy_uncompressed_size: u32,
    legacy_compressed_size: u32,
    legacy_local_header_offset: u32,
) -> Result<Zip64CentralValues, Zip64ExtraResolutionError> {
    if data.is_empty() || data.len() > 24 || !data.len().is_multiple_of(8) {
        return Err(Zip64ExtraResolutionError::InvalidLength);
    }

    let legacy = [
        legacy_uncompressed_size,
        legacy_compressed_size,
        legacy_local_header_offset,
    ];
    let required_mask = legacy
        .iter()
        .enumerate()
        .fold(0_u8, |mask, (index, value)| {
            if *value == ZIP64_U32_SENTINEL {
                mask | (1_u8 << index)
            } else {
                mask
            }
        });
    let value_count = data.len() / 8;
    let mut unique = None;
    let mut matching_masks = 0_u8;

    for presence_mask in 1_u8..8 {
        if presence_mask.count_ones() as usize != value_count
            || presence_mask & required_mask != required_mask
        {
            continue;
        }

        let mut cursor = 0_usize;
        let mut resolved = legacy.map(u64::from);
        let mut valid = true;
        for index in 0..3 {
            if presence_mask & (1_u8 << index) == 0 {
                continue;
            }
            let value = u64::from_le_bytes(data[cursor..cursor + 8].try_into().unwrap());
            cursor += 8;
            if legacy[index] == ZIP64_U32_SENTINEL {
                if value < u64::from(ZIP64_U32_SENTINEL) {
                    valid = false;
                    break;
                }
                resolved[index] = value;
            } else if value != u64::from(legacy[index]) {
                valid = false;
                break;
            }
        }
        if !valid || cursor != data.len() {
            continue;
        }

        matching_masks = matching_masks.saturating_add(1);
        unique = Some(Zip64CentralValues {
            uncompressed_size: resolved[0],
            compressed_size: resolved[1],
            local_header_offset: resolved[2],
            presence_mask,
        });
    }

    match (matching_masks, unique) {
        (0, _) if required_mask != 0 => Err(Zip64ExtraResolutionError::MissingRequiredValue),
        (0, _) => Err(Zip64ExtraResolutionError::InvalidLength),
        (1, Some(values)) => Ok(values),
        _ => Err(Zip64ExtraResolutionError::Ambiguous),
    }
}

/// Resolves the two size values permitted in a local ZIP64 extra field.
/// Forced ZIP64 writers may saturate both legacy fields for small members.
/// A gratuitously mixed forced representation is denied, while a mixed pair
/// remains valid when one resolved size genuinely requires saturation.
#[allow(dead_code)]
fn validate_zip64_local_values(
    data: &[u8],
    legacy_uncompressed_size: u32,
    legacy_compressed_size: u32,
    expected_uncompressed_size: u64,
    expected_compressed_size: u64,
) -> Result<(), Zip64ExtraResolutionError> {
    if data.len() != 16 {
        return Err(Zip64ExtraResolutionError::InvalidLength);
    }
    let uncompressed_size = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let compressed_size = u64::from_le_bytes(data[8..16].try_into().unwrap());
    if uncompressed_size != expected_uncompressed_size
        || compressed_size != expected_compressed_size
    {
        return Err(Zip64ExtraResolutionError::ValueMismatch);
    }

    let forced = legacy_uncompressed_size == u32::MAX && legacy_compressed_size == u32::MAX;
    let canonical = canonical_legacy_u32(legacy_uncompressed_size, uncompressed_size)
        && canonical_legacy_u32(legacy_compressed_size, compressed_size);
    if forced || canonical {
        Ok(())
    } else {
        Err(Zip64ExtraResolutionError::NoncanonicalLegacyValue)
    }
}

#[cfg(test)]
thread_local! {
    static PARSE_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_parse_calls() {
    PARSE_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(crate) fn parse_calls() -> u64 {
    PARSE_CALLS.with(std::cell::Cell::get)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZipMember {
    pub raw_name: Vec<u8>,
    pub name: String,
    pub method: u16,
    pub flags: u16,
    pub creator_system: u8,
    pub external_attributes: u32,
    pub crc: u32,
    pub comp_size: u64,
    pub uncomp_size: u64,
    pub lfh_offset: u64,
    pub data_offset: u64,
    pub record_end: u64,
    pub is_dir: bool,
    pub extra_fields: Vec<ExtraFieldRecord>,
    pub source_ranges: MemberSourceRanges,
}

struct LocalHeader {
    data_offset: u64,
    extra_offset: u64,
    name: Vec<u8>,
    method: u16,
    flags: u16,
    comp_size: u32,
    uncomp_size: u32,
    crc: u32,
    extra: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZipArchive {
    pub members: Vec<ZipMember>,
    pub cd_offset: u64,
    pub cd_size: u64,
    pub eocd_offset: u64,
    pub comment_len: u64,
    pub metadata_bytes: u64,
}

impl ZipArchive {
    pub fn covering(&self) -> crate::ir::ArchiveCovering {
        crate::ir::ArchiveCovering::from_zip32(
            self.cd_offset,
            self.cd_size,
            self.eocd_offset,
            self.comment_len,
        )
    }
}

#[cfg(test)]
pub fn parse_zip(
    bytes: &[u8],
    max_files: u64,
    max_metadata_bytes: u64,
) -> Result<ZipArchive, Finding> {
    let snapshot = SourceSnapshot::borrowed(None, bytes);
    parse_zip_with_profile(
        &snapshot,
        max_files,
        max_metadata_bytes,
        ZipInterpretationProfile::StrictAsciiV1,
    )
}

pub fn parse_zip_with_profile(
    snapshot: &SourceSnapshot<'_>,
    max_files: u64,
    max_metadata_bytes: u64,
    profile: ZipInterpretationProfile,
) -> Result<ZipArchive, Finding> {
    #[cfg(test)]
    PARSE_CALLS.with(|calls| calls.set(calls.get() + 1));

    if snapshot.len() < EOCD_MIN as u64 {
        return Err(Finding::error(
            FindingCode::FormatUnsupported,
            "too small to be ZIP",
        ));
    }
    let (eocd_off, comment_len) = find_eocd(snapshot)?;
    let mut eocd = [0_u8; EOCD_MIN];
    snapshot.read_exact_at(eocd_off, &mut eocd)?;
    let comment = snapshot.read_vec(eocd_off + EOCD_MIN as u64, u64::from(comment_len))?;
    reject_structural_metadata(&comment, "EOCD comment")?;
    let this_disk = u16::from_le_bytes(eocd[4..6].try_into().unwrap());
    let cd_disk = u16::from_le_bytes(eocd[6..8].try_into().unwrap());
    let this_count = u16::from_le_bytes(eocd[8..10].try_into().unwrap());
    let total_count = u16::from_le_bytes(eocd[10..12].try_into().unwrap());
    let cd_size = u32::from_le_bytes(eocd[12..16].try_into().unwrap());
    let cd_offset = u32::from_le_bytes(eocd[16..20].try_into().unwrap());
    if this_disk != 0 || cd_disk != 0 {
        return Err(Finding::error(FindingCode::ZipDiffC3Count, "spanned ZIP"));
    }
    if this_count != total_count {
        return Err(Finding::error(
            FindingCode::ZipDiffC3Count,
            "this-disk count != total",
        ));
    }
    if cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF || total_count == 0xFFFF {
        return Err(Finding::error(
            FindingCode::ZipDiffC5Zip64,
            "ZIP64 fields not implemented",
        ));
    }
    if u64::from(total_count) > max_files {
        return Err(Finding::error(
            FindingCode::QuotaFiles,
            format!("{total_count} entries; cap is {max_files}"),
        ));
    }
    let cd_offset = u64::from(cd_offset);
    let cd_size = u64::from(cd_size);
    let mut metadata_bytes = u64::from(comment_len).checked_add(cd_size).ok_or_else(|| {
        Finding::error(FindingCode::QuotaOverflow, "ZIP metadata counter overflow")
    })?;
    if metadata_bytes > max_metadata_bytes {
        return Err(Finding::error(
            FindingCode::QuotaMetadata,
            format!("ZIP metadata exceeds {max_metadata_bytes} bytes"),
        ));
    }
    if cd_offset.checked_add(cd_size) != Some(eocd_off) {
        return Err(Finding::error(
            FindingCode::ZipDiffC4Offset,
            "CD size+offset does not land on EOCD",
        ));
    }
    let central_directory = snapshot
        .read_vec(cd_offset, cd_size)
        .map_err(|_| Finding::error(FindingCode::ZipDiffC4Offset, "CD extends past file"))?;

    let mut members = Vec::new();
    let mut pos = 0_usize;
    let cd_end = central_directory.len();
    while pos < cd_end {
        let parsed_count = u64::try_from(members.len()).map_err(|_| {
            Finding::error(
                FindingCode::QuotaOverflow,
                "parsed member count does not fit u64",
            )
        })?;
        if parsed_count >= max_files {
            return Err(Finding::error(
                FindingCode::QuotaFiles,
                format!("central directory contains more than {max_files} entries"),
            ));
        }
        if pos + 46 > cd_end {
            return Err(Finding::error(FindingCode::ZipDiffC3Count, "truncated CDH"));
        }
        let sig = u32::from_le_bytes(central_directory[pos..pos + 4].try_into().unwrap());
        if sig != CDH_SIG {
            return Err(Finding::error(
                FindingCode::ZipDiffC3Count,
                "bad CDH signature",
            ));
        }
        let flags = u16::from_le_bytes(central_directory[pos + 8..pos + 10].try_into().unwrap());
        let method = u16::from_le_bytes(central_directory[pos + 10..pos + 12].try_into().unwrap());
        let version_made_by =
            u16::from_le_bytes(central_directory[pos + 4..pos + 6].try_into().unwrap());
        let crc = u32::from_le_bytes(central_directory[pos + 16..pos + 20].try_into().unwrap());
        let comp = u32::from_le_bytes(central_directory[pos + 20..pos + 24].try_into().unwrap());
        let uncomp = u32::from_le_bytes(central_directory[pos + 24..pos + 28].try_into().unwrap());
        let name_len =
            u16::from_le_bytes(central_directory[pos + 28..pos + 30].try_into().unwrap()) as usize;
        let extra_len =
            u16::from_le_bytes(central_directory[pos + 30..pos + 32].try_into().unwrap()) as usize;
        let comment_len =
            u16::from_le_bytes(central_directory[pos + 32..pos + 34].try_into().unwrap()) as usize;
        let disk_start =
            u16::from_le_bytes(central_directory[pos + 34..pos + 36].try_into().unwrap());
        let lfh_offset =
            u32::from_le_bytes(central_directory[pos + 42..pos + 46].try_into().unwrap());
        let external_attributes =
            u32::from_le_bytes(central_directory[pos + 38..pos + 42].try_into().unwrap());
        if comp == 0xFFFF_FFFF
            || uncomp == 0xFFFF_FFFF
            || lfh_offset == 0xFFFF_FFFF
            || disk_start == 0xFFFF
        {
            return Err(Finding::error(FindingCode::ZipDiffC5Zip64, "ZIP64 member").on(""));
        }
        if disk_start != 0 {
            return Err(Finding::error(
                FindingCode::ZipDiffC3Count,
                "central-directory member starts on another disk",
            )
            .on(""));
        }
        let name_off = pos + 46;
        if name_off + name_len + extra_len + comment_len > cd_end {
            return Err(Finding::error(
                FindingCode::ZipDiffC3Count,
                "CDH name overflows CD",
            ));
        }
        let name_bytes = &central_directory[name_off..name_off + name_len];
        let central_extra_off = name_off + name_len;
        let central_extra = &central_directory[central_extra_off..central_extra_off + extra_len];
        let central_comment = &central_directory
            [central_extra_off + extra_len..central_extra_off + extra_len + comment_len];
        let central_extra_absolute =
            cd_offset
                .checked_add(central_extra_off as u64)
                .ok_or_else(|| {
                    Finding::error(
                        FindingCode::ZipDiffC4Offset,
                        "central extra-field offset overflow",
                    )
                })?;
        let mut extra_fields = classify_extra_fields(
            central_extra,
            central_extra_absolute,
            ExtraSite::Central,
            "central directory",
            name_bytes,
            profile,
        )?;
        reject_structural_metadata(central_comment, "central-directory comment")?;
        let lfh_offset = u64::from(lfh_offset);
        let local = parse_lfh(snapshot, lfh_offset)?;
        extra_fields.extend(classify_extra_fields(
            &local.extra,
            local.extra_offset,
            ExtraSite::Local,
            "local header",
            name_bytes,
            profile,
        )?);
        let display_name = String::from_utf8_lossy(name_bytes);
        if local.name != name_bytes {
            return Err(
                Finding::error(FindingCode::ZipDiffA3Name, "CDH name != LFH name")
                    .on(display_name.as_ref()),
            );
        }
        if local.method != method {
            return Err(
                Finding::error(FindingCode::ZipDiffA1Method, "CDH method != LFH method")
                    .on(display_name.as_ref()),
            );
        }
        if local.flags != flags {
            let code = if (flags & 1) != (local.flags & 1) {
                FindingCode::ZipDiffA5Crypt
            } else {
                FindingCode::ZipFlags
            };
            return Err(Finding::error(code, "CDH flags != LFH flags").on(display_name.as_ref()));
        }
        validate_general_purpose_flags(flags, profile, name_bytes)?;
        let gp3 = flags & 0x8 != 0;
        if !gp3 && (local.comp_size != comp || local.uncomp_size != uncomp) {
            return Err(
                Finding::error(FindingCode::ZipDiffA2Size, "CDH sizes != LFH sizes")
                    .on(display_name.as_ref()),
            );
        }
        if !gp3 && local.crc != crc {
            // CRC stored in both; mismatch is A2-adjacent integrity confusion.
            return Err(
                Finding::error(FindingCode::ZipDiffA2Size, "CDH CRC != LFH CRC")
                    .on(display_name.as_ref()),
            );
        }
        if gp3
            && ((local.comp_size != 0 && local.comp_size != comp)
                || (local.uncomp_size != 0 && local.uncomp_size != uncomp)
                || (local.crc != 0 && local.crc != crc))
        {
            return Err(Finding::error(
                FindingCode::ZipDiffA2Size,
                "LFH data-descriptor placeholders disagree with the CDH",
            )
            .on(display_name.as_ref()));
        }
        let name = decode_name_for_profile(name_bytes, flags, profile)?;
        validate_directory_metadata(
            &name,
            version_made_by,
            external_attributes,
            method,
            crc,
            comp,
            uncomp,
        )?;
        let is_dir = name.ends_with('/');
        let payload_end = local
            .data_offset
            .checked_add(u64::from(comp))
            .ok_or_else(|| {
                Finding::error(FindingCode::ZipDiffC4Offset, "payload end overflows").on(&name)
            })?;
        if gp3
            && method == 0
            && contains_stream_signature_in_range(snapshot, local.data_offset, u64::from(comp))
                .map_err(|finding| finding.on(&name))?
        {
            return Err(Finding::error(
                FindingCode::ZipDiffC1Stream,
                "stored data-descriptor payload contains an alternate record signature",
            )
            .on(&name));
        }
        let record_end = if gp3 {
            parse_data_descriptor(snapshot, payload_end, crc, comp, uncomp)?
        } else {
            payload_end
        };
        let local_header_len = local.data_offset.checked_sub(lfh_offset).ok_or_else(|| {
            Finding::error(
                FindingCode::ZipDiffC4Offset,
                "local header length underflow",
            )
            .on(&name)
        })?;
        let payload_len = comp as u64;
        let descriptor_range = if gp3 {
            let start = local.data_offset.checked_add(payload_len).ok_or_else(|| {
                Finding::error(
                    FindingCode::ZipDiffC4Offset,
                    "data descriptor offset overflow",
                )
                .on(&name)
            })?;
            Some(ByteRange {
                offset: start,
                len: record_end.checked_sub(start).ok_or_else(|| {
                    Finding::error(
                        FindingCode::ZipDiffC4Offset,
                        "data descriptor length underflow",
                    )
                    .on(&name)
                })?,
            })
        } else {
            None
        };
        let cdh_len = 46_u64 + name_len as u64 + extra_len as u64 + comment_len as u64;
        members.push(ZipMember {
            raw_name: name_bytes.to_vec(),
            name,
            method,
            flags,
            creator_system: (version_made_by >> 8) as u8,
            external_attributes,
            crc,
            comp_size: payload_len,
            uncomp_size: uncomp as u64,
            lfh_offset,
            data_offset: local.data_offset,
            record_end,
            is_dir,
            extra_fields,
            source_ranges: MemberSourceRanges {
                local_header: ByteRange {
                    offset: lfh_offset,
                    len: local_header_len,
                },
                compressed_payload: ByteRange {
                    offset: local.data_offset,
                    len: payload_len,
                },
                data_descriptor: descriptor_range,
                central_header: ByteRange {
                    offset: cd_offset + pos as u64,
                    len: cdh_len,
                },
            },
        });
        metadata_bytes = metadata_bytes
            .checked_add(name_len as u64)
            .and_then(|value| value.checked_add(local.extra.len() as u64))
            .ok_or_else(|| {
                Finding::error(FindingCode::QuotaOverflow, "ZIP metadata counter overflow")
            })?;
        if metadata_bytes > max_metadata_bytes {
            return Err(Finding::error(
                FindingCode::QuotaMetadata,
                format!("ZIP metadata exceeds {max_metadata_bytes} bytes"),
            ));
        }
        pos = name_off + name_len + extra_len + comment_len;
    }
    let parsed_count = u64::try_from(members.len()).map_err(|_| {
        Finding::error(
            FindingCode::QuotaOverflow,
            "parsed member count does not fit u64",
        )
    })?;
    if parsed_count != u64::from(total_count) {
        return Err(Finding::error(
            FindingCode::ZipDiffC3Count,
            format!("parsed {} CDHs, EOCD says {total_count}", members.len()),
        ));
    }
    check_layout(&members, cd_offset)?;
    Ok(ZipArchive {
        members,
        cd_offset,
        cd_size,
        eocd_offset: eocd_off,
        comment_len: u64::from(comment_len),
        metadata_bytes,
    })
}

fn classify_extra_fields(
    extra: &[u8],
    extra_start: u64,
    site: ExtraSite,
    context: &str,
    name: &[u8],
    profile: ZipInterpretationProfile,
) -> Result<Vec<ExtraFieldRecord>, Finding> {
    let mut position = 0usize;
    let mut ids = BTreeSet::new();
    let mut records = Vec::new();
    while position < extra.len() {
        if extra.len() - position < 4 {
            return Err(Finding::error(
                FindingCode::ZipExtra,
                format!("truncated extra-field header in {context}"),
            )
            .on(String::from_utf8_lossy(name)));
        }
        let id = u16::from_le_bytes(extra[position..position + 2].try_into().unwrap());
        let size =
            u16::from_le_bytes(extra[position + 2..position + 4].try_into().unwrap()) as usize;
        let end = position
            .checked_add(4)
            .and_then(|start| start.checked_add(size))
            .ok_or_else(|| {
                Finding::error(FindingCode::ZipExtra, "extra-field length overflow")
                    .on(String::from_utf8_lossy(name))
            })?;
        if end > extra.len() {
            return Err(Finding::error(
                FindingCode::ZipExtra,
                format!("extra field 0x{id:04x} overflows {context}"),
            )
            .on(String::from_utf8_lossy(name)));
        }
        if !ids.insert(id) {
            return Err(Finding::error(
                FindingCode::ZipExtra,
                format!("duplicate extra field 0x{id:04x} in {context}"),
            )
            .on(String::from_utf8_lossy(name)));
        }
        if matches!(
            profile,
            ZipInterpretationProfile::StrictAsciiV2
                | ZipInterpretationProfile::PortableUtf8V1
                | ZipInterpretationProfile::WheelUtf8V1
        ) {
            return Err(Finding::error(
                FindingCode::ZipExtra,
                format!(
                    "extra field 0x{id:04x} is denied by {} in {context}",
                    profile.id()
                ),
            )
            .on(String::from_utf8_lossy(name)));
        }
        if is_denied_extra_id(id) {
            let code = if id == ZIP64_EXTRA_ID {
                FindingCode::ZipDiffC5Zip64
            } else {
                FindingCode::ZipDiffA3Name
            };
            let label = if id == ZIP64_EXTRA_ID {
                "ZIP64 extra field"
            } else {
                "alternate Unicode path extra field"
            };
            return Err(Finding::error(code, format!("{label} in {context}"))
                .on(String::from_utf8_lossy(name)));
        }
        let header_offset = extra_start + position as u64;
        records.push(ExtraFieldRecord {
            site,
            id,
            header_range: ByteRange {
                offset: header_offset,
                len: 4,
            },
            data_range: ByteRange {
                offset: header_offset + 4,
                len: size as u64,
            },
            disposition: ExtraDisposition::Ignored,
        });
        position = end;
    }
    Ok(records)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Zip64ExtraData {
    offset: usize,
    len: usize,
}

/// Classifies the closed extra-field language for ZIP64 strict ASCII v1.
/// Only one semantic ZIP64 field is permitted at either header site.
#[allow(dead_code)]
fn classify_zip64_extra_fields(
    extra: &[u8],
    extra_start: u64,
    site: ExtraSite,
    context: &str,
    name: &[u8],
) -> Result<(Vec<ExtraFieldRecord>, Option<Zip64ExtraData>), Finding> {
    let mut position = 0_usize;
    let mut zip64 = None;
    let mut records = Vec::new();
    while position < extra.len() {
        if extra.len() - position < 4 {
            return Err(Finding::error(
                FindingCode::ZipExtra,
                format!("truncated extra-field header in {context}"),
            )
            .on(String::from_utf8_lossy(name)));
        }
        let id = u16::from_le_bytes(extra[position..position + 2].try_into().unwrap());
        let size_u16 = u16::from_le_bytes(extra[position + 2..position + 4].try_into().unwrap());
        let size = usize::from(size_u16);
        let data_offset = position.checked_add(4).ok_or_else(|| {
            Finding::error(FindingCode::ZipExtra, "extra-field offset overflow")
                .on(String::from_utf8_lossy(name))
        })?;
        let end = data_offset.checked_add(size).ok_or_else(|| {
            Finding::error(FindingCode::ZipExtra, "extra-field length overflow")
                .on(String::from_utf8_lossy(name))
        })?;
        if end > extra.len() {
            return Err(Finding::error(
                FindingCode::ZipExtra,
                format!("extra field 0x{id:04x} overflows {context}"),
            )
            .on(String::from_utf8_lossy(name)));
        }
        if id != ZIP64_EXTRA_ID {
            let code = if id == 0x7075 {
                FindingCode::ZipDiffA3Name
            } else {
                FindingCode::ZipExtra
            };
            return Err(Finding::error(
                code,
                format!("extra field 0x{id:04x} is denied by ZIP64 strict ASCII v1 in {context}"),
            )
            .on(String::from_utf8_lossy(name)));
        }
        if zip64.is_some() {
            return Err(Finding::error(
                FindingCode::ZipExtra,
                format!("duplicate ZIP64 extra field in {context}"),
            )
            .on(String::from_utf8_lossy(name)));
        }
        let header_offset = extra_start.checked_add(position as u64).ok_or_else(|| {
            Finding::error(FindingCode::ZipDiffC4Offset, "ZIP64 extra offset overflow")
                .on(String::from_utf8_lossy(name))
        })?;
        records.push(ExtraFieldRecord {
            site,
            id,
            header_range: ByteRange {
                offset: header_offset,
                len: 4,
            },
            data_range: ByteRange {
                offset: header_offset.checked_add(4).ok_or_else(|| {
                    Finding::error(
                        FindingCode::ZipDiffC4Offset,
                        "ZIP64 extra data offset overflow",
                    )
                    .on(String::from_utf8_lossy(name))
                })?,
                len: u64::from(size_u16),
            },
            disposition: ExtraDisposition::Semantic,
        });
        zip64 = Some(Zip64ExtraData {
            offset: data_offset,
            len: size,
        });
        position = end;
    }
    Ok((records, zip64))
}

fn validate_general_purpose_flags(
    flags: u16,
    profile: ZipInterpretationProfile,
    name: &[u8],
) -> Result<(), Finding> {
    if matches!(
        profile,
        ZipInterpretationProfile::StrictAsciiV2
            | ZipInterpretationProfile::PortableUtf8V1
            | ZipInterpretationProfile::WheelUtf8V1
    ) {
        let allowed = match profile {
            ZipInterpretationProfile::StrictAsciiV2 => 1 << 3,
            ZipInterpretationProfile::PortableUtf8V1 => (1 << 3) | (1 << 11),
            ZipInterpretationProfile::WheelUtf8V1 => 1 << 11,
            ZipInterpretationProfile::StrictAsciiV1 => unreachable!(),
        };
        let denied = flags & !allowed;
        if denied != 0 {
            return Err(Finding::error(
                FindingCode::ZipFlags,
                format!(
                    "general-purpose flags 0x{flags:04x} contain denied bits 0x{denied:04x} under {}",
                    profile.id()
                ),
            )
            .on(String::from_utf8_lossy(name)));
        }
    }
    Ok(())
}

fn reject_structural_metadata(data: &[u8], context: &str) -> Result<(), Finding> {
    if contains_signature(data, ZIP64_EOCD_SIG) || contains_signature(data, ZIP64_LOCATOR_SIG) {
        return Err(Finding::error(
            FindingCode::ZipDiffC5Zip64,
            format!("ZIP64 record signature in {context}"),
        ));
    }
    if contains_signature(data, EOCD_SIG) {
        return Err(Finding::error(
            FindingCode::ZipDiffC2Eocd,
            format!("additional EOCD signature in {context}"),
        ));
    }
    if contains_stream_signature(data) {
        return Err(Finding::error(
            FindingCode::ZipDiffC1Stream,
            format!("archive record signature in {context}"),
        ));
    }
    Ok(())
}

fn contains_stream_signature(data: &[u8]) -> bool {
    [LFH_SIG, CDH_SIG, DATA_DESCRIPTOR_SIG]
        .into_iter()
        .any(|signature| contains_signature(data, signature))
}

fn contains_stream_signature_in_range(
    snapshot: &SourceSnapshot<'_>,
    offset: u64,
    len: u64,
) -> Result<bool, Finding> {
    let mut reader = snapshot.reader(offset, len).map_err(|_| {
        Finding::error(
            FindingCode::ZipDiffC4Offset,
            "stored payload extends past EOF",
        )
    })?;
    let mut buffer = [0_u8; 64 * 1024];
    let mut rolling = 0_u32;
    let mut seen = 0_u8;
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            Finding::error(
                FindingCode::SourceIo,
                format!("read stored payload while checking signatures: {error}"),
            )
        })?;
        if read == 0 {
            return Ok(false);
        }
        for byte in &buffer[..read] {
            rolling = (rolling >> 8) | (u32::from(*byte) << 24);
            seen = seen.saturating_add(1);
            if seen >= 4 && matches!(rolling, LFH_SIG | CDH_SIG | DATA_DESCRIPTOR_SIG) {
                return Ok(true);
            }
        }
    }
}

fn contains_signature(data: &[u8], signature: u32) -> bool {
    let signature = signature.to_le_bytes();
    data.windows(signature.len())
        .any(|window| window == signature)
}

fn validate_directory_metadata(
    name: &str,
    version_made_by: u16,
    external_attributes: u32,
    method: u16,
    crc: u32,
    compressed_size: u32,
    uncompressed_size: u32,
) -> Result<(), Finding> {
    let name_is_directory = name.ends_with('/');
    let dos_directory = external_attributes & 0x10 != 0;
    let unix_kind = (external_attributes >> 16) & 0xf000;
    let attribute_is_directory = dos_directory || unix_kind == 0x4000;
    let attribute_is_regular = unix_kind == 0x8000;
    let attribute_is_special = unix_kind != 0 && unix_kind != 0x4000 && unix_kind != 0x8000;
    let host = version_made_by >> 8;

    if attribute_is_special {
        return Err(Finding::error(
            FindingCode::ZipDiffA4Dir,
            format!("host {host} external attributes describe a non-regular entry"),
        )
        .on(name));
    }
    if attribute_is_directory && attribute_is_regular {
        return Err(Finding::error(
            FindingCode::ZipDiffA4Dir,
            format!("host {host} external attributes conflict on entry type"),
        )
        .on(name));
    }
    if attribute_is_directory != name_is_directory
        && (attribute_is_directory || attribute_is_regular)
    {
        return Err(Finding::error(
            FindingCode::ZipDiffA4Dir,
            format!("host {host} filename and external attributes disagree on entry type"),
        )
        .on(name));
    }
    if name_is_directory && (compressed_size != 0 || uncompressed_size != 0) {
        return Err(
            Finding::error(FindingCode::ZipDiffA4Dir, "directory with nonzero size").on(name),
        );
    }
    if name_is_directory && (method != 0 || crc != 0) {
        return Err(Finding::error(
            FindingCode::ZipDiffA4Dir,
            "directory entries must use Store with the CRC32 of empty content",
        )
        .on(name));
    }
    Ok(())
}

fn decode_name_for_profile(
    bytes: &[u8],
    flags: u16,
    profile: ZipInterpretationProfile,
) -> Result<String, Finding> {
    if profile == ZipInterpretationProfile::StrictAsciiV2 {
        if bytes.is_ascii() {
            return Ok(String::from_utf8(bytes.to_vec()).expect("ASCII is valid UTF-8"));
        }
        return Err(Finding::error(
            FindingCode::ZipEncoding,
            format!("non-ASCII member name is denied by {}", profile.id()),
        ));
    }
    if matches!(
        profile,
        ZipInterpretationProfile::PortableUtf8V1 | ZipInterpretationProfile::WheelUtf8V1
    ) {
        let name = std::str::from_utf8(bytes).map_err(|_| {
            Finding::error(
                FindingCode::ZipEncoding,
                format!("member name is not valid UTF-8 under {}", profile.id()),
            )
        })?;
        if !bytes.is_ascii() && (flags & (1 << 11)) == 0 {
            return Err(Finding::error(
                FindingCode::ZipEncoding,
                format!(
                    "non-ASCII member name lacks general-purpose UTF-8 bit 11 under {}",
                    profile.id()
                ),
            ));
        }
        return Ok(name.to_owned());
    }
    if (flags & (1 << 11)) != 0 {
        return std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| {
            Finding::error(
                FindingCode::ZipEncoding,
                "UTF-8 flag set on an invalid name",
            )
        });
    }
    if bytes.is_ascii() {
        return Ok(String::from_utf8(bytes.to_vec()).expect("ASCII is valid UTF-8"));
    }
    Err(Finding::error(
        FindingCode::ZipEncoding,
        "non-ASCII CP437 name support is not implemented",
    ))
}

fn find_eocd(snapshot: &SourceSnapshot<'_>) -> Result<(u64, u16), Finding> {
    let tail_len = snapshot.len().min(65_535 + EOCD_MIN as u64);
    let tail_offset = snapshot.len() - tail_len;
    let tail = snapshot.read_vec(tail_offset, tail_len)?;
    let max_back = tail.len().saturating_sub(EOCD_MIN);
    let start = tail.len() - EOCD_MIN;
    for i in 0..=max_back {
        let off = start.saturating_sub(i);
        if off + EOCD_MIN > tail.len() {
            continue;
        }
        let sig = u32::from_le_bytes(tail[off..off + 4].try_into().unwrap());
        if sig != EOCD_SIG {
            continue;
        }
        let comment_len = u16::from_le_bytes(tail[off + 20..off + 22].try_into().unwrap()) as usize;
        if off + EOCD_MIN + comment_len == tail.len() {
            return Ok((tail_offset + off as u64, comment_len as u16));
        }
    }
    Err(Finding::error(
        FindingCode::FormatUnsupported,
        "no EOCD with exact comment length",
    ))
}

fn parse_lfh(snapshot: &SourceSnapshot<'_>, off: u64) -> Result<LocalHeader, Finding> {
    let mut fixed = [0_u8; 30];
    snapshot
        .read_exact_at(off, &mut fixed)
        .map_err(|_| Finding::error(FindingCode::ZipDiffC4Offset, "LFH past EOF"))?;
    let sig = u32::from_le_bytes(fixed[0..4].try_into().unwrap());
    if sig != LFH_SIG {
        return Err(Finding::error(
            FindingCode::ZipDiffC1Stream,
            "LFH signature missing",
        ));
    }
    let flags = u16::from_le_bytes(fixed[6..8].try_into().unwrap());
    let method = u16::from_le_bytes(fixed[8..10].try_into().unwrap());
    let crc = u32::from_le_bytes(fixed[14..18].try_into().unwrap());
    let comp = u32::from_le_bytes(fixed[18..22].try_into().unwrap());
    let uncomp = u32::from_le_bytes(fixed[22..26].try_into().unwrap());
    let name_len = u16::from_le_bytes(fixed[26..28].try_into().unwrap());
    let extra_len = u16::from_le_bytes(fixed[28..30].try_into().unwrap());
    let name_off = off
        .checked_add(30)
        .ok_or_else(|| Finding::error(FindingCode::ZipDiffC4Offset, "LFH offset overflow"))?;
    let extra_offset = name_off
        .checked_add(u64::from(name_len))
        .ok_or_else(|| Finding::error(FindingCode::ZipDiffC4Offset, "LFH name past EOF"))?;
    let data_offset = extra_offset
        .checked_add(u64::from(extra_len))
        .filter(|end| *end <= snapshot.len())
        .ok_or_else(|| Finding::error(FindingCode::ZipDiffC4Offset, "LFH name past EOF"))?;
    let name = snapshot.read_vec(name_off, u64::from(name_len))?;
    let extra = snapshot.read_vec(extra_offset, u64::from(extra_len))?;
    Ok(LocalHeader {
        data_offset,
        extra_offset,
        name,
        method,
        flags,
        comp_size: comp,
        uncomp_size: uncomp,
        crc,
        extra,
    })
}

fn parse_data_descriptor(
    snapshot: &SourceSnapshot<'_>,
    offset: u64,
    expected_crc: u32,
    expected_comp: u32,
    expected_uncomp: u32,
) -> Result<u64, Finding> {
    parse_data_descriptor_with_width(
        snapshot,
        offset,
        expected_crc,
        u64::from(expected_comp),
        u64::from(expected_uncomp),
        DataDescriptorWidth::Zip32,
    )
}

#[allow(dead_code)]
fn parse_data_descriptor_with_width(
    snapshot: &SourceSnapshot<'_>,
    offset: u64,
    expected_crc: u32,
    expected_comp: u64,
    expected_uncomp: u64,
    width: DataDescriptorWidth,
) -> Result<u64, Finding> {
    let value_bytes = match width {
        DataDescriptorWidth::Zip32 => 4_usize,
        DataDescriptorWidth::Zip64 => 8_usize,
    };
    let unsigned_len = 4_usize + value_bytes * 2;
    let signed_len = unsigned_len + 4;
    let mut descriptor = [0_u8; 24];
    snapshot
        .read_exact_at(offset, &mut descriptor[..unsigned_len])
        .map_err(|_| {
            Finding::error(
                FindingCode::ZipDiffC4Offset,
                "data descriptor extends past EOF",
            )
        })?;
    let first = u32::from_le_bytes(descriptor[0..4].try_into().unwrap());
    let (values_offset, descriptor_len) = if first == DATA_DESCRIPTOR_SIG {
        let suffix_offset = offset.checked_add(unsigned_len as u64).ok_or_else(|| {
            Finding::error(
                FindingCode::ZipDiffC4Offset,
                "signed data descriptor offset overflow",
            )
        })?;
        snapshot
            .read_exact_at(suffix_offset, &mut descriptor[unsigned_len..signed_len])
            .map_err(|_| {
                Finding::error(
                    FindingCode::ZipDiffC4Offset,
                    "signed data descriptor extends past EOF",
                )
            })?;
        (4_usize, signed_len as u64)
    } else {
        (0_usize, unsigned_len as u64)
    };
    let crc = u32::from_le_bytes(
        descriptor[values_offset..values_offset + 4]
            .try_into()
            .unwrap(),
    );
    let sizes_offset = values_offset + 4;
    let comp = match width {
        DataDescriptorWidth::Zip32 => u64::from(u32::from_le_bytes(
            descriptor[sizes_offset..sizes_offset + 4]
                .try_into()
                .unwrap(),
        )),
        DataDescriptorWidth::Zip64 => u64::from_le_bytes(
            descriptor[sizes_offset..sizes_offset + 8]
                .try_into()
                .unwrap(),
        ),
    };
    let uncomp_offset = sizes_offset + value_bytes;
    let uncomp = match width {
        DataDescriptorWidth::Zip32 => u64::from(u32::from_le_bytes(
            descriptor[uncomp_offset..uncomp_offset + 4]
                .try_into()
                .unwrap(),
        )),
        DataDescriptorWidth::Zip64 => u64::from_le_bytes(
            descriptor[uncomp_offset..uncomp_offset + 8]
                .try_into()
                .unwrap(),
        ),
    };
    if crc != expected_crc || comp != expected_comp || uncomp != expected_uncomp {
        return Err(Finding::error(
            FindingCode::ZipDiffA2Size,
            "data descriptor disagrees with the CDH",
        ));
    }
    offset
        .checked_add(descriptor_len)
        .ok_or_else(|| Finding::error(FindingCode::ZipDiffC4Offset, "data descriptor end overflow"))
}

fn check_layout(members: &[ZipMember], cd_off: u64) -> Result<(), Finding> {
    if members.is_empty() {
        if cd_off != 0 {
            return Err(Finding::error(
                FindingCode::ZipDiffC1Stream,
                "empty ZIP has bytes before the central directory",
            ));
        }
        return Ok(());
    }
    let outer = CheckedInterval::from_bounds(0, cd_off)
        .expect("zero cannot exceed an unsigned central-directory offset");
    let mut ranges = Vec::with_capacity(members.len());
    for m in members {
        let start = m.lfh_offset;
        let end = m.record_end;
        let range = CheckedInterval::from_bounds(start, end).map_err(|error| match error {
            IntervalError::Reversed => {
                Finding::error(FindingCode::ZipDiffC4Offset, "empty local record range").on(&m.name)
            }
            IntervalError::EndOverflow => {
                unreachable!("a bounds interval does not perform addition")
            }
        })?;
        if end > cd_off {
            return Err(
                Finding::error(FindingCode::ZipOverlap, "local record overlaps the CD").on(&m.name),
            );
        }
        if range.is_empty() {
            return Err(
                Finding::error(FindingCode::ZipDiffC4Offset, "empty local record range")
                    .on(&m.name),
            );
        }
        ranges.push(range);
    }
    exact_partition(outer, &ranges).map_err(|error| match error {
        PartitionError::GapBeforeFirst { .. } => Finding::error(
            FindingCode::ZipDiffC1Stream,
            "bytes exist before the first referenced local record",
        ),
        PartitionError::Overlap { index } => {
            Finding::error(FindingCode::ZipOverlap, "overlapping compressed ranges")
                .on(&members[index].name)
        }
        PartitionError::Gap { index } => Finding::error(
            FindingCode::ZipDiffC1Stream,
            "unreferenced bytes between records",
        )
        .on(&members[index].name),
        PartitionError::GapAfterLast { .. } => Finding::error(
            FindingCode::ZipDiffC1Stream,
            "unreferenced bytes before the central directory",
        ),
        PartitionError::EmptyPart { index } => {
            Finding::error(FindingCode::ZipDiffC4Offset, "empty local record range")
                .on(&members[index].name)
        }
        PartitionError::PartOutside { index } => {
            Finding::error(FindingCode::ZipOverlap, "local record overlaps the CD")
                .on(&members[index].name)
        }
        PartitionError::MissingParts => Finding::error(
            FindingCode::ZipDiffC1Stream,
            "unreferenced bytes before the central directory",
        ),
    })
}

pub(crate) fn planned_payload_reader<'s, 'a>(
    snapshot: &'s SourceSnapshot<'a>,
    member: &IrMember,
) -> Result<crate::snapshot::SnapshotRangeReader<'s, 'a>, Finding> {
    let range = member
        .zip_evidence()
        .ok_or_else(|| {
            Finding::error(
                FindingCode::CoveringInconsistent,
                "ZIP payload reader received non-ZIP member evidence",
            )
        })?
        .source_ranges
        .compressed_payload;
    snapshot
        .reader(range.offset, range.len)
        .map_err(|finding| finding.on(&member.decoded_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::zip::write::SimpleFileOptions;
    use ::zip::{CompressionMethod, ZipWriter};
    use std::io::{Cursor, Write};

    fn zip_with_files(names: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let mut writer = ZipWriter::new(Cursor::new(&mut bytes));
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            for name in names {
                writer.start_file(*name, options).unwrap();
                writer.write_all(b"x").unwrap();
            }
            writer.finish().unwrap();
        }
        bytes
    }

    fn eocd_offset(bytes: &[u8]) -> usize {
        bytes
            .windows(4)
            .rposition(|window| window == EOCD_SIG.to_le_bytes())
            .expect("test ZIP has an EOCD")
    }

    fn set_eocd_counts(bytes: &mut [u8], count: u16) {
        let eocd = eocd_offset(bytes);
        bytes[eocd + 8..eocd + 10].copy_from_slice(&count.to_le_bytes());
        bytes[eocd + 10..eocd + 12].copy_from_slice(&count.to_le_bytes());
    }

    fn rejected(bytes: &[u8], max_files: u64) -> Finding {
        match parse_zip(bytes, max_files, 4 * 1024 * 1024) {
            Ok(_) => panic!("test archive unexpectedly parsed"),
            Err(finding) => finding,
        }
    }

    fn zip64_values_for_mask(mask: u8, legacy: [u32; 3]) -> Vec<u8> {
        let mut data = Vec::new();
        for (index, value) in legacy.into_iter().enumerate() {
            if mask & (1_u8 << index) == 0 {
                continue;
            }
            let resolved = if value == ZIP64_U32_SENTINEL {
                u64::from(ZIP64_U32_SENTINEL) + 17 + index as u64
            } else {
                u64::from(value)
            };
            data.extend_from_slice(&resolved.to_le_bytes());
        }
        data
    }

    fn empty_zip64_end(classic: ClassicEndFields) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ZIP64_EOCD_SIG.to_le_bytes());
        bytes.extend_from_slice(&44_u64.to_le_bytes());
        bytes.extend_from_slice(&45_u16.to_le_bytes());
        bytes.extend_from_slice(&45_u16.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        assert_eq!(bytes.len(), 56);
        bytes.extend_from_slice(&ZIP64_LOCATOR_SIG.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        assert_eq!(bytes.len(), 76);
        bytes.extend_from_slice(&EOCD_SIG.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&classic.entries_on_disk.to_le_bytes());
        bytes.extend_from_slice(&classic.total_entries.to_le_bytes());
        bytes.extend_from_slice(&classic.central_directory_size.to_le_bytes());
        bytes.extend_from_slice(&classic.central_directory_offset.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes
    }

    fn descriptor_bytes(
        width: DataDescriptorWidth,
        signed: bool,
        crc: u32,
        compressed_size: u64,
        uncompressed_size: u64,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        if signed {
            bytes.extend_from_slice(&DATA_DESCRIPTOR_SIG.to_le_bytes());
        }
        bytes.extend_from_slice(&crc.to_le_bytes());
        match width {
            DataDescriptorWidth::Zip32 => {
                bytes.extend_from_slice(&(compressed_size as u32).to_le_bytes());
                bytes.extend_from_slice(&(uncompressed_size as u32).to_le_bytes());
            }
            DataDescriptorWidth::Zip64 => {
                bytes.extend_from_slice(&compressed_size.to_le_bytes());
                bytes.extend_from_slice(&uncompressed_size.to_le_bytes());
            }
        }
        bytes
    }

    #[test]
    fn zip64_local_sizes_accept_canonical_and_forced_representations() {
        let mut data = Vec::new();
        data.extend_from_slice(&7_u64.to_le_bytes());
        data.extend_from_slice(&5_u64.to_le_bytes());

        assert_eq!(validate_zip64_local_values(&data, 7, 5, 7, 5), Ok(()));
        assert_eq!(
            validate_zip64_local_values(&data, u32::MAX, u32::MAX, 7, 5),
            Ok(())
        );
    }

    #[test]
    fn zip64_local_sizes_reject_mixed_or_mismatched_representations() {
        let mut data = Vec::new();
        data.extend_from_slice(&7_u64.to_le_bytes());
        data.extend_from_slice(&5_u64.to_le_bytes());

        assert_eq!(
            validate_zip64_local_values(&data, u32::MAX, 5, 7, 5),
            Err(Zip64ExtraResolutionError::NoncanonicalLegacyValue)
        );
        assert_eq!(
            validate_zip64_local_values(&data, 7, 5, 8, 5),
            Err(Zip64ExtraResolutionError::ValueMismatch)
        );
        assert_eq!(
            validate_zip64_local_values(&data[..15], 7, 5, 7, 5),
            Err(Zip64ExtraResolutionError::InvalidLength)
        );
    }

    #[test]
    fn zip64_descriptor_width_is_selected_for_signed_and_unsigned_forms() {
        let crc = 0x1234_5678;
        let compressed_size = u64::from(u32::MAX) + 17;
        let uncompressed_size = u64::from(u32::MAX) + 33;
        for signed in [false, true] {
            let bytes = descriptor_bytes(
                DataDescriptorWidth::Zip64,
                signed,
                crc,
                compressed_size,
                uncompressed_size,
            );
            let snapshot = SourceSnapshot::borrowed(None, &bytes);
            let end = parse_data_descriptor_with_width(
                &snapshot,
                0,
                crc,
                compressed_size,
                uncompressed_size,
                DataDescriptorWidth::Zip64,
            )
            .unwrap();
            assert_eq!(end, if signed { 24 } else { 20 });
        }
    }

    #[test]
    fn zip64_descriptor_rejects_a_selected_zip32_width() {
        let bytes = descriptor_bytes(DataDescriptorWidth::Zip64, true, 7, 5, 9);
        let snapshot = SourceSnapshot::borrowed(None, &bytes);

        let finding =
            parse_data_descriptor_with_width(&snapshot, 0, 7, 5, 9, DataDescriptorWidth::Zip32)
                .unwrap_err();

        assert_eq!(finding.code, FindingCode::ZipDiffA2Size);
    }

    #[test]
    fn zip64_end_pair_is_fixed_adjacent_and_canonically_redundant() {
        let classic = ClassicEndFields {
            entries_on_disk: 0,
            total_entries: 0,
            central_directory_size: 0,
            central_directory_offset: 0,
        };
        let bytes = empty_zip64_end(classic);
        let snapshot = SourceSnapshot::borrowed(None, &bytes);

        let resolved = resolve_zip64_end_records(&snapshot, 76, classic).unwrap();

        assert_eq!(resolved.total_entries, 0);
        assert_eq!(resolved.central_directory_size, 0);
        assert_eq!(resolved.central_directory_offset, 0);
        assert_eq!(resolved.zip64_eocd, Some(ByteRange { offset: 0, len: 56 }));
        assert_eq!(
            resolved.zip64_locator,
            Some(ByteRange {
                offset: 56,
                len: 20,
            })
        );
    }

    #[test]
    fn zip64_end_pair_rejects_noncanonical_small_value_sentinels() {
        let classic = ClassicEndFields {
            entries_on_disk: u16::MAX,
            total_entries: u16::MAX,
            central_directory_size: 0,
            central_directory_offset: 0,
        };
        let bytes = empty_zip64_end(classic);
        let snapshot = SourceSnapshot::borrowed(None, &bytes);

        let finding = resolve_zip64_end_records(&snapshot, 76, classic).unwrap_err();

        assert_eq!(finding.code, FindingCode::ZipDiffC5Zip64);
    }

    #[test]
    fn zip64_end_pair_rejects_forged_locator_offset() {
        let classic = ClassicEndFields {
            entries_on_disk: 0,
            total_entries: 0,
            central_directory_size: 0,
            central_directory_offset: 0,
        };
        let mut bytes = empty_zip64_end(classic);
        bytes[64..72].copy_from_slice(&1_u64.to_le_bytes());
        let snapshot = SourceSnapshot::borrowed(None, &bytes);

        let finding = resolve_zip64_end_records(&snapshot, 76, classic).unwrap_err();

        assert_eq!(finding.code, FindingCode::ZipDiffC4Offset);
    }

    #[test]
    fn zip64_end_pair_rejects_an_extensible_sector() {
        let classic = ClassicEndFields {
            entries_on_disk: 0,
            total_entries: 0,
            central_directory_size: 0,
            central_directory_offset: 0,
        };
        let mut bytes = empty_zip64_end(classic);
        bytes[4..12].copy_from_slice(&45_u64.to_le_bytes());
        let snapshot = SourceSnapshot::borrowed(None, &bytes);

        let finding = resolve_zip64_end_records(&snapshot, 76, classic).unwrap_err();

        assert_eq!(finding.code, FindingCode::ZipDiffC5Zip64);
    }

    #[test]
    fn zip64_end_sentinel_without_pair_is_rejected() {
        let bytes = zip_with_files(&[]);
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        let classic = ClassicEndFields {
            entries_on_disk: u16::MAX,
            total_entries: u16::MAX,
            central_directory_size: 0,
            central_directory_offset: 0,
        };

        let finding = resolve_zip64_end_records(&snapshot, 0, classic).unwrap_err();

        assert_eq!(finding.code, FindingCode::ZipDiffC5Zip64);
    }

    #[test]
    fn zip64_end_rejects_classic_per_disk_count_disagreement_first() {
        let bytes = zip_with_files(&[]);
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        let classic = ClassicEndFields {
            entries_on_disk: 1,
            total_entries: 2,
            central_directory_size: 0,
            central_directory_offset: 0,
        };

        let finding = resolve_zip64_end_records(&snapshot, 0, classic).unwrap_err();

        assert_eq!(finding.code, FindingCode::ZipDiffC3Count);
    }

    #[test]
    fn zip64_central_presence_masks_have_one_exact_interpretation() {
        for required_mask in 0_u8..8 {
            let legacy = std::array::from_fn(|index| {
                if required_mask & (1_u8 << index) != 0 {
                    ZIP64_U32_SENTINEL
                } else {
                    101 + index as u32 * 100
                }
            });
            for presence_mask in 1_u8..8 {
                if presence_mask & required_mask != required_mask {
                    continue;
                }
                let data = zip64_values_for_mask(presence_mask, legacy);
                let resolved = resolve_zip64_central_values(&data, legacy[0], legacy[1], legacy[2])
                    .expect("a complete unambiguous mask must resolve");
                assert_eq!(resolved.presence_mask, presence_mask);
                for (index, actual) in [
                    resolved.uncompressed_size,
                    resolved.compressed_size,
                    resolved.local_header_offset,
                ]
                .into_iter()
                .enumerate()
                {
                    let expected = if legacy[index] == ZIP64_U32_SENTINEL {
                        u64::from(ZIP64_U32_SENTINEL) + 17 + index as u64
                    } else {
                        u64::from(legacy[index])
                    };
                    assert_eq!(actual, expected);
                }
            }
        }
    }

    #[test]
    fn zip64_central_resolver_accepts_exact_go_style_redundant_offset() {
        let legacy = [ZIP64_U32_SENTINEL, ZIP64_U32_SENTINEL, 37];
        let data = zip64_values_for_mask(0b111, legacy);

        let resolved =
            resolve_zip64_central_values(&data, legacy[0], legacy[1], legacy[2]).unwrap();

        assert_eq!(resolved.presence_mask, 0b111);
        assert_eq!(resolved.local_header_offset, 37);
    }

    #[test]
    fn zip64_central_resolver_rejects_ambiguous_redundancy() {
        let data = 7_u64.to_le_bytes();
        let error = resolve_zip64_central_values(&data, 7, 7, 9).unwrap_err();
        assert_eq!(error, Zip64ExtraResolutionError::Ambiguous);
    }

    #[test]
    fn zip64_central_resolver_requires_canonical_sentinel_values() {
        let data = 42_u64.to_le_bytes();
        let error = resolve_zip64_central_values(&data, ZIP64_U32_SENTINEL, 12, 24).unwrap_err();
        assert_eq!(error, Zip64ExtraResolutionError::MissingRequiredValue);
    }

    #[test]
    fn zip64_central_resolver_rejects_non_field_lengths() {
        for len in [0_usize, 1, 7, 9, 17, 25, 32] {
            let data = vec![0_u8; len];
            let error = resolve_zip64_central_values(&data, 1, 2, 3).unwrap_err();
            assert_eq!(error, Zip64ExtraResolutionError::InvalidLength, "len {len}");
        }
    }

    #[test]
    fn zip64_extra_classifier_records_one_semantic_field_exactly() {
        let mut extra = Vec::new();
        extra.extend_from_slice(&ZIP64_EXTRA_ID.to_le_bytes());
        extra.extend_from_slice(&16_u16.to_le_bytes());
        extra.extend_from_slice(&[0_u8; 16]);

        let (records, data) = classify_zip64_extra_fields(
            &extra,
            100,
            ExtraSite::Central,
            "central directory",
            b"member",
        )
        .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].disposition, ExtraDisposition::Semantic);
        assert_eq!(
            records[0].header_range,
            ByteRange {
                offset: 100,
                len: 4
            }
        );
        assert_eq!(
            records[0].data_range,
            ByteRange {
                offset: 104,
                len: 16,
            }
        );
        assert_eq!(data, Some(Zip64ExtraData { offset: 4, len: 16 }));
    }

    #[test]
    fn zip64_extra_classifier_denies_every_other_identifier() {
        for id in 0_u16..=u16::MAX {
            if id == ZIP64_EXTRA_ID {
                continue;
            }
            let mut extra = Vec::new();
            extra.extend_from_slice(&id.to_le_bytes());
            extra.extend_from_slice(&0_u16.to_le_bytes());
            let finding =
                classify_zip64_extra_fields(&extra, 0, ExtraSite::Local, "local header", b"member")
                    .unwrap_err();
            let expected = if id == 0x7075 {
                FindingCode::ZipDiffA3Name
            } else {
                FindingCode::ZipExtra
            };
            assert_eq!(finding.code, expected, "extra field 0x{id:04x}");
        }
    }

    #[test]
    fn zip64_extra_classifier_rejects_duplicate_and_truncated_fields() {
        let field = [1_u8, 0, 0, 0];
        let duplicate = [field, field].concat();
        let duplicate_finding =
            classify_zip64_extra_fields(&duplicate, 0, ExtraSite::Local, "local header", b"member")
                .unwrap_err();
        assert_eq!(duplicate_finding.code, FindingCode::ZipExtra);

        let truncated_finding = classify_zip64_extra_fields(
            &[1, 0, 8, 0, 0],
            0,
            ExtraSite::Local,
            "local header",
            b"member",
        )
        .unwrap_err();
        assert_eq!(truncated_finding.code, FindingCode::ZipExtra);
    }

    #[test]
    fn zip64_count_sentinel_is_not_misclassified_as_a_file_quota() {
        let mut bytes = zip_with_files(&[]);
        set_eocd_counts(&mut bytes, u16::MAX);

        let finding = rejected(&bytes, 10_000);
        assert_eq!(finding.code, FindingCode::ZipDiffC5Zip64);
    }

    #[test]
    fn actual_central_header_count_cannot_exceed_the_file_cap() {
        let mut bytes = zip_with_files(&["a", "b"]);
        set_eocd_counts(&mut bytes, 1);

        let finding = rejected(&bytes, 1);
        assert_eq!(finding.code, FindingCode::QuotaFiles);
    }

    #[test]
    fn actual_central_header_count_is_compared_without_truncation() {
        let mut bytes = zip_with_files(&["a", "b"]);
        set_eocd_counts(&mut bytes, 1);

        let finding = rejected(&bytes, 2);
        assert_eq!(finding.code, FindingCode::ZipDiffC3Count);
        assert!(finding.detail.contains("parsed 2 CDHs"));
    }

    #[test]
    fn owned_and_borrowed_snapshots_produce_the_same_archive() {
        let bytes = zip_with_files(&["one.txt", "nested/two.txt"]);
        let borrowed = SourceSnapshot::borrowed(Some("same.zip".into()), &bytes);
        let owned = SourceSnapshot::owned(Some("same.zip".into()), bytes.clone());

        let from_borrowed = parse_zip_with_profile(
            &borrowed,
            10,
            4 * 1024 * 1024,
            ZipInterpretationProfile::StrictAsciiV1,
        )
        .unwrap();
        let from_owned = parse_zip_with_profile(
            &owned,
            10,
            4 * 1024 * 1024,
            ZipInterpretationProfile::StrictAsciiV1,
        )
        .unwrap();

        assert_eq!(from_owned, from_borrowed);
    }

    #[test]
    fn eocd_at_the_maximum_comment_distance_is_found() {
        let mut bytes = zip_with_files(&[]);
        let eocd = eocd_offset(&bytes);
        bytes[eocd + 20..eocd + 22].copy_from_slice(&u16::MAX.to_le_bytes());
        bytes.resize(bytes.len() + usize::from(u16::MAX), 0);

        let parsed = parse_zip(&bytes, 0, 128 * 1024).unwrap();
        assert_eq!(parsed.eocd_offset, eocd as u64);
        assert_eq!(parsed.comment_len, u64::from(u16::MAX));
    }

    #[test]
    fn local_header_offset_overflow_is_a_structured_error() {
        let snapshot = SourceSnapshot::borrowed(None, &[]);
        let finding = match parse_lfh(&snapshot, u64::MAX - 1) {
            Ok(_) => panic!("overflowing LFH offset unexpectedly parsed"),
            Err(finding) => finding,
        };
        assert_eq!(finding.code, FindingCode::ZipDiffC4Offset);
    }

    #[test]
    fn strict_ascii_v2_flag_language_is_exhaustive() {
        for flags in 0..=u16::MAX {
            let accepted = validate_general_purpose_flags(
                flags,
                ZipInterpretationProfile::StrictAsciiV2,
                b"member",
            )
            .is_ok();
            assert_eq!(
                accepted,
                flags == 0 || flags == 0x0008,
                "unexpected disposition for flag word 0x{flags:04x}"
            );
        }
    }

    #[test]
    fn wheel_utf8_v1_flag_language_is_exhaustive() {
        for flags in 0..=u16::MAX {
            let accepted = validate_general_purpose_flags(
                flags,
                ZipInterpretationProfile::WheelUtf8V1,
                b"member",
            )
            .is_ok();
            assert_eq!(
                accepted,
                flags == 0 || flags == 0x0800,
                "unexpected disposition for flag word 0x{flags:04x}"
            );
        }
    }

    #[test]
    fn portable_utf8_v1_flag_language_is_exhaustive() {
        for flags in 0..=u16::MAX {
            let accepted = validate_general_purpose_flags(
                flags,
                ZipInterpretationProfile::PortableUtf8V1,
                b"member",
            )
            .is_ok();
            assert_eq!(
                accepted,
                matches!(flags, 0 | 0x0008 | 0x0800 | 0x0808),
                "unexpected disposition for flag word 0x{flags:04x}"
            );
        }
    }

    #[test]
    fn portable_utf8_v1_name_language_is_exact() {
        assert_eq!(
            decode_name_for_profile(b"ascii", 0, ZipInterpretationProfile::PortableUtf8V1).unwrap(),
            "ascii"
        );
        assert_eq!(
            decode_name_for_profile(
                "caf\u{e9}".as_bytes(),
                0x0800,
                ZipInterpretationProfile::PortableUtf8V1,
            )
            .unwrap(),
            "caf\u{e9}"
        );
        assert!(decode_name_for_profile(
            "caf\u{e9}".as_bytes(),
            0,
            ZipInterpretationProfile::PortableUtf8V1,
        )
        .is_err());
        assert!(
            decode_name_for_profile(&[0xff], 0x0800, ZipInterpretationProfile::PortableUtf8V1,)
                .is_err()
        );
    }

    #[test]
    fn wheel_utf8_v1_name_language_is_exact() {
        assert_eq!(
            decode_name_for_profile(b"ascii", 0, ZipInterpretationProfile::WheelUtf8V1).unwrap(),
            "ascii"
        );
        assert_eq!(
            decode_name_for_profile(
                "caf\u{e9}".as_bytes(),
                0x0800,
                ZipInterpretationProfile::WheelUtf8V1,
            )
            .unwrap(),
            "caf\u{e9}"
        );
        assert!(decode_name_for_profile(
            "caf\u{e9}".as_bytes(),
            0,
            ZipInterpretationProfile::WheelUtf8V1,
        )
        .is_err());
        assert!(
            decode_name_for_profile(&[0xff], 0x0800, ZipInterpretationProfile::WheelUtf8V1,)
                .is_err()
        );
    }

    #[test]
    fn wheel_utf8_v1_extra_field_language_is_exhaustive() {
        for id in 0..=u16::MAX {
            let [lo, hi] = id.to_le_bytes();
            let field = [lo, hi, 0, 0];
            let finding = classify_extra_fields(
                &field,
                0,
                ExtraSite::Local,
                "local header",
                b"member",
                ZipInterpretationProfile::WheelUtf8V1,
            )
            .expect_err("wheel UTF-8 v1 admitted an extra field");
            assert_eq!(finding.code, FindingCode::ZipExtra);
        }
    }

    #[test]
    fn portable_utf8_v1_extra_field_language_is_exhaustive() {
        for id in 0..=u16::MAX {
            let [lo, hi] = id.to_le_bytes();
            let field = [lo, hi, 0, 0];
            let finding = classify_extra_fields(
                &field,
                0,
                ExtraSite::Local,
                "local header",
                b"member",
                ZipInterpretationProfile::PortableUtf8V1,
            )
            .expect_err("portable UTF-8 v1 admitted an extra field");
            assert_eq!(finding.code, FindingCode::ZipExtra);
        }
    }

    #[test]
    fn strict_ascii_v2_extra_field_language_is_exhaustive() {
        for id in 0..=u16::MAX {
            let [lo, hi] = id.to_le_bytes();
            let field = [lo, hi, 0, 0];
            let finding = classify_extra_fields(
                &field,
                0,
                ExtraSite::Local,
                "local header",
                b"member",
                ZipInterpretationProfile::StrictAsciiV2,
            )
            .expect_err("strict ASCII v2 admitted an extra field");
            assert_eq!(
                finding.code,
                FindingCode::ZipExtra,
                "extra field 0x{id:04x}"
            );
        }
    }
}
