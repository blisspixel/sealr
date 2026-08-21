//! CD-first ZIP reader. One interpretation. Disagreement is a finding.

use crate::findings::{Finding, FindingCode};
use crate::snapshot::SourceSnapshot;
use std::collections::BTreeSet;

const EOCD_SIG: u32 = 0x0605_4b50;
const CDH_SIG: u32 = 0x0201_4b50;
const LFH_SIG: u32 = 0x0403_4b50;
const DATA_DESCRIPTOR_SIG: u32 = 0x0807_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
const EOCD_MIN: usize = 22;

#[derive(Clone, Debug)]
pub struct ZipMember {
    pub name: String,
    pub method: u16,
    pub flags: u16,
    pub crc: u32,
    pub comp_size: u64,
    pub uncomp_size: u64,
    pub lfh_offset: u64,
    pub data_offset: u64,
    pub record_end: u64,
    pub is_dir: bool,
}

struct LocalHeader<'a> {
    data_offset: usize,
    name: &'a [u8],
    method: u16,
    flags: u16,
    comp_size: u32,
    uncomp_size: u32,
    crc: u32,
    extra: &'a [u8],
}

#[allow(dead_code)]
pub struct ZipArchive<'a> {
    pub bytes: &'a [u8],
    pub members: Vec<ZipMember>,
    pub cd_offset: u64,
    pub cd_size: u64,
    pub metadata_bytes: u64,
}

pub fn parse_zip(
    bytes: &[u8],
    max_files: u64,
    max_metadata_bytes: u64,
) -> Result<ZipArchive<'_>, Finding> {
    if bytes.len() < EOCD_MIN {
        return Err(Finding::error(
            FindingCode::FormatUnsupported,
            "too small to be ZIP",
        ));
    }
    let (eocd_off, comment_len) = find_eocd(bytes)?;
    let comment = &bytes[eocd_off + 22..eocd_off + 22 + comment_len as usize];
    reject_structural_metadata(comment, "EOCD comment")?;
    let this_disk = u16::from_le_bytes(bytes[eocd_off + 4..eocd_off + 6].try_into().unwrap());
    let cd_disk = u16::from_le_bytes(bytes[eocd_off + 6..eocd_off + 8].try_into().unwrap());
    let this_count = u16::from_le_bytes(bytes[eocd_off + 8..eocd_off + 10].try_into().unwrap());
    let total_count = u16::from_le_bytes(bytes[eocd_off + 10..eocd_off + 12].try_into().unwrap());
    let cd_size = u32::from_le_bytes(bytes[eocd_off + 12..eocd_off + 16].try_into().unwrap());
    let cd_offset = u32::from_le_bytes(bytes[eocd_off + 16..eocd_off + 20].try_into().unwrap());
    if this_disk != 0 || cd_disk != 0 {
        return Err(Finding::error(FindingCode::ZipDiffC3Count, "spanned ZIP"));
    }
    if this_count != total_count {
        return Err(Finding::error(
            FindingCode::ZipDiffC3Count,
            "this-disk count != total",
        ));
    }
    if total_count as u64 > max_files {
        return Err(Finding::error(
            FindingCode::QuotaFiles,
            format!("{total_count} entries; cap is {max_files}"),
        ));
    }
    if cd_size == 0xFFFF_FFFF || cd_offset == 0xFFFF_FFFF || total_count == 0xFFFF {
        return Err(Finding::error(
            FindingCode::ZipDiffC5Zip64,
            "ZIP64 fields not implemented",
        ));
    }
    let cd_offset = cd_offset as u64;
    let cd_size = cd_size as u64;
    let mut metadata_bytes = (comment_len as u64).saturating_add(cd_size);
    if metadata_bytes > max_metadata_bytes {
        return Err(Finding::error(
            FindingCode::QuotaMetadata,
            format!("ZIP metadata exceeds {max_metadata_bytes} bytes"),
        ));
    }
    if cd_offset + cd_size != eocd_off as u64 {
        return Err(Finding::error(
            FindingCode::ZipDiffC4Offset,
            "CD size+offset does not land on EOCD",
        ));
    }
    let cd_end = (cd_offset as usize).saturating_add(cd_size as usize);
    if cd_end > bytes.len() {
        return Err(Finding::error(
            FindingCode::ZipDiffC4Offset,
            "CD extends past file",
        ));
    }

    let mut members = Vec::new();
    let mut pos = cd_offset as usize;
    let cd_end = cd_offset as usize + cd_size as usize;
    while pos < cd_end {
        if pos + 46 > cd_end {
            return Err(Finding::error(FindingCode::ZipDiffC3Count, "truncated CDH"));
        }
        let sig = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
        if sig != CDH_SIG {
            return Err(Finding::error(
                FindingCode::ZipDiffC3Count,
                "bad CDH signature",
            ));
        }
        let flags = u16::from_le_bytes(bytes[pos + 8..pos + 10].try_into().unwrap());
        let method = u16::from_le_bytes(bytes[pos + 10..pos + 12].try_into().unwrap());
        let version_made_by = u16::from_le_bytes(bytes[pos + 4..pos + 6].try_into().unwrap());
        let crc = u32::from_le_bytes(bytes[pos + 16..pos + 20].try_into().unwrap());
        let comp = u32::from_le_bytes(bytes[pos + 20..pos + 24].try_into().unwrap());
        let uncomp = u32::from_le_bytes(bytes[pos + 24..pos + 28].try_into().unwrap());
        let name_len = u16::from_le_bytes(bytes[pos + 28..pos + 30].try_into().unwrap()) as usize;
        let extra_len = u16::from_le_bytes(bytes[pos + 30..pos + 32].try_into().unwrap()) as usize;
        let comment_len =
            u16::from_le_bytes(bytes[pos + 32..pos + 34].try_into().unwrap()) as usize;
        let lfh_offset = u32::from_le_bytes(bytes[pos + 42..pos + 46].try_into().unwrap());
        let external_attributes = u32::from_le_bytes(bytes[pos + 38..pos + 42].try_into().unwrap());
        if comp == 0xFFFF_FFFF || uncomp == 0xFFFF_FFFF || lfh_offset == 0xFFFF_FFFF {
            return Err(Finding::error(FindingCode::ZipDiffC5Zip64, "ZIP64 member").on(""));
        }
        let name_off = pos + 46;
        if name_off + name_len + extra_len + comment_len > cd_end {
            return Err(Finding::error(
                FindingCode::ZipDiffC3Count,
                "CDH name overflows CD",
            ));
        }
        let name_bytes = &bytes[name_off..name_off + name_len];
        let central_extra = &bytes[name_off + name_len..name_off + name_len + extra_len];
        let central_comment =
            &bytes[name_off + name_len + extra_len..name_off + name_len + extra_len + comment_len];
        validate_extra_fields(central_extra, "central directory", name_bytes)?;
        reject_structural_metadata(central_comment, "central-directory comment")?;
        let lfh = lfh_offset as usize;
        let local = parse_lfh(bytes, lfh)?;
        validate_extra_fields(local.extra, "local header", name_bytes)?;
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
        let gp3 = flags & 0x8 != 0;
        if !gp3 && (local.comp_size != comp || local.uncomp_size != uncomp) {
            return Err(
                Finding::error(FindingCode::ZipDiffA2Size, "CDH sizes != LFH sizes")
                    .on(display_name.as_ref()),
            );
        }
        if !gp3 && local.crc != crc && crc != 0 {
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
        let name = decode_name(name_bytes, flags)?;
        validate_directory_metadata(&name, version_made_by, external_attributes, comp, uncomp)?;
        let is_dir = name.ends_with('/');
        let payload_end = (local.data_offset as u64).saturating_add(comp as u64);
        if gp3 && method == 0 {
            let payload_end = usize::try_from(payload_end).map_err(|_| {
                Finding::error(
                    FindingCode::ZipDiffC4Offset,
                    "stored payload end does not fit this platform",
                )
            })?;
            let stored_payload = bytes.get(local.data_offset..payload_end).ok_or_else(|| {
                Finding::error(
                    FindingCode::ZipDiffC4Offset,
                    "stored payload extends past EOF",
                )
                .on(&name)
            })?;
            if contains_stream_signature(stored_payload) {
                return Err(Finding::error(
                    FindingCode::ZipDiffC1Stream,
                    "stored data-descriptor payload contains an alternate record signature",
                )
                .on(&name));
            }
        }
        let record_end = if gp3 {
            let descriptor_offset = usize::try_from(payload_end).map_err(|_| {
                Finding::error(
                    FindingCode::ZipDiffC4Offset,
                    "data descriptor offset does not fit this platform",
                )
            })?;
            parse_data_descriptor(bytes, descriptor_offset, crc, comp, uncomp)? as u64
        } else {
            payload_end
        };
        members.push(ZipMember {
            name,
            method,
            flags,
            crc,
            comp_size: comp as u64,
            uncomp_size: uncomp as u64,
            lfh_offset: lfh_offset as u64,
            data_offset: local.data_offset as u64,
            record_end,
            is_dir,
        });
        metadata_bytes = metadata_bytes
            .saturating_add(name_len as u64)
            .saturating_add(local.extra.len() as u64);
        if metadata_bytes > max_metadata_bytes {
            return Err(Finding::error(
                FindingCode::QuotaMetadata,
                format!("ZIP metadata exceeds {max_metadata_bytes} bytes"),
            ));
        }
        pos = name_off + name_len + extra_len + comment_len;
    }
    if members.len() as u16 != total_count {
        return Err(Finding::error(
            FindingCode::ZipDiffC3Count,
            format!("parsed {} CDHs, EOCD says {total_count}", members.len()),
        ));
    }
    check_layout(&members, cd_offset)?;
    Ok(ZipArchive {
        bytes,
        members,
        cd_offset,
        cd_size,
        metadata_bytes,
    })
}

fn validate_extra_fields(extra: &[u8], context: &str, name: &[u8]) -> Result<(), Finding> {
    let mut position = 0usize;
    let mut ids = BTreeSet::new();
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
        match id {
            0x0001 => {
                return Err(Finding::error(
                    FindingCode::ZipDiffC5Zip64,
                    format!("ZIP64 extra field in {context}"),
                )
                .on(String::from_utf8_lossy(name)));
            }
            0x7075 => {
                return Err(Finding::error(
                    FindingCode::ZipDiffA3Name,
                    format!("alternate Unicode path extra field in {context}"),
                )
                .on(String::from_utf8_lossy(name)));
            }
            _ => {}
        }
        position = end;
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

fn contains_signature(data: &[u8], signature: u32) -> bool {
    let signature = signature.to_le_bytes();
    data.windows(signature.len())
        .any(|window| window == signature)
}

fn validate_directory_metadata(
    name: &str,
    version_made_by: u16,
    external_attributes: u32,
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
    Ok(())
}

fn decode_name(bytes: &[u8], flags: u16) -> Result<String, Finding> {
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

fn find_eocd(bytes: &[u8]) -> Result<(usize, u16), Finding> {
    let max_back = bytes.len().saturating_sub(EOCD_MIN);
    let scan = max_back.min(65535 + EOCD_MIN);
    let start = bytes.len() - EOCD_MIN;
    for i in 0..=scan {
        let off = start.saturating_sub(i);
        if off + 22 > bytes.len() {
            continue;
        }
        let sig = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        if sig != EOCD_SIG {
            continue;
        }
        let comment_len =
            u16::from_le_bytes(bytes[off + 20..off + 22].try_into().unwrap()) as usize;
        if off + 22 + comment_len == bytes.len() {
            return Ok((off, comment_len as u16));
        }
    }
    Err(Finding::error(
        FindingCode::FormatUnsupported,
        "no EOCD with exact comment length",
    ))
}

fn parse_lfh(bytes: &[u8], off: usize) -> Result<LocalHeader<'_>, Finding> {
    if off + 30 > bytes.len() {
        return Err(Finding::error(FindingCode::ZipDiffC4Offset, "LFH past EOF"));
    }
    let sig = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    if sig != LFH_SIG {
        return Err(Finding::error(
            FindingCode::ZipDiffC1Stream,
            "LFH signature missing",
        ));
    }
    let flags = u16::from_le_bytes(bytes[off + 6..off + 8].try_into().unwrap());
    let method = u16::from_le_bytes(bytes[off + 8..off + 10].try_into().unwrap());
    let crc = u32::from_le_bytes(bytes[off + 14..off + 18].try_into().unwrap());
    let comp = u32::from_le_bytes(bytes[off + 18..off + 22].try_into().unwrap());
    let uncomp = u32::from_le_bytes(bytes[off + 22..off + 26].try_into().unwrap());
    let name_len = u16::from_le_bytes(bytes[off + 26..off + 28].try_into().unwrap()) as usize;
    let extra_len = u16::from_le_bytes(bytes[off + 28..off + 30].try_into().unwrap()) as usize;
    let name_off = off + 30;
    if name_off + name_len + extra_len > bytes.len() {
        return Err(Finding::error(
            FindingCode::ZipDiffC4Offset,
            "LFH name past EOF",
        ));
    }
    let name = &bytes[name_off..name_off + name_len];
    let extra_offset = name_off + name_len;
    let data_offset = extra_offset + extra_len;
    Ok(LocalHeader {
        data_offset,
        name,
        method,
        flags,
        comp_size: comp,
        uncomp_size: uncomp,
        crc,
        extra: &bytes[extra_offset..data_offset],
    })
}

fn parse_data_descriptor(
    bytes: &[u8],
    offset: usize,
    expected_crc: u32,
    expected_comp: u32,
    expected_uncomp: u32,
) -> Result<usize, Finding> {
    if offset.saturating_add(12) > bytes.len() {
        return Err(Finding::error(
            FindingCode::ZipDiffC4Offset,
            "data descriptor extends past EOF",
        ));
    }
    let first = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let (values_offset, end) = if first == DATA_DESCRIPTOR_SIG {
        (offset + 4, offset.saturating_add(16))
    } else {
        (offset, offset.saturating_add(12))
    };
    if end > bytes.len() {
        return Err(Finding::error(
            FindingCode::ZipDiffC4Offset,
            "signed data descriptor extends past EOF",
        ));
    }
    let crc = u32::from_le_bytes(bytes[values_offset..values_offset + 4].try_into().unwrap());
    let comp = u32::from_le_bytes(
        bytes[values_offset + 4..values_offset + 8]
            .try_into()
            .unwrap(),
    );
    let uncomp = u32::from_le_bytes(
        bytes[values_offset + 8..values_offset + 12]
            .try_into()
            .unwrap(),
    );
    if crc != expected_crc || comp != expected_comp || uncomp != expected_uncomp {
        return Err(Finding::error(
            FindingCode::ZipDiffA2Size,
            "data descriptor disagrees with the CDH",
        ));
    }
    Ok(end)
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
    let mut ranges: Vec<(u64, u64, &str)> = Vec::new();
    for m in members {
        let start = m.lfh_offset;
        let end = m.record_end;
        if end > cd_off {
            return Err(
                Finding::error(FindingCode::ZipOverlap, "local record overlaps the CD").on(&m.name),
            );
        }
        if start >= end {
            return Err(
                Finding::error(FindingCode::ZipDiffC4Offset, "empty local record range")
                    .on(&m.name),
            );
        }
        ranges.push((start, end, &m.name));
    }
    ranges.sort_by_key(|r| r.0);
    if ranges[0].0 != 0 {
        return Err(Finding::error(
            FindingCode::ZipDiffC1Stream,
            "bytes exist before the first referenced local record",
        ));
    }
    for w in ranges.windows(2) {
        if w[0].1 > w[1].0 {
            return Err(
                Finding::error(FindingCode::ZipOverlap, "overlapping compressed ranges").on(w[1].2),
            );
        }
        if w[0].1 < w[1].0 {
            return Err(Finding::error(
                FindingCode::ZipDiffC1Stream,
                "unreferenced bytes between records",
            )
            .on(w[1].2));
        }
    }
    if ranges.last().is_some_and(|range| range.1 != cd_off) {
        return Err(Finding::error(
            FindingCode::ZipDiffC1Stream,
            "unreferenced bytes before the central directory",
        ));
    }
    Ok(())
}

pub fn payload<'s>(snapshot: &'s SourceSnapshot<'_>, m: &ZipMember) -> Result<&'s [u8], Finding> {
    snapshot
        .range(m.data_offset, m.comp_size)
        .map_err(|finding| finding.on(&m.name))
}
