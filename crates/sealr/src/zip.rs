//! CD-first ZIP reader. One interpretation. Disagreement is a finding.

use crate::findings::{Finding, FindingCode};
use crate::interval::{exact_partition, CheckedInterval, IntervalError, PartitionError};
use crate::ir::{
    is_denied_extra_id, ByteRange, ExtraDisposition, ExtraFieldRecord, ExtraSite,
    MemberSourceRanges,
};
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
    pub raw_name: Vec<u8>,
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
    pub extra_fields: Vec<ExtraFieldRecord>,
    pub source_ranges: MemberSourceRanges,
}

struct LocalHeader<'a> {
    data_offset: usize,
    extra_offset: usize,
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
    pub eocd_offset: u64,
    pub comment_len: u64,
    pub metadata_bytes: u64,
}

impl ZipArchive<'_> {
    pub fn covering(&self) -> crate::ir::ArchiveCovering {
        crate::ir::ArchiveCovering::from_zip32(
            self.cd_offset,
            self.cd_size,
            self.eocd_offset,
            self.comment_len,
        )
    }
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
    let cd_offset = cd_offset as u64;
    let cd_size = cd_size as u64;
    let mut metadata_bytes = (comment_len as u64).checked_add(cd_size).ok_or_else(|| {
        Finding::error(FindingCode::QuotaOverflow, "ZIP metadata counter overflow")
    })?;
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
        let central_extra_off = name_off + name_len;
        let central_extra = &bytes[central_extra_off..central_extra_off + extra_len];
        let central_comment =
            &bytes[central_extra_off + extra_len..central_extra_off + extra_len + comment_len];
        let mut extra_fields = classify_extra_fields(
            central_extra,
            central_extra_off as u64,
            ExtraSite::Central,
            "central directory",
            name_bytes,
        )?;
        reject_structural_metadata(central_comment, "central-directory comment")?;
        let lfh = lfh_offset as usize;
        let local = parse_lfh(bytes, lfh)?;
        extra_fields.extend(classify_extra_fields(
            local.extra,
            local.extra_offset as u64,
            ExtraSite::Local,
            "local header",
            name_bytes,
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
        let name = decode_name(name_bytes, flags)?;
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
        let local_header_len = (local.data_offset as u64)
            .checked_sub(lfh_offset as u64)
            .ok_or_else(|| {
                Finding::error(
                    FindingCode::ZipDiffC4Offset,
                    "local header length underflow",
                )
                .on(&name)
            })?;
        let payload_len = comp as u64;
        let descriptor_range = if gp3 {
            let start = local.data_offset as u64 + payload_len;
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
            crc,
            comp_size: payload_len,
            uncomp_size: uncomp as u64,
            lfh_offset: lfh_offset as u64,
            data_offset: local.data_offset as u64,
            record_end,
            is_dir,
            extra_fields,
            source_ranges: MemberSourceRanges {
                local_header: ByteRange {
                    offset: lfh_offset as u64,
                    len: local_header_len,
                },
                compressed_payload: ByteRange {
                    offset: local.data_offset as u64,
                    len: payload_len,
                },
                data_descriptor: descriptor_range,
                central_header: ByteRange {
                    offset: pos as u64,
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
        bytes,
        members,
        cd_offset,
        cd_size,
        eocd_offset: eocd_off as u64,
        comment_len: comment_len as u64,
        metadata_bytes,
    })
}

fn classify_extra_fields(
    extra: &[u8],
    extra_start: u64,
    site: ExtraSite,
    context: &str,
    name: &[u8],
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
        if is_denied_extra_id(id) {
            let code = if id == 0x0001 {
                FindingCode::ZipDiffC5Zip64
            } else {
                FindingCode::ZipDiffA3Name
            };
            let label = if id == 0x0001 {
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
    let fixed_end = off
        .checked_add(30)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| Finding::error(FindingCode::ZipDiffC4Offset, "LFH past EOF"))?;
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
    let name_off = fixed_end;
    let extra_offset = name_off
        .checked_add(name_len)
        .ok_or_else(|| Finding::error(FindingCode::ZipDiffC4Offset, "LFH name past EOF"))?;
    let data_offset = extra_offset
        .checked_add(extra_len)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| Finding::error(FindingCode::ZipDiffC4Offset, "LFH name past EOF"))?;
    let name = &bytes[name_off..extra_offset];
    Ok(LocalHeader {
        data_offset,
        extra_offset,
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

pub fn payload<'s>(snapshot: &'s SourceSnapshot<'_>, m: &ZipMember) -> Result<&'s [u8], Finding> {
    snapshot
        .range(m.data_offset, m.comp_size)
        .map_err(|finding| finding.on(&m.name))
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
    fn local_header_offset_overflow_is_a_structured_error() {
        let finding = match parse_lfh(&[], usize::MAX - 1) {
            Ok(_) => panic!("overflowing LFH offset unexpectedly parsed"),
            Err(finding) => finding,
        };
        assert_eq!(finding.code, FindingCode::ZipDiffC4Offset);
    }
}
