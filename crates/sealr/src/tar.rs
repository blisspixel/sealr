//! Bounded POSIX ustar reader for the portable v1 profile.
//!
//! This parser deliberately accepts a closed subset: regular files and
//! directories, exact POSIX ustar magic and version, octal numeric fields,
//! zero member padding, two zero end blocks, and zero-only record padding.
//! Links, special files, PAX, GNU extensions, sparse encodings, base-256
//! numbers, concatenation, and recovery parsing fail closed.

use crate::findings::{Finding, FindingCode};
use crate::ir::ByteRange;
use crate::policy::hex_sha256;
use crate::snapshot::SourceSnapshot;

const BLOCK_LEN: u64 = 512;
const BLOCK_LEN_USIZE: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TarMember {
    pub raw_name: Vec<u8>,
    pub name: String,
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
    pub header_checksum: u32,
    pub header_sha256: String,
    pub header: ByteRange,
    pub payload: ByteRange,
    pub padding: ByteRange,
    pub is_dir: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TarArchive {
    pub members: Vec<TarMember>,
    pub member_records: ByteRange,
    pub terminator: ByteRange,
    pub trailing_zeros: ByteRange,
    pub metadata_bytes: u64,
}

pub(crate) fn recognizes_ustar(snapshot: &SourceSnapshot<'_>) -> bool {
    if snapshot.len() < BLOCK_LEN {
        return false;
    }
    let mut signature = [0_u8; 8];
    snapshot.read_exact_at(257, &mut signature).is_ok() && signature == *b"ustar\x0000"
}

pub(crate) fn parse_ustar_portable_v1(
    snapshot: &SourceSnapshot<'_>,
    max_files: u64,
    max_metadata_bytes: u64,
) -> Result<TarArchive, Finding> {
    let source_len = snapshot.len();
    if source_len < BLOCK_LEN * 2 || !source_len.is_multiple_of(BLOCK_LEN) {
        return Err(Finding::error(
            FindingCode::TarTruncated,
            "ustar source must contain at least two complete 512-byte blocks",
        ));
    }

    let mut members = Vec::new();
    let mut offset = 0_u64;
    let mut metadata_bytes = 0_u64;
    loop {
        let header_end = checked_add(offset, BLOCK_LEN, "header end")?;
        if header_end > source_len {
            return Err(Finding::error(
                FindingCode::TarTruncated,
                "member header extends beyond the source",
            ));
        }
        let mut header = [0_u8; BLOCK_LEN_USIZE];
        snapshot.read_exact_at(offset, &mut header)?;
        if is_zero_block(&header) {
            let second_offset = header_end;
            let second_end = checked_add(second_offset, BLOCK_LEN, "terminator end")?;
            if second_end > source_len {
                return Err(Finding::error(
                    FindingCode::TarTerminator,
                    "archive has only one zero end block",
                ));
            }
            let mut second = [0_u8; BLOCK_LEN_USIZE];
            snapshot.read_exact_at(second_offset, &mut second)?;
            if !is_zero_block(&second) {
                return Err(Finding::error(
                    FindingCode::TarTerminator,
                    "a zero header block is not followed by the required second zero block",
                ));
            }
            metadata_bytes = checked_add(metadata_bytes, BLOCK_LEN * 2, "metadata bytes")?;
            if metadata_bytes > max_metadata_bytes {
                return Err(Finding::error(
                    FindingCode::QuotaMetadata,
                    format!("TAR metadata is {metadata_bytes} bytes; cap is {max_metadata_bytes}"),
                ));
            }
            ensure_zero_range(
                snapshot,
                second_end,
                source_len - second_end,
                "record padding",
            )?;
            return Ok(TarArchive {
                members,
                member_records: ByteRange {
                    offset: 0,
                    len: offset,
                },
                terminator: ByteRange {
                    offset,
                    len: BLOCK_LEN * 2,
                },
                trailing_zeros: ByteRange {
                    offset: second_end,
                    len: source_len - second_end,
                },
                metadata_bytes,
            });
        }

        let member = parse_header(&header, offset)?;

        if members.len() as u64 >= max_files {
            return Err(Finding::error(
                FindingCode::QuotaFiles,
                format!("TAR contains more than {max_files} members"),
            ));
        }
        metadata_bytes = checked_add(metadata_bytes, BLOCK_LEN, "metadata bytes")?;
        if metadata_bytes > max_metadata_bytes {
            return Err(Finding::error(
                FindingCode::QuotaMetadata,
                format!("TAR metadata exceeds the {max_metadata_bytes}-byte cap"),
            ));
        }

        let payload_offset = header_end;
        let payload_end = checked_add(payload_offset, member.size, "payload end")?;
        let padded_size = round_up_block(member.size)?;
        let record_end = checked_add(payload_offset, padded_size, "member record end")?;
        if record_end > source_len {
            return Err(Finding::error(
                FindingCode::TarTruncated,
                "declared member payload extends beyond the source",
            )
            .on(&member.name));
        }
        let padding_len = padded_size - member.size;
        ensure_zero_range(snapshot, payload_end, padding_len, "member padding")
            .map_err(|finding| finding.on(&member.name))?;

        members.push(TarMember {
            payload: ByteRange {
                offset: payload_offset,
                len: member.size,
            },
            padding: ByteRange {
                offset: payload_end,
                len: padding_len,
            },
            ..member
        });
        offset = record_end;
    }
}

fn parse_header(header: &[u8; BLOCK_LEN_USIZE], offset: u64) -> Result<TarMember, Finding> {
    if &header[257..263] != b"ustar\0" || &header[263..265] != b"00" {
        return Err(Finding::error(
            FindingCode::TarDialect,
            "header is not exact POSIX ustar magic and version",
        ));
    }
    let stored_checksum = parse_checksum(&header[148..156])?;
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
    if stored_checksum != actual_checksum {
        return Err(Finding::error(
            FindingCode::TarChecksum,
            format!("header checksum {stored_checksum:o} != computed {actual_checksum:o}"),
        ));
    }

    let is_dir = match header[156] {
        b'0' | 0 => false,
        b'5' => true,
        typeflag if is_known_unsupported_typeflag(typeflag) => {
            return Err(Finding::error(
                FindingCode::TarFeatureUnsupported,
                format!("unsupported ustar typeflag 0x{typeflag:02x}"),
            ));
        }
        typeflag => {
            return Err(Finding::error(
                FindingCode::TarType,
                format!("unknown ustar typeflag 0x{typeflag:02x}"),
            ));
        }
    };
    if header[500..].iter().any(|byte| *byte != 0) {
        return Err(Finding::error(
            FindingCode::TarDialect,
            "reserved ustar header bytes are not zero",
        ));
    }
    if header[157..257].iter().any(|byte| *byte != 0) {
        return Err(Finding::error(
            FindingCode::TarType,
            "linkname must be empty for regular files and directories",
        ));
    }

    let mode = parse_octal(&header[100..108], "mode")?;
    if mode > 0o7777 {
        return Err(Finding::error(
            FindingCode::TarNumeric,
            "mode exceeds the portable permission-bit range",
        ));
    }
    let _uid = parse_octal(&header[108..116], "uid")?;
    let _gid = parse_octal(&header[116..124], "gid")?;
    let size = parse_octal(&header[124..136], "size")?;
    let mtime = parse_octal(&header[136..148], "mtime")?;
    let devmajor = parse_device_number(&header[329..337], "devmajor")?;
    let devminor = parse_device_number(&header[337..345], "devminor")?;
    if devmajor != 0 || devminor != 0 {
        return Err(Finding::error(
            FindingCode::TarType,
            "device numbers must be zero for regular files and directories",
        ));
    }
    validate_owner_text(&header[265..297], "uname")?;
    validate_owner_text(&header[297..329], "gname")?;

    let name = parse_text_field(&header[0..100], "name", false)?;
    let prefix = parse_text_field(&header[345..500], "prefix", true)?;
    let mut raw_name =
        Vec::with_capacity(prefix.len() + usize::from(!prefix.is_empty()) + name.len());
    if !prefix.is_empty() {
        raw_name.extend_from_slice(&prefix);
        raw_name.push(b'/');
    }
    raw_name.extend_from_slice(&name);
    let decoded_name = std::str::from_utf8(&raw_name)
        .map_err(|_| {
            Finding::error(
                FindingCode::PathUnicode,
                "ustar member name is not strict UTF-8",
            )
        })?
        .to_owned();

    if is_dir && size != 0 {
        return Err(Finding::error(
            FindingCode::TarType,
            "directory member declares a nonzero payload size",
        )
        .on(&decoded_name));
    }

    Ok(TarMember {
        raw_name,
        name: decoded_name,
        size,
        mode: u32::try_from(mode).expect("portable mode fits u32"),
        mtime,
        header_checksum: stored_checksum,
        header_sha256: hex_sha256(header),
        header: ByteRange {
            offset,
            len: BLOCK_LEN,
        },
        payload: ByteRange { offset: 0, len: 0 },
        padding: ByteRange { offset: 0, len: 0 },
        is_dir,
    })
}

fn is_known_unsupported_typeflag(typeflag: u8) -> bool {
    matches!(
        typeflag,
        b'1' | b'2'
            | b'3'
            | b'4'
            | b'6'
            | b'7'
            | b'x'
            | b'g'
            | b'L'
            | b'K'
            | b'S'
            | b'D'
            | b'M'
            | b'N'
            | b'V'
    )
}

fn parse_checksum(field: &[u8]) -> Result<u32, Finding> {
    if field.len() != 8
        || !field[..6].iter().all(|byte| matches!(byte, b'0'..=b'7'))
        || field[6] != 0
        || field[7] != b' '
    {
        return Err(Finding::error(
            FindingCode::TarChecksum,
            "checksum field must be six octal digits followed by NUL and space",
        ));
    }
    let value = parse_octal_digits(&field[..6], "checksum")?;
    u32::try_from(value)
        .map_err(|_| Finding::error(FindingCode::TarChecksum, "header checksum does not fit u32"))
}

fn parse_device_number(field: &[u8], label: &str) -> Result<u64, Finding> {
    if field.iter().all(|byte| *byte == 0) {
        Ok(0)
    } else {
        parse_octal(field, label)
    }
}

fn parse_octal(field: &[u8], label: &str) -> Result<u64, Finding> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(Finding::error(
            FindingCode::TarFeatureUnsupported,
            format!("{label} uses denied base-256 encoding"),
        ));
    }
    let mut end = 0;
    while end < field.len() && matches!(field[end], b'0'..=b'7') {
        end += 1;
    }
    if end == 0 || end == field.len() || field[end..].iter().any(|byte| !matches!(byte, 0 | b' ')) {
        return Err(Finding::error(
            FindingCode::TarNumeric,
            format!(
                "{label} must contain ASCII-octal digits followed by at least one NUL or space"
            ),
        ));
    }
    parse_octal_digits(&field[..end], label)
}

fn parse_octal_digits(digits: &[u8], label: &str) -> Result<u64, Finding> {
    digits.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(8)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| {
                Finding::error(
                    FindingCode::TarNumeric,
                    format!("{label} octal value overflowed u64"),
                )
            })
    })
}

fn parse_text_field(field: &[u8], label: &str, empty_allowed: bool) -> Result<Vec<u8>, Finding> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(Finding::error(
            FindingCode::TarDialect,
            format!("{label} contains bytes after its first NUL"),
        ));
    }
    if !empty_allowed && end == 0 {
        return Err(Finding::error(
            FindingCode::TarDialect,
            format!("{label} is empty"),
        ));
    }
    Ok(field[..end].to_vec())
}

fn validate_owner_text(field: &[u8], label: &str) -> Result<(), Finding> {
    let Some(end) = field.iter().position(|byte| *byte == 0) else {
        return Err(Finding::error(
            FindingCode::TarDialect,
            format!("{label} is not NUL-terminated"),
        ));
    };
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(Finding::error(
            FindingCode::TarDialect,
            format!("{label} contains bytes after its first NUL"),
        ));
    }
    let value = &field[..end];
    if value.iter().any(|byte| !matches!(byte, b' '..=b'~')) {
        return Err(Finding::error(
            FindingCode::TarDialect,
            format!("{label} must contain only printable ASCII"),
        ));
    }
    Ok(())
}

fn ensure_zero_range(
    snapshot: &SourceSnapshot<'_>,
    offset: u64,
    len: u64,
    label: &str,
) -> Result<(), Finding> {
    let mut cursor = offset;
    let mut remaining = len;
    let mut buffer = [0_u8; 8 * 1024];
    while remaining != 0 {
        let chunk = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded zero-check chunk fits usize");
        snapshot.read_exact_at(cursor, &mut buffer[..chunk])?;
        if buffer[..chunk].iter().any(|byte| *byte != 0) {
            return Err(Finding::error(
                FindingCode::TarPadding,
                format!("{label} contains nonzero bytes"),
            ));
        }
        cursor = checked_add(cursor, chunk as u64, "zero-check cursor")?;
        remaining -= chunk as u64;
    }
    Ok(())
}

fn round_up_block(value: u64) -> Result<u64, Finding> {
    let remainder = value % BLOCK_LEN;
    if remainder == 0 {
        Ok(value)
    } else {
        checked_add(value, BLOCK_LEN - remainder, "padded member size")
    }
}

fn checked_add(left: u64, right: u64, label: &str) -> Result<u64, Finding> {
    left.checked_add(right)
        .ok_or_else(|| Finding::error(FindingCode::TarTruncated, format!("{label} overflowed u64")))
}

fn is_zero_block(block: &[u8; BLOCK_LEN_USIZE]) -> bool {
    block.iter().all(|byte| *byte == 0)
}

#[cfg(feature = "__internal-fuzzing")]
pub(crate) fn exercise_fuzz_input(input: &[u8]) {
    const MAX_FUZZ_INPUT: usize = 4 * 1024 * 1024;
    if input.len() > MAX_FUZZ_INPUT {
        return;
    }

    exercise_fuzz_candidate(input);

    let mut canonical = canonical_fuzz_archive();
    for mutation in input.as_chunks::<3>().0.iter().take(128) {
        let index = usize::from(u16::from_le_bytes([mutation[0], mutation[1]])) % 512;
        canonical[index] = mutation[2];
    }
    canonical[257..263].copy_from_slice(b"ustar\0");
    canonical[263..265].copy_from_slice(b"00");
    fix_fuzz_checksum(&mut canonical[..512]);
    exercise_fuzz_candidate(&canonical);
}

#[cfg(feature = "__internal-fuzzing")]
fn exercise_fuzz_candidate(input: &[u8]) {
    let snapshot = SourceSnapshot::borrowed(None, input);
    let file_cap = u64::try_from(input.len() / BLOCK_LEN_USIZE).unwrap();
    let metadata_cap = u64::try_from(input.len()).unwrap();
    let parsed = parse_ustar_portable_v1(&snapshot, file_cap, metadata_cap);
    let Ok(archive) = parsed else {
        return;
    };

    assert_eq!(
        parse_ustar_portable_v1(&snapshot, file_cap, metadata_cap).unwrap(),
        archive
    );
    let exact_files = u64::try_from(archive.members.len()).unwrap();
    assert_eq!(
        parse_ustar_portable_v1(&snapshot, exact_files, archive.metadata_bytes).unwrap(),
        archive
    );
    if exact_files > 0 {
        assert_eq!(
            parse_ustar_portable_v1(&snapshot, exact_files - 1, archive.metadata_bytes)
                .unwrap_err()
                .code,
            FindingCode::QuotaFiles
        );
    }
    if archive.metadata_bytes > 0 {
        assert_eq!(
            parse_ustar_portable_v1(&snapshot, exact_files, archive.metadata_bytes - 1)
                .unwrap_err()
                .code,
            FindingCode::QuotaMetadata
        );
    }

    let mut cursor = 0_u64;
    for member in &archive.members {
        assert_eq!(member.header.offset, cursor);
        assert_eq!(member.header.len, BLOCK_LEN);
        assert_eq!(member.payload.offset, member.header.end());
        assert_eq!(member.padding.offset, member.payload.end());
        cursor = member.padding.end();
    }
    assert_eq!(archive.member_records.offset, 0);
    assert_eq!(archive.member_records.len, cursor);
    assert_eq!(archive.terminator.offset, cursor);
    assert_eq!(archive.terminator.len, BLOCK_LEN * 2);
    assert_eq!(archive.trailing_zeros.offset, archive.terminator.end());
    assert_eq!(archive.trailing_zeros.end(), snapshot.len());

    let mut policy = crate::Policy::default_v2();
    policy.max_files = file_cap.min(u64::from(u32::MAX));
    policy.max_metadata_bytes = metadata_cap;
    policy.max_member_bytes = metadata_cap;
    policy.max_total_bytes = metadata_cap;
    let options = crate::ApplyOptions::new()
        .with_tar_interpretation_profile(crate::TarInterpretationProfile::UstarPortableV1);
    let outcome = crate::apply_with_options(
        crate::Request {
            source: crate::Source::Bytes {
                path: None,
                data: input,
            },
            policy: &policy,
            dest: None,
        },
        &options,
    );
    assert!(!outcome.wrote());
}

#[cfg(feature = "__internal-fuzzing")]
fn canonical_fuzz_archive() -> Vec<u8> {
    let mut bytes = vec![0_u8; BLOCK_LEN_USIZE * 4];
    bytes[..8].copy_from_slice(b"file.txt");
    write_fuzz_octal(&mut bytes[100..108], 0o644);
    write_fuzz_octal(&mut bytes[108..116], 0);
    write_fuzz_octal(&mut bytes[116..124], 0);
    write_fuzz_octal(&mut bytes[124..136], 1);
    write_fuzz_octal(&mut bytes[136..148], 0);
    bytes[156] = b'0';
    bytes[257..263].copy_from_slice(b"ustar\0");
    bytes[263..265].copy_from_slice(b"00");
    bytes[512] = b'x';
    fix_fuzz_checksum(&mut bytes[..512]);
    bytes
}

#[cfg(feature = "__internal-fuzzing")]
fn write_fuzz_octal(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let octal = format!("{value:o}");
    let digits = field.len() - 1;
    field[digits - octal.len()..digits].copy_from_slice(octal.as_bytes());
    field[digits] = 0;
}

#[cfg(feature = "__internal-fuzzing")]
fn fix_fuzz_checksum(header: &mut [u8]) {
    header[148..156].fill(b' ');
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    let encoded = format!("{checksum:06o}");
    header[148..154].copy_from_slice(encoded.as_bytes());
    header[154] = 0;
    header[155] = b' ';
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_octal(field: &mut [u8], value: u64) {
        field.fill(b'0');
        let octal = format!("{value:o}");
        let digits = field.len() - 1;
        field[digits - octal.len()..digits].copy_from_slice(octal.as_bytes());
        field[digits] = 0;
    }

    fn header(name: &str, size: u64, typeflag: u8) -> [u8; 512] {
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], size);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        write_octal(&mut header[329..337], 0);
        write_octal(&mut header[337..345], 0);
        fix_checksum(&mut header);
        header
    }

    fn fix_checksum(header: &mut [u8; 512]) {
        header[148..156].fill(b' ');
        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        let encoded = format!("{checksum:06o}");
        header[148..154].copy_from_slice(encoded.as_bytes());
        header[154] = 0;
        header[155] = b' ';
    }

    fn archive(name: &str, content: &[u8]) -> Vec<u8> {
        let mut bytes = header(name, content.len() as u64, b'0').to_vec();
        bytes.extend_from_slice(content);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
        bytes.resize(bytes.len() + 1024, 0);
        bytes
    }

    #[cfg(feature = "__internal-fuzzing")]
    #[test]
    fn fuzz_driver_exercises_raw_and_checksum_repaired_lanes() {
        exercise_fuzz_input(b"portable ustar mutation bytes");
        exercise_fuzz_input(&archive("file.txt", b"content"));
    }

    #[test]
    fn parses_exact_regular_file_and_covering() {
        let bytes = archive("dir/file.txt", b"mars");
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        let parsed = parse_ustar_portable_v1(&snapshot, 10, 4096).unwrap();
        assert_eq!(parsed.members.len(), 1);
        let member = &parsed.members[0];
        assert_eq!(member.name, "dir/file.txt");
        assert_eq!(member.size, 4);
        assert_eq!(
            member.payload,
            ByteRange {
                offset: 512,
                len: 4
            }
        );
        assert_eq!(
            member.padding,
            ByteRange {
                offset: 516,
                len: 508
            }
        );
        assert_eq!(
            parsed.member_records,
            ByteRange {
                offset: 0,
                len: 1024
            }
        );
        assert_eq!(
            parsed.terminator,
            ByteRange {
                offset: 1024,
                len: 1024
            }
        );
    }

    #[test]
    fn rejects_checksum_drift() {
        let mut bytes = archive("file", b"x");
        bytes[100] ^= 1;
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        let finding = parse_ustar_portable_v1(&snapshot, 10, 4096).unwrap_err();
        assert_eq!(finding.code, FindingCode::TarChecksum);
    }

    #[test]
    fn rejects_nonzero_member_padding() {
        let mut bytes = archive("file", b"x");
        bytes[513] = 1;
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        let finding = parse_ustar_portable_v1(&snapshot, 10, 4096).unwrap_err();
        assert_eq!(finding.code, FindingCode::TarPadding);
    }

    #[test]
    fn rejects_single_zero_terminator_before_another_member() {
        let mut bytes = archive("file", b"x");
        let next = header("other", 0, b'0');
        bytes[1536..2048].copy_from_slice(&next);
        bytes.resize(3072, 0);
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        let finding = parse_ustar_portable_v1(&snapshot, 10, 4096).unwrap_err();
        assert_eq!(finding.code, FindingCode::TarTerminator);
    }

    #[test]
    fn rejects_pax_and_gnu_dialects() {
        for typeflag in *b"xgLS" {
            let mut bytes = header("extension", 0, typeflag).to_vec();
            bytes.resize(1536, 0);
            let snapshot = SourceSnapshot::borrowed(None, &bytes);
            let finding = parse_ustar_portable_v1(&snapshot, 10, 4096).unwrap_err();
            assert_eq!(finding.code, FindingCode::TarFeatureUnsupported);
        }
    }

    #[test]
    fn rejects_base_256_size() {
        let mut bytes = archive("file", b"");
        bytes[124] = 0x80;
        bytes[148..156].fill(b' ');
        let checksum: u32 = bytes[..512].iter().map(|byte| u32::from(*byte)).sum();
        let encoded = format!("{checksum:06o}");
        bytes[148..154].copy_from_slice(encoded.as_bytes());
        bytes[154] = 0;
        bytes[155] = b' ';
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        let finding = parse_ustar_portable_v1(&snapshot, 10, 4096).unwrap_err();
        assert_eq!(finding.code, FindingCode::TarFeatureUnsupported);
    }

    #[test]
    fn numeric_fields_require_digits_then_a_terminator() {
        for field in [100..108, 108..116, 116..124, 124..136, 136..148] {
            for invalid in [b' ', 0] {
                let mut bytes = archive("file", b"");
                bytes[field.clone()].fill(invalid);
                fix_checksum((&mut bytes[..512]).try_into().unwrap());
                let snapshot = SourceSnapshot::borrowed(None, &bytes);
                assert_eq!(
                    parse_ustar_portable_v1(&snapshot, 10, 4096)
                        .unwrap_err()
                        .code,
                    FindingCode::TarNumeric
                );
            }

            let mut bytes = archive("file", b"");
            bytes[field.clone()].fill(b'0');
            fix_checksum((&mut bytes[..512]).try_into().unwrap());
            let snapshot = SourceSnapshot::borrowed(None, &bytes);
            assert_eq!(
                parse_ustar_portable_v1(&snapshot, 10, 4096)
                    .unwrap_err()
                    .code,
                FindingCode::TarNumeric
            );

            let mut bytes = archive("file", b"");
            bytes[field.clone()].fill(b'0');
            bytes[field.start] = b' ';
            bytes[field.end - 1] = 0;
            fix_checksum((&mut bytes[..512]).try_into().unwrap());
            let snapshot = SourceSnapshot::borrowed(None, &bytes);
            assert_eq!(
                parse_ustar_portable_v1(&snapshot, 10, 4096)
                    .unwrap_err()
                    .code,
                FindingCode::TarNumeric
            );
        }
    }

    #[test]
    fn ignored_device_fields_allow_only_zero_encodings() {
        let mut bytes = archive("file", b"");
        bytes[329..345].fill(0);
        fix_checksum((&mut bytes[..512]).try_into().unwrap());
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        assert!(parse_ustar_portable_v1(&snapshot, 10, 4096).is_ok());

        let mut bytes = archive("file", b"");
        write_octal(&mut bytes[329..337], 1);
        fix_checksum((&mut bytes[..512]).try_into().unwrap());
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        assert_eq!(
            parse_ustar_portable_v1(&snapshot, 10, 4096)
                .unwrap_err()
                .code,
            FindingCode::TarType
        );
    }

    #[test]
    fn owner_names_must_be_nul_terminated_printable_ascii() {
        for field in [265..297, 297..329] {
            let mut bytes = archive("file", b"");
            bytes[field.clone()].fill(b'a');
            fix_checksum((&mut bytes[..512]).try_into().unwrap());
            let snapshot = SourceSnapshot::borrowed(None, &bytes);
            assert_eq!(
                parse_ustar_portable_v1(&snapshot, 10, 4096)
                    .unwrap_err()
                    .code,
                FindingCode::TarDialect
            );

            let mut bytes = archive("file", b"");
            bytes[field.start] = 0x1f;
            fix_checksum((&mut bytes[..512]).try_into().unwrap());
            let snapshot = SourceSnapshot::borrowed(None, &bytes);
            assert_eq!(
                parse_ustar_portable_v1(&snapshot, 10, 4096)
                    .unwrap_err()
                    .code,
                FindingCode::TarDialect
            );
        }
    }

    #[test]
    fn every_typeflag_is_closed_and_explicit() {
        for typeflag in 0_u8..=u8::MAX {
            let mut bytes = header("entry", 0, typeflag).to_vec();
            bytes.resize(1536, 0);
            let snapshot = SourceSnapshot::borrowed(None, &bytes);
            let result = parse_ustar_portable_v1(&snapshot, 10, 4096);
            match typeflag {
                0 | b'0' | b'5' => assert!(result.is_ok(), "typeflag 0x{typeflag:02x}"),
                value if is_known_unsupported_typeflag(value) => assert_eq!(
                    result.unwrap_err().code,
                    FindingCode::TarFeatureUnsupported,
                    "typeflag 0x{typeflag:02x}"
                ),
                _ => assert_eq!(
                    result.unwrap_err().code,
                    FindingCode::TarType,
                    "typeflag 0x{typeflag:02x}"
                ),
            }
        }
    }

    #[test]
    fn malformed_header_precedes_file_and_metadata_quota_classification() {
        let mut bytes = archive("file", b"");
        bytes[257] = b'X';
        fix_checksum((&mut bytes[..512]).try_into().unwrap());
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        for (max_files, max_metadata) in [(0, 4096), (1, 511)] {
            assert_eq!(
                parse_ustar_portable_v1(&snapshot, max_files, max_metadata)
                    .unwrap_err()
                    .code,
                FindingCode::TarDialect
            );
        }
    }

    #[test]
    fn every_truncation_fails_closed() {
        let bytes = archive("file", b"payload");
        for end in 0..bytes.len() {
            let snapshot = SourceSnapshot::borrowed(None, &bytes[..end]);
            assert!(
                parse_ustar_portable_v1(&snapshot, 10, 4096).is_err(),
                "truncation at {end}"
            );
        }
    }

    #[test]
    fn every_member_padding_position_is_checked() {
        let original = archive("file", b"x");
        for offset in 513..1024 {
            let mut bytes = original.clone();
            bytes[offset] = 1;
            let snapshot = SourceSnapshot::borrowed(None, &bytes);
            let finding = parse_ustar_portable_v1(&snapshot, 10, 4096).unwrap_err();
            assert_eq!(finding.code, FindingCode::TarPadding, "offset {offset}");
        }
    }

    #[test]
    fn prefix_is_semantic_and_hidden_suffix_bytes_are_denied() {
        let mut valid = header("file", 0, b'0');
        valid[345..348].copy_from_slice(b"dir");
        fix_checksum(&mut valid);
        let mut bytes = valid.to_vec();
        bytes.resize(1536, 0);
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        let parsed = parse_ustar_portable_v1(&snapshot, 10, 4096).unwrap();
        assert_eq!(parsed.members[0].name, "dir/file");

        bytes[346] = 0;
        bytes[347] = b'x';
        fix_checksum((&mut bytes[..512]).try_into().unwrap());
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        let finding = parse_ustar_portable_v1(&snapshot, 10, 4096).unwrap_err();
        assert_eq!(finding.code, FindingCode::TarDialect);
    }

    #[test]
    fn file_and_metadata_caps_are_enforced_before_growth() {
        let bytes = archive("file", b"");
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        assert_eq!(
            parse_ustar_portable_v1(&snapshot, 0, 4096)
                .unwrap_err()
                .code,
            FindingCode::QuotaFiles
        );
        assert_eq!(
            parse_ustar_portable_v1(&snapshot, 1, 1535)
                .unwrap_err()
                .code,
            FindingCode::QuotaMetadata
        );
        assert!(parse_ustar_portable_v1(&snapshot, 1, 1536).is_ok());
    }

    #[test]
    fn large_zero_record_padding_uses_fixed_bounded_reads() {
        let mut bytes = archive("file", b"");
        bytes.resize(1024 * 1024, 0);
        crate::snapshot::reset_test_read_ranges();
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        parse_ustar_portable_v1(&snapshot, 1, 4096).unwrap();
        let reads = crate::snapshot::test_read_ranges();
        assert!(reads.iter().all(|(_, len)| *len <= 8 * 1024));
        assert!(reads.iter().any(|(_, len)| *len == 8 * 1024));
    }

    #[test]
    fn metadata_rejection_precedes_trailing_padding_scan() {
        let mut bytes = archive("file", b"");
        bytes.resize(1024 * 1024, 0);
        crate::snapshot::reset_test_read_ranges();
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        assert_eq!(
            parse_ustar_portable_v1(&snapshot, 1, 1535)
                .unwrap_err()
                .code,
            FindingCode::QuotaMetadata
        );
        assert!(crate::snapshot::test_read_ranges()
            .iter()
            .all(|(offset, len)| offset + len <= 1536));
    }

    #[test]
    fn every_single_header_byte_mutation_is_structured_and_panic_free() {
        let original = archive("file", b"");
        for offset in 0..512 {
            let mut bytes = original.clone();
            bytes[offset] = bytes[offset].wrapping_add(1);
            let snapshot = SourceSnapshot::borrowed(None, &bytes);
            let result = std::panic::catch_unwind(|| {
                let _ = parse_ustar_portable_v1(&snapshot, 10, 4096);
            });
            assert!(result.is_ok(), "header offset {offset}");
        }
    }
}
