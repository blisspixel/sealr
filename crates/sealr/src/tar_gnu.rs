//! Bounded old-GNU TAR reader for the long-name portable v1 profile.
//!
//! The accepted language is deliberately small: exact old-GNU headers,
//! regular files, directories, and one structurally named `L` carrier consumed
//! by exactly one following ordinary member. Long-link,
//! sparse, PAX, base-256, special-file, concatenation, and recovery behavior
//! fail closed.

use crate::findings::{Finding, FindingCode};
use crate::ir::ByteRange;
use crate::policy::hex_sha256;
use crate::snapshot::SourceSnapshot;

const BLOCK_LEN: u64 = 512;
const BLOCK_LEN_USIZE: usize = 512;
const MAX_CARRIERS: u64 = 1024;
const MAX_EFFECTIVE_PATH_BYTES: usize = 8191;
const MAX_CARRIER_PAYLOAD_BYTES: u64 = MAX_EFFECTIVE_PATH_BYTES as u64 + 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GnuLongNameCarrier {
    pub raw_name: Vec<u8>,
    pub path_bytes: Vec<u8>,
    pub header_checksum: u32,
    pub header_sha256: String,
    pub payload_sha256: String,
    pub mode: u32,
    pub mtime: u64,
    pub header: ByteRange,
    pub payload: ByteRange,
    pub path: ByteRange,
    pub padding: ByteRange,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GnuLongNameMember {
    /// The name encoded by the ordinary old-GNU header before `L` precedence.
    pub raw_name: Vec<u8>,
    /// The effective strict UTF-8 pathname after optional `L` precedence.
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
    pub carrier_index: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GnuLongNameArchive {
    pub members: Vec<GnuLongNameMember>,
    pub carriers: Vec<GnuLongNameCarrier>,
    pub member_records: ByteRange,
    pub terminator: ByteRange,
    pub trailing_zeros: ByteRange,
    pub metadata_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeaderKind {
    File,
    Directory,
    LongName,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedHeader {
    raw_name: Vec<u8>,
    size: u64,
    mode: u32,
    mtime: u64,
    header_checksum: u32,
    header_sha256: String,
    header: ByteRange,
    kind: HeaderKind,
}

#[derive(Clone, Debug)]
struct PendingLongName {
    path: String,
    carrier_index: u32,
}

pub(crate) fn recognizes_oldgnu(snapshot: &SourceSnapshot<'_>) -> bool {
    if snapshot.len() < BLOCK_LEN {
        return false;
    }
    let mut signature = [0_u8; 8];
    snapshot.read_exact_at(257, &mut signature).is_ok() && signature == *b"ustar  \0"
}

pub(crate) fn parse_gnu_longname_portable_v1(
    snapshot: &SourceSnapshot<'_>,
    max_files: u64,
    max_metadata_bytes: u64,
) -> Result<GnuLongNameArchive, Finding> {
    let source_len = snapshot.len();
    if source_len < BLOCK_LEN * 2 || !source_len.is_multiple_of(BLOCK_LEN) {
        return Err(Finding::error(
            FindingCode::TarTruncated,
            "GNU TAR source must contain at least two complete 512-byte blocks",
        ));
    }

    let mut members = Vec::new();
    let mut carriers = Vec::new();
    let mut pending: Option<PendingLongName> = None;
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
        let mut header_bytes = [0_u8; BLOCK_LEN_USIZE];
        snapshot.read_exact_at(offset, &mut header_bytes)?;
        if is_zero_block(&header_bytes) {
            if pending.is_some() {
                return Err(gnu_state(
                    "GNU long-name carrier is not followed by an ordinary member",
                ));
            }
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
            metadata_bytes = add_metadata(metadata_bytes, BLOCK_LEN * 2, max_metadata_bytes)?;
            ensure_zero_range(
                snapshot,
                second_end,
                source_len - second_end,
                "record padding",
            )?;
            return Ok(GnuLongNameArchive {
                members,
                carriers,
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

        let header = parse_header(&header_bytes, offset)?;
        match header.kind {
            HeaderKind::LongName => {
                if pending.is_some() {
                    return Err(gnu_state(
                        "GNU long-name carrier must be followed immediately by an ordinary member",
                    ));
                }
                if header.size > MAX_CARRIER_PAYLOAD_BYTES {
                    return Err(Finding::error(
                        FindingCode::QuotaMetadata,
                        format!(
                            "GNU long-name carrier is {} bytes; cap is {MAX_CARRIER_PAYLOAD_BYTES}",
                            header.size
                        ),
                    ));
                }
                if carriers.len() as u64 >= MAX_CARRIERS {
                    return Err(Finding::error(
                        FindingCode::QuotaMetadata,
                        format!("GNU TAR contains more than {MAX_CARRIERS} long-name carriers"),
                    ));
                }

                let padded_size = round_up_block(header.size)?;
                let payload_offset = header_end;
                let payload_end = checked_add(payload_offset, header.size, "carrier payload end")?;
                let record_end = checked_add(payload_offset, padded_size, "carrier record end")?;
                if record_end > source_len {
                    return Err(Finding::error(
                        FindingCode::TarTruncated,
                        "declared GNU long-name carrier payload extends beyond the source",
                    ));
                }
                metadata_bytes = add_metadata(
                    metadata_bytes,
                    checked_add(BLOCK_LEN, padded_size, "carrier metadata bytes")?,
                    max_metadata_bytes,
                )?;
                let payload_len = usize::try_from(header.size).map_err(|_| {
                    Finding::error(
                        FindingCode::QuotaMetadata,
                        "GNU long-name carrier size does not fit this platform",
                    )
                })?;
                let mut payload = Vec::new();
                payload.try_reserve_exact(payload_len).map_err(|_| {
                    Finding::error(
                        FindingCode::QuotaMetadata,
                        "could not allocate the bounded GNU long-name carrier",
                    )
                })?;
                payload.resize(payload_len, 0);
                snapshot.read_exact_at(payload_offset, &mut payload)?;
                let (path, path_bytes) = parse_carrier_payload(&payload)?;
                let padding_len = padded_size - header.size;
                ensure_zero_range(snapshot, payload_end, padding_len, "GNU carrier padding")?;

                let carrier_index =
                    u32::try_from(carriers.len()).expect("1024-carrier profile cap fits u32");
                reserve_one(&mut carriers, "GNU carrier table")?;
                carriers.push(GnuLongNameCarrier {
                    raw_name: header.raw_name,
                    path_bytes,
                    header_checksum: header.header_checksum,
                    header_sha256: header.header_sha256,
                    payload_sha256: hex_sha256(&payload),
                    mode: header.mode,
                    mtime: header.mtime,
                    header: header.header,
                    payload: ByteRange {
                        offset: payload_offset,
                        len: header.size,
                    },
                    path: ByteRange {
                        offset: payload_offset,
                        len: header.size - 1,
                    },
                    padding: ByteRange {
                        offset: payload_end,
                        len: padding_len,
                    },
                });
                pending = Some(PendingLongName {
                    path,
                    carrier_index,
                });
                offset = record_end;
            }
            HeaderKind::File | HeaderKind::Directory => {
                if members.len() as u64 >= max_files {
                    return Err(Finding::error(
                        FindingCode::QuotaFiles,
                        format!("GNU TAR contains more than {max_files} members"),
                    ));
                }
                metadata_bytes = add_metadata(metadata_bytes, BLOCK_LEN, max_metadata_bytes)?;

                let state = pending.take();
                let (name, carrier_index) = if let Some(state) = state {
                    (state.path, Some(state.carrier_index))
                } else {
                    (decode_effective_path(&header.raw_name)?, None)
                };
                let is_dir = header.kind == HeaderKind::Directory;

                let payload_offset = header_end;
                let payload_end = checked_add(payload_offset, header.size, "payload end")?;
                let padded_size = round_up_block(header.size)?;
                let record_end = checked_add(payload_offset, padded_size, "member record end")?;
                if record_end > source_len {
                    return Err(Finding::error(
                        FindingCode::TarTruncated,
                        "declared member payload extends beyond the source",
                    )
                    .on(&name));
                }
                let padding_len = padded_size - header.size;
                ensure_zero_range(snapshot, payload_end, padding_len, "member padding")
                    .map_err(|finding| finding.on(&name))?;

                reserve_one(&mut members, "GNU member table")?;
                members.push(GnuLongNameMember {
                    raw_name: header.raw_name,
                    name,
                    size: header.size,
                    mode: header.mode,
                    mtime: header.mtime,
                    header_checksum: header.header_checksum,
                    header_sha256: header.header_sha256,
                    header: header.header,
                    payload: ByteRange {
                        offset: payload_offset,
                        len: header.size,
                    },
                    padding: ByteRange {
                        offset: payload_end,
                        len: padding_len,
                    },
                    is_dir,
                    carrier_index,
                });
                offset = record_end;
            }
        }
    }
}

fn parse_carrier_payload(payload: &[u8]) -> Result<(String, Vec<u8>), Finding> {
    if !(2..=MAX_CARRIER_PAYLOAD_BYTES as usize).contains(&payload.len())
        || payload.last() != Some(&0)
    {
        return Err(gnu_syntax(
            "GNU long-name payload must contain 1 through 8191 path bytes and one final NUL",
        ));
    }
    let path_bytes = &payload[..payload.len() - 1];
    if path_bytes.contains(&0) {
        return Err(gnu_syntax(
            "GNU long-name payload contains an embedded NUL before its terminator",
        ));
    }
    validate_effective_path(path_bytes)?;
    let decoded = std::str::from_utf8(path_bytes).map_err(|_| {
        Finding::error(
            FindingCode::PathUnicode,
            "GNU long-name path is not strict UTF-8",
        )
    })?;
    let mut path = String::new();
    path.try_reserve_exact(path_bytes.len()).map_err(|_| {
        Finding::error(
            FindingCode::QuotaOverflow,
            "could not allocate the bounded GNU long-name path",
        )
    })?;
    path.push_str(decoded);
    let mut evidence = Vec::new();
    evidence.try_reserve_exact(path_bytes.len()).map_err(|_| {
        Finding::error(
            FindingCode::QuotaOverflow,
            "could not allocate bounded GNU long-name evidence",
        )
    })?;
    evidence.extend_from_slice(path_bytes);
    Ok((path, evidence))
}

fn decode_effective_path(raw_name: &[u8]) -> Result<String, Finding> {
    validate_effective_path(raw_name)?;
    let decoded = std::str::from_utf8(raw_name).map_err(|_| {
        Finding::error(
            FindingCode::PathUnicode,
            "effective old-GNU member name is not strict UTF-8",
        )
    })?;
    Ok(decoded.to_owned())
}

fn validate_effective_path(path: &[u8]) -> Result<(), Finding> {
    if path.is_empty() {
        return Err(Finding::error(
            FindingCode::PathEmpty,
            "effective GNU TAR path is empty",
        ));
    }
    if path.len() > MAX_EFFECTIVE_PATH_BYTES {
        return Err(Finding::error(
            FindingCode::PathDepth,
            format!(
                "effective GNU TAR path is {} bytes; profile cap is {MAX_EFFECTIVE_PATH_BYTES}",
                path.len()
            ),
        ));
    }
    if path.contains(&0) {
        return Err(Finding::error(
            FindingCode::PathNul,
            "effective GNU TAR path contains NUL",
        ));
    }
    Ok(())
}

fn parse_header(header: &[u8; BLOCK_LEN_USIZE], offset: u64) -> Result<ParsedHeader, Finding> {
    if &header[257..265] != b"ustar  \0" {
        return Err(Finding::error(
            FindingCode::TarDialect,
            "header is not exact old-GNU magic and version",
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

    let kind = match header[156] {
        b'0' | 0 => HeaderKind::File,
        b'5' => HeaderKind::Directory,
        b'L' => HeaderKind::LongName,
        typeflag if is_known_unsupported_typeflag(typeflag) => {
            return Err(Finding::error(
                FindingCode::TarFeatureUnsupported,
                format!("unsupported GNU-longname-profile typeflag 0x{typeflag:02x}"),
            ));
        }
        typeflag => {
            return Err(Finding::error(
                FindingCode::TarType,
                format!("unknown old-GNU typeflag 0x{typeflag:02x}"),
            ));
        }
    };
    if header[157..257].iter().any(|byte| *byte != 0) {
        return Err(Finding::error(
            FindingCode::TarType,
            "linkname must be empty in the closed GNU long-name profile",
        ));
    }
    if header[345..].iter().any(|byte| *byte != 0) {
        return Err(Finding::error(
            FindingCode::TarDialect,
            "old-GNU time, sparse, and reserved tail bytes must be zero",
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
    if kind == HeaderKind::Directory && size != 0 {
        return Err(Finding::error(
            FindingCode::TarType,
            "directory member declares a nonzero payload size",
        ));
    }
    let devmajor = parse_device_number(&header[329..337], "devmajor")?;
    let devminor = parse_device_number(&header[337..345], "devminor")?;
    if devmajor != 0 || devminor != 0 {
        return Err(Finding::error(
            FindingCode::TarType,
            "device numbers must be zero in the closed GNU long-name profile",
        ));
    }
    validate_owner_text(&header[265..297], "uname")?;
    validate_owner_text(&header[297..329], "gname")?;
    let raw_name = parse_text_field(&header[0..100], "name")?;

    Ok(ParsedHeader {
        raw_name,
        size,
        mode: u32::try_from(mode).expect("portable mode fits u32"),
        mtime,
        header_checksum: stored_checksum,
        header_sha256: hex_sha256(header),
        header: ByteRange {
            offset,
            len: BLOCK_LEN,
        },
        kind,
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
            | b'X'
            | b'K'
            | b'S'
            | b'D'
            | b'M'
            | b'N'
            | b'V'
    )
}

fn parse_device_number(field: &[u8], label: &str) -> Result<u64, Finding> {
    if field.iter().all(|byte| *byte == 0) {
        Ok(0)
    } else {
        parse_octal(field, label)
    }
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

fn parse_text_field(field: &[u8], label: &str) -> Result<Vec<u8>, Finding> {
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
    if end == 0 {
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
    if field[..end].iter().any(|byte| !matches!(byte, b' '..=b'~')) {
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

fn add_metadata(current: u64, amount: u64, cap: u64) -> Result<u64, Finding> {
    let total = current.checked_add(amount).ok_or_else(|| {
        Finding::error(
            FindingCode::QuotaOverflow,
            "GNU TAR metadata accounting overflowed u64",
        )
    })?;
    if total > cap {
        return Err(Finding::error(
            FindingCode::QuotaMetadata,
            format!("GNU TAR metadata is {total} bytes; cap is {cap}"),
        ));
    }
    Ok(total)
}

fn reserve_one<T>(values: &mut Vec<T>, label: &str) -> Result<(), Finding> {
    values.try_reserve(1).map_err(|_| {
        Finding::error(
            FindingCode::QuotaOverflow,
            format!("could not grow bounded {label}"),
        )
    })
}

fn gnu_syntax(detail: &str) -> Finding {
    Finding::error(FindingCode::TarGnuLongName, detail)
}

fn gnu_state(detail: &str) -> Finding {
    Finding::error(FindingCode::TarGnuState, detail)
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
    for mutation in input.as_chunks::<3>().0.iter().take(256) {
        let index = usize::from(u16::from_le_bytes([mutation[0], mutation[1]])) % 1536;
        canonical[index] = mutation[2];
    }
    for offset in [0_usize, 1024] {
        canonical[offset + 257..offset + 265].copy_from_slice(b"ustar  \0");
        fix_fuzz_checksum(&mut canonical[offset..offset + 512]);
    }
    exercise_fuzz_candidate(&canonical);
}

#[cfg(feature = "__internal-fuzzing")]
fn exercise_fuzz_candidate(input: &[u8]) {
    let snapshot = SourceSnapshot::borrowed(None, input);
    let file_cap = u64::try_from(input.len() / BLOCK_LEN_USIZE).unwrap();
    let metadata_cap = u64::try_from(input.len()).unwrap();
    let parsed = parse_gnu_longname_portable_v1(&snapshot, file_cap, metadata_cap);
    let Ok(archive) = parsed else {
        return;
    };
    assert_eq!(
        parse_gnu_longname_portable_v1(&snapshot, file_cap, metadata_cap).unwrap(),
        archive
    );
    let exact_files = u64::try_from(archive.members.len()).unwrap();
    assert_eq!(
        parse_gnu_longname_portable_v1(&snapshot, exact_files, archive.metadata_bytes).unwrap(),
        archive
    );
    if exact_files > 0 {
        assert_eq!(
            parse_gnu_longname_portable_v1(&snapshot, exact_files - 1, archive.metadata_bytes,)
                .unwrap_err()
                .code,
            FindingCode::QuotaFiles
        );
    }
    if archive.metadata_bytes > 0 {
        assert_eq!(
            parse_gnu_longname_portable_v1(&snapshot, exact_files, archive.metadata_bytes - 1,)
                .unwrap_err()
                .code,
            FindingCode::QuotaMetadata
        );
    }

    let mut cursor = 0_u64;
    let mut carrier_index = 0_usize;
    for member in &archive.members {
        if let Some(index) = member.carrier_index {
            assert_eq!(usize::try_from(index).unwrap(), carrier_index);
            let carrier = &archive.carriers[carrier_index];
            assert_eq!(carrier.header.offset, cursor);
            assert_eq!(carrier.payload.offset, carrier.header.end());
            assert_eq!(carrier.path.offset, carrier.payload.offset);
            assert_eq!(carrier.path.len + 1, carrier.payload.len);
            assert_eq!(carrier.padding.offset, carrier.payload.end());
            cursor = carrier.padding.end();
            carrier_index += 1;
        }
        assert_eq!(member.header.offset, cursor);
        assert_eq!(member.payload.offset, member.header.end());
        assert_eq!(member.padding.offset, member.payload.end());
        cursor = member.padding.end();
    }
    assert_eq!(carrier_index, archive.carriers.len());
    assert_eq!(
        archive.member_records,
        (ByteRange {
            offset: 0,
            len: cursor
        })
    );
    assert_eq!(archive.terminator.offset, cursor);
    assert_eq!(archive.trailing_zeros.end(), snapshot.len());

    let mut policy = crate::Policy::default_v6();
    policy.max_archive_bytes = metadata_cap;
    policy.max_files = file_cap.min(u64::from(u32::MAX));
    policy.max_metadata_bytes = metadata_cap;
    policy.max_member_bytes = metadata_cap;
    policy.max_total_bytes = metadata_cap;
    let options = crate::ApplyOptions::new().with_tar_gnu_longname_interpretation_profile(
        crate::TarGnuLongNameInterpretationProfile::PortableV1,
    );
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
    let path = format!("{}.txt", "g".repeat(110));
    let mut carrier_payload = path.as_bytes().to_vec();
    carrier_payload.push(0);
    let mut bytes = Vec::new();
    append_fuzz_record(
        &mut bytes,
        fuzz_header(b"././@LongLink", carrier_payload.len() as u64, b'L'),
        &carrier_payload,
    );
    append_fuzz_record(
        &mut bytes,
        fuzz_header(&path.as_bytes()[..100], 1, b'0'),
        b"x",
    );
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

#[cfg(feature = "__internal-fuzzing")]
fn fuzz_header(name: &[u8], size: u64, typeflag: u8) -> [u8; 512] {
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name);
    write_fuzz_octal(&mut header[100..108], 0o644);
    write_fuzz_octal(&mut header[108..116], 0);
    write_fuzz_octal(&mut header[116..124], 0);
    write_fuzz_octal(&mut header[124..136], size);
    write_fuzz_octal(&mut header[136..148], 0);
    header[156] = typeflag;
    header[257..265].copy_from_slice(b"ustar  \0");
    fix_fuzz_checksum(&mut header);
    header
}

#[cfg(feature = "__internal-fuzzing")]
fn append_fuzz_record(bytes: &mut Vec<u8>, header: [u8; 512], payload: &[u8]) {
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().next_multiple_of(512), 0);
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

    fn fix_checksum(header: &mut [u8; 512]) {
        header[148..156].fill(b' ');
        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        let encoded = format!("{checksum:06o}");
        header[148..154].copy_from_slice(encoded.as_bytes());
        header[154] = 0;
        header[155] = b' ';
    }

    fn header(name: &[u8], size: u64, typeflag: u8) -> [u8; 512] {
        assert!(name.len() <= 100);
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name);
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], size);
        write_octal(&mut header[136..148], 0);
        header[156] = typeflag;
        header[257..265].copy_from_slice(b"ustar  \0");
        fix_checksum(&mut header);
        header
    }

    fn append_record(bytes: &mut Vec<u8>, record_header: [u8; 512], payload: &[u8]) {
        bytes.extend_from_slice(&record_header);
        bytes.extend_from_slice(payload);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
    }

    fn finish(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.resize(bytes.len() + 1024, 0);
        bytes
    }

    fn long_file(path: &[u8], content: &[u8]) -> Vec<u8> {
        let mut carrier_payload = path.to_vec();
        carrier_payload.push(0);
        let mut bytes = Vec::new();
        append_record(
            &mut bytes,
            header(b"././@LongLink", carrier_payload.len() as u64, b'L'),
            &carrier_payload,
        );
        append_record(
            &mut bytes,
            header(&path[..path.len().min(100)], content.len() as u64, b'0'),
            content,
        );
        finish(bytes)
    }

    fn parse(bytes: &[u8]) -> Result<GnuLongNameArchive, Finding> {
        let snapshot = SourceSnapshot::borrowed(None, bytes);
        parse_gnu_longname_portable_v1(&snapshot, 4096, bytes.len() as u64)
    }

    #[test]
    fn long_name_is_metadata_consumed_by_one_member() {
        let path = format!("{}.txt", "g".repeat(110));
        let bytes = long_file(path.as_bytes(), b"mars");
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.carriers.len(), 1);
        assert_eq!(archive.members.len(), 1);
        assert_eq!(archive.members[0].name, path);
        assert_eq!(archive.members[0].raw_name, vec![b'g'; 100]);
        assert_eq!(archive.members[0].carrier_index, Some(0));
        assert_eq!(archive.carriers[0].raw_name, b"././@LongLink");
        assert_eq!(archive.carriers[0].path_bytes, path.as_bytes());
        assert_eq!(archive.carriers[0].payload.offset, 512);
        assert_eq!(archive.members[0].header.offset, 1024);
        assert_eq!(archive.members[0].payload.offset, 1536);
        assert_eq!(archive.metadata_bytes, 2560);
    }

    #[test]
    fn ordinary_old_gnu_member_needs_no_carrier() {
        let mut bytes = Vec::new();
        append_record(&mut bytes, header(b"plain.txt", 1, b'0'), b"x");
        let archive = parse(&finish(bytes)).unwrap();
        assert_eq!(archive.members[0].name, "plain.txt");
        assert_eq!(archive.members[0].carrier_index, None);
    }

    #[test]
    fn carrier_state_is_exactly_one_deep_and_must_be_consumed() {
        let path = vec![b'g'; 101];
        let mut payload = path.clone();
        payload.push(0);
        let mut chained = Vec::new();
        append_record(
            &mut chained,
            header(b"././@LongLink", payload.len() as u64, b'L'),
            &payload,
        );
        append_record(
            &mut chained,
            header(b"././@LongLink", payload.len() as u64, b'L'),
            &payload,
        );
        assert_eq!(
            parse(&finish(chained)).unwrap_err().code,
            FindingCode::TarGnuState
        );

        let mut orphan = Vec::new();
        append_record(
            &mut orphan,
            header(b"././@LongLink", payload.len() as u64, b'L'),
            &payload,
        );
        assert_eq!(
            parse(&finish(orphan)).unwrap_err().code,
            FindingCode::TarGnuState
        );
    }

    #[test]
    fn carrier_payload_requires_one_final_nul() {
        for payload in [b"path".as_slice(), b"\0".as_slice(), b"a\0b\0".as_slice()] {
            let mut bytes = Vec::new();
            append_record(
                &mut bytes,
                header(b"././@LongLink", payload.len() as u64, b'L'),
                payload,
            );
            append_record(&mut bytes, header(b"base", 0, b'0'), b"");
            assert_eq!(
                parse(&finish(bytes)).unwrap_err().code,
                FindingCode::TarGnuLongName
            );
        }
    }

    #[test]
    fn exact_magic_and_zero_tail_are_required_while_carrier_name_is_evidence() {
        let mut wrong_magic = long_file(b"long.txt", b"");
        wrong_magic[263] = b'0';
        fix_checksum((&mut wrong_magic[..512]).try_into().unwrap());
        assert_eq!(
            parse(&wrong_magic).unwrap_err().code,
            FindingCode::TarDialect
        );

        let mut wrong_name = long_file(b"long.txt", b"");
        wrong_name[0] = b'x';
        fix_checksum((&mut wrong_name[..512]).try_into().unwrap());
        assert_eq!(parse(&wrong_name).unwrap().carriers[0].raw_name[0], b'x');

        let mut nonzero_tail = long_file(b"long.txt", b"");
        nonzero_tail[345] = 1;
        fix_checksum((&mut nonzero_tail[..512]).try_into().unwrap());
        assert_eq!(
            parse(&nonzero_tail).unwrap_err().code,
            FindingCode::TarDialect
        );
    }

    #[test]
    fn pax_and_other_gnu_extensions_fail_before_state_exists() {
        for typeflag in *b"xgKSDMNV123467" {
            let bytes = finish(header(b"entry", 0, typeflag).to_vec());
            assert_eq!(
                parse(&bytes).unwrap_err().code,
                FindingCode::TarFeatureUnsupported
            );
        }
    }

    #[test]
    fn base256_and_nonzero_padding_fail_closed() {
        let mut base256 = finish(header(b"entry", 0, b'0').to_vec());
        base256[124] = 0x80;
        fix_checksum((&mut base256[..512]).try_into().unwrap());
        assert_eq!(
            parse(&base256).unwrap_err().code,
            FindingCode::TarFeatureUnsupported
        );

        let mut padding = long_file(b"long.txt", b"");
        padding[522] = 1;
        assert_eq!(parse(&padding).unwrap_err().code, FindingCode::TarPadding);
    }

    #[test]
    fn path_and_carrier_count_boundaries_are_exact() {
        let maximum_path = vec![b'a'; MAX_EFFECTIVE_PATH_BYTES];
        let archive = parse(&long_file(&maximum_path, b"")).unwrap();
        assert_eq!(
            archive.carriers[0].path_bytes.len(),
            MAX_EFFECTIVE_PATH_BYTES
        );

        let mut overlong_payload = vec![b'a'; MAX_EFFECTIVE_PATH_BYTES + 1];
        overlong_payload.push(0);
        let mut overlong = Vec::new();
        append_record(
            &mut overlong,
            header(b"carrier", overlong_payload.len() as u64, b'L'),
            &overlong_payload,
        );
        assert_eq!(
            parse(&finish(overlong)).unwrap_err().code,
            FindingCode::QuotaMetadata
        );

        let mut exact = Vec::new();
        for index in 0..MAX_CARRIERS {
            let path = format!("f{index}");
            let mut payload = path.as_bytes().to_vec();
            payload.push(0);
            append_record(
                &mut exact,
                header(b"carrier", payload.len() as u64, b'L'),
                &payload,
            );
            append_record(&mut exact, header(b"base", 0, b'0'), b"");
        }
        let exact = finish(exact);
        assert_eq!(parse(&exact).unwrap().carriers.len(), MAX_CARRIERS as usize);

        let mut one_over = exact[..exact.len() - 1024].to_vec();
        let mut payload = b"overflow".to_vec();
        payload.push(0);
        append_record(
            &mut one_over,
            header(b"carrier", payload.len() as u64, b'L'),
            &payload,
        );
        append_record(&mut one_over, header(b"base", 0, b'0'), b"");
        assert_eq!(
            parse(&finish(one_over)).unwrap_err().code,
            FindingCode::QuotaMetadata
        );
    }

    #[test]
    fn every_identity_numeric_field_denies_base256() {
        for offset in [100_usize, 108, 116, 124, 136, 329, 337] {
            let mut bytes = finish(header(b"entry", 0, b'0').to_vec());
            bytes[offset] = 0x80;
            fix_checksum((&mut bytes[..512]).try_into().unwrap());
            assert_eq!(
                parse(&bytes).unwrap_err().code,
                FindingCode::TarFeatureUnsupported,
                "numeric field beginning at byte {offset}"
            );
        }
    }

    #[test]
    fn pax_state_confusion_shapes_are_rejected_as_mixed_dialects() {
        for typeflag in *b"xg" {
            let mut bytes = Vec::new();
            append_record(&mut bytes, header(b"pax-size", 0, typeflag), b"");
            let path = b"effective.txt\0";
            append_record(
                &mut bytes,
                header(b"carrier", path.len() as u64, b'L'),
                path,
            );
            append_record(&mut bytes, header(b"file-a", 0, b'0'), b"");
            append_record(&mut bytes, header(b"file-b", 0, b'0'), b"");
            assert_eq!(
                parse(&finish(bytes)).unwrap_err().code,
                FindingCode::TarFeatureUnsupported
            );
        }
    }

    #[test]
    fn every_truncation_fails_closed() {
        let bytes = long_file(format!("{}.txt", "g".repeat(110)).as_bytes(), b"mars");
        for end in 0..bytes.len() {
            let snapshot = SourceSnapshot::borrowed(None, &bytes[..end]);
            assert!(
                parse_gnu_longname_portable_v1(&snapshot, 1, bytes.len() as u64).is_err(),
                "truncation at {end}"
            );
        }
    }
}
