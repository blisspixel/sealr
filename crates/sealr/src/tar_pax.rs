//! Bounded POSIX pax reader for the portable v1 profile.
//!
//! This parser accepts exact POSIX ustar headers plus a deliberately closed
//! pax grammar. Global (`g`) and local (`x`) extension headers may contain one
//! or two canonical `path` and `size` records. All other pax keywords and TAR
//! member types fail closed. Extension carriers are metadata and their names
//! are therefore retained as bytes without applying destination-path rules.

use crate::findings::{Finding, FindingCode};
use crate::ir::{ByteRange, PaxExtensionKind, PaxKeyword, PaxValueSource};
use crate::policy::hex_sha256;
use crate::snapshot::SourceSnapshot;

const BLOCK_LEN: u64 = 512;
const BLOCK_LEN_USIZE: usize = 512;
const MAX_EXTENSION_BYTES: u64 = 64 * 1024;
const MAX_EXTENSIONS: u64 = 1024;
const MAX_EFFECTIVE_PATH_BYTES: usize = 8191;
const MAX_RECORD_LENGTH_DIGITS: usize = 20;
const MAX_KEYWORD_BYTES: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PaxRecordValue {
    Path(String),
    Size(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PaxRecord {
    pub keyword: PaxKeyword,
    pub value: PaxRecordValue,
    pub record: ByteRange,
    pub value_range: ByteRange,
    pub raw_value_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PaxExtension {
    pub kind: PaxExtensionKind,
    pub raw_name: Vec<u8>,
    pub header_checksum: u32,
    pub header_sha256: String,
    pub payload_sha256: String,
    pub mode: u32,
    pub mtime: u64,
    pub header: ByteRange,
    pub payload: ByteRange,
    pub padding: ByteRange,
    pub records: Vec<PaxRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PaxMemberSources {
    pub path: PaxValueSource,
    pub size: PaxValueSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PaxMember {
    /// The name encoded by the ordinary ustar header before pax precedence.
    pub raw_name: Vec<u8>,
    /// The effective strict UTF-8 name after local, global, and ustar precedence.
    pub name: String,
    /// The size encoded by the ordinary ustar header before pax precedence.
    pub header_size: u64,
    /// The effective payload size after local, global, and ustar precedence.
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
    pub header_checksum: u32,
    pub header_sha256: String,
    pub header: ByteRange,
    pub payload: ByteRange,
    pub padding: ByteRange,
    pub is_dir: bool,
    pub sources: PaxMemberSources,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PaxArchive {
    pub members: Vec<PaxMember>,
    pub extensions: Vec<PaxExtension>,
    pub member_records: ByteRange,
    pub terminator: ByteRange,
    pub trailing_zeros: ByteRange,
    pub metadata_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeaderKind {
    File,
    Directory,
    GlobalExtension,
    LocalExtension,
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
struct StateValue<T> {
    value: T,
    extension_index: u32,
    record_index: u32,
}

#[derive(Clone, Debug, Default)]
struct OverrideState {
    path: Option<StateValue<String>>,
    size: Option<StateValue<u64>>,
}

impl OverrideState {
    fn from_records(records: &[PaxRecord], extension_index: usize) -> Self {
        let mut state = Self::default();
        let extension_index =
            u32::try_from(extension_index).expect("1024-extension profile cap fits u32");
        for (record_index, record) in records.iter().enumerate() {
            let record_index =
                u32::try_from(record_index).expect("two-record profile cap fits u32");
            match &record.value {
                PaxRecordValue::Path(path) => {
                    state.path = Some(StateValue {
                        value: path.clone(),
                        extension_index,
                        record_index,
                    });
                }
                PaxRecordValue::Size(size) => {
                    state.size = Some(StateValue {
                        value: *size,
                        extension_index,
                        record_index,
                    });
                }
            }
        }
        state
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

pub(crate) fn parse_pax_portable_v1(
    snapshot: &SourceSnapshot<'_>,
    max_files: u64,
    max_metadata_bytes: u64,
) -> Result<PaxArchive, Finding> {
    let source_len = snapshot.len();
    if source_len < BLOCK_LEN * 2 || !source_len.is_multiple_of(BLOCK_LEN) {
        return Err(Finding::error(
            FindingCode::TarTruncated,
            "pax source must contain at least two complete 512-byte blocks",
        ));
    }

    let mut members = Vec::new();
    let mut extensions = Vec::new();
    let mut globals = OverrideState::default();
    let mut pending_local: Option<OverrideState> = None;
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
            if pending_local.is_some() {
                return Err(Finding::error(
                    FindingCode::TarPaxState,
                    "local pax header is not followed by an ordinary member",
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
            return Ok(PaxArchive {
                members,
                extensions,
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
            HeaderKind::GlobalExtension | HeaderKind::LocalExtension => {
                if pending_local.is_some() {
                    return Err(Finding::error(
                        FindingCode::TarPaxState,
                        "local pax header must be followed immediately by an ordinary member",
                    ));
                }
                if header.size > MAX_EXTENSION_BYTES {
                    return Err(Finding::error(
                        FindingCode::QuotaMetadata,
                        format!(
                            "pax extension is {} bytes; per-extension cap is {MAX_EXTENSION_BYTES}",
                            header.size
                        ),
                    ));
                }
                if extensions.len() as u64 >= MAX_EXTENSIONS {
                    return Err(Finding::error(
                        FindingCode::QuotaMetadata,
                        format!("pax archive contains more than {MAX_EXTENSIONS} extensions"),
                    ));
                }

                let padded_size = round_up_block(header.size)?;
                let payload_offset = header_end;
                let payload_end =
                    checked_add(payload_offset, header.size, "extension payload end")?;
                let record_end = checked_add(payload_offset, padded_size, "extension record end")?;
                if record_end > source_len {
                    return Err(Finding::error(
                        FindingCode::TarTruncated,
                        "declared pax extension payload extends beyond the source",
                    ));
                }
                metadata_bytes = add_metadata(
                    metadata_bytes,
                    checked_add(BLOCK_LEN, padded_size, "extension metadata bytes")?,
                    max_metadata_bytes,
                )?;
                let payload_len = usize::try_from(header.size).map_err(|_| {
                    Finding::error(
                        FindingCode::QuotaMetadata,
                        "pax extension size does not fit this platform",
                    )
                })?;
                let mut payload = Vec::new();
                payload.try_reserve_exact(payload_len).map_err(|_| {
                    Finding::error(
                        FindingCode::QuotaMetadata,
                        "could not allocate the bounded pax extension payload",
                    )
                })?;
                payload.resize(payload_len, 0);
                snapshot.read_exact_at(payload_offset, &mut payload)?;
                let records = parse_records(&payload, payload_offset)?;
                let padding_len = padded_size - header.size;
                ensure_zero_range(snapshot, payload_end, padding_len, "pax extension padding")?;

                let kind = match header.kind {
                    HeaderKind::GlobalExtension => PaxExtensionKind::Global,
                    HeaderKind::LocalExtension => PaxExtensionKind::Local,
                    HeaderKind::File | HeaderKind::Directory => unreachable!(),
                };
                let extension_index = extensions.len();
                reserve_one(&mut extensions, "pax extension table")?;
                extensions.push(PaxExtension {
                    kind,
                    raw_name: header.raw_name,
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
                    padding: ByteRange {
                        offset: payload_end,
                        len: padding_len,
                    },
                    records,
                });
                let update = OverrideState::from_records(
                    &extensions[extension_index].records,
                    extension_index,
                );
                match kind {
                    PaxExtensionKind::Global => globals.update_from(update),
                    PaxExtensionKind::Local => pending_local = Some(update),
                }
                offset = record_end;
            }
            HeaderKind::File | HeaderKind::Directory => {
                if members.len() as u64 >= max_files {
                    return Err(Finding::error(
                        FindingCode::QuotaFiles,
                        format!("pax TAR contains more than {max_files} members"),
                    ));
                }
                metadata_bytes = add_metadata(metadata_bytes, BLOCK_LEN, max_metadata_bytes)?;

                let local = pending_local.take();
                let (name, path_origin) = resolve_path(&header.raw_name, &globals, local.as_ref())?;
                let (size, size_origin) = resolve_size(header.size, &globals, local.as_ref());
                let is_dir = header.kind == HeaderKind::Directory;
                if is_dir && size != 0 {
                    return Err(Finding::error(
                        FindingCode::TarType,
                        "directory member declares a nonzero effective payload size",
                    )
                    .on(&name));
                }

                let payload_offset = header_end;
                let payload_end = checked_add(payload_offset, size, "payload end")?;
                let padded_size = round_up_block(size)?;
                let record_end = checked_add(payload_offset, padded_size, "member record end")?;
                if record_end > source_len {
                    return Err(Finding::error(
                        FindingCode::TarTruncated,
                        "declared member payload extends beyond the source",
                    )
                    .on(&name));
                }
                let padding_len = padded_size - size;
                ensure_zero_range(snapshot, payload_end, padding_len, "member padding")
                    .map_err(|finding| finding.on(&name))?;

                reserve_one(&mut members, "pax member table")?;
                members.push(PaxMember {
                    raw_name: header.raw_name,
                    name,
                    header_size: header.size,
                    size,
                    mode: header.mode,
                    mtime: header.mtime,
                    header_checksum: header.header_checksum,
                    header_sha256: header.header_sha256,
                    header: header.header,
                    payload: ByteRange {
                        offset: payload_offset,
                        len: size,
                    },
                    padding: ByteRange {
                        offset: payload_end,
                        len: padding_len,
                    },
                    is_dir,
                    sources: PaxMemberSources {
                        path: path_origin,
                        size: size_origin,
                    },
                });
                offset = record_end;
            }
        }
    }
}

fn resolve_path(
    raw_name: &[u8],
    globals: &OverrideState,
    local: Option<&OverrideState>,
) -> Result<(String, PaxValueSource), Finding> {
    let (name, origin) = if let Some(value) = local.and_then(|state| state.path.as_ref()) {
        (
            value.value.clone(),
            PaxValueSource::Local {
                extension_index: value.extension_index,
                record_index: value.record_index,
            },
        )
    } else if let Some(value) = globals.path.as_ref() {
        (
            value.value.clone(),
            PaxValueSource::Global {
                extension_index: value.extension_index,
                record_index: value.record_index,
            },
        )
    } else {
        let name = std::str::from_utf8(raw_name)
            .map_err(|_| {
                Finding::error(
                    FindingCode::PathUnicode,
                    "effective ustar member name is not strict UTF-8",
                )
            })?
            .to_owned();
        (name, PaxValueSource::Ustar)
    };
    validate_effective_path(&name)?;
    Ok((name, origin))
}

fn resolve_size(
    header_size: u64,
    globals: &OverrideState,
    local: Option<&OverrideState>,
) -> (u64, PaxValueSource) {
    if let Some(value) = local.and_then(|state| state.size.as_ref()) {
        (
            value.value,
            PaxValueSource::Local {
                extension_index: value.extension_index,
                record_index: value.record_index,
            },
        )
    } else if let Some(value) = globals.size.as_ref() {
        (
            value.value,
            PaxValueSource::Global {
                extension_index: value.extension_index,
                record_index: value.record_index,
            },
        )
    } else {
        (header_size, PaxValueSource::Ustar)
    }
}

fn parse_records(payload: &[u8], payload_offset: u64) -> Result<Vec<PaxRecord>, Finding> {
    let mut records = Vec::new();
    let mut cursor = 0_usize;
    let mut saw_path = false;
    let mut saw_size = false;
    while cursor < payload.len() {
        if records.len() == 2 {
            return Err(pax_syntax("pax extension contains more than two records"));
        }
        let length_start = cursor;
        while cursor < payload.len() && payload[cursor].is_ascii_digit() {
            cursor += 1;
            if cursor - length_start > MAX_RECORD_LENGTH_DIGITS {
                return Err(pax_syntax("pax record length exceeds 20 decimal digits"));
            }
        }
        if cursor == length_start || cursor == payload.len() || payload[cursor] != b' ' {
            return Err(pax_syntax(
                "pax record must start with decimal length followed by one space",
            ));
        }
        let length_digits = &payload[length_start..cursor];
        if length_digits.len() > 1 && length_digits[0] == b'0' {
            return Err(pax_syntax("pax record length has a leading zero"));
        }
        let record_len_u64 = parse_decimal(length_digits, "pax record length")?;
        let record_len = usize::try_from(record_len_u64)
            .map_err(|_| pax_syntax("pax record length does not fit this platform"))?;
        let record_end = length_start
            .checked_add(record_len)
            .ok_or_else(|| pax_syntax("pax record end overflowed usize"))?;
        if record_len == 0 || record_end > payload.len() {
            return Err(pax_syntax(
                "pax record length extends beyond the extension payload",
            ));
        }
        if payload[record_end - 1] != b'\n' {
            return Err(pax_syntax("pax record is not terminated by newline"));
        }
        cursor += 1;
        if cursor >= record_end - 1 {
            return Err(pax_syntax("pax record has an empty key/value body"));
        }
        let body = &payload[cursor..record_end - 1];
        let equals = body
            .iter()
            .take(MAX_KEYWORD_BYTES)
            .position(|byte| *byte == b'=')
            .ok_or_else(|| {
                pax_syntax("pax record lacks '=' within the 16-byte keyword scan bound")
            })?;
        if equals == 0 {
            return Err(pax_syntax(
                "pax keyword length is outside the closed profile",
            ));
        }
        let keyword_bytes = &body[..equals];
        let value_bytes = &body[equals + 1..];
        let value_start = cursor
            .checked_add(equals + 1)
            .ok_or_else(|| pax_syntax("pax value offset overflowed usize"))?;
        let (keyword, value) = match keyword_bytes {
            b"path" => {
                if saw_path {
                    return Err(pax_syntax("pax extension repeats the path keyword"));
                }
                saw_path = true;
                let path = parse_path_value(value_bytes)?;
                (PaxKeyword::Path, PaxRecordValue::Path(path))
            }
            b"size" => {
                if saw_size {
                    return Err(pax_syntax("pax extension repeats the size keyword"));
                }
                saw_size = true;
                if value_bytes.is_empty()
                    || !value_bytes.iter().all(u8::is_ascii_digit)
                    || (value_bytes.len() > 1 && value_bytes[0] == b'0')
                    || value_bytes.len() > MAX_RECORD_LENGTH_DIGITS
                {
                    return Err(pax_syntax(
                        "pax size must be canonical unsigned decimal without a leading zero",
                    ));
                }
                (
                    PaxKeyword::Size,
                    PaxRecordValue::Size(parse_decimal(value_bytes, "pax size")?),
                )
            }
            _ => {
                return Err(Finding::error(
                    FindingCode::TarFeatureUnsupported,
                    "pax keyword is outside the closed path/size profile",
                ));
            }
        };
        let relative_offset = u64::try_from(length_start)
            .map_err(|_| pax_syntax("pax record offset does not fit u64"))?;
        let source_offset = checked_add(payload_offset, relative_offset, "pax record offset")?;
        let relative_value_offset = u64::try_from(value_start)
            .map_err(|_| pax_syntax("pax value offset does not fit u64"))?;
        let value_offset = checked_add(payload_offset, relative_value_offset, "pax value offset")?;
        let value_len = u64::try_from(value_bytes.len())
            .map_err(|_| pax_syntax("pax value length does not fit u64"))?;
        reserve_one(&mut records, "pax record table")?;
        records.push(PaxRecord {
            keyword,
            value,
            record: ByteRange {
                offset: source_offset,
                len: record_len_u64,
            },
            value_range: ByteRange {
                offset: value_offset,
                len: value_len,
            },
            raw_value_bytes: copy_value_bytes(value_bytes)?,
        });
        cursor = record_end;
    }
    if records.is_empty() {
        return Err(pax_syntax("pax extension must contain one or two records"));
    }
    Ok(records)
}

fn validate_effective_path(path: &str) -> Result<(), Finding> {
    validate_path_bytes(path.as_bytes())
}

fn validate_path_bytes(path: &[u8]) -> Result<(), Finding> {
    if path.is_empty() {
        return Err(Finding::error(
            FindingCode::PathEmpty,
            "effective pax path is empty",
        ));
    }
    if path.len() > MAX_EFFECTIVE_PATH_BYTES {
        return Err(Finding::error(
            FindingCode::PathDepth,
            format!(
                "effective pax path is {} bytes; profile cap is {MAX_EFFECTIVE_PATH_BYTES}",
                path.len()
            ),
        ));
    }
    if path.contains(&0) {
        return Err(Finding::error(
            FindingCode::PathNul,
            "effective pax path contains NUL",
        ));
    }
    Ok(())
}

fn parse_path_value(value: &[u8]) -> Result<String, Finding> {
    validate_path_bytes(value)?;
    let decoded = std::str::from_utf8(value).map_err(|_| {
        Finding::error(
            FindingCode::PathUnicode,
            "pax path value is not strict UTF-8",
        )
    })?;
    let mut path = String::new();
    path.try_reserve_exact(value.len()).map_err(|_| {
        Finding::error(
            FindingCode::QuotaOverflow,
            "could not allocate the bounded pax path value",
        )
    })?;
    path.push_str(decoded);
    Ok(path)
}

fn copy_value_bytes(value: &[u8]) -> Result<Vec<u8>, Finding> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(value.len()).map_err(|_| {
        Finding::error(
            FindingCode::QuotaOverflow,
            "could not allocate bounded pax record evidence",
        )
    })?;
    copy.extend_from_slice(value);
    Ok(copy)
}

fn parse_header(header: &[u8; BLOCK_LEN_USIZE], offset: u64) -> Result<ParsedHeader, Finding> {
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
    let kind = match header[156] {
        b'0' | 0 => HeaderKind::File,
        b'5' => HeaderKind::Directory,
        b'g' => HeaderKind::GlobalExtension,
        b'x' => HeaderKind::LocalExtension,
        typeflag if is_known_unsupported_typeflag(typeflag) => {
            return Err(Finding::error(
                FindingCode::TarFeatureUnsupported,
                format!("unsupported pax-profile typeflag 0x{typeflag:02x}"),
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
            "linkname must be empty in the closed pax profile",
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
            "directory member declares a nonzero underlying payload size",
        ));
    }
    let devmajor = parse_device_number(&header[329..337], "devmajor")?;
    let devminor = parse_device_number(&header[337..345], "devminor")?;
    if devmajor != 0 || devminor != 0 {
        return Err(Finding::error(
            FindingCode::TarType,
            "device numbers must be zero in the closed pax profile",
        ));
    }
    validate_owner_text(&header[265..297], "uname")?;
    validate_owner_text(&header[297..329], "gname")?;

    let name = parse_text_field(&header[0..100], "name", false)?;
    let prefix = parse_text_field(&header[345..500], "prefix", true)?;
    let capacity = prefix
        .len()
        .checked_add(usize::from(!prefix.is_empty()))
        .and_then(|value| value.checked_add(name.len()))
        .ok_or_else(|| pax_syntax("ustar name capacity overflowed usize"))?;
    let mut raw_name = Vec::new();
    raw_name.try_reserve_exact(capacity).map_err(|_| {
        Finding::error(
            FindingCode::QuotaMetadata,
            "could not allocate bounded ustar name",
        )
    })?;
    if !prefix.is_empty() {
        raw_name.extend_from_slice(&prefix);
        raw_name.push(b'/');
    }
    raw_name.extend_from_slice(&name);

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
        b'1' | b'2' | b'3' | b'4' | b'6' | b'7' | b'L' | b'K' | b'S' | b'D' | b'M' | b'N' | b'V'
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

fn parse_decimal(digits: &[u8], label: &str) -> Result<u64, Finding> {
    digits.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| pax_syntax(&format!("{label} overflowed u64")))
    })
}

#[cfg(feature = "__internal-fuzzing")]
pub(crate) fn exercise_fuzz_input(input: &[u8]) {
    const MAX_FUZZ_INPUT: usize = 4 * 1024 * 1024;
    if input.len() > MAX_FUZZ_INPUT {
        return;
    }
    let snapshot = SourceSnapshot::borrowed(None, input);
    let file_cap = u64::try_from(input.len() / BLOCK_LEN_USIZE).unwrap();
    let metadata_cap = u64::try_from(input.len()).unwrap();
    let parsed = parse_pax_portable_v1(&snapshot, file_cap, metadata_cap);
    let Ok(archive) = parsed else {
        return;
    };
    assert_eq!(
        parse_pax_portable_v1(&snapshot, file_cap, metadata_cap).unwrap(),
        archive
    );
    let exact_files = u64::try_from(archive.members.len()).unwrap();
    assert_eq!(
        parse_pax_portable_v1(&snapshot, exact_files, archive.metadata_bytes).unwrap(),
        archive
    );
    if exact_files > 0 {
        assert_eq!(
            parse_pax_portable_v1(&snapshot, exact_files - 1, archive.metadata_bytes)
                .unwrap_err()
                .code,
            FindingCode::QuotaFiles
        );
    }
    if archive.metadata_bytes > 0 {
        assert_eq!(
            parse_pax_portable_v1(&snapshot, exact_files, archive.metadata_bytes - 1)
                .unwrap_err()
                .code,
            FindingCode::QuotaMetadata
        );
    }

    let mut policy = crate::Policy::default_v5();
    policy.max_archive_bytes = metadata_cap;
    policy.max_files = file_cap.min(u64::from(u32::MAX));
    policy.max_metadata_bytes = metadata_cap;
    policy.max_member_bytes = metadata_cap;
    policy.max_total_bytes = metadata_cap;
    let options = crate::ApplyOptions::new()
        .with_tar_pax_interpretation_profile(crate::TarPaxInterpretationProfile::PortableV1);
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
            "pax metadata accounting overflowed u64",
        )
    })?;
    if total > cap {
        return Err(Finding::error(
            FindingCode::QuotaMetadata,
            format!("pax TAR metadata is {total} bytes; cap is {cap}"),
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

fn pax_syntax(detail: &str) -> Finding {
    Finding::error(FindingCode::TarPaxRecord, detail)
}

fn is_zero_block(block: &[u8; BLOCK_LEN_USIZE]) -> bool {
    block.iter().all(|byte| *byte == 0)
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

    fn header(name: &str, size: u64, typeflag: u8) -> [u8; 512] {
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], size);
        write_octal(&mut header[136..148], 0);
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        write_octal(&mut header[329..337], 0);
        write_octal(&mut header[337..345], 0);
        fix_checksum(&mut header);
        header
    }

    fn record(key: &str, value: &str) -> Vec<u8> {
        let body = format!(" {key}={value}\n");
        let mut digits = 1_usize;
        loop {
            let length = digits + body.len();
            let next_digits = length.to_string().len();
            if digits == next_digits {
                return format!("{length}{body}").into_bytes();
            }
            digits = next_digits;
        }
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

    fn one_local(records: &[Vec<u8>], content: &[u8]) -> Vec<u8> {
        let payload = records.concat();
        let mut bytes = Vec::new();
        append_record(
            &mut bytes,
            header("../../carrier", payload.len() as u64, b'x'),
            &payload,
        );
        append_record(
            &mut bytes,
            header("placeholder", content.len() as u64, b'0'),
            content,
        );
        finish(bytes)
    }

    fn parse(bytes: &[u8]) -> Result<PaxArchive, Finding> {
        let snapshot = SourceSnapshot::borrowed(None, bytes);
        parse_pax_portable_v1(&snapshot, 4096, bytes.len() as u64)
    }

    #[test]
    fn local_path_and_size_override_geometry_with_explicit_sources() {
        let bytes = one_local(
            &[record("path", "dir/on-mars.txt"), record("size", "4")],
            b"mars",
        );
        let archive = parse(&bytes).unwrap();
        assert_eq!(archive.members.len(), 1);
        assert_eq!(archive.extensions.len(), 1);
        let member = &archive.members[0];
        assert_eq!(member.name, "dir/on-mars.txt");
        assert_eq!(member.size, 4);
        assert_eq!(
            member.payload,
            ByteRange {
                offset: 1536,
                len: 4
            }
        );
        assert_eq!(
            member.sources.path,
            PaxValueSource::Local {
                extension_index: 0,
                record_index: 0
            }
        );
        assert_eq!(
            member.sources.size,
            PaxValueSource::Local {
                extension_index: 0,
                record_index: 1
            }
        );
        assert_eq!(archive.extensions[0].raw_name, b"../../carrier");
        assert_eq!(archive.extensions[0].payload_sha256.len(), 64);
        assert_eq!(
            archive.extensions[0].records[0].raw_value_bytes,
            b"dir/on-mars.txt"
        );
        assert_eq!(
            archive.extensions[0].records[0].record,
            ByteRange {
                offset: 512,
                len: 24
            }
        );
        assert_eq!(
            archive.extensions[0].records[0].value_range,
            ByteRange {
                offset: 520,
                len: 15
            }
        );
        assert_eq!(archive.metadata_bytes, 2560);
        assert_eq!(
            archive.member_records,
            ByteRange {
                offset: 0,
                len: 2048
            }
        );
    }

    #[test]
    fn global_values_persist_and_local_values_win_once() {
        let global_payload = [record("path", "global.txt"), record("size", "1")].concat();
        let local_payload = record("path", "local.txt");
        let mut bytes = Vec::new();
        append_record(
            &mut bytes,
            header("g", global_payload.len() as u64, b'g'),
            &global_payload,
        );
        append_record(
            &mut bytes,
            header("x", local_payload.len() as u64, b'x'),
            &local_payload,
        );
        append_record(&mut bytes, header("first", 9, b'0'), b"a");
        append_record(&mut bytes, header("second", 9, b'0'), b"b");
        let archive = parse(&finish(bytes)).unwrap();
        assert_eq!(archive.members[0].name, "local.txt");
        assert_eq!(archive.members[0].size, 1);
        assert_eq!(archive.members[0].header_size, 9);
        assert!(matches!(
            archive.members[0].sources.path,
            PaxValueSource::Local { .. }
        ));
        assert!(matches!(
            archive.members[0].sources.size,
            PaxValueSource::Global { .. }
        ));
        assert_eq!(archive.members[1].name, "global.txt");
        assert_eq!(archive.members[1].size, 1);
        assert!(matches!(
            archive.members[1].sources.path,
            PaxValueSource::Global { .. }
        ));
    }

    #[test]
    fn global_updates_merge_by_keyword() {
        let mut bytes = Vec::new();
        let path = record("path", "persistent.txt");
        let size = record("size", "2");
        append_record(&mut bytes, header("g1", path.len() as u64, b'g'), &path);
        append_record(&mut bytes, header("g2", size.len() as u64, b'g'), &size);
        append_record(&mut bytes, header("ordinary", 0, b'0'), b"ok");
        let archive = parse(&finish(bytes)).unwrap();
        assert_eq!(archive.members[0].name, "persistent.txt");
        assert_eq!(archive.members[0].size, 2);
    }

    #[test]
    fn overridden_base_name_is_evidence_not_a_destination_path() {
        let payload = record("path", "effective.txt");
        let mut bytes = Vec::new();
        append_record(
            &mut bytes,
            header("../../carrier", payload.len() as u64, b'x'),
            &payload,
        );
        let mut ordinary = header("placeholder", 0, b'0');
        ordinary[0] = 0xff;
        fix_checksum(&mut ordinary);
        append_record(&mut bytes, ordinary, b"");
        let archive = parse(&finish(bytes)).unwrap();
        assert_eq!(archive.members[0].raw_name[0], 0xff);
        assert_eq!(archive.members[0].name, "effective.txt");
    }

    #[test]
    fn local_header_must_be_immediately_consumed() {
        let payload = record("path", "local.txt");
        let mut chained = Vec::new();
        append_record(
            &mut chained,
            header("x", payload.len() as u64, b'x'),
            &payload,
        );
        append_record(
            &mut chained,
            header("g", payload.len() as u64, b'g'),
            &payload,
        );
        assert_eq!(
            parse(&finish(chained)).unwrap_err().code,
            FindingCode::TarPaxState
        );

        let mut orphan = Vec::new();
        append_record(
            &mut orphan,
            header("x", payload.len() as u64, b'x'),
            &payload,
        );
        assert_eq!(
            parse(&finish(orphan)).unwrap_err().code,
            FindingCode::TarPaxState
        );
    }

    #[test]
    fn record_grammar_is_closed_and_canonical() {
        let bounded_keyword = record("abcdefghijklmnop", "x");
        let malformed: [&[u8]; 8] = [
            b"013 path=a\n".as_slice(),
            b"99 path=a\n".as_slice(),
            b"10 path=a!".as_slice(),
            b"11 unknown=x\n".as_slice(),
            b"11 size=01\n".as_slice(),
            b"8 size=\n".as_slice(),
            b"7 path=\n".as_slice(),
            &bounded_keyword,
        ];
        for payload in malformed {
            let mut bytes = Vec::new();
            append_record(&mut bytes, header("x", payload.len() as u64, b'x'), payload);
            append_record(&mut bytes, header("member", 0, b'0'), b"");
            assert!(parse(&finish(bytes)).is_err(), "payload {payload:?}");
        }
    }

    #[test]
    fn duplicate_and_third_records_are_denied() {
        for payload in [
            [record("path", "a"), record("path", "b")].concat(),
            [
                record("path", "a"),
                record("size", "0"),
                record("path", "b"),
            ]
            .concat(),
        ] {
            let mut bytes = Vec::new();
            append_record(
                &mut bytes,
                header("x", payload.len() as u64, b'x'),
                &payload,
            );
            append_record(&mut bytes, header("member", 0, b'0'), b"");
            assert_eq!(
                parse(&finish(bytes)).unwrap_err().code,
                FindingCode::TarPaxRecord
            );
        }
    }

    #[test]
    fn unknown_keyword_is_feature_unsupported() {
        let payload = record("mtime", "0");
        let mut bytes = Vec::new();
        append_record(
            &mut bytes,
            header("x", payload.len() as u64, b'x'),
            &payload,
        );
        append_record(&mut bytes, header("member", 0, b'0'), b"");
        assert_eq!(
            parse(&finish(bytes)).unwrap_err().code,
            FindingCode::TarFeatureUnsupported
        );
    }

    #[test]
    fn invalid_utf8_nul_and_oversized_paths_are_denied() {
        let mut invalid_utf8 = record("path", "a");
        let value = invalid_utf8.iter().position(|byte| *byte == b'a').unwrap();
        invalid_utf8[value] = 0xff;
        for payload in [
            invalid_utf8,
            record("path", "a\0b"),
            record("path", &"x".repeat(8192)),
        ] {
            let mut bytes = Vec::new();
            append_record(
                &mut bytes,
                header("x", payload.len() as u64, b'x'),
                &payload,
            );
            append_record(&mut bytes, header("member", 0, b'0'), b"");
            assert!(parse(&finish(bytes)).is_err());
        }

        let bytes = one_local(&[record("path", &"x".repeat(8191))], b"");
        assert_eq!(parse(&bytes).unwrap().members[0].name.len(), 8191);
    }

    #[test]
    fn decimal_u64_overflow_is_denied() {
        let bytes = one_local(&[record("size", "18446744073709551616")], b"");
        assert_eq!(parse(&bytes).unwrap_err().code, FindingCode::TarPaxRecord);
    }

    #[test]
    fn extension_size_and_count_caps_are_enforced() {
        let mut oversized = header("x", MAX_EXTENSION_BYTES + 1, b'x').to_vec();
        oversized.resize(
            512 + (MAX_EXTENSION_BYTES as usize + 1).next_multiple_of(512),
            0,
        );
        oversized.resize(oversized.len() + 1024, 0);
        assert_eq!(
            parse(&oversized).unwrap_err().code,
            FindingCode::QuotaMetadata
        );

        let payload = record("size", "0");
        let mut too_many = Vec::new();
        for _ in 0..=MAX_EXTENSIONS {
            append_record(
                &mut too_many,
                header("g", payload.len() as u64, b'g'),
                &payload,
            );
        }
        assert_eq!(
            parse(&finish(too_many)).unwrap_err().code,
            FindingCode::QuotaMetadata
        );
    }

    #[test]
    fn nonzero_extension_and_member_padding_are_denied() {
        let mut extension = one_local(&[record("path", "file")], b"");
        extension[530] = 1;
        assert_eq!(parse(&extension).unwrap_err().code, FindingCode::TarPadding);

        let mut member = one_local(&[record("path", "file")], b"x");
        member[1537] = 1;
        assert_eq!(parse(&member).unwrap_err().code, FindingCode::TarPadding);
    }

    #[test]
    fn effective_directory_size_must_be_zero() {
        let payload = record("size", "1");
        let mut bytes = Vec::new();
        append_record(
            &mut bytes,
            header("x", payload.len() as u64, b'x'),
            &payload,
        );
        append_record(&mut bytes, header("dir", 0, b'5'), b"");
        assert_eq!(
            parse(&finish(bytes)).unwrap_err().code,
            FindingCode::TarType
        );

        let zero = record("size", "0");
        let mut underlying = Vec::new();
        append_record(&mut underlying, header("x", zero.len() as u64, b'x'), &zero);
        append_record(&mut underlying, header("dir", 1, b'5'), b"");
        assert_eq!(
            parse(&finish(underlying)).unwrap_err().code,
            FindingCode::TarType
        );
    }

    #[test]
    fn metadata_budget_accounts_for_extension_records() {
        let bytes = one_local(&[record("path", "file")], b"");
        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        assert_eq!(
            parse_pax_portable_v1(&snapshot, 1, 2559).unwrap_err().code,
            FindingCode::QuotaMetadata
        );
        assert!(parse_pax_portable_v1(&snapshot, 1, 2560).is_ok());
    }

    #[test]
    fn unsupported_tar_types_and_base256_fail_closed() {
        for typeflag in *b"123467LKSDMNV" {
            let bytes = finish(header("entry", 0, typeflag).to_vec());
            assert_eq!(
                parse(&bytes).unwrap_err().code,
                FindingCode::TarFeatureUnsupported
            );
        }
        let mut bytes = finish(header("entry", 0, b'0').to_vec());
        bytes[124] = 0x80;
        fix_checksum((&mut bytes[..512]).try_into().unwrap());
        assert_eq!(
            parse(&bytes).unwrap_err().code,
            FindingCode::TarFeatureUnsupported
        );
    }

    #[test]
    fn every_truncation_fails_closed() {
        let bytes = one_local(&[record("path", "file")], b"mars");
        for end in 0..bytes.len() {
            let snapshot = SourceSnapshot::borrowed(None, &bytes[..end]);
            assert!(
                parse_pax_portable_v1(&snapshot, 2, bytes.len() as u64).is_err(),
                "truncation at {end}"
            );
        }
    }
}
