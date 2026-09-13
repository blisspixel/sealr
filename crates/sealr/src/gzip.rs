//! Strict, bounded RFC 1952 single-member decoding.
//!
//! This module is deliberately crate-private until the wrapper profile and its
//! transformation identity are part of the public admission contract.

use std::cell::RefCell;
use std::io::{self, BufReader, Read};
use std::rc::Rc;

use crate::deflate::DeflateDecoder;
use crc32fast::Hasher as Crc;

use crate::findings::{Finding, FindingCode};
use crate::ir::ByteRange;
use crate::snapshot::{
    as_io_error, finding_from_io, DomainRange, SnapshotDomainId, SnapshotRangeReader, SnapshotSet,
    SourceSnapshot, TransformGraph, TransformProfile,
};

const FIXED_HEADER_LEN: u64 = 10;
const TRAILER_LEN: u64 = 8;
const DEFLATE_INPUT_BUFFER_BYTES: usize = 64 * 1024;

const FLAG_TEXT: u8 = 1 << 0;
const FLAG_HEADER_CRC: u8 = 1 << 1;
const FLAG_EXTRA: u8 = 1 << 2;
const FLAG_NAME: u8 = 1 << 3;
const FLAG_COMMENT: u8 = 1 << 4;
const FLAG_RESERVED: u8 = 0b1110_0000;

/// Resource limits for the private gzip transformation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GzipLimits {
    /// Maximum wrapper metadata bytes. This includes the fixed and optional
    /// header fields, delimiters, optional FHCRC, and the eight-byte trailer.
    pub(crate) max_metadata_bytes: u64,
    /// Maximum number of uncompressed bytes copied to the private snapshot.
    pub(crate) max_output_bytes: u64,
}

/// Exact byte ranges and fixed fields established before Deflate decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GzipHeader {
    pub(crate) flags: u8,
    pub(crate) modification_time: u32,
    pub(crate) extra_flags: u8,
    pub(crate) operating_system: u8,
    pub(crate) header: ByteRange,
    /// Includes the two-byte XLEN field and its exact payload.
    pub(crate) extra: Option<ByteRange>,
    pub(crate) extra_subfield_count: u32,
    /// Includes the terminating NUL byte.
    pub(crate) original_name: Option<ByteRange>,
    /// Includes the terminating NUL byte.
    pub(crate) comment: Option<ByteRange>,
    pub(crate) header_crc16: Option<ByteRange>,
}

/// A fully verified single gzip member and its bounded private output.
#[derive(Debug)]
pub(crate) struct DecodedGzipMember {
    pub(crate) header: GzipHeader,
    pub(crate) compressed_payload: ByteRange,
    pub(crate) trailer: ByteRange,
    pub(crate) declared_crc32: u32,
    pub(crate) declared_isize: u32,
    pub(crate) output: SourceSnapshot<'static>,
}

/// Verified wrapper evidence after the output has become a retained snapshot
/// domain and the transformation graph has bound both byte identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransformedGzipMember {
    pub(crate) header: GzipHeader,
    pub(crate) compressed_payload: ByteRange,
    pub(crate) trailer: ByteRange,
    pub(crate) declared_crc32: u32,
    pub(crate) declared_isize: u32,
    pub(crate) output_domain: SnapshotDomainId,
    pub(crate) output_len: u64,
    pub(crate) output_sha256: String,
}

/// Internal failure classes kept distinct before they are mapped to the
/// repository's stable finding vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GzipErrorKind {
    Source,
    Truncated,
    Magic,
    CompressionMethod,
    ReservedFlags,
    HeaderLimit,
    ExtraField,
    HeaderChecksum,
    DeflateStream,
    DeflateAccounting,
    ConcatenatedMember,
    TrailingInput,
    DataChecksum,
    DeclaredSize,
    OutputLimit,
    TransformAuthority,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GzipError {
    pub(crate) kind: GzipErrorKind,
    finding: Finding,
}

impl GzipError {
    pub(crate) fn finding(&self) -> &Finding {
        &self.finding
    }

    pub(crate) fn into_finding(self) -> Finding {
        self.finding
    }

    fn new(kind: GzipErrorKind, code: FindingCode, detail: impl Into<String>) -> Self {
        Self {
            kind,
            finding: Finding::error(code, detail),
        }
    }

    fn source(finding: Finding) -> Self {
        Self {
            kind: GzipErrorKind::Source,
            finding,
        }
    }

    fn truncated(detail: impl Into<String>) -> Self {
        Self::new(
            GzipErrorKind::Truncated,
            FindingCode::CodecDeflateInvalidStream,
            detail,
        )
    }

    fn deflate(detail: impl Into<String>) -> Self {
        Self::new(
            GzipErrorKind::DeflateStream,
            FindingCode::CodecDeflateInvalidStream,
            detail,
        )
    }
}

#[derive(Clone, Debug)]
struct TrailerEvidence {
    compressed_payload: ByteRange,
    trailer: ByteRange,
    declared_crc32: u32,
    declared_isize: u32,
}

type Completion = Rc<RefCell<Option<Result<TrailerEvidence, GzipError>>>>;

/// Decode exactly one RFC 1952 member into a private immutable snapshot.
///
/// Concatenated members, zero padding, and every other trailing byte are
/// rejected. The caller supplies independent header and output bounds.
pub(crate) fn decode_single_member(
    source: &SourceSnapshot<'_>,
    limits: GzipLimits,
) -> Result<DecodedGzipMember, GzipError> {
    let max_header_bytes = limits
        .max_metadata_bytes
        .checked_sub(TRAILER_LEN)
        .ok_or_else(|| metadata_limit(limits.max_metadata_bytes))?;
    let header = parse_header(source, max_header_bytes, limits.max_metadata_bytes)?;
    let input_len = source
        .len()
        .checked_sub(header.header.len)
        .ok_or_else(|| GzipError::truncated("gzip header extends past the source"))?;
    if input_len < TRAILER_LEN {
        return Err(GzipError::truncated(
            "gzip member does not contain a complete Deflate stream and trailer",
        ));
    }

    let input = source
        .reader(header.header.len, input_len)
        .map_err(GzipError::source)?;
    let completion = Rc::new(RefCell::new(None));
    let reader = VerifiedDeflateReader {
        decoder: DeflateDecoder::new(BufReader::with_capacity(DEFLATE_INPUT_BUFFER_BYTES, input)),
        source,
        payload_offset: header.header.len,
        crc32: Crc::new(),
        output_len: 0,
        terminal: false,
        completion: Rc::clone(&completion),
    };

    let output = match SourceSnapshot::private_derived_from_reader(reader, limits.max_output_bytes)
    {
        Ok(output) => output,
        Err(finding) => {
            if let Some(Err(error)) = completion.borrow().as_ref() {
                return Err(error.clone());
            }
            if finding.code == FindingCode::QuotaArchive {
                return Err(GzipError::new(
                    GzipErrorKind::OutputLimit,
                    FindingCode::QuotaDerived,
                    format!(
                        "gzip derived output exceeds the {}-byte cap",
                        limits.max_output_bytes
                    ),
                ));
            }
            return Err(GzipError {
                kind: GzipErrorKind::Source,
                finding,
            });
        }
    };

    let evidence = completion
        .borrow()
        .as_ref()
        .cloned()
        .ok_or_else(|| GzipError::deflate("Deflate reader ended without trailer evidence"))??;

    if evidence.trailer.end() != source.len() {
        scan_trailing_members(
            source,
            evidence.trailer.end(),
            limits,
            header.header.len + TRAILER_LEN,
            output.len(),
        )?;
        return Err(GzipError::new(
            GzipErrorKind::ConcatenatedMember,
            FindingCode::CodecDeflateTrailingInput,
            "concatenated gzip members are outside the single-member profile",
        ));
    }

    Ok(DecodedGzipMember {
        header,
        compressed_payload: evidence.compressed_payload,
        trailer: evidence.trailer,
        declared_crc32: evidence.declared_crc32,
        declared_isize: evidence.declared_isize,
        output,
    })
}

/// Decode the original domain and atomically append its verified private
/// output plus the registered RFC 1952 transformation record.
pub(crate) fn transform_single_member(
    snapshots: &mut SnapshotSet<'_>,
    transforms: &mut TransformGraph,
    limits: GzipLimits,
) -> Result<TransformedGzipMember, GzipError> {
    let original_len = snapshots.original().len();
    let decoded = decode_single_member(snapshots.original(), limits)?;
    let DecodedGzipMember {
        header,
        compressed_payload,
        trailer,
        declared_crc32,
        declared_isize,
        output,
    } = decoded;
    let output_len = output.len();
    let output_sha256 = output
        .digest()
        .sha256()
        .expect("private derived gzip output always has a SHA-256")
        .to_owned();
    let output_domain = snapshots
        .append_derived_snapshot(
            transforms,
            TransformProfile::GzipRfc1952SingleMemberV1,
            DomainRange::original(ByteRange {
                offset: 0,
                len: original_len,
            }),
            output,
        )
        .map_err(|finding| GzipError {
            kind: GzipErrorKind::TransformAuthority,
            finding,
        })?;
    Ok(TransformedGzipMember {
        header,
        compressed_payload,
        trailer,
        declared_crc32,
        declared_isize,
        output_domain,
        output_len,
        output_sha256,
    })
}

fn parse_header(
    source: &SourceSnapshot<'_>,
    max_header_bytes: u64,
    max_metadata_bytes: u64,
) -> Result<GzipHeader, GzipError> {
    parse_header_at(source, 0, max_header_bytes, max_metadata_bytes)
}

fn parse_header_at(
    source: &SourceSnapshot<'_>,
    member_offset: u64,
    max_header_bytes: u64,
    max_metadata_bytes: u64,
) -> Result<GzipHeader, GzipError> {
    if max_header_bytes < FIXED_HEADER_LEN {
        return Err(metadata_limit(max_metadata_bytes));
    }
    let header_limit = member_offset
        .checked_add(max_header_bytes)
        .ok_or_else(|| metadata_limit(max_metadata_bytes))?;
    let mut fixed = [0_u8; FIXED_HEADER_LEN as usize];
    read_exact(
        source,
        member_offset,
        &mut fixed,
        "gzip fixed header is truncated",
    )?;
    if fixed[..2] != [0x1f, 0x8b] {
        return Err(GzipError::new(
            GzipErrorKind::Magic,
            FindingCode::FormatMagic,
            "gzip magic is not 1f 8b",
        ));
    }
    if fixed[2] != 8 {
        return Err(GzipError::new(
            GzipErrorKind::CompressionMethod,
            FindingCode::FormatUnsupported,
            format!("gzip compression method {} is not Deflate (8)", fixed[2]),
        ));
    }
    let flags = fixed[3];
    if flags & FLAG_RESERVED != 0 {
        return Err(GzipError::new(
            GzipErrorKind::ReservedFlags,
            FindingCode::FormatUnsupported,
            format!("gzip FLG has reserved bits set: {flags:#04x}"),
        ));
    }

    let mut header_crc = Crc::new();
    header_crc.update(&fixed);
    let mut cursor = member_offset + FIXED_HEADER_LEN;

    let (extra, extra_subfield_count) = if flags & FLAG_EXTRA != 0 {
        let start = cursor;
        let mut xlen_bytes = [0_u8; 2];
        reserve_header(&mut cursor, 2, header_limit, max_metadata_bytes)?;
        read_exact(
            source,
            start,
            &mut xlen_bytes,
            "gzip FEXTRA length is truncated",
        )?;
        header_crc.update(&xlen_bytes);
        let xlen = u64::from(u16::from_le_bytes(xlen_bytes));
        reserve_header(&mut cursor, xlen, header_limit, max_metadata_bytes)?;
        let subfield_count = validate_extra_subfields(source, start + 2, xlen)?;
        hash_range(
            source,
            start + 2,
            xlen,
            &mut header_crc,
            "gzip FEXTRA payload is truncated",
        )?;
        (
            Some(ByteRange {
                offset: start,
                len: xlen + 2,
            }),
            subfield_count,
        )
    } else {
        (None, 0)
    };

    let original_name = if flags & FLAG_NAME != 0 {
        Some(read_c_string(
            source,
            &mut cursor,
            header_limit,
            max_metadata_bytes,
            &mut header_crc,
            "gzip FNAME is not NUL-terminated",
        )?)
    } else {
        None
    };

    let comment = if flags & FLAG_COMMENT != 0 {
        Some(read_c_string(
            source,
            &mut cursor,
            header_limit,
            max_metadata_bytes,
            &mut header_crc,
            "gzip FCOMMENT is not NUL-terminated",
        )?)
    } else {
        None
    };

    let header_crc16 = if flags & FLAG_HEADER_CRC != 0 {
        let start = cursor;
        reserve_header(&mut cursor, 2, header_limit, max_metadata_bytes)?;
        let mut expected = [0_u8; 2];
        read_exact(source, start, &mut expected, "gzip FHCRC is truncated")?;
        let expected = u16::from_le_bytes(expected);
        let actual = header_crc.finalize() as u16;
        if actual != expected {
            return Err(GzipError::new(
                GzipErrorKind::HeaderChecksum,
                FindingCode::CrcMismatch,
                format!("gzip FHCRC is {expected:04x}; computed {actual:04x}"),
            ));
        }
        Some(ByteRange {
            offset: start,
            len: 2,
        })
    } else {
        None
    };

    let modification_time = u32::from_le_bytes(fixed[4..8].try_into().unwrap());
    Ok(GzipHeader {
        flags,
        modification_time,
        extra_flags: fixed[8],
        operating_system: fixed[9],
        header: ByteRange {
            offset: member_offset,
            len: cursor - member_offset,
        },
        extra,
        extra_subfield_count,
        original_name,
        comment,
        header_crc16,
    })
}

fn validate_extra_subfields(
    source: &SourceSnapshot<'_>,
    offset: u64,
    len: u64,
) -> Result<u32, GzipError> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| malformed_extra("gzip FEXTRA range overflowed u64"))?;
    let mut cursor = offset;
    let mut count = 0_u32;
    let mut seen = [0_u64; 1024];
    while cursor < end {
        let remaining = end - cursor;
        if remaining < 4 {
            return Err(malformed_extra(format!(
                "gzip FEXTRA has {remaining} trailing byte(s) outside a complete subfield header"
            )));
        }
        let mut fixed = [0_u8; 4];
        read_exact(
            source,
            cursor,
            &mut fixed,
            "gzip FEXTRA subfield header is truncated",
        )?;
        if fixed[1] == 0 {
            return Err(malformed_extra(format!(
                "gzip FEXTRA subfield ID {:02x}00 uses reserved SI2 value zero",
                fixed[0]
            )));
        }
        let id = u16::from_le_bytes([fixed[0], fixed[1]]);
        let word = usize::from(id / 64);
        let bit = u32::from(id % 64);
        if seen[word] & (1_u64 << bit) != 0 {
            return Err(malformed_extra(format!(
                "gzip FEXTRA repeats subfield ID {:02x}{:02x}",
                fixed[0], fixed[1]
            )));
        }
        seen[word] |= 1_u64 << bit;
        let data_len = u64::from(u16::from_le_bytes([fixed[2], fixed[3]]));
        let subfield_end = cursor
            .checked_add(4)
            .and_then(|value| value.checked_add(data_len))
            .ok_or_else(|| malformed_extra("gzip FEXTRA subfield range overflowed u64"))?;
        if subfield_end > end {
            return Err(malformed_extra(format!(
                "gzip FEXTRA subfield {:02x}{:02x} declares {data_len} data byte(s) with only {} available",
                fixed[0],
                fixed[1],
                end - cursor - 4
            )));
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| malformed_extra("gzip FEXTRA subfield count overflowed u32"))?;
        cursor = subfield_end;
    }
    Ok(count)
}

fn malformed_extra(detail: impl Into<String>) -> GzipError {
    GzipError::new(GzipErrorKind::ExtraField, FindingCode::GzipExtra, detail)
}

fn reserve_header(
    cursor: &mut u64,
    len: u64,
    max_header_bytes: u64,
    max_metadata_bytes: u64,
) -> Result<(), GzipError> {
    let end = cursor.checked_add(len).ok_or_else(|| {
        GzipError::new(
            GzipErrorKind::HeaderLimit,
            FindingCode::QuotaMetadata,
            "gzip header length overflowed u64",
        )
    })?;
    if end > max_header_bytes {
        return Err(metadata_limit(max_metadata_bytes));
    }
    *cursor = end;
    Ok(())
}

fn metadata_limit(max_metadata_bytes: u64) -> GzipError {
    GzipError::new(
        GzipErrorKind::HeaderLimit,
        FindingCode::QuotaMetadata,
        format!("gzip wrapper metadata exceeds the {max_metadata_bytes}-byte cap"),
    )
}

fn read_exact(
    source: &SourceSnapshot<'_>,
    offset: u64,
    output: &mut [u8],
    truncated_detail: &'static str,
) -> Result<(), GzipError> {
    let len = u64::try_from(output.len())
        .map_err(|_| GzipError::truncated("gzip read length does not fit u64"))?;
    let end = offset
        .checked_add(len)
        .ok_or_else(|| GzipError::truncated(truncated_detail))?;
    if end > source.len() {
        return Err(GzipError::truncated(truncated_detail));
    }
    source
        .read_exact_at(offset, output)
        .map_err(GzipError::source)
}

fn hash_range(
    source: &SourceSnapshot<'_>,
    mut offset: u64,
    mut len: u64,
    crc: &mut Crc,
    truncated_detail: &'static str,
) -> Result<(), GzipError> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| GzipError::truncated(truncated_detail))?;
    if end > source.len() {
        return Err(GzipError::truncated(truncated_detail));
    }
    let mut buffer = [0_u8; 4096];
    while len != 0 {
        let count = usize::try_from(len.min(buffer.len() as u64)).unwrap();
        read_exact(source, offset, &mut buffer[..count], truncated_detail)?;
        crc.update(&buffer[..count]);
        offset += count as u64;
        len -= count as u64;
    }
    Ok(())
}

fn read_c_string(
    source: &SourceSnapshot<'_>,
    cursor: &mut u64,
    max_header_bytes: u64,
    max_metadata_bytes: u64,
    crc: &mut Crc,
    truncated_detail: &'static str,
) -> Result<ByteRange, GzipError> {
    let start = *cursor;
    let mut buffer = [0_u8; 4096];
    loop {
        if *cursor == max_header_bytes {
            return Err(metadata_limit(max_metadata_bytes));
        }
        if *cursor == source.len() {
            return Err(GzipError::truncated(truncated_detail));
        }
        let allowed = max_header_bytes - *cursor;
        let available = source.len() - *cursor;
        let count = usize::try_from(allowed.min(available).min(buffer.len() as u64)).unwrap();
        read_exact(source, *cursor, &mut buffer[..count], truncated_detail)?;
        if let Some(index) = buffer[..count].iter().position(|byte| *byte == 0) {
            let used = index + 1;
            crc.update(&buffer[..used]);
            *cursor += used as u64;
            return Ok(ByteRange {
                offset: start,
                len: *cursor - start,
            });
        }
        crc.update(&buffer[..count]);
        *cursor += count as u64;
    }
}

struct VerifiedDeflateReader<'s, 'a> {
    decoder: DeflateDecoder<BufReader<SnapshotRangeReader<'s, 'a>>>,
    source: &'s SourceSnapshot<'a>,
    payload_offset: u64,
    crc32: Crc,
    output_len: u64,
    terminal: bool,
    completion: Completion,
}

impl Read for VerifiedDeflateReader<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.terminal || output.is_empty() {
            return Ok(0);
        }
        match self.decoder.read(output) {
            Ok(0) => {
                self.terminal = true;
                let evidence = self.finish_member();
                *self.completion.borrow_mut() = Some(evidence.clone());
                match evidence {
                    Ok(_) => Ok(0),
                    Err(error) => Err(as_io_error(error.into_finding())),
                }
            }
            Ok(read) => {
                self.output_len = match self.output_len.checked_add(read as u64) {
                    Some(len) => len,
                    None => {
                        let error = GzipError::new(
                            GzipErrorKind::OutputLimit,
                            FindingCode::QuotaDerived,
                            "gzip output length overflowed u64",
                        );
                        self.terminal = true;
                        *self.completion.borrow_mut() = Some(Err(error.clone()));
                        return Err(as_io_error(error.into_finding()));
                    }
                };
                self.crc32.update(&output[..read]);
                Ok(read)
            }
            Err(error) => {
                self.terminal = true;
                let gzip_error = if let Some(finding) = finding_from_io(&error) {
                    GzipError::source(finding)
                } else {
                    GzipError::deflate(format!("invalid gzip Deflate stream: {error}"))
                };
                *self.completion.borrow_mut() = Some(Err(gzip_error.clone()));
                Err(as_io_error(gzip_error.into_finding()))
            }
        }
    }
}

impl VerifiedDeflateReader<'_, '_> {
    fn finish_member(&self) -> Result<TrailerEvidence, GzipError> {
        if self.decoder.total_out() != self.output_len {
            return Err(GzipError::new(
                GzipErrorKind::DeflateAccounting,
                FindingCode::CodecDeflateInvalidStream,
                format!(
                    "Deflate reported {} output bytes; observed {}",
                    self.decoder.total_out(),
                    self.output_len
                ),
            ));
        }
        let compressed_len = self.decoder.total_in();
        let trailer_offset = self
            .payload_offset
            .checked_add(compressed_len)
            .ok_or_else(|| GzipError::truncated("gzip trailer offset overflowed u64"))?;
        let trailer_end = trailer_offset
            .checked_add(TRAILER_LEN)
            .ok_or_else(|| GzipError::truncated("gzip trailer end overflowed u64"))?;
        if trailer_end > self.source.len() {
            return Err(GzipError::truncated("gzip trailer is truncated"));
        }

        let mut trailer = [0_u8; TRAILER_LEN as usize];
        read_exact(
            self.source,
            trailer_offset,
            &mut trailer,
            "gzip trailer is truncated",
        )?;
        let declared_crc32 = u32::from_le_bytes(trailer[..4].try_into().unwrap());
        let declared_isize = u32::from_le_bytes(trailer[4..].try_into().unwrap());
        let actual_crc32 = self.crc32.clone().finalize();
        if declared_crc32 != actual_crc32 {
            return Err(GzipError::new(
                GzipErrorKind::DataChecksum,
                FindingCode::CrcMismatch,
                format!("gzip CRC32 is {declared_crc32:08x}; computed {actual_crc32:08x}"),
            ));
        }
        let output_isize = gzip_isize(self.output_len);
        if declared_isize != output_isize {
            return Err(GzipError::new(
                GzipErrorKind::DeclaredSize,
                FindingCode::QuotaDeclaredLie,
                format!(
                    "gzip ISIZE is {declared_isize}; decoded size modulo 2^32 is {}",
                    output_isize
                ),
            ));
        }
        Ok(TrailerEvidence {
            compressed_payload: ByteRange {
                offset: self.payload_offset,
                len: compressed_len,
            },
            trailer: ByteRange {
                offset: trailer_offset,
                len: TRAILER_LEN,
            },
            declared_crc32,
            declared_isize,
        })
    }
}

fn scan_trailing_members(
    source: &SourceSnapshot<'_>,
    mut member_offset: u64,
    limits: GzipLimits,
    mut metadata_bytes: u64,
    mut output_bytes: u64,
) -> Result<(), GzipError> {
    let _scan = ConcatScanGuard::enter();
    let trailing_len = source.len() - member_offset;
    while member_offset != source.len() {
        let member_start = member_offset;
        if source.len() - member_offset < 2 {
            return Err(trailing_input(trailing_len));
        }
        let mut magic = [0_u8; 2];
        read_exact(
            source,
            member_offset,
            &mut magic,
            "gzip trailing input is truncated",
        )?;
        if magic != [0x1f, 0x8b] {
            return Err(trailing_input(trailing_len));
        }

        let remaining_metadata = limits
            .max_metadata_bytes
            .checked_sub(metadata_bytes)
            .ok_or_else(|| metadata_limit(limits.max_metadata_bytes))?;
        let max_header_bytes = remaining_metadata
            .checked_sub(TRAILER_LEN)
            .ok_or_else(|| metadata_limit(limits.max_metadata_bytes))?;
        let header = match parse_header_at(
            source,
            member_offset,
            max_header_bytes,
            limits.max_metadata_bytes,
        ) {
            Ok(header) => header,
            Err(error)
                if matches!(
                    error.kind,
                    GzipErrorKind::Source | GzipErrorKind::HeaderLimit
                ) =>
            {
                return Err(error);
            }
            Err(_) => return Err(trailing_input(trailing_len)),
        };
        metadata_bytes = metadata_bytes
            .checked_add(header.header.len)
            .and_then(|value| value.checked_add(TRAILER_LEN))
            .ok_or_else(|| metadata_limit(limits.max_metadata_bytes))?;

        let payload_offset = header.header.end();
        let input_len = source
            .len()
            .checked_sub(payload_offset)
            .ok_or_else(|| GzipError::truncated("gzip trailing member header exceeds source"))?;
        if input_len < TRAILER_LEN {
            return Err(trailing_input(trailing_len));
        }
        let input = source
            .reader(payload_offset, input_len)
            .map_err(GzipError::source)?;
        let mut decoder = DeflateDecoder::new(BufReader::with_capacity(4096, input));
        let mut crc32 = Crc::new();
        let mut member_output = 0_u64;
        let mut buffer = [0_u8; 32 * 1024];
        loop {
            let read = match decoder.read(&mut buffer) {
                Ok(read) => read,
                Err(error) => {
                    if let Some(finding) = finding_from_io(&error) {
                        return Err(GzipError::source(finding));
                    }
                    return Err(trailing_input(trailing_len));
                }
            };
            if read == 0 {
                break;
            }
            member_output = member_output.checked_add(read as u64).ok_or_else(|| {
                GzipError::new(
                    GzipErrorKind::OutputLimit,
                    FindingCode::QuotaDerived,
                    "gzip concatenation recognition output length overflowed u64",
                )
            })?;
            let aggregate_output = output_bytes.checked_add(member_output).ok_or_else(|| {
                GzipError::new(
                    GzipErrorKind::OutputLimit,
                    FindingCode::QuotaDerived,
                    "gzip concatenation recognition output length overflowed u64",
                )
            })?;
            if aggregate_output > limits.max_output_bytes {
                return Err(GzipError::new(
                    GzipErrorKind::OutputLimit,
                    FindingCode::QuotaDerived,
                    format!(
                        "gzip concatenation recognition output exceeds the {}-byte cap",
                        limits.max_output_bytes
                    ),
                ));
            }
            crc32.update(&buffer[..read]);
        }

        let trailer_offset = payload_offset
            .checked_add(decoder.total_in())
            .ok_or_else(|| trailing_input(trailing_len))?;
        let trailer_end = trailer_offset
            .checked_add(TRAILER_LEN)
            .ok_or_else(|| trailing_input(trailing_len))?;
        if trailer_end > source.len() {
            return Err(trailing_input(trailing_len));
        }
        let mut trailer = [0_u8; TRAILER_LEN as usize];
        read_exact(
            source,
            trailer_offset,
            &mut trailer,
            "gzip trailing member trailer is truncated",
        )?;
        let declared_crc32 = u32::from_le_bytes(trailer[..4].try_into().unwrap());
        let declared_isize = u32::from_le_bytes(trailer[4..].try_into().unwrap());
        if declared_crc32 != crc32.finalize() || declared_isize != gzip_isize(member_output) {
            return Err(trailing_input(trailing_len));
        }

        output_bytes = output_bytes
            .checked_add(member_output)
            .ok_or_else(|| trailing_input(trailing_len))?;
        ConcatScanGuard::record_member(trailer_end - member_start, member_output);
        member_offset = trailer_end;
    }
    Ok(())
}

fn trailing_input(trailing_len: u64) -> GzipError {
    GzipError::new(
        GzipErrorKind::TrailingInput,
        FindingCode::CodecDeflateTrailingInput,
        format!("gzip member has {trailing_len} trailing byte(s)"),
    )
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ConcatScanStats {
    members: u64,
    source_bytes: u64,
    output_bytes: u64,
    active_depth: u64,
    max_depth: u64,
}

#[cfg(test)]
thread_local! {
    static CONCAT_SCAN_STATS: RefCell<ConcatScanStats> = RefCell::new(ConcatScanStats::default());
}

struct ConcatScanGuard;

impl ConcatScanGuard {
    fn enter() -> Self {
        #[cfg(test)]
        CONCAT_SCAN_STATS.with(|stats| {
            let mut stats = stats.borrow_mut();
            stats.active_depth += 1;
            stats.max_depth = stats.max_depth.max(stats.active_depth);
        });
        Self
    }

    fn record_member(source_bytes: u64, output_bytes: u64) {
        #[cfg(not(test))]
        let _ = (source_bytes, output_bytes);
        #[cfg(test)]
        CONCAT_SCAN_STATS.with(|stats| {
            let mut stats = stats.borrow_mut();
            stats.members += 1;
            stats.source_bytes += source_bytes;
            stats.output_bytes += output_bytes;
        });
    }
}

impl Drop for ConcatScanGuard {
    fn drop(&mut self) {
        #[cfg(test)]
        CONCAT_SCAN_STATS.with(|stats| stats.borrow_mut().active_depth -= 1);
    }
}

#[cfg(test)]
fn reset_concat_scan_stats() {
    CONCAT_SCAN_STATS.with(|stats| *stats.borrow_mut() = ConcatScanStats::default());
}

#[cfg(test)]
fn concat_scan_stats() -> ConcatScanStats {
    CONCAT_SCAN_STATS.with(|stats| *stats.borrow())
}

fn gzip_isize(len: u64) -> u32 {
    u32::try_from(len % (u64::from(u32::MAX) + 1)).expect("gzip ISIZE modulo always fits u32")
}

#[cfg(feature = "__internal-fuzzing")]
#[derive(Debug, PartialEq, Eq)]
enum FuzzClassification {
    Accepted {
        header: GzipHeader,
        compressed_payload: ByteRange,
        trailer: ByteRange,
        declared_crc32: u32,
        declared_isize: u32,
        output_len: u64,
        output_sha256: String,
    },
    Rejected {
        kind: GzipErrorKind,
        code: FindingCode,
    },
}

#[cfg(feature = "__internal-fuzzing")]
const FUZZ_LIMITS: GzipLimits = GzipLimits {
    max_metadata_bytes: 4 * 1024,
    max_output_bytes: 64 * 1024,
};

#[cfg(feature = "__internal-fuzzing")]
pub(crate) fn exercise_fuzz_input(input: &[u8]) {
    const MAX_FUZZ_INPUT_BYTES: usize = 1024 * 1024;
    if input.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    let first = classify_fuzz_input(input);
    let second = classify_fuzz_input(input);
    assert_eq!(first, second);

    let FuzzClassification::Accepted {
        header,
        compressed_payload,
        trailer,
        declared_crc32,
        declared_isize,
        output_len,
        output_sha256,
    } = first
    else {
        return;
    };

    let source_len = u64::try_from(input.len()).unwrap();
    assert_eq!(header.header.offset, 0);
    assert_eq!(compressed_payload.offset, header.header.end());
    assert_eq!(trailer.offset, compressed_payload.end());
    assert_eq!(trailer.len, TRAILER_LEN);
    assert_eq!(trailer.end(), source_len);
    assert!(header.header.len + trailer.len <= FUZZ_LIMITS.max_metadata_bytes);
    assert!(output_len <= FUZZ_LIMITS.max_output_bytes);

    let mut header_cursor = FIXED_HEADER_LEN;
    for optional in [
        header.extra,
        header.original_name,
        header.comment,
        header.header_crc16,
    ]
    .into_iter()
    .flatten()
    {
        assert_eq!(optional.offset, header_cursor);
        header_cursor = optional.end();
    }
    assert_eq!(header_cursor, header.header.end());
    assert_eq!(header.extra.is_some(), header.flags & FLAG_EXTRA != 0);
    assert_eq!(
        header.original_name.is_some(),
        header.flags & FLAG_NAME != 0
    );
    assert_eq!(header.comment.is_some(), header.flags & FLAG_COMMENT != 0);
    assert_eq!(
        header.header_crc16.is_some(),
        header.flags & FLAG_HEADER_CRC != 0
    );
    assert_eq!(header.flags & FLAG_RESERVED, 0);

    let mut snapshots = SnapshotSet::from_original(SourceSnapshot::borrowed(None, input));
    let mut transforms = TransformGraph::empty();
    let transformed =
        transform_single_member(&mut snapshots, &mut transforms, FUZZ_LIMITS).unwrap();
    assert_eq!(snapshots.len(), 2);
    assert!(transforms.validates(&snapshots));
    assert_eq!(transforms.records().len(), 1);
    assert_eq!(transformed.header, header);
    assert_eq!(transformed.compressed_payload, compressed_payload);
    assert_eq!(transformed.trailer, trailer);
    assert_eq!(transformed.declared_crc32, declared_crc32);
    assert_eq!(transformed.declared_isize, declared_isize);

    let record = &transforms.records()[0];
    assert_eq!(record.profile, TransformProfile::GzipRfc1952SingleMemberV1);
    assert_eq!(
        record.input,
        DomainRange::original(ByteRange {
            offset: 0,
            len: source_len,
        })
    );
    assert_eq!(record.output_domain, transformed.output_domain);
    assert_eq!(record.output_len, output_len);
    assert_eq!(record.output_sha256, output_sha256);
    let retained = snapshots.domain(transformed.output_domain).unwrap();
    assert_eq!(retained.len(), output_len);
    assert_eq!(retained.digest().sha256(), Some(output_sha256.as_str()));
}

#[cfg(feature = "__internal-fuzzing")]
fn classify_fuzz_input(input: &[u8]) -> FuzzClassification {
    match decode_single_member(&SourceSnapshot::borrowed(None, input), FUZZ_LIMITS) {
        Ok(decoded) => FuzzClassification::Accepted {
            header: decoded.header,
            compressed_payload: decoded.compressed_payload,
            trailer: decoded.trailer,
            declared_crc32: decoded.declared_crc32,
            declared_isize: decoded.declared_isize,
            output_len: decoded.output.len(),
            output_sha256: decoded.output.digest().sha256().unwrap().to_owned(),
        },
        Err(error) => FuzzClassification::Rejected {
            kind: error.kind,
            code: error.finding().code,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::write::DeflateEncoder;
    use flate2::Compression;

    use super::*;
    use crate::snapshot::SnapshotKind;

    const LARGE_LIMITS: GzipLimits = GzipLimits {
        max_metadata_bytes: 1 << 20,
        max_output_bytes: 1 << 20,
    };

    fn fixture(flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x1f, 0x8b, 8, flags, 0x78, 0x56, 0x34, 0x12, 0, 255];
        if flags & FLAG_EXTRA != 0 {
            bytes.extend_from_slice(&7_u16.to_le_bytes());
            bytes.extend_from_slice(b"SL");
            bytes.extend_from_slice(&3_u16.to_le_bytes());
            bytes.extend_from_slice(b"xyz");
        }
        if flags & FLAG_NAME != 0 {
            bytes.extend_from_slice(b"archive.tar\0");
        }
        if flags & FLAG_COMMENT != 0 {
            bytes.extend_from_slice(b"sealr fixture\0");
        }
        if flags & FLAG_HEADER_CRC != 0 {
            let mut crc = Crc::new();
            crc.update(&bytes);
            bytes.extend_from_slice(&(crc.finalize() as u16).to_le_bytes());
        }
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        bytes.extend_from_slice(&encoder.finish().unwrap());
        let mut crc = Crc::new();
        crc.update(payload);
        bytes.extend_from_slice(&crc.finalize().to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes
    }

    fn fixture_with_extra(extra: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut bytes = fixture(0, payload);
        bytes[3] = FLAG_EXTRA;
        let mut field = Vec::with_capacity(2 + extra.len());
        field.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        field.extend_from_slice(extra);
        bytes.splice(FIXED_HEADER_LEN as usize..FIXED_HEADER_LEN as usize, field);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<DecodedGzipMember, GzipError> {
        decode_single_member(&SourceSnapshot::borrowed(None, bytes), LARGE_LIMITS)
    }

    #[test]
    fn an_unterminated_deflate_block_cannot_borrow_the_gzip_trailer() {
        let mut bytes = fixture(0, b"LATIN = 1\n");
        assert_ne!(bytes[10] & 1, 0, "fixture must begin with a final block");
        bytes[10] &= !1;
        assert!(decode(&bytes).is_err());
        for removed in 1..=8 {
            assert!(decode(&bytes[..bytes.len() - removed]).is_err());
        }
    }

    #[test]
    fn valid_optional_fields_are_exact_and_output_is_private() {
        let payload = b"ustar payload bytes";
        let bytes = fixture(
            FLAG_TEXT | FLAG_EXTRA | FLAG_NAME | FLAG_COMMENT | FLAG_HEADER_CRC,
            payload,
        );
        let decoded = decode(&bytes).unwrap();

        assert_eq!(decoded.header.flags, 0x1f);
        assert_eq!(decoded.header.modification_time, 0x1234_5678);
        assert_eq!(decoded.header.extra_flags, 0);
        assert_eq!(decoded.header.operating_system, 255);
        assert_eq!(decoded.header.extra, Some(ByteRange { offset: 10, len: 9 }));
        assert_eq!(decoded.header.extra_subfield_count, 1);
        assert_eq!(
            decoded.header.original_name,
            Some(ByteRange {
                offset: 19,
                len: 12
            })
        );
        assert_eq!(
            decoded.header.comment,
            Some(ByteRange {
                offset: 31,
                len: 14
            })
        );
        assert_eq!(
            decoded.header.header_crc16,
            Some(ByteRange { offset: 45, len: 2 })
        );
        assert_eq!(decoded.header.header, ByteRange { offset: 0, len: 47 });
        assert_eq!(decoded.compressed_payload.offset, 47);
        assert_eq!(decoded.trailer.len, 8);
        assert_eq!(
            decoded.trailer.offset,
            decoded.compressed_payload.offset + decoded.compressed_payload.len
        );
        assert_eq!(decoded.declared_isize, payload.len() as u32);
        let mut crc = Crc::new();
        crc.update(payload);
        assert_eq!(decoded.declared_crc32, crc.finalize());
        assert_eq!(decoded.output.kind(), SnapshotKind::PrivateFile);
        assert_eq!(
            decoded.output.read_vec(0, decoded.output.len()).unwrap(),
            payload
        );
    }

    #[test]
    fn fextra_is_an_exact_sequence_of_rfc_1952_subfields() {
        let valid = fixture_with_extra(b"SL\x03\x00xyzAB\x00\x00", b"payload");
        let decoded = decode(&valid).unwrap();
        assert_eq!(decoded.header.extra_subfield_count, 2);

        let empty = fixture_with_extra(b"", b"payload");
        assert_eq!(decode(&empty).unwrap().header.extra_subfield_count, 0);

        for (label, extra) in [
            ("truncated fixed header", b"SL\x00".as_slice()),
            ("declared data overrun", b"SL\x04\x00x".as_slice()),
            ("trailing remainder", b"SL\x00\x00x".as_slice()),
            ("reserved SI2", b"S\x00\x00\x00".as_slice()),
            ("duplicate ID", b"SL\x00\x00SL\x00\x00".as_slice()),
        ] {
            let error = decode(&fixture_with_extra(extra, b"payload")).unwrap_err();
            assert_eq!(error.kind, GzipErrorKind::ExtraField, "{label}");
            assert_eq!(error.finding().code, FindingCode::GzipExtra, "{label}");
        }
    }

    #[test]
    fn verified_member_becomes_one_identity_bound_derived_domain() {
        let payload = b"portable ustar bytes";
        let bytes = fixture(FLAG_HEADER_CRC, payload);
        let source_len = bytes.len() as u64;
        let mut snapshots = SnapshotSet::from_original(SourceSnapshot::borrowed(
            Some("input.tar.gz".into()),
            &bytes,
        ));
        let mut transforms = TransformGraph::empty();

        let transformed =
            transform_single_member(&mut snapshots, &mut transforms, LARGE_LIMITS).unwrap();

        assert_ne!(transformed.output_domain, SnapshotDomainId::ORIGINAL);
        assert_eq!(snapshots.len(), 2);
        assert!(transforms.validates(&snapshots));
        assert_eq!(transforms.records().len(), 1);
        let record = &transforms.records()[0];
        assert_eq!(record.profile, TransformProfile::GzipRfc1952SingleMemberV1);
        assert_eq!(
            record.input,
            DomainRange::original(ByteRange {
                offset: 0,
                len: source_len
            })
        );
        assert_eq!(record.output_domain, transformed.output_domain);
        assert_eq!(record.output_len, payload.len() as u64);
        assert_eq!(
            snapshots
                .domain(transformed.output_domain)
                .unwrap()
                .read_vec(0, payload.len() as u64)
                .unwrap(),
            payload
        );
    }

    #[test]
    fn every_flg_byte_has_an_explicit_reserved_bit_result() {
        for flags in u8::MIN..=u8::MAX {
            let result = decode(&fixture(flags, b"flags"));
            if flags & FLAG_RESERVED == 0 {
                assert!(result.is_ok(), "FLG {flags:#04x}: {result:?}");
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.kind, GzipErrorKind::ReservedFlags, "FLG {flags:#04x}");
                assert_eq!(error.finding().code, FindingCode::FormatUnsupported);
            }
        }
    }

    #[test]
    fn every_proper_prefix_of_a_valid_member_is_rejected() {
        let bytes = fixture(
            FLAG_EXTRA | FLAG_NAME | FLAG_COMMENT | FLAG_HEADER_CRC,
            b"payload",
        );
        for len in 0..bytes.len() {
            assert!(
                decode(&bytes[..len]).is_err(),
                "accepted truncated prefix of length {len}"
            );
        }
        assert!(decode(&bytes).is_ok());
    }

    #[test]
    fn aggregate_wrapper_metadata_cap_includes_header_and_trailer() {
        let bytes = fixture(
            FLAG_EXTRA | FLAG_NAME | FLAG_COMMENT | FLAG_HEADER_CRC,
            b"payload",
        );
        let header_len = 47;
        let metadata_len = header_len + TRAILER_LEN;
        let exact = decode_single_member(
            &SourceSnapshot::borrowed(None, &bytes),
            GzipLimits {
                max_metadata_bytes: metadata_len,
                max_output_bytes: 1024,
            },
        )
        .unwrap();
        assert_eq!(exact.header.header.len, header_len);

        for cap in 0..metadata_len {
            let error = decode_single_member(
                &SourceSnapshot::borrowed(None, &bytes),
                GzipLimits {
                    max_metadata_bytes: cap,
                    max_output_bytes: 1024,
                },
            )
            .unwrap_err();
            assert_eq!(error.kind, GzipErrorKind::HeaderLimit, "cap {cap}");
            assert_eq!(error.finding().code, FindingCode::QuotaMetadata);
        }
    }

    #[test]
    fn header_crc_uses_the_low_sixteen_bits_of_crc32() {
        let mut bytes = fixture(FLAG_HEADER_CRC, b"payload");
        bytes[10] ^= 1;
        let error = decode(&bytes).unwrap_err();
        assert_eq!(error.kind, GzipErrorKind::HeaderChecksum);
        assert_eq!(error.finding().code, FindingCode::CrcMismatch);
    }

    #[test]
    fn trailer_crc_and_isize_are_verified_independently() {
        let mut bad_crc = fixture(0, b"payload");
        let trailer = bad_crc.len() - TRAILER_LEN as usize;
        bad_crc[trailer] ^= 1;
        let error = decode(&bad_crc).unwrap_err();
        assert_eq!(error.kind, GzipErrorKind::DataChecksum);
        assert_eq!(error.finding().code, FindingCode::CrcMismatch);

        let mut bad_size = fixture(0, b"payload");
        let trailer = bad_size.len() - TRAILER_LEN as usize;
        bad_size[trailer + 4] ^= 1;
        let error = decode(&bad_size).unwrap_err();
        assert_eq!(error.kind, GzipErrorKind::DeclaredSize);
        assert_eq!(error.finding().code, FindingCode::QuotaDeclaredLie);
    }

    #[test]
    fn malformed_deflate_is_not_reported_as_source_io() {
        let mut bytes = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        bytes.extend_from_slice(&[0x07, 0, 0, 0]);
        bytes.extend_from_slice(&[0; TRAILER_LEN as usize]);
        let error = decode(&bytes).unwrap_err();
        assert_eq!(error.kind, GzipErrorKind::DeflateStream);
        assert_eq!(error.finding().code, FindingCode::CodecDeflateInvalidStream);
    }

    #[test]
    fn concatenation_trailing_bytes_and_zero_padding_are_rejected() {
        let member = fixture(0, b"payload");
        let mut concatenated = member.clone();
        concatenated.extend_from_slice(&fixture(0, b"second"));
        let error = decode(&concatenated).unwrap_err();
        assert_eq!(error.kind, GzipErrorKind::ConcatenatedMember);
        assert_eq!(error.finding().code, FindingCode::CodecDeflateTrailingInput);

        let mut trailing = member.clone();
        trailing.push(0x7f);
        assert_eq!(
            decode(&trailing).unwrap_err().kind,
            GzipErrorKind::TrailingInput
        );

        let mut gzip_prefix = member.clone();
        gzip_prefix.extend_from_slice(&[0x1f, 0x8b]);
        assert_eq!(
            decode(&gzip_prefix).unwrap_err().kind,
            GzipErrorKind::TrailingInput
        );

        let mut invalid_second_header = member.clone();
        invalid_second_header.extend_from_slice(&[0x1f, 0x8b, 0, 0, 0, 0, 0, 0, 0, 255]);
        assert_eq!(
            decode(&invalid_second_header).unwrap_err().kind,
            GzipErrorKind::TrailingInput
        );

        let mut invalid_second_trailer = member.clone();
        let mut second = fixture(0, b"second");
        let second_trailer = second.len() - TRAILER_LEN as usize;
        second[second_trailer] ^= 1;
        invalid_second_trailer.extend_from_slice(&second);
        assert_eq!(
            decode(&invalid_second_trailer).unwrap_err().kind,
            GzipErrorKind::TrailingInput
        );

        let mut padded = member;
        padded.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            decode(&padded).unwrap_err().kind,
            GzipErrorKind::TrailingInput
        );
    }

    #[test]
    fn concatenation_recognition_is_iterative_and_linear() {
        for count in [2_usize, 3, 128] {
            let members: Vec<_> = (0..count)
                .map(|index| fixture(0, format!("member-{index}").as_bytes()))
                .collect();
            let source: Vec<_> = members.iter().flatten().copied().collect();
            let expected_source_bytes: u64 =
                members[1..].iter().map(|member| member.len() as u64).sum();
            let expected_output_bytes: u64 = (1..count)
                .map(|index| format!("member-{index}").len() as u64)
                .sum();

            reset_concat_scan_stats();
            let error = decode(&source).unwrap_err();
            assert_eq!(error.kind, GzipErrorKind::ConcatenatedMember);
            let stats = concat_scan_stats();
            assert_eq!(stats.members, (count - 1) as u64);
            assert_eq!(stats.source_bytes, expected_source_bytes);
            assert_eq!(stats.output_bytes, expected_output_bytes);
            assert_eq!(stats.active_depth, 0);
            assert_eq!(stats.max_depth, 1);
        }
    }

    #[test]
    fn output_cap_is_enforced_during_streaming_derivation() {
        let bytes = fixture(0, b"one byte too many");
        let error = decode_single_member(
            &SourceSnapshot::borrowed(None, &bytes),
            GzipLimits {
                max_metadata_bytes: FIXED_HEADER_LEN + TRAILER_LEN,
                max_output_bytes: 16,
            },
        )
        .unwrap_err();
        assert_eq!(error.kind, GzipErrorKind::OutputLimit);
        assert_eq!(error.finding().code, FindingCode::QuotaDerived);
    }

    #[test]
    fn fixed_header_fields_are_classified_before_decode() {
        let mut bad_magic = fixture(0, b"payload");
        bad_magic[0] = 0;
        assert_eq!(decode(&bad_magic).unwrap_err().kind, GzipErrorKind::Magic);

        let mut bad_method = fixture(0, b"payload");
        bad_method[2] = 0;
        assert_eq!(
            decode(&bad_method).unwrap_err().kind,
            GzipErrorKind::CompressionMethod
        );
    }
}
