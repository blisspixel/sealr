//! Strict, bounded XZ single-stream decoding.
//!
//! This module is deliberately crate-private until the wrapper profile and its
//! transformation identity are part of the public admission contract.
//!
//! The `lzma-rust2` decoder parses the XZ container itself, so Sealr keeps its
//! own byte-exact container parse as the structural authority: the decoder
//! establishes bounded decode and the exact consumed length, and Sealr then
//! replays the complete stream grammar — header, every block header, index,
//! and footer, including the spec obligations the decoder does not enforce
//! (footer backward size, declared block sizes, reserved block-flag bits) —
//! and cross-checks the two interpretations. Any disagreement fails closed.

use std::cell::RefCell;
use std::io::{self, Read};
use std::rc::Rc;

use lzma_rust2::{Action, Status, XzStream};
use sha2::{Digest, Sha256};

use crate::findings::{Finding, FindingCode};
use crate::ir::ByteRange;
use crate::snapshot::{
    as_io_error, finding_from_io, DomainRange, SnapshotDomainId, SnapshotRangeReader, SnapshotSet,
    SourceSnapshot, TransformGraph, TransformProfile,
};

pub(crate) const STREAM_HEADER_LEN: u64 = 12;
pub(crate) const STREAM_FOOTER_LEN: u64 = 12;
const HEADER_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];
const FOOTER_MAGIC: [u8; 2] = *b"YZ";
const LZMA2_FILTER_ID: u64 = 0x21;
/// The zstd-precedent dictionary ceiling: the `xz -6` / Python / dpkg default.
pub(crate) const MAX_DICT_BYTES: u32 = 8 * 1024 * 1024;
/// Bounded multi-block: stock `xz` splits at three dictionaries per block, so
/// this comfortably covers every admissible producer shape under the source cap.
pub(crate) const MAX_BLOCKS: u64 = 4096;
/// Decoder memory authority: the dictionary ceiling plus the decoder's fixed
/// per-stream overhead, in KiB.
const DECODER_MEM_LIMIT_KB: u32 = (MAX_DICT_BYTES / 1024) + 64;
const DECODE_STEP_BYTES: usize = 64 * 1024;

const CHECK_NONE: u8 = 0x00;
const CHECK_CRC32: u8 = 0x01;
const CHECK_CRC64: u8 = 0x04;
const CHECK_SHA256: u8 = 0x0A;

/// Resource limits for the private XZ transformation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct XzLimits {
    /// Maximum wrapper metadata bytes: stream header and footer, index, block
    /// headers, block padding, and block check fields. Compressed block bodies
    /// are payload, not metadata.
    pub(crate) max_metadata_bytes: u64,
    /// Maximum number of decoded bytes copied to the private snapshot.
    pub(crate) max_output_bytes: u64,
}

/// Exact evidence for one block of the restricted stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct XzBlockFrame {
    pub(crate) header: ByteRange,
    pub(crate) compressed: ByteRange,
    pub(crate) padding: ByteRange,
    pub(crate) check: ByteRange,
    pub(crate) dict_size: u32,
    pub(crate) declared_compressed: Option<u64>,
    pub(crate) declared_uncompressed: Option<u64>,
    pub(crate) uncompressed_len: u64,
    pub(crate) check_value: Vec<u8>,
}

/// A fully verified single XZ stream and its bounded private output.
#[derive(Debug)]
pub(crate) struct DecodedXzStream {
    pub(crate) check_id: u8,
    pub(crate) header: ByteRange,
    pub(crate) blocks: Vec<XzBlockFrame>,
    pub(crate) index: ByteRange,
    pub(crate) footer: ByteRange,
    pub(crate) output: SourceSnapshot<'static>,
}

/// Verified wrapper evidence after the output has become a retained snapshot
/// domain and the transformation graph has bound both byte identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransformedXzStream {
    pub(crate) check_id: u8,
    pub(crate) header: ByteRange,
    pub(crate) blocks: Vec<XzBlockFrame>,
    pub(crate) index: ByteRange,
    pub(crate) footer: ByteRange,
    pub(crate) output_domain: SnapshotDomainId,
    pub(crate) output_len: u64,
    pub(crate) output_sha256: String,
}

/// Internal failure classes kept distinct before they are mapped to the
/// repository's stable finding vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum XzErrorKind {
    Source,
    Truncated,
    Magic,
    CheckUnsupported,
    FilterUnsupported,
    DictBounds,
    BlockBounds,
    EmptyStream,
    HeaderLimit,
    StreamStructure,
    ConcatenatedStream,
    TrailingInput,
    CheckMismatch,
    DeclaredSize,
    OutputLimit,
    DecoderDisagreement,
    TransformAuthority,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct XzError {
    pub(crate) kind: XzErrorKind,
    finding: Finding,
}

impl XzError {
    pub(crate) fn finding(&self) -> &Finding {
        &self.finding
    }

    pub(crate) fn into_finding(self) -> Finding {
        self.finding
    }

    fn new(kind: XzErrorKind, code: FindingCode, detail: impl Into<String>) -> Self {
        Self {
            kind,
            finding: Finding::error(code, detail),
        }
    }

    fn source(finding: Finding) -> Self {
        Self {
            kind: XzErrorKind::Source,
            finding,
        }
    }

    fn truncated(detail: impl Into<String>) -> Self {
        Self::new(
            XzErrorKind::Truncated,
            FindingCode::CodecXzInvalidStream,
            detail,
        )
    }

    fn structure(detail: impl Into<String>) -> Self {
        Self::new(
            XzErrorKind::StreamStructure,
            FindingCode::CodecXzInvalidStream,
            detail,
        )
    }

    fn unsupported(kind: XzErrorKind, detail: impl Into<String>) -> Self {
        Self::new(kind, FindingCode::FormatUnsupported, detail)
    }

    fn disagreement(detail: impl Into<String>) -> Self {
        Self::new(
            XzErrorKind::DecoderDisagreement,
            FindingCode::CoveringInconsistent,
            detail,
        )
    }
}

fn metadata_limit(max_metadata_bytes: u64) -> XzError {
    XzError::new(
        XzErrorKind::HeaderLimit,
        FindingCode::QuotaMetadata,
        format!("xz wrapper metadata exceeds the {max_metadata_bytes}-byte cap"),
    )
}

/// CRC64/ECMA-182 in its reflected form, as required by the XZ format.
pub(crate) struct Crc64 {
    value: u64,
}

const CRC64_POLY: u64 = 0xC96C_5795_D787_0F42;

const CRC64_TABLE: [u64; 256] = {
    let mut table = [0_u64; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u64;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 {
                (value >> 1) ^ CRC64_POLY
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
};

impl Crc64 {
    pub(crate) fn new() -> Self {
        Self { value: !0 }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            let index = usize::from((self.value as u8) ^ byte);
            self.value = CRC64_TABLE[index] ^ (self.value >> 8);
        }
    }

    pub(crate) fn finalize(self) -> u64 {
        !self.value
    }
}

/// Length in bytes of the recorded check field for an admitted check id.
pub(crate) fn check_len(check_id: u8) -> Option<u64> {
    match check_id {
        CHECK_CRC32 => Some(4),
        CHECK_CRC64 => Some(8),
        CHECK_SHA256 => Some(32),
        _ => None,
    }
}

/// Hash `bytes` under the admitted check id and compare with the recorded value.
pub(crate) fn check_matches(check_id: u8, bytes: &[u8], expected: &[u8]) -> bool {
    match check_id {
        CHECK_CRC32 => {
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(bytes);
            expected == hasher.finalize().to_le_bytes()
        }
        CHECK_CRC64 => {
            let mut hasher = Crc64::new();
            hasher.update(bytes);
            expected == hasher.finalize().to_le_bytes()
        }
        CHECK_SHA256 => {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            expected == hasher.finalize().as_slice()
        }
        _ => false,
    }
}

#[derive(Clone, Copy, Debug)]
struct StreamCompletion {
    consumed_total: u64,
    produced_total: u64,
}

type Completion = Rc<RefCell<Option<Result<StreamCompletion, XzError>>>>;

/// Decode exactly one restricted XZ stream into a private immutable snapshot.
///
/// Concatenated streams, stream padding, unsupported checks and filters,
/// oversized dictionaries, and every other trailing byte are rejected. The
/// caller supplies independent wrapper-metadata and output bounds.
pub(crate) fn decode_single_stream(
    source: &SourceSnapshot<'_>,
    limits: XzLimits,
) -> Result<DecodedXzStream, XzError> {
    let check_id = parse_stream_header(source)?;
    let trailer_check_len =
        check_len(check_id).expect("admitted check ids always have a recorded length");

    let decoder = XzStream::new_mem_limit(false, DECODER_MEM_LIMIT_KB);
    let stream_reader = source.reader(0, source.len()).map_err(XzError::source)?;
    let completion: Completion = Rc::new(RefCell::new(None));
    let reader = XzStreamReader {
        decoder,
        source_reader: stream_reader,
        input: Vec::new(),
        input_pos: 0,
        input_done: false,
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
                return Err(XzError::new(
                    XzErrorKind::OutputLimit,
                    FindingCode::QuotaDerived,
                    format!(
                        "xz derived output exceeds the {}-byte cap",
                        limits.max_output_bytes
                    ),
                ));
            }
            return Err(XzError::source(finding));
        }
    };
    let evidence = completion.borrow().as_ref().cloned().ok_or_else(|| {
        XzError::structure("xz stream reader ended without completion evidence")
    })??;

    if evidence.consumed_total != source.len() {
        return Err(classify_trailing(source, evidence.consumed_total));
    }
    if evidence.produced_total != output.len() {
        return Err(XzError::disagreement(
            "the decoder's produced total disagrees with the derived snapshot",
        ));
    }

    let parsed = parse_container(source, check_id, trailer_check_len, limits)?;
    let uncompressed_total = parsed
        .blocks
        .iter()
        .try_fold(0_u64, |total, block| {
            total.checked_add(block.uncompressed_len)
        })
        .ok_or_else(|| XzError::structure("xz uncompressed total overflowed u64"))?;
    if uncompressed_total != output.len() {
        return Err(XzError::disagreement(
            "the decoder's output length disagrees with the recorded index",
        ));
    }

    verify_block_checks(check_id, &parsed.blocks, &output)?;

    Ok(DecodedXzStream {
        check_id,
        header: ByteRange {
            offset: 0,
            len: STREAM_HEADER_LEN,
        },
        blocks: parsed.blocks,
        index: parsed.index,
        footer: parsed.footer,
        output,
    })
}

/// Decode the original domain and atomically append its verified private
/// output plus the registered XZ transformation record.
pub(crate) fn transform_single_stream(
    snapshots: &mut SnapshotSet<'_>,
    transforms: &mut TransformGraph,
    limits: XzLimits,
) -> Result<TransformedXzStream, XzError> {
    let original_len = snapshots.original().len();
    let decoded = decode_single_stream(snapshots.original(), limits)?;
    let DecodedXzStream {
        check_id,
        header,
        blocks,
        index,
        footer,
        output,
    } = decoded;
    let output_len = output.len();
    let output_sha256 = output
        .digest()
        .sha256()
        .expect("private derived xz output always has a SHA-256")
        .to_owned();
    let output_domain = snapshots
        .append_derived_snapshot(
            transforms,
            TransformProfile::XzSingleStreamV1,
            DomainRange::original(ByteRange {
                offset: 0,
                len: original_len,
            }),
            output,
        )
        .map_err(|finding| XzError {
            kind: XzErrorKind::TransformAuthority,
            finding,
        })?;
    Ok(TransformedXzStream {
        check_id,
        header,
        blocks,
        index,
        footer,
        output_domain,
        output_len,
        output_sha256,
    })
}

/// Parse and validate the twelve-byte stream header under the restricted
/// grammar, returning the admitted check id.
fn parse_stream_header(source: &SourceSnapshot<'_>) -> Result<u8, XzError> {
    if source.len() < STREAM_HEADER_LEN + STREAM_FOOTER_LEN {
        return Err(XzError::truncated("source is shorter than an XZ stream"));
    }
    let mut header = [0_u8; 12];
    read_bytes(source, 0, &mut header)?;
    if header[..6] != HEADER_MAGIC {
        return Err(XzError::new(
            XzErrorKind::Magic,
            FindingCode::FormatMagic,
            "source does not begin with the XZ stream magic",
        ));
    }
    if header[6] != 0 {
        return Err(XzError::structure(
            "the first XZ stream-flags byte must be zero",
        ));
    }
    let check_id = header[7];
    let declared_crc = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    if crc32(&header[6..8]) != declared_crc {
        return Err(XzError::structure("XZ stream-header CRC32 mismatch"));
    }
    match check_id {
        CHECK_CRC32 | CHECK_CRC64 | CHECK_SHA256 => Ok(check_id),
        CHECK_NONE => Err(XzError::unsupported(
            XzErrorKind::CheckUnsupported,
            "xz streams without an integrity check are outside the restricted profile",
        )),
        _ => Err(XzError::unsupported(
            XzErrorKind::CheckUnsupported,
            format!("xz check id {check_id:#04x} is outside the restricted profile"),
        )),
    }
}

struct ParsedContainer {
    blocks: Vec<XzBlockFrame>,
    index: ByteRange,
    footer: ByteRange,
}

/// Byte-exact replay of the complete container: footer, index, and every
/// block header, enforcing the restricted grammar and the spec obligations
/// the decoder does not check.
fn parse_container(
    source: &SourceSnapshot<'_>,
    check_id: u8,
    trailer_check_len: u64,
    limits: XzLimits,
) -> Result<ParsedContainer, XzError> {
    let len = source.len();
    let footer_offset = len - STREAM_FOOTER_LEN;
    let mut footer = [0_u8; 12];
    read_bytes(source, footer_offset, &mut footer)?;
    if footer[10..12] != FOOTER_MAGIC {
        return Err(XzError::structure(
            "the source does not end with the XZ footer magic",
        ));
    }
    let footer_crc = u32::from_le_bytes([footer[0], footer[1], footer[2], footer[3]]);
    if crc32(&footer[4..10]) != footer_crc {
        return Err(XzError::structure("XZ stream-footer CRC32 mismatch"));
    }
    if footer[8] != 0 || footer[9] != check_id {
        return Err(XzError::structure(
            "XZ footer stream flags disagree with the stream header",
        ));
    }
    let backward_stored = u32::from_le_bytes([footer[4], footer[5], footer[6], footer[7]]);
    let index_len = (u64::from(backward_stored) + 1) * 4;
    let index_offset = footer_offset
        .checked_sub(index_len)
        .filter(|offset| *offset >= STREAM_HEADER_LEN)
        .ok_or_else(|| {
            XzError::structure("the XZ footer backward size points outside the stream")
        })?;

    let index_bytes = read_vec(source, index_offset, index_len)?;
    if index_bytes[0] != 0 {
        return Err(XzError::structure(
            "the XZ index does not begin with its indicator byte",
        ));
    }
    let mut cursor = 1_usize;
    let record_count = decode_varint(&index_bytes, &mut cursor)?;
    if record_count == 0 {
        return Err(XzError::unsupported(
            XzErrorKind::EmptyStream,
            "zero-block xz streams are outside the composition profile",
        ));
    }
    if record_count > MAX_BLOCKS {
        return Err(XzError::unsupported(
            XzErrorKind::BlockBounds,
            format!("xz streams above {MAX_BLOCKS} blocks are outside the restricted profile"),
        ));
    }
    let mut records = Vec::new();
    for _ in 0..record_count {
        let unpadded = decode_varint(&index_bytes, &mut cursor)?;
        let uncompressed = decode_varint(&index_bytes, &mut cursor)?;
        records.push((unpadded, uncompressed));
    }
    while !cursor.is_multiple_of(4) {
        if *index_bytes
            .get(cursor)
            .ok_or_else(|| XzError::structure("the XZ index padding is truncated"))?
            != 0
        {
            return Err(XzError::structure("the XZ index padding is not zero"));
        }
        cursor += 1;
    }
    let crc_offset = cursor;
    if crc_offset + 4 != index_bytes.len() {
        return Err(XzError::structure(
            "the XZ footer backward size disagrees with the real index size",
        ));
    }
    let index_crc = u32::from_le_bytes([
        index_bytes[crc_offset],
        index_bytes[crc_offset + 1],
        index_bytes[crc_offset + 2],
        index_bytes[crc_offset + 3],
    ]);
    if crc32(&index_bytes[..crc_offset]) != index_crc {
        return Err(XzError::structure("XZ index CRC32 mismatch"));
    }

    let mut blocks = Vec::new();
    let mut block_offset = STREAM_HEADER_LEN;
    let mut wrapper_metadata = STREAM_HEADER_LEN + STREAM_FOOTER_LEN + index_len;
    for (unpadded, uncompressed) in records {
        let block = parse_block(
            source,
            block_offset,
            index_offset,
            trailer_check_len,
            unpadded,
            uncompressed,
        )?;
        let physical = block
            .header
            .len
            .checked_add(block.compressed.len)
            .and_then(|value| value.checked_add(block.padding.len))
            .and_then(|value| value.checked_add(block.check.len))
            .ok_or_else(|| XzError::structure("xz block extent overflowed u64"))?;
        wrapper_metadata = wrapper_metadata
            .checked_add(block.header.len)
            .and_then(|value| value.checked_add(block.padding.len))
            .and_then(|value| value.checked_add(block.check.len))
            .ok_or_else(|| metadata_limit(limits.max_metadata_bytes))?;
        block_offset += physical;
        blocks.push(block);
    }
    if block_offset != index_offset {
        return Err(XzError::structure(
            "the XZ index records do not exactly tile the block region",
        ));
    }
    if wrapper_metadata > limits.max_metadata_bytes {
        return Err(metadata_limit(limits.max_metadata_bytes));
    }

    Ok(ParsedContainer {
        blocks,
        index: ByteRange {
            offset: index_offset,
            len: index_len,
        },
        footer: ByteRange {
            offset: footer_offset,
            len: STREAM_FOOTER_LEN,
        },
    })
}

fn parse_block(
    source: &SourceSnapshot<'_>,
    block_offset: u64,
    region_end: u64,
    trailer_check_len: u64,
    unpadded: u64,
    uncompressed: u64,
) -> Result<XzBlockFrame, XzError> {
    let mut size_byte = [0_u8; 1];
    read_bytes(source, block_offset, &mut size_byte)?;
    if size_byte[0] == 0 {
        return Err(XzError::structure(
            "an XZ index indicator appeared where a block header was recorded",
        ));
    }
    let header_len = (u64::from(size_byte[0]) + 1) * 4;
    if block_offset
        .checked_add(header_len)
        .is_none_or(|end| end > region_end)
    {
        return Err(XzError::structure("an XZ block header exceeds the stream"));
    }
    let header_bytes = read_vec(source, block_offset, header_len)?;
    let declared_crc = u32::from_le_bytes([
        header_bytes[header_bytes.len() - 4],
        header_bytes[header_bytes.len() - 3],
        header_bytes[header_bytes.len() - 2],
        header_bytes[header_bytes.len() - 1],
    ]);
    if crc32(&header_bytes[..header_bytes.len() - 4]) != declared_crc {
        return Err(XzError::structure("XZ block-header CRC32 mismatch"));
    }
    let flags = header_bytes[1];
    if flags & 0x3C != 0 {
        return Err(XzError::structure(
            "reserved XZ block-flag bits must be zero",
        ));
    }
    let filter_count = (flags & 0x03) + 1;
    if filter_count != 1 {
        return Err(XzError::unsupported(
            XzErrorKind::FilterUnsupported,
            "xz filter chains are outside the restricted profile",
        ));
    }
    let has_compressed = flags & 0x40 != 0;
    let has_uncompressed = flags & 0x80 != 0;
    if has_compressed != has_uncompressed {
        return Err(XzError::unsupported(
            XzErrorKind::FilterUnsupported,
            "xz block headers must declare both sizes or neither",
        ));
    }
    let mut cursor = 2_usize;
    let declared_compressed = if has_compressed {
        Some(decode_varint(&header_bytes, &mut cursor)?)
    } else {
        None
    };
    let declared_uncompressed = if has_uncompressed {
        Some(decode_varint(&header_bytes, &mut cursor)?)
    } else {
        None
    };
    let filter_id = decode_varint(&header_bytes, &mut cursor)?;
    if filter_id != LZMA2_FILTER_ID {
        return Err(XzError::unsupported(
            XzErrorKind::FilterUnsupported,
            format!("xz filter {filter_id:#x} is outside the LZMA2-only profile"),
        ));
    }
    let properties_len = decode_varint(&header_bytes, &mut cursor)?;
    if properties_len != 1 {
        return Err(XzError::structure(
            "the LZMA2 filter carries an unexpected properties length",
        ));
    }
    let dict_property = *header_bytes
        .get(cursor)
        .ok_or_else(|| XzError::structure("the LZMA2 dictionary property is truncated"))?;
    cursor += 1;
    if dict_property > 40 {
        return Err(XzError::structure(
            "the LZMA2 dictionary property is invalid",
        ));
    }
    let dict_size = if dict_property == 40 {
        u32::MAX
    } else {
        (2 | (u32::from(dict_property) & 1)) << (dict_property / 2 + 11)
    };
    if dict_size > MAX_DICT_BYTES {
        return Err(XzError::unsupported(
            XzErrorKind::DictBounds,
            format!(
                "the LZMA2 dictionary of {dict_size} bytes exceeds the {MAX_DICT_BYTES}-byte profile ceiling"
            ),
        ));
    }
    for byte in &header_bytes[cursor..header_bytes.len() - 4] {
        if *byte != 0 {
            return Err(XzError::structure("XZ block-header padding is not zero"));
        }
    }

    let compressed_len = unpadded
        .checked_sub(header_len)
        .and_then(|value| value.checked_sub(trailer_check_len))
        .filter(|value| *value >= 1)
        .ok_or_else(|| {
            XzError::structure("an XZ index record is smaller than its block framing")
        })?;
    if let Some(declared) = declared_compressed {
        if declared != compressed_len {
            return Err(XzError::new(
                XzErrorKind::DeclaredSize,
                FindingCode::QuotaDeclaredLie,
                format!(
                    "xz block declares {declared} compressed bytes but the index records {compressed_len}"
                ),
            ));
        }
    }
    if let Some(declared) = declared_uncompressed {
        if declared != uncompressed {
            return Err(XzError::new(
                XzErrorKind::DeclaredSize,
                FindingCode::QuotaDeclaredLie,
                format!(
                    "xz block declares {declared} uncompressed bytes but the index records {uncompressed}"
                ),
            ));
        }
    }

    let compressed_offset = block_offset + header_len;
    let padded_len = compressed_len
        .checked_add(header_len)
        .map(|value| value.next_multiple_of(4) - value)
        .ok_or_else(|| XzError::structure("xz block padding overflowed u64"))?;
    let padding_offset = compressed_offset + compressed_len;
    let check_offset = padding_offset + padded_len;
    if check_offset
        .checked_add(trailer_check_len)
        .is_none_or(|end| end > region_end)
    {
        return Err(XzError::structure("an XZ block exceeds the block region"));
    }
    let padding_bytes = read_vec(source, padding_offset, padded_len)?;
    if padding_bytes.iter().any(|byte| *byte != 0) {
        return Err(XzError::structure("XZ block padding is not zero"));
    }
    let check_value = read_vec(source, check_offset, trailer_check_len)?;

    Ok(XzBlockFrame {
        header: ByteRange {
            offset: block_offset,
            len: header_len,
        },
        compressed: ByteRange {
            offset: compressed_offset,
            len: compressed_len,
        },
        padding: ByteRange {
            offset: padding_offset,
            len: padded_len,
        },
        check: ByteRange {
            offset: check_offset,
            len: trailer_check_len,
        },
        dict_size,
        declared_compressed,
        declared_uncompressed,
        uncompressed_len: uncompressed,
        check_value,
    })
}

/// Independently re-hash each block's decoded range and compare it with the
/// recorded check value, without trusting the decoder's internal verification.
fn verify_block_checks(
    check_id: u8,
    blocks: &[XzBlockFrame],
    output: &SourceSnapshot<'static>,
) -> Result<(), XzError> {
    let mut cursor = 0_u64;
    for block in blocks {
        let decoded = output
            .read_vec(cursor, block.uncompressed_len)
            .map_err(XzError::source)?;
        if !check_matches(check_id, &decoded, &block.check_value) {
            return Err(XzError::new(
                XzErrorKind::CheckMismatch,
                FindingCode::CrcMismatch,
                "an XZ block check does not match the decoded bytes",
            ));
        }
        cursor += block.uncompressed_len;
    }
    Ok(())
}

fn classify_trailing(source: &SourceSnapshot<'_>, consumed: u64) -> XzError {
    let mut magic = [0_u8; 6];
    let has_magic = consumed
        .checked_add(6)
        .is_some_and(|end| end <= source.len())
        && source.read_exact_at(consumed, &mut magic).is_ok();
    if has_magic && magic == HEADER_MAGIC {
        return XzError::new(
            XzErrorKind::ConcatenatedStream,
            FindingCode::CodecXzTrailingInput,
            "concatenated xz streams are outside the single-stream profile",
        );
    }
    let trailing_len = source.len() - consumed;
    if trailing_len.is_multiple_of(4) {
        if let Ok(trailing) = source.read_vec(consumed, trailing_len) {
            if trailing.iter().all(|byte| *byte == 0) {
                return XzError::new(
                    XzErrorKind::ConcatenatedStream,
                    FindingCode::CodecXzTrailingInput,
                    "xz stream padding is outside the single-stream profile",
                );
            }
        }
    }
    XzError::new(
        XzErrorKind::TrailingInput,
        FindingCode::CodecXzTrailingInput,
        "trailing bytes after the xz stream are rejected",
    )
}

/// Decode the spec's multibyte integer, requiring minimal encoding.
fn decode_varint(bytes: &[u8], cursor: &mut usize) -> Result<u64, XzError> {
    let mut value = 0_u64;
    let mut consumed = 0_usize;
    loop {
        let byte = *bytes
            .get(*cursor + consumed)
            .ok_or_else(|| XzError::structure("an XZ multibyte integer is truncated"))?;
        if consumed >= 9 {
            return Err(XzError::structure(
                "an XZ multibyte integer exceeds nine bytes",
            ));
        }
        if consumed > 0 && byte == 0 {
            return Err(XzError::structure(
                "an XZ multibyte integer is not minimally encoded",
            ));
        }
        value |= u64::from(byte & 0x7F) << (consumed * 7);
        consumed += 1;
        if byte & 0x80 == 0 {
            break;
        }
    }
    *cursor += consumed;
    Ok(value)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn read_bytes(source: &SourceSnapshot<'_>, offset: u64, buffer: &mut [u8]) -> Result<(), XzError> {
    let len = buffer.len() as u64;
    if offset.checked_add(len).is_none_or(|end| end > source.len()) {
        return Err(XzError::truncated("source ends inside the XZ structure"));
    }
    source
        .read_exact_at(offset, buffer)
        .map_err(XzError::source)
}

fn read_vec(source: &SourceSnapshot<'_>, offset: u64, len: u64) -> Result<Vec<u8>, XzError> {
    if offset.checked_add(len).is_none_or(|end| end > source.len()) {
        return Err(XzError::truncated("source ends inside the XZ structure"));
    }
    source.read_vec(offset, len).map_err(XzError::source)
}

struct XzStreamReader<'s, 'a> {
    decoder: XzStream,
    source_reader: SnapshotRangeReader<'s, 'a>,
    input: Vec<u8>,
    input_pos: usize,
    input_done: bool,
    terminal: bool,
    completion: Completion,
}

impl XzStreamReader<'_, '_> {
    fn fail(&self, error: XzError) -> io::Error {
        let finding = error.finding().clone();
        *self.completion.borrow_mut() = Some(Err(error));
        as_io_error(finding)
    }

    fn refill(&mut self) -> Result<(), io::Error> {
        if self.input_pos < self.input.len() || self.input_done {
            return Ok(());
        }
        self.input.resize(DECODE_STEP_BYTES, 0);
        let mut filled = 0;
        while filled < self.input.len() {
            let read = self
                .source_reader
                .read(&mut self.input[filled..])
                .map_err(|error| self.fail(classify_read_error(&error)))?;
            if read == 0 {
                self.input_done = true;
                break;
            }
            filled += read;
        }
        self.input.truncate(filled);
        self.input_pos = 0;
        Ok(())
    }
}

impl Read for XzStreamReader<'_, '_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.terminal {
            return Ok(0);
        }
        loop {
            self.refill()?;
            let action = if self.input_done {
                Action::Finish
            } else {
                Action::Run
            };
            let result = self
                .decoder
                .process(&self.input[self.input_pos..], buffer, action)
                .map_err(|error| self.fail(classify_decoder_error(&error)))?;
            self.input_pos += result.bytes_consumed;
            if result.status == Status::StreamEnd {
                self.terminal = true;
                *self.completion.borrow_mut() = Some(Ok(StreamCompletion {
                    consumed_total: self.decoder.total_in(),
                    produced_total: self.decoder.total_out(),
                }));
                return Ok(result.bytes_produced);
            }
            if result.bytes_produced > 0 {
                return Ok(result.bytes_produced);
            }
            if self.input_done && result.bytes_consumed == 0 {
                return Err(self.fail(XzError::structure(
                    "the xz decoder made no progress on the remaining input",
                )));
            }
        }
    }
}

fn classify_read_error(error: &io::Error) -> XzError {
    finding_from_io(error).map_or_else(
        || XzError::structure(format!("xz source read failed: {error}")),
        XzError::source,
    )
}

fn classify_decoder_error(error: &io::Error) -> XzError {
    if let Some(finding) = finding_from_io(error) {
        return XzError::source(finding);
    }
    let message = error.to_string();
    if error.kind() == io::ErrorKind::OutOfMemory {
        return XzError::unsupported(
            XzErrorKind::DictBounds,
            format!("the xz decoder refused the stream's memory demand: {message}"),
        );
    }
    if message.contains("check type") {
        return XzError::unsupported(
            XzErrorKind::CheckUnsupported,
            format!("the xz decoder refused the stream's check type: {message}"),
        );
    }
    if message.contains("filter") {
        return XzError::unsupported(
            XzErrorKind::FilterUnsupported,
            format!("the xz decoder refused the stream's filter chain: {message}"),
        );
    }
    if message.contains("checksum mismatch") {
        return XzError::new(
            XzErrorKind::CheckMismatch,
            FindingCode::CrcMismatch,
            format!("the xz decoder observed a check mismatch: {message}"),
        );
    }
    if message.contains("unexpected end") || message.contains("eof") {
        return XzError::truncated(format!("the xz stream is truncated: {message}"));
    }
    XzError::structure(format!("xz stream decoding failed: {message}"))
}

/// Test-only grammar builders shared by unit and composite tests.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Build a restricted-language stream from uncompressed LZMA2 chunks,
    /// giving tests full grammar control including hostile mutations.
    pub(crate) fn built_stream(content: &[u8], check_id: u8, declared_sizes: bool) -> Vec<u8> {
        let mut lzma2 = Vec::new();
        let mut first = true;
        for chunk in content.chunks(0xFFFF.min(content.len().max(1))) {
            lzma2.push(if first { 0x01 } else { 0x02 });
            first = false;
            let size = (chunk.len() - 1) as u16;
            lzma2.extend_from_slice(&size.to_be_bytes());
            lzma2.extend_from_slice(chunk);
        }
        lzma2.push(0x00);

        let check_value: Vec<u8> = match check_id {
            CHECK_CRC32 => {
                let mut hasher = crc32fast::Hasher::new();
                hasher.update(content);
                hasher.finalize().to_le_bytes().to_vec()
            }
            CHECK_CRC64 => {
                let mut hasher = Crc64::new();
                hasher.update(content);
                hasher.finalize().to_le_bytes().to_vec()
            }
            CHECK_SHA256 => {
                let mut hasher = Sha256::new();
                hasher.update(content);
                hasher.finalize().to_vec()
            }
            _ => Vec::new(),
        };

        let mut header = vec![0_u8; 2];
        header[1] = if declared_sizes { 0xC0 } else { 0x00 };
        if declared_sizes {
            push_varint(&mut header, lzma2.len() as u64);
            push_varint(&mut header, content.len() as u64);
        }
        push_varint(&mut header, LZMA2_FILTER_ID);
        push_varint(&mut header, 1);
        header.push(22);
        while !(header.len() + 4).is_multiple_of(4) {
            header.push(0);
        }
        header[0] = ((header.len() + 4) / 4 - 1) as u8;
        let header_crc = crc32(&header);
        header.extend_from_slice(&header_crc.to_le_bytes());

        let mut stream = HEADER_MAGIC.to_vec();
        stream.push(0);
        stream.push(check_id);
        stream.extend_from_slice(&crc32(&[0, check_id]).to_le_bytes());

        let block_start = stream.len();
        stream.extend_from_slice(&header);
        stream.extend_from_slice(&lzma2);
        let unpadded = (stream.len() - block_start + check_value.len()) as u64;
        while !(stream.len() - block_start).is_multiple_of(4) {
            stream.push(0);
        }
        stream.extend_from_slice(&check_value);

        let index_start = stream.len();
        stream.push(0);
        push_varint(&mut stream, 1);
        push_varint(&mut stream, unpadded);
        push_varint(&mut stream, content.len() as u64);
        while !(stream.len() - index_start).is_multiple_of(4) {
            stream.push(0);
        }
        let index_crc = crc32(&stream[index_start..]);
        stream.extend_from_slice(&index_crc.to_le_bytes());
        let index_len = stream.len() - index_start;

        let backward = (index_len as u32 / 4) - 1;
        let mut footer_body = backward.to_le_bytes().to_vec();
        footer_body.push(0);
        footer_body.push(check_id);
        stream.extend_from_slice(&crc32(&footer_body).to_le_bytes());
        stream.extend_from_slice(&footer_body);
        stream.extend_from_slice(&FOOTER_MAGIC);
        stream
    }

    pub(crate) fn push_varint(out: &mut Vec<u8>, mut value: u64) {
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn decode_hex(value: &str) -> Vec<u8> {
        let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
        let (pairs, remainder) = cleaned.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    /// Zstandard-of-the-session's sibling: `xz -6 -T1` over the standard
    /// conformance derived TAR (XZ Utils 5.8.1; byte-identical to CPython
    /// 3.12.10 `lzma.compress` defaults).
    const XZ_CLI_CRC64_HEX: &str = "fd377a585a000004e6d6b4460200210116000000742fe5a3e007ff00705d\
        00369a4adff3ff4173689225555d5c3da569f20e0f1e46ed67823a5dcf0c5c5749d5f12bb878efa1897bcf\
        a2a38633f7d28fc607eaad183da7c2063caa76c99a73e3434b174e4fa5f5dd59582a4d6308d2ffca92620a\
        f736cdb6f7b1240ae87699d3cfb3eb7748f4ff4a5b315efe8cd37d00ec921496b86e87ef00018c01801000\
        00853c3866b1c467fb020000000004595a";

    /// `xz -6 -T1 --block-size=1024` over the same TAR: two blocks.
    const XZ_CLI_MULTIBLOCK_HEX: &str = "fd377a585a000004e6d6b4460200210116000000742fe5a3e003ff\
        006c5d00369a4adff3ff4173689225555d5c3da569f20e0f1e46ed67823a5dcf0c5c5749d5f12bb878efa1\
        897bcfa2a38633f7d28fc607eaad183da7c2063caa76c99a73e3434b174e4fa5f5dd59582a4d6308d2ffca\
        92620af736cdb6f7b1240ae87699d3cfb3eb7748f6f71983400000ade5c000d130fdd60200210116000000\
        742fe5a3e003ff000b5d00006ffdffffa3b77f46320000000c276920976378c30002880180082780080000\
        0056443fcf14173b30030000000004595a";

    /// `xz -6 -T1 -C sha256` over the same TAR.
    const XZ_CLI_SHA256_HEX: &str = "fd377a585a00000ae1fb0ca10200210116000000742fe5a3e007ff0070\
        5d00369a4adff3ff4173689225555d5c3da569f20e0f1e46ed67823a5dcf0c5c5749d5f12bb878efa1897b\
        cfa2a38633f7d28fc607eaad183da7c2063caa76c99a73e3434b174e4fa5f5dd59582a4d6308d2ffca9262\
        0af736cdb6f7b1240ae87699d3cfb3eb7748f4ff4a5b315efe8cd37d0036631c7b6055995f66c07c86f39b\
        baa386b893b177c693bb38a5f73aaa83837c0001a40180100000debbc78db6e9df1c02000000000a595a";

    /// `xz -6 -T1 -C crc32` over the same TAR.
    const XZ_CLI_CRC32_HEX: &str = "fd377a585a0000016922de360200210116000000742fe5a3e007ff00705d\
        00369a4adff3ff4173689225555d5c3da569f20e0f1e46ed67823a5dcf0c5c5749d5f12bb878efa1897bcf\
        a2a38633f7d28fc607eaad183da7c2063caa76c99a73e3434b174e4fa5f5dd59582a4d6308d2ffca92620a\
        f736cdb6f7b1240ae87699d3cfb3eb7748f4ff4a5b315efe8cd37d005999950c0001880180100000937ea9\
        fd3e300d8b020000000001595a";

    /// `xz -6 -T1 -C none` over the same TAR (denied by the profile).
    const XZ_CLI_NONE_HEX: &str = "fd377a585a000000ff12d9410200210116000000742fe5a3e007ff00705d\
        00369a4adff3ff4173689225555d5c3da569f20e0f1e46ed67823a5dcf0c5c5749d5f12bb878efa1897bcf\
        a2a38633f7d28fc607eaad183da7c2063caa76c99a73e3434b174e4fa5f5dd59582a4d6308d2ffca92620a\
        f736cdb6f7b1240ae87699d3cfb3eb7748f4ff4a5b315efe8cd37d000001840180100000e8be6b8aa8000a\
        fc020000000000595a";

    /// `xz -9 -T1` over the same TAR: a 64 MiB dictionary (denied).
    const XZ_CLI_DICT64M_HEX: &str = "fd377a585a000004e6d6b446020021011c00000010cf58cce007ff0070\
        5d00369a4adff3ff4173689225555d5c3da569f20e0f1e46ed67823a5dcf0c5c5749d5f12bb878efa1897b\
        cfa2a38633f7d28fc607eaad183da7c2063caa76c99a73e3434b174e4fa5f5dd59582a4d6308d2ffca9262\
        0af736cdb6f7b1240ae87699d3cfb3eb7748f4ff4a5b315efe8cd37d00ec921496b86e87ef00018c018010\
        0000853c3866b1c467fb020000000004595a";

    fn conformance_tar() -> Vec<u8> {
        fn write_octal(field: &mut [u8], value: u64) {
            field.fill(b'0');
            let octal = format!("{value:o}");
            let digits = field.len() - 1;
            field[digits - octal.len()..digits].copy_from_slice(octal.as_bytes());
            field[digits] = 0;
        }
        let name = "mission/plan.txt";
        let body = b"verify twice, decode once";
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], body.len() as u64);
        write_octal(&mut header[136..148], 1_788_000_000);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[265..269].copy_from_slice(b"root");
        header[297..301].copy_from_slice(b"root");
        write_octal(&mut header[329..337], 0);
        write_octal(&mut header[337..345], 0);
        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
        header[154] = 0;
        header[155] = b' ';
        let mut tar = header.to_vec();
        tar.extend_from_slice(body);
        tar.resize(tar.len().next_multiple_of(512), 0);
        tar.resize(tar.len() + 1024, 0);
        tar
    }

    use super::test_support::built_stream;

    fn snapshot(bytes: &[u8]) -> SourceSnapshot<'_> {
        SourceSnapshot::borrowed(None, bytes)
    }

    fn limits() -> XzLimits {
        XzLimits {
            max_metadata_bytes: 1024 * 1024,
            max_output_bytes: 4 * 1024 * 1024,
        }
    }

    fn output_bytes(output: &SourceSnapshot<'static>) -> Vec<u8> {
        output
            .read_vec(0, output.len())
            .expect("private output reads back")
    }

    #[test]
    fn crc64_matches_the_published_vectors() {
        // ECMA-182 reflected check value for "123456789".
        let mut hasher = Crc64::new();
        hasher.update(b"123456789");
        assert_eq!(hasher.finalize(), 0x995D_C9BB_DF19_39FA);
        let empty = Crc64::new();
        assert_eq!(empty.finalize(), 0);
    }

    #[test]
    fn pinned_xz_cli_stream_decodes_with_exact_geometry() {
        let tar = conformance_tar();
        let source = decode_hex(XZ_CLI_CRC64_HEX);
        let decoded = decode_single_stream(&snapshot(&source), limits()).unwrap();
        assert_eq!(decoded.check_id, CHECK_CRC64);
        assert_eq!(decoded.blocks.len(), 1);
        let block = &decoded.blocks[0];
        assert_eq!(block.dict_size, MAX_DICT_BYTES);
        assert_eq!(block.declared_compressed, None);
        assert_eq!(block.declared_uncompressed, None);
        assert_eq!(block.uncompressed_len, tar.len() as u64);
        assert_eq!(block.check.len, 8);
        assert_eq!(decoded.footer.end(), source.len() as u64);
        assert_eq!(decoded.index.end() + STREAM_FOOTER_LEN, source.len() as u64);
        assert_eq!(output_bytes(&decoded.output), tar);
    }

    #[test]
    fn pinned_multiblock_crc32_and_sha256_streams_decode() {
        let tar = conformance_tar();
        let multi = decode_hex(XZ_CLI_MULTIBLOCK_HEX);
        let decoded = decode_single_stream(&snapshot(&multi), limits()).unwrap();
        assert_eq!(decoded.blocks.len(), 2);
        assert_eq!(
            decoded.blocks[0].uncompressed_len + decoded.blocks[1].uncompressed_len,
            tar.len() as u64
        );
        assert_eq!(output_bytes(&decoded.output), tar);

        let crc32_stream = decode_hex(XZ_CLI_CRC32_HEX);
        let decoded = decode_single_stream(&snapshot(&crc32_stream), limits()).unwrap();
        assert_eq!(decoded.check_id, CHECK_CRC32);
        assert_eq!(decoded.blocks[0].check.len, 4);

        let sha_stream = decode_hex(XZ_CLI_SHA256_HEX);
        let decoded = decode_single_stream(&snapshot(&sha_stream), limits()).unwrap();
        assert_eq!(decoded.check_id, CHECK_SHA256);
        assert_eq!(decoded.blocks[0].check.len, 32);
        let mut hasher = Sha256::new();
        hasher.update(&tar);
        assert_eq!(decoded.blocks[0].check_value, hasher.finalize().as_slice());
    }

    #[test]
    fn built_streams_round_trip_across_checks_and_declared_sizes() {
        let content = b"restricted xz stream payload".repeat(20);
        for check_id in [CHECK_CRC32, CHECK_CRC64, CHECK_SHA256] {
            for declared in [false, true] {
                let source = built_stream(&content, check_id, declared);
                let decoded = decode_single_stream(&snapshot(&source), limits()).unwrap();
                assert_eq!(decoded.check_id, check_id);
                assert_eq!(decoded.blocks[0].declared_uncompressed.is_some(), declared);
                assert_eq!(output_bytes(&decoded.output), content);
            }
        }
    }

    #[test]
    fn unsupported_checks_dictionaries_and_filters_fail_closed() {
        let none = decode_hex(XZ_CLI_NONE_HEX);
        let error = decode_single_stream(&snapshot(&none), limits()).unwrap_err();
        assert_eq!(error.kind, XzErrorKind::CheckUnsupported);
        assert_eq!(error.finding().code, FindingCode::FormatUnsupported);

        let big_dict = decode_hex(XZ_CLI_DICT64M_HEX);
        let error = decode_single_stream(&snapshot(&big_dict), limits()).unwrap_err();
        assert_eq!(error.kind, XzErrorKind::DictBounds);
        assert_eq!(error.finding().code, FindingCode::FormatUnsupported);

        let error = decode_single_stream(
            &snapshot(b"this is long enough but is not an xz stream"),
            limits(),
        )
        .unwrap_err();
        assert_eq!(error.kind, XzErrorKind::Magic);
        assert_eq!(error.finding().code, FindingCode::FormatMagic);

        let error = decode_single_stream(&snapshot(&[0xFD]), limits()).unwrap_err();
        assert_eq!(error.kind, XzErrorKind::Truncated);
    }

    #[test]
    fn trailing_input_is_classified_exactly() {
        let member = built_stream(b"payload", CHECK_CRC64, false);

        let mut concatenated = member.clone();
        concatenated.extend_from_slice(&built_stream(b"second", CHECK_CRC64, false));
        let error = decode_single_stream(&snapshot(&concatenated), limits()).unwrap_err();
        assert_eq!(error.kind, XzErrorKind::ConcatenatedStream);
        assert_eq!(error.finding().code, FindingCode::CodecXzTrailingInput);

        let mut padded = member.clone();
        padded.extend_from_slice(&[0, 0, 0, 0]);
        let error = decode_single_stream(&snapshot(&padded), limits()).unwrap_err();
        assert_eq!(error.kind, XzErrorKind::ConcatenatedStream);

        let mut garbage = member.clone();
        garbage.push(0x7F);
        let error = decode_single_stream(&snapshot(&garbage), limits()).unwrap_err();
        assert_eq!(error.kind, XzErrorKind::TrailingInput);
        assert_eq!(error.finding().code, FindingCode::CodecXzTrailingInput);
    }

    #[test]
    fn structural_and_integrity_mutations_fail_closed() {
        let member = built_stream(b"integrity payload", CHECK_CRC64, true);

        // Block check mutation: the decoder verifies internally, so the error
        // surfaces from the decode stage as a stream failure.
        let mut check_lie = member.clone();
        let footer_and_index = 12 + 16;
        let check_end = check_lie.len() - footer_and_index;
        check_lie[check_end - 1] ^= 0x01;
        assert!(decode_single_stream(&snapshot(&check_lie), limits()).is_err());

        // Declared uncompressed-size lie: rebuild with a wrong declared value.
        let mut size_lie = member.clone();
        // header layout: [0]=size,[1]=0xC0,[2]=comp varint...,
        // the declared sizes for this small payload are single-byte varints.
        size_lie[12 + 3] ^= 0x01;
        // fix the block-header CRC so the size lie survives to semantic checks
        let header_len = ((size_lie[12] as usize) + 1) * 4;
        let crc = crc32(&size_lie[12..12 + header_len - 4]);
        size_lie[12 + header_len - 4..12 + header_len].copy_from_slice(&crc.to_le_bytes());
        let error = decode_single_stream(&snapshot(&size_lie), limits()).unwrap_err();
        assert!(matches!(
            error.kind,
            XzErrorKind::DeclaredSize | XzErrorKind::StreamStructure
        ));

        // Footer backward-size drift.
        let mut backward = member.clone();
        let footer_offset = backward.len() - 12;
        backward[footer_offset + 4] ^= 0x01;
        let crc = crc32(&backward[footer_offset + 4..footer_offset + 10]);
        backward[footer_offset..footer_offset + 4].copy_from_slice(&crc.to_le_bytes());
        assert!(decode_single_stream(&snapshot(&backward), limits()).is_err());

        // Reserved block-flag bit with a repaired header CRC.
        let mut reserved = member.clone();
        reserved[13] |= 0x04;
        let header_len = ((reserved[12] as usize) + 1) * 4;
        let crc = crc32(&reserved[12..12 + header_len - 4]);
        reserved[12 + header_len - 4..12 + header_len].copy_from_slice(&crc.to_le_bytes());
        assert!(decode_single_stream(&snapshot(&reserved), limits()).is_err());

        // Truncation sweep.
        for len in 1..member.len() {
            assert!(
                decode_single_stream(&snapshot(&member[..len]), limits()).is_err(),
                "prefix {len} unexpectedly decoded"
            );
        }
    }

    #[test]
    fn metadata_and_output_caps_are_exact() {
        let content = b"capped xz content";
        let member = built_stream(content, CHECK_CRC64, false);
        let generous = decode_single_stream(&snapshot(&member), limits()).unwrap();
        let block = &generous.blocks[0];
        let wrapper_metadata = STREAM_HEADER_LEN
            + STREAM_FOOTER_LEN
            + generous.index.len
            + block.header.len
            + block.padding.len
            + block.check.len;
        let exact = XzLimits {
            max_metadata_bytes: wrapper_metadata,
            max_output_bytes: content.len() as u64,
        };
        assert!(decode_single_stream(&snapshot(&member), exact).is_ok());

        let below = XzLimits {
            max_metadata_bytes: wrapper_metadata - 1,
            max_output_bytes: 1024,
        };
        let error = decode_single_stream(&snapshot(&member), below).unwrap_err();
        assert_eq!(error.kind, XzErrorKind::HeaderLimit);
        assert_eq!(error.finding().code, FindingCode::QuotaMetadata);

        let output_cap = XzLimits {
            max_metadata_bytes: 1024 * 1024,
            max_output_bytes: content.len() as u64 - 1,
        };
        let error = decode_single_stream(&snapshot(&member), output_cap).unwrap_err();
        assert_eq!(error.kind, XzErrorKind::OutputLimit);
        assert_eq!(error.finding().code, FindingCode::QuotaDerived);
    }

    #[test]
    fn transform_registers_one_identity_bound_derived_domain() {
        let content = b"derived xz domain payload";
        let member = built_stream(content, CHECK_SHA256, false);
        let snapshot = SourceSnapshot::borrowed(None, &member);
        let mut snapshots = SnapshotSet::from_original(snapshot);
        let mut transforms = TransformGraph::empty();
        let transformed =
            transform_single_stream(&mut snapshots, &mut transforms, limits()).unwrap();
        assert_eq!(transformed.output_domain, SnapshotDomainId::FIRST_DERIVED);
        assert_eq!(transformed.output_len, content.len() as u64);
        assert!(transforms.validates(&snapshots));
        assert_eq!(
            transforms.records()[0].profile,
            TransformProfile::XzSingleStreamV1
        );
    }
}
