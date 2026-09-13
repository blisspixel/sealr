//! Strict, bounded bzip2 single-stream decoding.
//!
//! This module is deliberately crate-private until the wrapper profile and its
//! transformation identity are part of the public admission contract.
//!
//! The `libbz2-rs-sys` decoder parses the container itself, so Sealr keeps its
//! own bit-exact container parse as the structural authority. The bzip2
//! container is bit-aligned — blocks begin at arbitrary bit offsets with no
//! padding between them — so Sealr's independent replay is a bit-level design:
//! the header and first-block fields sit at fixed offsets, the footer is
//! recovered by an eight-shift scan from the decoder-established end with a
//! unique-match requirement, and a full-stream scan for the 48-bit block magic
//! yields an independent block count and per-block CRC list whose chain fold
//! must reproduce the footer's combined CRC exactly. Single-block streams are
//! additionally re-hashed end to end with Sealr's own bzip2-variant CRC32.
//! Any disagreement between the two interpretations fails closed.

use std::cell::RefCell;
use std::io::{self, Read};
use std::rc::Rc;

use ::bzip2::{Decompress, Status};

use crate::findings::{Finding, FindingCode};
use crate::ir::ByteRange;
use crate::snapshot::{
    as_io_error, DomainRange, SnapshotDomainId, SnapshotRangeReader, SnapshotSet, SourceSnapshot,
    TransformGraph, TransformProfile,
};

/// The four-byte stream header: `"BZh"` plus the level digit.
pub(crate) const STREAM_HEADER_LEN: u64 = 4;
/// A zero-block stream is header plus footer with no padding: 14 bytes.
const MIN_STREAM_LEN: u64 = 14;
/// 48-bit block magic (BCD pi).
const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
/// 48-bit end-of-stream magic (BCD sqrt pi).
const EOS_MAGIC: u64 = 0x1772_4538_5090;
/// Bits per recorded block frame: magic, CRC, and the deprecated
/// `randomised` flag.
const BLOCK_FRAME_BITS: u64 = 48 + 32 + 1;
/// Footer bits before padding: magic plus combined CRC.
const FOOTER_BITS: u64 = 48 + 32;
/// Bounded multi-block: a 512 MiB derived cap at the smallest level-1 block
/// size is ~5,300 blocks, so this comfortably covers every admissible
/// producer shape while bounding the recorded evidence vectors.
pub(crate) const MAX_BLOCKS: u64 = 65536;
const DECODE_STEP_BYTES: usize = 64 * 1024;

/// Resource limits for the private bzip2 transformation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bzip2Limits {
    /// Maximum wrapper metadata bytes: the stream header, every block's
    /// magic, CRC, and flag bits, and the footer including its padding,
    /// rounded up to whole bytes. Compressed block bodies are payload.
    pub(crate) max_metadata_bytes: u64,
    /// Maximum number of decoded bytes copied to the private snapshot.
    pub(crate) max_output_bytes: u64,
}

/// A fully verified single bzip2 stream and its bounded private output.
#[derive(Debug)]
pub(crate) struct DecodedBzip2Stream {
    pub(crate) level: u8,
    pub(crate) header: ByteRange,
    pub(crate) payload_bits: u64,
    pub(crate) padding_bits: u8,
    pub(crate) block_bit_offsets: Vec<u64>,
    pub(crate) block_crcs: Vec<u32>,
    pub(crate) combined_crc: u32,
    pub(crate) output: SourceSnapshot<'static>,
}

/// Verified wrapper evidence after the output has become a retained snapshot
/// domain and the transformation graph has bound both byte identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransformedBzip2Stream {
    pub(crate) level: u8,
    pub(crate) header: ByteRange,
    pub(crate) payload_bits: u64,
    pub(crate) padding_bits: u8,
    pub(crate) block_bit_offsets: Vec<u64>,
    pub(crate) block_crcs: Vec<u32>,
    pub(crate) combined_crc: u32,
    pub(crate) output_domain: SnapshotDomainId,
    pub(crate) output_len: u64,
    pub(crate) output_sha256: String,
}

/// Internal failure classes kept distinct before they are mapped to the
/// repository's stable finding vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Bzip2ErrorKind {
    Source,
    Truncated,
    Magic,
    VersionUnsupported,
    LevelBounds,
    RandomizedBlock,
    BlockBounds,
    EmptyStream,
    HeaderLimit,
    StreamStructure,
    ConcatenatedStream,
    TrailingInput,
    CheckMismatch,
    OutputLimit,
    DecoderDisagreement,
    TransformAuthority,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Bzip2Error {
    pub(crate) kind: Bzip2ErrorKind,
    finding: Finding,
}

impl Bzip2Error {
    pub(crate) fn finding(&self) -> &Finding {
        &self.finding
    }

    pub(crate) fn into_finding(self) -> Finding {
        self.finding
    }

    fn new(kind: Bzip2ErrorKind, code: FindingCode, detail: impl Into<String>) -> Self {
        Self {
            kind,
            finding: Finding::error(code, detail),
        }
    }

    fn source(finding: Finding) -> Self {
        Self {
            kind: Bzip2ErrorKind::Source,
            finding,
        }
    }

    fn truncated(detail: impl Into<String>) -> Self {
        Self::new(
            Bzip2ErrorKind::Truncated,
            FindingCode::CodecBzip2InvalidStream,
            detail,
        )
    }

    fn structure(detail: impl Into<String>) -> Self {
        Self::new(
            Bzip2ErrorKind::StreamStructure,
            FindingCode::CodecBzip2InvalidStream,
            detail,
        )
    }

    fn unsupported(kind: Bzip2ErrorKind, detail: impl Into<String>) -> Self {
        Self::new(kind, FindingCode::FormatUnsupported, detail)
    }

    fn disagreement(detail: impl Into<String>) -> Self {
        Self::new(
            Bzip2ErrorKind::DecoderDisagreement,
            FindingCode::CoveringInconsistent,
            detail,
        )
    }
}

fn metadata_limit(max_metadata_bytes: u64) -> Bzip2Error {
    Bzip2Error::new(
        Bzip2ErrorKind::HeaderLimit,
        FindingCode::QuotaMetadata,
        format!("bzip2 wrapper metadata exceeds the {max_metadata_bytes}-byte cap"),
    )
}

/// The bzip2 CRC32 variant: MSB-first (non-reflected) polynomial 0x04C11DB7
/// with all-ones initialization and final complement. This is not the
/// reflected zlib CRC32.
pub(crate) struct Bzip2Crc32 {
    value: u32,
}

const BZIP2_CRC32_POLY: u32 = 0x04C1_1DB7;

const BZIP2_CRC32_TABLE: [u32; 256] = {
    let mut table = [0_u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = (index as u32) << 24;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 0x8000_0000 != 0 {
                (value << 1) ^ BZIP2_CRC32_POLY
            } else {
                value << 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
};

impl Bzip2Crc32 {
    pub(crate) fn new() -> Self {
        Self { value: !0 }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            let index = usize::from(((self.value >> 24) as u8) ^ byte);
            self.value = (self.value << 8) ^ BZIP2_CRC32_TABLE[index];
        }
    }

    pub(crate) fn finalize(self) -> u32 {
        !self.value
    }
}

/// Fold one block CRC into the running combined CRC exactly as the reference
/// implementation does: rotate left one bit, then XOR.
pub(crate) fn fold_combined_crc(combined: u32, block_crc: u32) -> u32 {
    combined.rotate_left(1) ^ block_crc
}

#[derive(Clone, Copy, Debug)]
struct StreamCompletion {
    consumed_total: u64,
    produced_total: u64,
}

type Completion = Rc<RefCell<Option<Result<StreamCompletion, Bzip2Error>>>>;

/// Decode exactly one restricted bzip2 stream into a private immutable
/// snapshot.
///
/// Concatenated streams, randomized blocks, empty streams, and every other
/// trailing byte are rejected. The caller supplies independent
/// wrapper-metadata and output bounds.
pub(crate) fn decode_single_stream(
    source: &SourceSnapshot<'_>,
    limits: Bzip2Limits,
) -> Result<DecodedBzip2Stream, Bzip2Error> {
    let level = parse_stream_prefix(source)?;

    let decoder = Decompress::new(false);
    let stream_reader = source.reader(0, source.len()).map_err(Bzip2Error::source)?;
    let completion: Completion = Rc::new(RefCell::new(None));
    let reader = Bzip2StreamReader {
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
                return Err(Bzip2Error::new(
                    Bzip2ErrorKind::OutputLimit,
                    FindingCode::QuotaDerived,
                    format!(
                        "bzip2 derived output exceeds the {}-byte cap",
                        limits.max_output_bytes
                    ),
                ));
            }
            return Err(Bzip2Error::source(finding));
        }
    };
    let evidence = completion.borrow().as_ref().cloned().ok_or_else(|| {
        Bzip2Error::structure("bzip2 stream reader ended without completion evidence")
    })??;

    if evidence.consumed_total != source.len() {
        return Err(classify_trailing(source, evidence.consumed_total));
    }
    if evidence.produced_total != output.len() {
        return Err(Bzip2Error::disagreement(
            "the decoder's produced total disagrees with the derived snapshot",
        ));
    }

    let parsed = parse_container(source, limits)?;
    if parsed.block_crcs.len() == 1 {
        let mut hasher = Bzip2Crc32::new();
        let mut reader = output.reader(0, output.len()).map_err(Bzip2Error::source)?;
        let mut chunk = vec![0_u8; DECODE_STEP_BYTES];
        loop {
            let read = reader.read(&mut chunk).map_err(|error| {
                Bzip2Error::structure(format!("bzip2 derived output read failed: {error}"))
            })?;
            if read == 0 {
                break;
            }
            hasher.update(&chunk[..read]);
        }
        if hasher.finalize() != parsed.combined_crc {
            return Err(Bzip2Error::new(
                Bzip2ErrorKind::CheckMismatch,
                FindingCode::CrcMismatch,
                "the single bzip2 block's CRC does not match the derived bytes",
            ));
        }
    }

    Ok(DecodedBzip2Stream {
        level,
        header: ByteRange {
            offset: 0,
            len: STREAM_HEADER_LEN,
        },
        payload_bits: parsed.payload_bits,
        padding_bits: parsed.padding_bits,
        block_bit_offsets: parsed.block_bit_offsets,
        block_crcs: parsed.block_crcs,
        combined_crc: parsed.combined_crc,
        output,
    })
}

/// Decode the original domain and atomically append its verified private
/// output plus the registered bzip2 transformation record.
pub(crate) fn transform_single_stream(
    snapshots: &mut SnapshotSet<'_>,
    transforms: &mut TransformGraph,
    limits: Bzip2Limits,
) -> Result<TransformedBzip2Stream, Bzip2Error> {
    let original_len = snapshots.original().len();
    let decoded = decode_single_stream(snapshots.original(), limits)?;
    let DecodedBzip2Stream {
        level,
        header,
        payload_bits,
        padding_bits,
        block_bit_offsets,
        block_crcs,
        combined_crc,
        output,
    } = decoded;
    let output_len = output.len();
    let output_sha256 = output
        .digest()
        .sha256()
        .expect("private derived bzip2 output always has a SHA-256")
        .to_owned();
    let output_domain = snapshots
        .append_derived_snapshot(
            transforms,
            TransformProfile::Bzip2SingleStreamV1,
            DomainRange::original(ByteRange {
                offset: 0,
                len: original_len,
            }),
            output,
        )
        .map_err(|finding| Bzip2Error {
            kind: Bzip2ErrorKind::TransformAuthority,
            finding,
        })?;
    Ok(TransformedBzip2Stream {
        level,
        header,
        payload_bits,
        padding_bits,
        block_bit_offsets,
        block_crcs,
        combined_crc,
        output_domain,
        output_len,
        output_sha256,
    })
}

/// Parse and validate the fixed-offset stream prefix — header magic, version,
/// level digit, first block magic, and the first `randomised` flag — under
/// the restricted grammar, returning the admitted level.
fn parse_stream_prefix(source: &SourceSnapshot<'_>) -> Result<u8, Bzip2Error> {
    if source.len() < MIN_STREAM_LEN {
        return Err(Bzip2Error::truncated(
            "source is shorter than a bzip2 stream",
        ));
    }
    let mut header = [0_u8; 4];
    read_bytes(source, 0, &mut header)?;
    if header[..2] != *b"BZ" {
        return Err(Bzip2Error::new(
            Bzip2ErrorKind::Magic,
            FindingCode::FormatMagic,
            "source does not begin with the bzip2 stream magic",
        ));
    }
    if header[2] == b'0' {
        return Err(Bzip2Error::unsupported(
            Bzip2ErrorKind::VersionUnsupported,
            "the deprecated bzip1 container is outside the restricted profile",
        ));
    }
    if header[2] != b'h' {
        return Err(Bzip2Error::new(
            Bzip2ErrorKind::Magic,
            FindingCode::FormatMagic,
            "the bzip2 version byte is not the Huffman-coded 'h'",
        ));
    }
    if !header[3].is_ascii_digit() || header[3] == b'0' {
        return Err(Bzip2Error::unsupported(
            Bzip2ErrorKind::LevelBounds,
            "the bzip2 level digit is outside '1'..'9'",
        ));
    }
    let level = header[3] - b'0';

    let mut first = [0_u8; 10];
    read_bytes(source, 4, &mut first)?;
    let first_magic = u64::from_be_bytes([
        0, 0, first[0], first[1], first[2], first[3], first[4], first[5],
    ]);
    if first_magic == EOS_MAGIC {
        return Err(Bzip2Error::unsupported(
            Bzip2ErrorKind::EmptyStream,
            "an empty zero-block bzip2 stream cannot carry a TAR archive",
        ));
    }
    if first_magic != BLOCK_MAGIC {
        return Err(Bzip2Error::structure(
            "the first bzip2 block magic is missing",
        ));
    }
    if source.len() < MIN_STREAM_LEN + 1 {
        return Err(Bzip2Error::truncated(
            "source ends inside the first bzip2 block header",
        ));
    }
    let mut randomised = [0_u8; 1];
    read_bytes(source, 14, &mut randomised)?;
    if randomised[0] & 0x80 != 0 {
        return Err(Bzip2Error::unsupported(
            Bzip2ErrorKind::RandomizedBlock,
            "deprecated randomized bzip2 blocks are outside the restricted profile",
        ));
    }
    Ok(level)
}

struct ParsedContainer {
    payload_bits: u64,
    padding_bits: u8,
    block_bit_offsets: Vec<u64>,
    block_crcs: Vec<u32>,
    combined_crc: u32,
}

/// Bit-exact replay of the complete container over the decoder-established
/// consumed range: unique-shift footer recovery, the full block-magic scan,
/// per-block CRC and flag extraction, and the combined-CRC chain fold.
fn parse_container(
    source: &SourceSnapshot<'_>,
    limits: Bzip2Limits,
) -> Result<ParsedContainer, Bzip2Error> {
    let total_bits = source
        .len()
        .checked_mul(8)
        .ok_or_else(|| Bzip2Error::structure("bzip2 stream bit length overflowed u64"))?;

    // Footer recovery: exactly one padding shift may place the end-of-stream
    // magic and combined CRC flush against the end, and the padding bits
    // themselves must be zero.
    let tail_len = source.len().min(16);
    let tail = read_vec(source, source.len() - tail_len, tail_len)?;
    let mut tail_value = 0_u128;
    for byte in &tail {
        tail_value = (tail_value << 8) | u128::from(*byte);
    }
    let mut footer: Option<(u8, u32)> = None;
    for pad in 0..8_u8 {
        if u64::from(pad) + FOOTER_BITS > tail_len * 8 {
            break;
        }
        let magic = (tail_value >> (u32::from(pad) + 32)) & 0xFFFF_FFFF_FFFF;
        if magic != u128::from(EOS_MAGIC) {
            continue;
        }
        if footer.is_some() {
            return Err(Bzip2Error::structure(
                "bzip2 footer recovery is ambiguous across padding shifts",
            ));
        }
        let combined = ((tail_value >> pad) & 0xFFFF_FFFF) as u32;
        if pad > 0 && tail_value & ((1 << pad) - 1) != 0 {
            return Err(Bzip2Error::structure(
                "bzip2 footer padding bits are not zero",
            ));
        }
        footer = Some((pad, combined));
    }
    let Some((padding_bits, combined_crc)) = footer else {
        return Err(Bzip2Error::structure(
            "no padding shift places the bzip2 end-of-stream magic at the end",
        ));
    };
    let payload_bits = total_bits - u64::from(padding_bits);
    let footer_magic_start = payload_bits - FOOTER_BITS;

    // Full-stream scan for the 48-bit block magic over the block region.
    let block_bit_offsets = scan_block_magics(source, footer_magic_start)?;
    if block_bit_offsets.is_empty() || block_bit_offsets[0] != 32 {
        return Err(Bzip2Error::structure(
            "the bzip2 block-magic scan does not begin at the first block",
        ));
    }
    if block_bit_offsets.len() as u64 > MAX_BLOCKS {
        return Err(Bzip2Error::unsupported(
            Bzip2ErrorKind::BlockBounds,
            format!("bzip2 streams with more than {MAX_BLOCKS} blocks are outside the profile"),
        ));
    }

    let metadata_bits = 32_u64
        + BLOCK_FRAME_BITS * block_bit_offsets.len() as u64
        + FOOTER_BITS
        + u64::from(padding_bits);
    if metadata_bits.div_ceil(8) > limits.max_metadata_bytes {
        return Err(metadata_limit(limits.max_metadata_bytes));
    }

    let mut block_crcs = Vec::with_capacity(block_bit_offsets.len());
    let mut fold = 0_u32;
    for offset in &block_bit_offsets {
        if offset + BLOCK_FRAME_BITS > footer_magic_start {
            return Err(Bzip2Error::structure(
                "a bzip2 block frame overlaps the stream footer",
            ));
        }
        let (crc, randomised) = read_block_frame(source, *offset)?;
        if randomised {
            return Err(Bzip2Error::unsupported(
                Bzip2ErrorKind::RandomizedBlock,
                "deprecated randomized bzip2 blocks are outside the restricted profile",
            ));
        }
        fold = fold_combined_crc(fold, crc);
        block_crcs.push(crc);
    }
    if fold != combined_crc {
        return Err(Bzip2Error::structure(
            "the bzip2 block-CRC chain fold disagrees with the footer combined CRC",
        ));
    }

    Ok(ParsedContainer {
        payload_bits,
        padding_bits,
        block_bit_offsets,
        block_crcs,
        combined_crc,
    })
}

/// Scan bits `[32, footer_magic_start)` for every occurrence of the 48-bit
/// block magic, in increasing bit order, over bounded chunks.
fn scan_block_magics(
    source: &SourceSnapshot<'_>,
    footer_magic_start: u64,
) -> Result<Vec<u64>, Bzip2Error> {
    let mut offsets = Vec::new();
    let mut acc = 0_u64;
    let mut position = 0_u64;
    let len = source.len();
    let mut cursor = 0_u64;
    while cursor < len {
        let step = DECODE_STEP_BYTES.min((len - cursor) as usize) as u64;
        let chunk = read_vec(source, cursor, step)?;
        for byte in &chunk {
            acc = (acc << 8) | u64::from(*byte);
            position += 1;
            let end_bits = position * 8;
            if end_bits < 32 + 48 {
                continue;
            }
            for shift in (0..8_u64).rev() {
                let start = end_bits - shift - 48;
                if start < 32 || start + 48 > footer_magic_start {
                    continue;
                }
                if (acc >> shift) & 0xFFFF_FFFF_FFFF == BLOCK_MAGIC {
                    offsets.push(start);
                    if offsets.len() as u64 > MAX_BLOCKS {
                        return Err(Bzip2Error::unsupported(
                            Bzip2ErrorKind::BlockBounds,
                            format!(
                                "bzip2 streams with more than {MAX_BLOCKS} blocks are outside the profile"
                            ),
                        ));
                    }
                }
            }
        }
        cursor += step;
    }
    Ok(offsets)
}

/// Read one block's 32-bit CRC and its `randomised` flag from the bits
/// immediately after the magic at `bit_offset`.
fn read_block_frame(
    source: &SourceSnapshot<'_>,
    bit_offset: u64,
) -> Result<(u32, bool), Bzip2Error> {
    let crc_start = bit_offset + 48;
    let first_byte = crc_start / 8;
    let mut bytes = [0_u8; 6];
    read_bytes(source, first_byte, &mut bytes)?;
    let mut window = 0_u64;
    for byte in bytes {
        window = (window << 8) | u64::from(byte);
    }
    let lead = crc_start - first_byte * 8;
    let crc = ((window >> (48 - 32 - lead)) & 0xFFFF_FFFF) as u32;
    let randomised = (window >> (48 - 33 - lead)) & 1 != 0;
    Ok((crc, randomised))
}

fn classify_trailing(source: &SourceSnapshot<'_>, consumed: u64) -> Bzip2Error {
    let mut magic = [0_u8; 4];
    let has_magic = consumed
        .checked_add(4)
        .is_some_and(|end| end <= source.len())
        && source.read_exact_at(consumed, &mut magic).is_ok();
    if has_magic && magic[..3] == *b"BZh" && magic[3].is_ascii_digit() && magic[3] != b'0' {
        return Bzip2Error::new(
            Bzip2ErrorKind::ConcatenatedStream,
            FindingCode::CodecBzip2TrailingInput,
            "concatenated bzip2 streams are outside the single-stream profile",
        );
    }
    Bzip2Error::new(
        Bzip2ErrorKind::TrailingInput,
        FindingCode::CodecBzip2TrailingInput,
        "trailing bytes after the bzip2 stream are rejected",
    )
}

fn read_bytes(
    source: &SourceSnapshot<'_>,
    offset: u64,
    buffer: &mut [u8],
) -> Result<(), Bzip2Error> {
    let len = buffer.len() as u64;
    if offset.checked_add(len).is_none_or(|end| end > source.len()) {
        return Err(Bzip2Error::truncated(
            "source ends inside the bzip2 structure",
        ));
    }
    source
        .read_exact_at(offset, buffer)
        .map_err(Bzip2Error::source)
}

fn read_vec(source: &SourceSnapshot<'_>, offset: u64, len: u64) -> Result<Vec<u8>, Bzip2Error> {
    if offset.checked_add(len).is_none_or(|end| end > source.len()) {
        return Err(Bzip2Error::truncated(
            "source ends inside the bzip2 structure",
        ));
    }
    source.read_vec(offset, len).map_err(Bzip2Error::source)
}

struct Bzip2StreamReader<'s, 'a> {
    decoder: Decompress,
    source_reader: SnapshotRangeReader<'s, 'a>,
    input: Vec<u8>,
    input_pos: usize,
    input_done: bool,
    terminal: bool,
    completion: Completion,
}

impl Bzip2StreamReader<'_, '_> {
    fn fail(&self, error: Bzip2Error) -> io::Error {
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

impl Read for Bzip2StreamReader<'_, '_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.terminal {
            return Ok(0);
        }
        loop {
            self.refill()?;
            let before_in = self.decoder.total_in();
            let before_out = self.decoder.total_out();
            let status = self
                .decoder
                .decompress(&self.input[self.input_pos..], buffer)
                .map_err(|error| self.fail(classify_decoder_error(error)))?;
            let consumed = (self.decoder.total_in() - before_in) as usize;
            let produced = (self.decoder.total_out() - before_out) as usize;
            self.input_pos += consumed;
            if status == Status::StreamEnd {
                self.terminal = true;
                *self.completion.borrow_mut() = Some(Ok(StreamCompletion {
                    consumed_total: self.decoder.total_in(),
                    produced_total: self.decoder.total_out(),
                }));
                return Ok(produced);
            }
            if produced > 0 {
                return Ok(produced);
            }
            if self.input_done && consumed == 0 {
                return Err(self.fail(Bzip2Error::truncated(
                    "the bzip2 stream ended before its footer",
                )));
            }
        }
    }
}

fn classify_read_error(error: &io::Error) -> Bzip2Error {
    crate::snapshot::finding_from_io(error).map_or_else(
        || Bzip2Error::structure(format!("bzip2 source read failed: {error}")),
        Bzip2Error::source,
    )
}

fn classify_decoder_error(error: ::bzip2::Error) -> Bzip2Error {
    match error {
        ::bzip2::Error::DataMagic => Bzip2Error::new(
            Bzip2ErrorKind::Magic,
            FindingCode::FormatMagic,
            "the bzip2 decoder rejected the stream magic",
        ),
        // libbz2's BZ_DATA_ERROR covers both structural corruption and CRC
        // mismatch without distinguishing them; Sealr's own container replay
        // and single-block re-hash carry the precise classifications it can
        // establish independently.
        ::bzip2::Error::Data => {
            Bzip2Error::structure("the bzip2 decoder reported invalid stream data")
        }
        ::bzip2::Error::Sequence | ::bzip2::Error::Param => {
            Bzip2Error::structure("the bzip2 decoder rejected its driving sequence")
        }
    }
}

/// Test-only fixtures shared by unit and composite tests: pinned producer
/// bytes and the deterministic conformance inputs they decode to.
#[cfg(test)]
pub(crate) mod test_support {
    /// CPython 3.12.10 `bz2.compress(tar, 9)` over the standard conformance
    /// derived TAR (bundled libbz2 1.0.8; byte-identical to `bzip2 -9`).
    pub(crate) const BZ2_CLI_LEVEL9_HEX: &str = "425a68393141592653597b1dc2a70000447b91ca000040\
        4005ff0040006f27dfe0040000400008200074226a64f51a64d0340640c4d064a0d341a680034d001e65\
        87e2308c005913503e46a2880842162fc4d83544cc801bd752180f90d0c026e224716664838d467b58fb\
        fac1cf118147687b09c160a4ad2080f498e75a99561f215194f509f0637e2ee48a70a120f63b854e";

    /// `bz2.compress(tar, 1)`: identical compressed body, level digit '1'.
    pub(crate) const BZ2_CLI_LEVEL1_HEX: &str = "425a68313141592653597b1dc2a70000447b91ca000040\
        4005ff0040006f27dfe0040000400008200074226a64f51a64d0340640c4d064a0d341a680034d001e65\
        87e2308c005913503e46a2880842162fc4d83544cc801bd752180f90d0c026e224716664838d467b58fb\
        fac1cf118147687b09c160a4ad2080f498e75a99561f215194f509f0637e2ee48a70a120f63b854e";

    /// `bz2.compress(multiblock_tar(), 1)`: three level-1 blocks over the
    /// 261,120-byte compressible telemetry TAR.
    pub(crate) const BZ2_CLI_MULTIBLOCK_HEX: &str = "425a6831314159265359957b66fa007a18fd906810\
        00404005ff8800087fe79fa00400400238d00018c9a640c9a1906469811832534d00d0006800009aaa13\
        54dea9ed23d536a068f53d4c9ea7a9e48632699032686419
1a60467f6e5ae7ba9e38b6e99b360bc648962e4489779225b1225cc912c8912d4912c0912dc4897dc912ea48\
        9624890428820824109cd518019338016b0d68548982dad2d8516b57e6c31d3c3d36244b2b0244bd3d49\
        12d9244bf84897992259922581225d4912dc489748912f81225d0912d24896048975244b2244b2ebd9244\
        b7781225a1225a922586f244bc2244bb9225ec4896448972d3cbdb792258ebbe88977244b81225d8912e0\
        4897c8912d0912db3c4912f2b4bb922591225a6a48973e78c912c8912e3c4912e3aedad97ac912edc2244\
        b7e04896648977f7f7922599225c0912cc912f34912ec48961c648972ff98a0ac9329ace1ea564d802e1c\
        2cc00008200280041ff1cfd02000ec000283468d0640685068d1a0c80d04d5529fa4c4d4da9a69a3ca141\
        a346832034c2225dd112e9112ec8897cd112c5112f1444b2444b3a225b2225ee8897c22258288971444b7\
        9112f28897a444b3444b2a225f8889668897a5112d1112f48897ea22592225ee88961112e5112db2a225a\
        d112da8896e88967444b65112e9112e5112c5112d288968889748896b444b9a225ad112f088968a225d22\
        2595112f32225da88977a225f688967152aadd112e9112d2889708896288970a225fc8896e8897f98a0ac\
        9329acf6a878ea80128aece06008200280041ff1cfd0100000042000deeaa51453468034000
14d1a00d000026aa91a3468000d014aaa79194c8f51868326f30c11c62a2fc1516d151662a2d1429ad429cd4\
        29854298a8533151788a8b0151628545ff150e2a853b5429e2a14c6a14c2a12dfc0a8b88a8b5854598a8b\
        514a7c50a6150a7b50a6ba85345429b542992853854299a85372aa8b71516c2a2c62a2ca2a2c80a7ea853\
        250a68a14c9429c6a14daa853f542982853aaa14d8a14dea14eca14c549159d429b0a8b28a8b415163151\
        688a87ba853350a693f8bb9229c28481f8a198400";

    /// `bz2.compress(b"", 9)`: the legal 14-byte zero-block stream.
    pub(crate) const BZ2_EMPTY_HEX: &str = "425a683917724538509000000000";

    /// `bz2.compress` of plain non-TAR text.
    pub(crate) const BZ2_NON_TAR_HEX: &str = "425a683931415926535993c898e900001391804004\
        2af7df402000545323234680f41aa7a9b269369b5353450dddd94a39cce5119018e5943f34621e3d5b0a\
        3353890f80d37a00ac52aa076817724538509093c898e9";

    pub(crate) fn decode_hex(value: &str) -> Vec<u8> {
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

    fn write_octal(field: &mut [u8], value: u64) {
        field.fill(b'0');
        let octal = format!("{value:o}");
        let digits = field.len() - 1;
        field[digits - octal.len()..digits].copy_from_slice(octal.as_bytes());
        field[digits] = 0;
    }

    pub(crate) fn ustar(name: &str, body: &[u8]) -> Vec<u8> {
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

    pub(crate) fn conformance_tar() -> Vec<u8> {
        ustar("mission/plan.txt", b"verify twice, decode once")
    }

    pub(crate) fn multiblock_tar() -> Vec<u8> {
        let line = b"verify twice, decode once; the boundary owns the meaning of every byte.\n";
        let mut body = Vec::with_capacity(line.len() * 3600);
        for _ in 0..3600 {
            body.extend_from_slice(line);
        }
        ustar("mission/telemetry.log", &body)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{
        conformance_tar, decode_hex, multiblock_tar, BZ2_CLI_LEVEL1_HEX, BZ2_CLI_LEVEL9_HEX,
        BZ2_CLI_MULTIBLOCK_HEX, BZ2_EMPTY_HEX, BZ2_NON_TAR_HEX,
    };
    use super::*;

    fn snapshot(bytes: &[u8]) -> SourceSnapshot<'_> {
        SourceSnapshot::borrowed(None, bytes)
    }

    fn limits() -> Bzip2Limits {
        Bzip2Limits {
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
    fn the_pinned_level_nine_stream_decodes_with_exact_wrapper_evidence() {
        let source = decode_hex(BZ2_CLI_LEVEL9_HEX);
        let decoded = decode_single_stream(&snapshot(&source), limits()).unwrap();
        assert_eq!(decoded.level, 9);
        assert_eq!(decoded.header, ByteRange { offset: 0, len: 4 });
        assert_eq!(decoded.block_bit_offsets, vec![32]);
        assert_eq!(decoded.block_crcs.len(), 1);
        assert_eq!(decoded.combined_crc, decoded.block_crcs[0]);
        assert_eq!(
            decoded.payload_bits + u64::from(decoded.padding_bits),
            source.len() as u64 * 8
        );
        let tar = conformance_tar();
        assert_eq!(output_bytes(&decoded.output), tar);
        let mut hasher = Bzip2Crc32::new();
        hasher.update(&tar);
        assert_eq!(hasher.finalize(), decoded.combined_crc);
    }

    #[test]
    fn levels_change_only_the_header_digit_for_small_inputs() {
        let nine = decode_hex(BZ2_CLI_LEVEL9_HEX);
        let one = decode_hex(BZ2_CLI_LEVEL1_HEX);
        assert_eq!(nine[4..], one[4..]);
        let decoded = decode_single_stream(&snapshot(&one), limits()).unwrap();
        assert_eq!(decoded.level, 1);
        assert_eq!(output_bytes(&decoded.output), conformance_tar());
    }

    #[test]
    fn the_pinned_multiblock_stream_chain_folds_across_three_blocks() {
        let source = decode_hex(BZ2_CLI_MULTIBLOCK_HEX);
        let decoded = decode_single_stream(&snapshot(&source), limits()).unwrap();
        assert_eq!(decoded.level, 1);
        assert_eq!(decoded.block_bit_offsets, vec![32, 2641, 4421]);
        assert_eq!(decoded.block_crcs.len(), 3);
        let fold = decoded
            .block_crcs
            .iter()
            .fold(0_u32, |fold, crc| fold_combined_crc(fold, *crc));
        assert_eq!(fold, decoded.combined_crc);
        assert_eq!(output_bytes(&decoded.output), multiblock_tar());
    }

    #[test]
    fn non_bzip2_prefixes_classify_as_magic_version_or_level_failures() {
        let error =
            decode_single_stream(&snapshot(b"not a bzip2 stream at all"), limits()).unwrap_err();
        assert_eq!(error.kind, Bzip2ErrorKind::Magic);
        assert_eq!(error.finding().code, FindingCode::FormatMagic);

        let mut bzip1 = decode_hex(BZ2_CLI_LEVEL9_HEX);
        bzip1[2] = b'0';
        let error = decode_single_stream(&snapshot(&bzip1), limits()).unwrap_err();
        assert_eq!(error.kind, Bzip2ErrorKind::VersionUnsupported);
        assert_eq!(error.finding().code, FindingCode::FormatUnsupported);

        let mut level = decode_hex(BZ2_CLI_LEVEL9_HEX);
        level[3] = b'0';
        let error = decode_single_stream(&snapshot(&level), limits()).unwrap_err();
        assert_eq!(error.kind, Bzip2ErrorKind::LevelBounds);

        let mut short = decode_hex(BZ2_CLI_LEVEL9_HEX);
        short.truncate(10);
        let error = decode_single_stream(&snapshot(&short), limits()).unwrap_err();
        assert_eq!(error.kind, Bzip2ErrorKind::Truncated);
    }

    #[test]
    fn empty_zero_block_streams_are_unsupported() {
        let source = decode_hex(BZ2_EMPTY_HEX);
        let error = decode_single_stream(&snapshot(&source), limits()).unwrap_err();
        assert_eq!(error.kind, Bzip2ErrorKind::EmptyStream);
        assert_eq!(error.finding().code, FindingCode::FormatUnsupported);
    }

    #[test]
    fn randomized_first_blocks_are_unsupported_before_decoding() {
        let mut source = decode_hex(BZ2_CLI_LEVEL9_HEX);
        source[14] |= 0x80;
        let error = decode_single_stream(&snapshot(&source), limits()).unwrap_err();
        assert_eq!(error.kind, Bzip2ErrorKind::RandomizedBlock);
        assert_eq!(error.finding().code, FindingCode::FormatUnsupported);
    }

    #[test]
    fn truncated_streams_fail_closed_before_any_container_claim() {
        let mut source = decode_hex(BZ2_CLI_LEVEL9_HEX);
        source.truncate(source.len() / 2);
        let error = decode_single_stream(&snapshot(&source), limits()).unwrap_err();
        assert_eq!(error.kind, Bzip2ErrorKind::Truncated);
        assert_eq!(error.finding().code, FindingCode::CodecBzip2InvalidStream);
    }

    #[test]
    fn corrupted_payload_bytes_classify_as_stream_structure() {
        let mut source = decode_hex(BZ2_CLI_LEVEL9_HEX);
        let middle = source.len() / 2;
        source[middle] ^= 0x40;
        let error = decode_single_stream(&snapshot(&source), limits()).unwrap_err();
        assert_eq!(error.kind, Bzip2ErrorKind::StreamStructure);
        assert_eq!(error.finding().code, FindingCode::CodecBzip2InvalidStream);
    }

    #[test]
    fn trailing_bytes_and_concatenated_streams_classify_separately() {
        let member = decode_hex(BZ2_CLI_LEVEL9_HEX);

        let mut trailing = member.clone();
        trailing.push(0x7F);
        let error = decode_single_stream(&snapshot(&trailing), limits()).unwrap_err();
        assert_eq!(error.kind, Bzip2ErrorKind::TrailingInput);
        assert_eq!(error.finding().code, FindingCode::CodecBzip2TrailingInput);

        let concatenated = [member.clone(), member].concat();
        let error = decode_single_stream(&snapshot(&concatenated), limits()).unwrap_err();
        assert_eq!(error.kind, Bzip2ErrorKind::ConcatenatedStream);
        assert_eq!(error.finding().code, FindingCode::CodecBzip2TrailingInput);
    }

    #[test]
    fn output_and_metadata_caps_deny_before_admission() {
        let source = decode_hex(BZ2_CLI_LEVEL9_HEX);
        let error = decode_single_stream(
            &snapshot(&source),
            Bzip2Limits {
                max_metadata_bytes: 1024 * 1024,
                max_output_bytes: 100,
            },
        )
        .unwrap_err();
        assert_eq!(error.kind, Bzip2ErrorKind::OutputLimit);
        assert_eq!(error.finding().code, FindingCode::QuotaDerived);

        let error = decode_single_stream(
            &snapshot(&source),
            Bzip2Limits {
                max_metadata_bytes: 20,
                max_output_bytes: 4 * 1024 * 1024,
            },
        )
        .unwrap_err();
        assert_eq!(error.kind, Bzip2ErrorKind::HeaderLimit);
        assert_eq!(error.finding().code, FindingCode::QuotaMetadata);
    }

    #[test]
    fn non_tar_content_still_decodes_at_the_codec_layer() {
        let source = decode_hex(BZ2_NON_TAR_HEX);
        let decoded = decode_single_stream(&snapshot(&source), limits()).unwrap();
        assert_eq!(
            output_bytes(&decoded.output),
            b"not a tar archive at all, just plain text long enough to matter"
        );
    }

    #[test]
    fn the_transform_registers_the_derived_domain_and_binds_both_identities() {
        let source = decode_hex(BZ2_CLI_LEVEL9_HEX);
        let snapshot = SourceSnapshot::borrowed(None, &source);
        let mut snapshots = SnapshotSet::from_original(snapshot);
        let mut transforms = TransformGraph::empty();
        let transformed =
            transform_single_stream(&mut snapshots, &mut transforms, limits()).unwrap();
        assert_eq!(transformed.output_domain, SnapshotDomainId::FIRST_DERIVED);
        assert_eq!(transformed.output_len, 2048);
        assert_eq!(
            transformed.output_sha256,
            crate::policy::hex_sha256(&conformance_tar())
        );
        assert_eq!(snapshots.len(), 2);
        assert_eq!(transforms.records().len(), 1);
        assert!(transforms.validates(&snapshots));
        assert_eq!(
            transforms.records()[0].profile,
            TransformProfile::Bzip2SingleStreamV1
        );
    }
}
