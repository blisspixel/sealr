//! Strict, bounded RFC 8878 single-frame decoding.
//!
//! This module is deliberately crate-private until the wrapper profile and its
//! transformation identity are part of the public admission contract.
//!
//! Sealr parses the frame header itself for byte-exact evidence and grammar
//! enforcement, then drives one bounded `ruzstd` frame decode over the same
//! bytes. The two header interpretations are cross-checked and any
//! disagreement fails closed: neither parser's reading is ever preferred
//! silently.

use std::cell::RefCell;
use std::io::{self, Read};
use std::rc::Rc;

use ruzstd::decoding::errors::{FrameDecoderError, FrameHeaderError, ReadFrameHeaderError};
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};

use crate::findings::{Finding, FindingCode};
use crate::ir::ByteRange;
use crate::snapshot::{
    as_io_error, finding_from_io, DomainRange, SnapshotDomainId, SnapshotRangeReader, SnapshotSet,
    SourceSnapshot, TransformGraph, TransformProfile,
};

const MAGIC: u32 = 0xFD2F_B528;
const SKIPPABLE_MAGIC_FIRST: u32 = 0x184D_2A50;
const SKIPPABLE_MAGIC_LAST: u32 = 0x184D_2A5F;
/// RFC 8878 interoperability ceiling: decoders should support windows up to
/// 8 MiB, and this restricted profile refuses anything larger.
pub(crate) const MAX_WINDOW_BYTES: u64 = 8 * 1024 * 1024;
const MIN_WINDOW_BYTES: u64 = 1024;
const CHECKSUM_LEN: u64 = 4;
const BLOCK_DECODE_STEP_BYTES: usize = 64 * 1024;

const DESCRIPTOR_SINGLE_SEGMENT: u8 = 1 << 5;
const DESCRIPTOR_UNUSED: u8 = 1 << 4;
const DESCRIPTOR_RESERVED: u8 = 1 << 3;
const DESCRIPTOR_CHECKSUM: u8 = 1 << 2;
const DESCRIPTOR_DICTIONARY_ID: u8 = 0b0000_0011;

/// Resource limits for the private Zstandard transformation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ZstdLimits {
    /// Maximum wrapper metadata bytes. This covers the frame header plus the
    /// optional four-byte content-checksum trailer; block headers are part of
    /// the compressed payload accounting.
    pub(crate) max_metadata_bytes: u64,
    /// Maximum number of decoded bytes copied to the private snapshot.
    pub(crate) max_output_bytes: u64,
}

/// Exact byte ranges and fixed fields established before block decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ZstdFrameHeader {
    pub(crate) descriptor: u8,
    pub(crate) single_segment: bool,
    pub(crate) checksum_flag: bool,
    pub(crate) window_descriptor: Option<u8>,
    /// The effective window authorization: the descriptor formula for windowed
    /// frames, or the frame content size for single-segment frames.
    pub(crate) window_size: u64,
    pub(crate) frame_content_size: Option<u64>,
    pub(crate) header: ByteRange,
}

/// A fully verified single Zstandard frame and its bounded private output.
#[derive(Debug)]
pub(crate) struct DecodedZstdFrame {
    pub(crate) header: ZstdFrameHeader,
    /// Every block header and block body between the frame header and trailer.
    pub(crate) compressed_payload: ByteRange,
    /// The four-byte content checksum, or an empty terminal range.
    pub(crate) trailer: ByteRange,
    pub(crate) declared_checksum: Option<u32>,
    pub(crate) output: SourceSnapshot<'static>,
}

/// Verified wrapper evidence after the output has become a retained snapshot
/// domain and the transformation graph has bound both byte identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransformedZstdFrame {
    pub(crate) header: ZstdFrameHeader,
    pub(crate) compressed_payload: ByteRange,
    pub(crate) trailer: ByteRange,
    pub(crate) declared_checksum: Option<u32>,
    pub(crate) output_domain: SnapshotDomainId,
    pub(crate) output_len: u64,
    pub(crate) output_sha256: String,
}

/// Internal failure classes kept distinct before they are mapped to the
/// repository's stable finding vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ZstdErrorKind {
    Source,
    Truncated,
    Magic,
    SkippableFrame,
    ReservedBits,
    Dictionary,
    WindowBounds,
    HeaderLimit,
    FrameStream,
    ConcatenatedFrame,
    TrailingInput,
    DataChecksum,
    DeclaredSize,
    OutputLimit,
    DecoderDisagreement,
    TransformAuthority,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ZstdError {
    pub(crate) kind: ZstdErrorKind,
    finding: Finding,
}

impl ZstdError {
    pub(crate) fn finding(&self) -> &Finding {
        &self.finding
    }

    pub(crate) fn into_finding(self) -> Finding {
        self.finding
    }

    fn new(kind: ZstdErrorKind, code: FindingCode, detail: impl Into<String>) -> Self {
        Self {
            kind,
            finding: Finding::error(code, detail),
        }
    }

    fn source(finding: Finding) -> Self {
        Self {
            kind: ZstdErrorKind::Source,
            finding,
        }
    }

    fn truncated(detail: impl Into<String>) -> Self {
        Self::new(
            ZstdErrorKind::Truncated,
            FindingCode::CodecZstdInvalidFrame,
            detail,
        )
    }

    fn frame(detail: impl Into<String>) -> Self {
        Self::new(
            ZstdErrorKind::FrameStream,
            FindingCode::CodecZstdInvalidFrame,
            detail,
        )
    }

    fn disagreement(detail: impl Into<String>) -> Self {
        Self::new(
            ZstdErrorKind::DecoderDisagreement,
            FindingCode::CoveringInconsistent,
            detail,
        )
    }
}

fn metadata_limit(max_metadata_bytes: u64) -> ZstdError {
    ZstdError::new(
        ZstdErrorKind::HeaderLimit,
        FindingCode::QuotaMetadata,
        format!("zstd wrapper metadata exceeds the {max_metadata_bytes}-byte cap"),
    )
}

#[derive(Clone, Copy, Debug)]
struct FrameCompletion {
    consumed_total: u64,
    declared_checksum: Option<u32>,
}

type Completion = Rc<RefCell<Option<Result<FrameCompletion, ZstdError>>>>;

/// Decode exactly one RFC 8878 frame into a private immutable snapshot.
///
/// Skippable frames, dictionaries, oversized windows, concatenated frames,
/// and every other trailing byte are rejected. The caller supplies
/// independent wrapper-metadata and output bounds.
pub(crate) fn decode_single_frame(
    source: &SourceSnapshot<'_>,
    limits: ZstdLimits,
) -> Result<DecodedZstdFrame, ZstdError> {
    let header = parse_frame_header(source)?;
    let trailer_len = if header.checksum_flag {
        CHECKSUM_LEN
    } else {
        0
    };
    let wrapper_metadata = header
        .header
        .len
        .checked_add(trailer_len)
        .ok_or_else(|| metadata_limit(limits.max_metadata_bytes))?;
    if wrapper_metadata > limits.max_metadata_bytes {
        return Err(metadata_limit(limits.max_metadata_bytes));
    }

    let mut decoder = FrameDecoder::new();
    decoder.set_max_window_size(MAX_WINDOW_BYTES);
    let mut frame_reader = source.reader(0, source.len()).map_err(ZstdError::source)?;
    decoder
        .init(&mut frame_reader)
        .map_err(classify_decoder_error)?;
    if decoder.bytes_read_from_source() != header.header.len {
        return Err(ZstdError::disagreement(
            "the decoder consumed a different zstd frame-header length",
        ));
    }
    match header.frame_content_size {
        Some(declared) if decoder.content_size() != declared => {
            return Err(ZstdError::disagreement(
                "the decoder read a different declared zstd frame content size",
            ));
        }
        None if decoder.content_size() != 0 => {
            return Err(ZstdError::disagreement(
                "the decoder invented a zstd frame content size",
            ));
        }
        _ => {}
    }

    let completion: Completion = Rc::new(RefCell::new(None));
    let reader = ZstdFrameReader {
        decoder,
        source_reader: frame_reader,
        checksum_flag: header.checksum_flag,
        frame_content_size: header.frame_content_size,
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
                return Err(ZstdError::new(
                    ZstdErrorKind::OutputLimit,
                    FindingCode::QuotaDerived,
                    format!(
                        "zstd derived output exceeds the {}-byte cap",
                        limits.max_output_bytes
                    ),
                ));
            }
            return Err(ZstdError::source(finding));
        }
    };

    let evidence =
        completion.borrow().as_ref().cloned().ok_or_else(|| {
            ZstdError::frame("zstd frame reader ended without completion evidence")
        })??;

    let payload_end = evidence
        .consumed_total
        .checked_sub(trailer_len)
        .filter(|end| *end >= header.header.len)
        .ok_or_else(|| {
            ZstdError::disagreement("zstd frame consumption does not cover header and trailer")
        })?;
    if evidence.consumed_total != source.len() {
        return Err(classify_trailing(source, evidence.consumed_total));
    }

    Ok(DecodedZstdFrame {
        compressed_payload: ByteRange {
            offset: header.header.len,
            len: payload_end - header.header.len,
        },
        trailer: ByteRange {
            offset: payload_end,
            len: trailer_len,
        },
        declared_checksum: evidence.declared_checksum,
        header,
        output,
    })
}

/// Decode the original domain and atomically append its verified private
/// output plus the registered RFC 8878 transformation record.
pub(crate) fn transform_single_frame(
    snapshots: &mut SnapshotSet<'_>,
    transforms: &mut TransformGraph,
    limits: ZstdLimits,
) -> Result<TransformedZstdFrame, ZstdError> {
    let original_len = snapshots.original().len();
    let decoded = decode_single_frame(snapshots.original(), limits)?;
    let DecodedZstdFrame {
        header,
        compressed_payload,
        trailer,
        declared_checksum,
        output,
    } = decoded;
    let output_len = output.len();
    let output_sha256 = output
        .digest()
        .sha256()
        .expect("private derived zstd output always has a SHA-256")
        .to_owned();
    let output_domain = snapshots
        .append_derived_snapshot(
            transforms,
            TransformProfile::ZstdRfc8878SingleFrameV1,
            DomainRange::original(ByteRange {
                offset: 0,
                len: original_len,
            }),
            output,
        )
        .map_err(|finding| ZstdError {
            kind: ZstdErrorKind::TransformAuthority,
            finding,
        })?;
    Ok(TransformedZstdFrame {
        header,
        compressed_payload,
        trailer,
        declared_checksum,
        output_domain,
        output_len,
        output_sha256,
    })
}

/// Parse the frame header byte-exactly under the restricted grammar.
fn parse_frame_header(source: &SourceSnapshot<'_>) -> Result<ZstdFrameHeader, ZstdError> {
    let mut magic = [0_u8; 4];
    read_header_bytes(source, 0, &mut magic)?;
    let magic = u32::from_le_bytes(magic);
    if (SKIPPABLE_MAGIC_FIRST..=SKIPPABLE_MAGIC_LAST).contains(&magic) {
        return Err(ZstdError::new(
            ZstdErrorKind::SkippableFrame,
            FindingCode::FormatUnsupported,
            "zstd skippable frames are outside the single-frame profile",
        ));
    }
    if magic != MAGIC {
        return Err(ZstdError::new(
            ZstdErrorKind::Magic,
            FindingCode::FormatMagic,
            "source does not begin with the zstd frame magic",
        ));
    }

    let mut descriptor = [0_u8; 1];
    read_header_bytes(source, 4, &mut descriptor)?;
    let descriptor = descriptor[0];
    if descriptor & DESCRIPTOR_RESERVED != 0 {
        return Err(ZstdError::new(
            ZstdErrorKind::ReservedBits,
            FindingCode::FormatUnsupported,
            "the reserved zstd frame-descriptor bit is set",
        ));
    }
    if descriptor & DESCRIPTOR_UNUSED != 0 {
        return Err(ZstdError::new(
            ZstdErrorKind::ReservedBits,
            FindingCode::FormatUnsupported,
            "the unused zstd frame-descriptor bit is outside the restricted profile",
        ));
    }
    if descriptor & DESCRIPTOR_DICTIONARY_ID != 0 {
        return Err(ZstdError::new(
            ZstdErrorKind::Dictionary,
            FindingCode::FormatUnsupported,
            "zstd dictionaries are outside the restricted profile",
        ));
    }
    let single_segment = descriptor & DESCRIPTOR_SINGLE_SEGMENT != 0;
    let checksum_flag = descriptor & DESCRIPTOR_CHECKSUM != 0;
    let fcs_flag = descriptor >> 6;

    let mut offset = 5_u64;
    let window_descriptor = if single_segment {
        None
    } else {
        let mut window = [0_u8; 1];
        read_header_bytes(source, offset, &mut window)?;
        offset += 1;
        Some(window[0])
    };

    let fcs_len = match (fcs_flag, single_segment) {
        (0, false) => 0_u64,
        (0, true) => 1,
        (1, _) => 2,
        (2, _) => 4,
        (3, _) => 8,
        _ => unreachable!("a two-bit flag has four values"),
    };
    let frame_content_size = if fcs_len == 0 {
        None
    } else {
        let mut fcs_bytes = [0_u8; 8];
        read_header_bytes(source, offset, &mut fcs_bytes[..fcs_len as usize])?;
        offset += fcs_len;
        let mut value = u64::from_le_bytes(fcs_bytes);
        if fcs_len == 2 {
            value += 256;
        }
        Some(value)
    };

    let window_size = match window_descriptor {
        Some(window) => {
            let exponent = u64::from(window >> 3);
            let mantissa = u64::from(window & 0x7);
            let window_base = 1_u64 << (10 + exponent);
            window_base + (window_base / 8) * mantissa
        }
        None => frame_content_size.expect("single-segment frames always declare a content size"),
    };
    if !single_segment && window_size < MIN_WINDOW_BYTES {
        return Err(ZstdError::new(
            ZstdErrorKind::WindowBounds,
            FindingCode::FormatUnsupported,
            format!("zstd window of {window_size} bytes is below the {MIN_WINDOW_BYTES}-byte spec minimum"),
        ));
    }
    if window_size > MAX_WINDOW_BYTES {
        return Err(ZstdError::new(
            ZstdErrorKind::WindowBounds,
            FindingCode::FormatUnsupported,
            format!("zstd window of {window_size} bytes exceeds the {MAX_WINDOW_BYTES}-byte profile ceiling"),
        ));
    }

    Ok(ZstdFrameHeader {
        descriptor,
        single_segment,
        checksum_flag,
        window_descriptor,
        window_size,
        frame_content_size,
        header: ByteRange {
            offset: 0,
            len: offset,
        },
    })
}

fn read_header_bytes(
    source: &SourceSnapshot<'_>,
    offset: u64,
    buffer: &mut [u8],
) -> Result<(), ZstdError> {
    let len = buffer.len() as u64;
    if offset.checked_add(len).is_none_or(|end| end > source.len()) {
        return Err(ZstdError::truncated(
            "source ends inside the zstd frame header",
        ));
    }
    source
        .read_exact_at(offset, buffer)
        .map_err(finding_from_io_result)
}

fn finding_from_io_result(finding: Finding) -> ZstdError {
    if finding.code == FindingCode::SourceIo {
        ZstdError::source(finding)
    } else {
        ZstdError {
            kind: ZstdErrorKind::Source,
            finding,
        }
    }
}

struct ZstdFrameReader<'s, 'a> {
    decoder: FrameDecoder,
    source_reader: SnapshotRangeReader<'s, 'a>,
    checksum_flag: bool,
    frame_content_size: Option<u64>,
    output_len: u64,
    terminal: bool,
    completion: Completion,
}

impl ZstdFrameReader<'_, '_> {
    fn fail(&self, error: ZstdError) -> io::Error {
        let finding = error.finding().clone();
        *self.completion.borrow_mut() = Some(Err(error));
        as_io_error(finding)
    }

    fn finish(&mut self) -> Result<(), io::Error> {
        let declared = self.decoder.get_checksum_from_data();
        if self.checksum_flag {
            let declared = declared.ok_or_else(|| {
                self.fail(ZstdError::disagreement(
                    "the decoder finished a checksummed zstd frame without a declared checksum",
                ))
            })?;
            let calculated = self.decoder.get_calculated_checksum().ok_or_else(|| {
                self.fail(ZstdError::disagreement(
                    "the decoder finished a checksummed zstd frame without a computed checksum",
                ))
            })?;
            if declared != calculated {
                return Err(self.fail(ZstdError::new(
                    ZstdErrorKind::DataChecksum,
                    FindingCode::CrcMismatch,
                    "zstd content checksum does not match the decoded bytes",
                )));
            }
        } else if declared.is_some() {
            return Err(self.fail(ZstdError::disagreement(
                "the decoder read a checksum for a zstd frame that declares none",
            )));
        }
        if let Some(declared) = self.frame_content_size {
            if self.output_len != declared {
                return Err(self.fail(ZstdError::new(
                    ZstdErrorKind::DeclaredSize,
                    FindingCode::QuotaDeclaredLie,
                    format!(
                        "zstd frame content size declares {declared} bytes but {} were decoded",
                        self.output_len
                    ),
                )));
            }
        }
        *self.completion.borrow_mut() = Some(Ok(FrameCompletion {
            consumed_total: self.decoder.bytes_read_from_source(),
            declared_checksum: if self.checksum_flag { declared } else { None },
        }));
        Ok(())
    }
}

impl Read for ZstdFrameReader<'_, '_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let drained = self
                .decoder
                .read(buffer)
                .map_err(|error| self.fail(classify_drain_error(&error)))?;
            if drained > 0 {
                self.output_len = self.output_len.checked_add(drained as u64).ok_or_else(|| {
                    self.fail(ZstdError::frame(
                        "zstd decoded output length overflowed u64",
                    ))
                })?;
                return Ok(drained);
            }
            if self.decoder.is_finished() {
                if !self.terminal {
                    self.finish()?;
                    self.terminal = true;
                }
                return Ok(0);
            }
            self.decoder
                .decode_blocks(
                    &mut self.source_reader,
                    BlockDecodingStrategy::UptoBytes(BLOCK_DECODE_STEP_BYTES),
                )
                .map_err(|error| self.fail(classify_decoder_error(error)))?;
        }
    }
}

fn classify_drain_error(error: &io::Error) -> ZstdError {
    finding_from_io(error).map_or_else(
        || ZstdError::frame(format!("zstd decode buffer drain failed: {error}")),
        ZstdError::source,
    )
}

fn classify_decoder_error(error: FrameDecoderError) -> ZstdError {
    match &error {
        FrameDecoderError::ReadFrameHeaderError(header_error) => match header_error {
            ReadFrameHeaderError::SkipFrame { .. } => ZstdError::new(
                ZstdErrorKind::SkippableFrame,
                FindingCode::FormatUnsupported,
                "zstd skippable frames are outside the single-frame profile",
            ),
            ReadFrameHeaderError::BadMagicNumber(_) => ZstdError::new(
                ZstdErrorKind::Magic,
                FindingCode::FormatMagic,
                "source does not begin with the zstd frame magic",
            ),
            ReadFrameHeaderError::MagicNumberReadError(io_error)
            | ReadFrameHeaderError::FrameDescriptorReadError(io_error)
            | ReadFrameHeaderError::WindowDescriptorReadError(io_error)
            | ReadFrameHeaderError::DictionaryIdReadError(io_error)
            | ReadFrameHeaderError::FrameContentSizeReadError(io_error) => {
                source_or(io_error, || {
                    ZstdError::truncated("source ends inside the zstd frame header")
                })
            }
            ReadFrameHeaderError::InvalidFrameDescriptor(_) => {
                ZstdError::frame(format!("invalid zstd frame descriptor: {error}"))
            }
            _ => ZstdError::frame(format!("invalid zstd frame header: {error}")),
        },
        FrameDecoderError::FrameHeaderError(header_error) => match header_error {
            FrameHeaderError::WindowTooBig { .. } | FrameHeaderError::WindowTooSmall { .. } => {
                ZstdError::new(
                    ZstdErrorKind::WindowBounds,
                    FindingCode::FormatUnsupported,
                    format!("zstd window is outside the supported bounds: {error}"),
                )
            }
            _ => ZstdError::frame(format!("invalid zstd frame header: {error}")),
        },
        FrameDecoderError::WindowSizeTooBig { .. } => ZstdError::new(
            ZstdErrorKind::WindowBounds,
            FindingCode::FormatUnsupported,
            format!("zstd window exceeds the profile ceiling: {error}"),
        ),
        FrameDecoderError::DictNotProvided { .. } => ZstdError::new(
            ZstdErrorKind::Dictionary,
            FindingCode::FormatUnsupported,
            "zstd dictionaries are outside the restricted profile",
        ),
        FrameDecoderError::FailedToReadChecksum(io_error) => source_or(io_error, || {
            ZstdError::truncated("source ends inside the zstd content checksum")
        }),
        FrameDecoderError::FailedToReadBlockHeader(_)
        | FrameDecoderError::FailedToReadBlockBody(_) => {
            if let Some(finding) = nested_source_finding(&error) {
                ZstdError::source(finding)
            } else {
                ZstdError::frame(format!("invalid zstd block structure: {error}"))
            }
        }
        _ => ZstdError::frame(format!("zstd frame decoding failed: {error}")),
    }
}

fn source_or(io_error: &io::Error, fallback: impl FnOnce() -> ZstdError) -> ZstdError {
    finding_from_io(io_error).map_or_else(fallback, ZstdError::source)
}

/// Walk the decoder error's source chain for an embedded snapshot finding.
fn nested_source_finding(error: &FrameDecoderError) -> Option<Finding> {
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(error);
    while let Some(current) = source {
        if let Some(io_error) = current.downcast_ref::<io::Error>() {
            if let Some(finding) = finding_from_io(io_error) {
                return Some(finding);
            }
        }
        source = std::error::Error::source(current);
    }
    None
}

fn classify_trailing(source: &SourceSnapshot<'_>, consumed: u64) -> ZstdError {
    let mut magic = [0_u8; 4];
    let has_magic = consumed
        .checked_add(4)
        .is_some_and(|end| end <= source.len())
        && source.read_exact_at(consumed, &mut magic).is_ok();
    if has_magic {
        let magic = u32::from_le_bytes(magic);
        if magic == MAGIC {
            return ZstdError::new(
                ZstdErrorKind::ConcatenatedFrame,
                FindingCode::CodecZstdTrailingInput,
                "concatenated zstd frames are outside the single-frame profile",
            );
        }
        if (SKIPPABLE_MAGIC_FIRST..=SKIPPABLE_MAGIC_LAST).contains(&magic) {
            return ZstdError::new(
                ZstdErrorKind::ConcatenatedFrame,
                FindingCode::CodecZstdTrailingInput,
                "trailing zstd skippable frames are outside the single-frame profile",
            );
        }
    }
    ZstdError::new(
        ZstdErrorKind::TrailingInput,
        FindingCode::CodecZstdTrailingInput,
        "trailing bytes after the zstd frame are rejected",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::hash::Hasher as _;

    fn xxh64_checksum(data: &[u8]) -> [u8; 4] {
        let mut hasher = twox_hash::XxHash64::with_seed(0);
        hasher.write(data);
        ((hasher.finish() & 0xFFFF_FFFF) as u32).to_le_bytes()
    }

    #[derive(Clone, Copy)]
    enum Fcs {
        Absent,
        Bytes(u8),
    }

    fn frame_with(
        content: &[u8],
        single_segment: bool,
        window_descriptor: u8,
        fcs: Fcs,
        checksum: bool,
        block_split: usize,
    ) -> Vec<u8> {
        let mut descriptor = 0_u8;
        if single_segment {
            descriptor |= DESCRIPTOR_SINGLE_SEGMENT;
        }
        if checksum {
            descriptor |= DESCRIPTOR_CHECKSUM;
        }
        let fcs_len = match fcs {
            Fcs::Absent => {
                assert!(!single_segment);
                0
            }
            Fcs::Bytes(len) => {
                descriptor |= match len {
                    1 => {
                        assert!(single_segment);
                        0
                    }
                    2 => 0b0100_0000,
                    4 => 0b1000_0000,
                    8 => 0b1100_0000,
                    _ => panic!("unsupported FCS width"),
                };
                len
            }
        };
        let mut bytes = MAGIC.to_le_bytes().to_vec();
        bytes.push(descriptor);
        if !single_segment {
            bytes.push(window_descriptor);
        }
        match fcs {
            Fcs::Absent => {}
            Fcs::Bytes(len) => {
                let stored = if len == 2 {
                    (content.len() as u64) - 256
                } else {
                    content.len() as u64
                };
                bytes.extend_from_slice(&stored.to_le_bytes()[..len as usize]);
            }
        }
        let _ = fcs_len;
        let mut chunks: Vec<&[u8]> = content.chunks(block_split.max(1)).collect();
        if chunks.is_empty() {
            chunks.push(&[]);
        }
        let last = chunks.len() - 1;
        for (index, chunk) in chunks.iter().enumerate() {
            let header = ((chunk.len() as u32) << 3) | u32::from(index == last);
            bytes.extend_from_slice(&header.to_le_bytes()[..3]);
            bytes.extend_from_slice(chunk);
        }
        if checksum {
            bytes.extend_from_slice(&xxh64_checksum(content));
        }
        bytes
    }

    fn windowed_frame(content: &[u8], checksum: bool) -> Vec<u8> {
        frame_with(content, false, 0, Fcs::Absent, checksum, usize::MAX)
    }

    fn single_segment_frame(content: &[u8], checksum: bool) -> Vec<u8> {
        assert!(content.len() <= 255);
        frame_with(content, true, 0, Fcs::Bytes(1), checksum, usize::MAX)
    }

    fn snapshot(bytes: &[u8]) -> SourceSnapshot<'_> {
        SourceSnapshot::borrowed(None, bytes)
    }

    fn limits() -> ZstdLimits {
        ZstdLimits {
            max_metadata_bytes: 4096,
            max_output_bytes: 1024 * 1024,
        }
    }

    fn output_bytes(output: &SourceSnapshot<'static>) -> Vec<u8> {
        output
            .read_vec(0, output.len())
            .expect("private output reads back")
    }

    #[test]
    fn minimal_windowed_frame_decodes_with_exact_geometry() {
        let content = b"bounded zstd payload";
        let source = windowed_frame(content, false);
        let decoded = decode_single_frame(&snapshot(&source), limits()).unwrap();
        assert_eq!(decoded.header.header, ByteRange { offset: 0, len: 6 });
        assert!(!decoded.header.single_segment);
        assert!(!decoded.header.checksum_flag);
        assert_eq!(decoded.header.window_descriptor, Some(0));
        assert_eq!(decoded.header.window_size, 1024);
        assert_eq!(decoded.header.frame_content_size, None);
        assert_eq!(decoded.declared_checksum, None);
        assert_eq!(decoded.trailer.len, 0);
        assert_eq!(
            decoded.compressed_payload,
            ByteRange {
                offset: 6,
                len: source.len() as u64 - 6,
            }
        );
        assert_eq!(decoded.trailer.end(), source.len() as u64);
        assert_eq!(output_bytes(&decoded.output), content);
    }

    #[test]
    fn single_segment_frame_binds_content_size_and_checksum() {
        let content = b"verified single-segment payload";
        let source = single_segment_frame(content, true);
        let decoded = decode_single_frame(&snapshot(&source), limits()).unwrap();
        assert!(decoded.header.single_segment);
        assert!(decoded.header.checksum_flag);
        assert_eq!(decoded.header.window_descriptor, None);
        assert_eq!(decoded.header.window_size, content.len() as u64);
        assert_eq!(
            decoded.header.frame_content_size,
            Some(content.len() as u64)
        );
        assert_eq!(decoded.header.header, ByteRange { offset: 0, len: 6 });
        assert_eq!(decoded.trailer.len, 4);
        assert_eq!(decoded.trailer.end(), source.len() as u64);
        assert_eq!(
            decoded.declared_checksum,
            Some(u32::from_le_bytes(xxh64_checksum(content)))
        );
        assert_eq!(output_bytes(&decoded.output), content);
    }

    #[test]
    fn multi_block_and_empty_frames_decode_exactly() {
        let content = b"one block boundary crosses here";
        let multi = frame_with(content, false, 0, Fcs::Absent, true, 7);
        let decoded = decode_single_frame(&snapshot(&multi), limits()).unwrap();
        assert_eq!(output_bytes(&decoded.output), content);

        let empty = windowed_frame(b"", false);
        let decoded = decode_single_frame(&snapshot(&empty), limits()).unwrap();
        assert_eq!(decoded.output.len(), 0);
    }

    #[test]
    fn two_and_four_byte_content_sizes_round_trip() {
        let content = vec![0x5a_u8; 300];
        let two = frame_with(&content, false, 0, Fcs::Bytes(2), false, usize::MAX);
        let decoded = decode_single_frame(&snapshot(&two), limits()).unwrap();
        assert_eq!(decoded.header.frame_content_size, Some(300));
        assert_eq!(decoded.output.len(), 300);

        let four = frame_with(&content, false, 0, Fcs::Bytes(4), false, usize::MAX);
        let decoded = decode_single_frame(&snapshot(&four), limits()).unwrap();
        assert_eq!(decoded.header.frame_content_size, Some(300));
    }

    #[test]
    fn checksum_mismatch_fails_closed() {
        let mut source = single_segment_frame(b"integrity payload", true);
        let last = source.len() - 1;
        source[last] ^= 0x01;
        let error = decode_single_frame(&snapshot(&source), limits()).unwrap_err();
        assert_eq!(error.kind, ZstdErrorKind::DataChecksum);
        assert_eq!(error.finding().code, FindingCode::CrcMismatch);
    }

    #[test]
    fn content_size_lie_fails_closed() {
        let content = b"true payload bytes";
        let mut source = frame_with(content, false, 0, Fcs::Bytes(4), false, usize::MAX);
        source[6] = (content.len() as u8) + 1;
        let error = decode_single_frame(&snapshot(&source), limits()).unwrap_err();
        assert_eq!(error.kind, ZstdErrorKind::DeclaredSize);
        assert_eq!(error.finding().code, FindingCode::QuotaDeclaredLie);
    }

    #[test]
    fn skippable_dictionary_reserved_and_magic_grammar_fails_closed() {
        let mut skippable = SKIPPABLE_MAGIC_FIRST.to_le_bytes().to_vec();
        skippable.extend_from_slice(&4_u32.to_le_bytes());
        skippable.extend_from_slice(b"skip");
        let error = decode_single_frame(&snapshot(&skippable), limits()).unwrap_err();
        assert_eq!(error.kind, ZstdErrorKind::SkippableFrame);
        assert_eq!(error.finding().code, FindingCode::FormatUnsupported);

        let mut dictionary = windowed_frame(b"payload", false);
        dictionary[4] |= 0b0000_0001;
        let error = decode_single_frame(&snapshot(&dictionary), limits()).unwrap_err();
        assert_eq!(error.kind, ZstdErrorKind::Dictionary);

        let mut reserved = windowed_frame(b"payload", false);
        reserved[4] |= DESCRIPTOR_RESERVED;
        let error = decode_single_frame(&snapshot(&reserved), limits()).unwrap_err();
        assert_eq!(error.kind, ZstdErrorKind::ReservedBits);

        let mut unused = windowed_frame(b"payload", false);
        unused[4] |= DESCRIPTOR_UNUSED;
        let error = decode_single_frame(&snapshot(&unused), limits()).unwrap_err();
        assert_eq!(error.kind, ZstdErrorKind::ReservedBits);

        let error = decode_single_frame(&snapshot(b"not a zstd frame"), limits()).unwrap_err();
        assert_eq!(error.kind, ZstdErrorKind::Magic);
        assert_eq!(error.finding().code, FindingCode::FormatMagic);

        let error = decode_single_frame(&snapshot(&[0x28]), limits()).unwrap_err();
        assert_eq!(error.kind, ZstdErrorKind::Truncated);
    }

    #[test]
    fn window_bounds_are_enforced_before_decoding() {
        let oversized = frame_with(b"payload", false, 0x70, Fcs::Absent, false, usize::MAX);
        let error = decode_single_frame(&snapshot(&oversized), limits()).unwrap_err();
        assert_eq!(error.kind, ZstdErrorKind::WindowBounds);
        assert_eq!(error.finding().code, FindingCode::FormatUnsupported);

        let mut single_over = MAGIC.to_le_bytes().to_vec();
        single_over.push(DESCRIPTOR_SINGLE_SEGMENT | 0b1000_0000);
        single_over.extend_from_slice(&(MAX_WINDOW_BYTES as u32 + 1).to_le_bytes());
        let error = decode_single_frame(&snapshot(&single_over), limits()).unwrap_err();
        assert_eq!(error.kind, ZstdErrorKind::WindowBounds);
    }

    #[test]
    fn trailing_input_is_classified_exactly() {
        let member = windowed_frame(b"payload", false);

        let mut concatenated = member.clone();
        concatenated.extend_from_slice(&windowed_frame(b"second", false));
        let error = decode_single_frame(&snapshot(&concatenated), limits()).unwrap_err();
        assert_eq!(error.kind, ZstdErrorKind::ConcatenatedFrame);
        assert_eq!(error.finding().code, FindingCode::CodecZstdTrailingInput);

        let mut skippable_tail = member.clone();
        skippable_tail.extend_from_slice(&SKIPPABLE_MAGIC_LAST.to_le_bytes());
        skippable_tail.extend_from_slice(&0_u32.to_le_bytes());
        let error = decode_single_frame(&snapshot(&skippable_tail), limits()).unwrap_err();
        assert_eq!(error.kind, ZstdErrorKind::ConcatenatedFrame);

        let mut garbage = member.clone();
        garbage.push(0x00);
        let error = decode_single_frame(&snapshot(&garbage), limits()).unwrap_err();
        assert_eq!(error.kind, ZstdErrorKind::TrailingInput);
        assert_eq!(error.finding().code, FindingCode::CodecZstdTrailingInput);
    }

    #[test]
    fn truncation_inside_the_frame_fails_closed() {
        let member = single_segment_frame(b"truncation target payload", true);
        for len in 6..member.len() {
            let error = decode_single_frame(&snapshot(&member[..len]), limits()).unwrap_err();
            assert!(
                matches!(
                    error.kind,
                    ZstdErrorKind::Truncated
                        | ZstdErrorKind::FrameStream
                        | ZstdErrorKind::DeclaredSize
                ),
                "prefix {len}: {:?}",
                error.kind
            );
        }
    }

    #[test]
    fn wrapper_metadata_and_output_caps_are_exact() {
        let content = b"capped content";
        let member = single_segment_frame(content, true);
        let exact = ZstdLimits {
            max_metadata_bytes: 10,
            max_output_bytes: content.len() as u64,
        };
        assert!(decode_single_frame(&snapshot(&member), exact).is_ok());

        let below = ZstdLimits {
            max_metadata_bytes: 9,
            max_output_bytes: 1024,
        };
        let error = decode_single_frame(&snapshot(&member), below).unwrap_err();
        assert_eq!(error.kind, ZstdErrorKind::HeaderLimit);
        assert_eq!(error.finding().code, FindingCode::QuotaMetadata);

        let output_cap = ZstdLimits {
            max_metadata_bytes: 4096,
            max_output_bytes: content.len() as u64 - 1,
        };
        let error = decode_single_frame(&snapshot(&member), output_cap).unwrap_err();
        assert_eq!(error.kind, ZstdErrorKind::OutputLimit);
        assert_eq!(error.finding().code, FindingCode::QuotaDerived);
    }

    #[test]
    fn pinned_zstd_cli_frame_decodes_through_the_compressed_block_path() {
        // Produced by Zstandard CLI v1.5.7: `zstd -3` over
        // ("sealr zstd producer probe " * 100)[..2048]. The frame uses real
        // compressed blocks, a single-segment header, FCS, and a checksum.
        let source: Vec<u8> = "28b52ffd640007050100b07365616c72207a7374642070726f6475636572626\
                               5200200e3f7fc916c090388666390"
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let expected: Vec<u8> = b"sealr zstd producer probe "
            .iter()
            .copied()
            .cycle()
            .take(2048)
            .collect();
        let decoded = decode_single_frame(&snapshot(&source), limits()).unwrap();
        assert!(decoded.header.single_segment);
        assert!(decoded.header.checksum_flag);
        assert_eq!(decoded.header.frame_content_size, Some(2048));
        assert_eq!(decoded.header.window_size, 2048);
        assert_eq!(output_bytes(&decoded.output), expected);
        assert_eq!(
            decoded.declared_checksum,
            Some(u32::from_le_bytes(xxh64_checksum(&expected)))
        );
    }

    #[test]
    fn transform_registers_one_identity_bound_derived_domain() {
        let content = b"derived domain payload";
        let member = windowed_frame(content, true);
        let snapshot = SourceSnapshot::borrowed(None, &member);
        let mut snapshots = SnapshotSet::from_original(snapshot);
        let mut transforms = TransformGraph::empty();
        let transformed =
            transform_single_frame(&mut snapshots, &mut transforms, limits()).unwrap();
        assert_eq!(transformed.output_domain, SnapshotDomainId::FIRST_DERIVED);
        assert_eq!(transformed.output_len, content.len() as u64);
        assert!(transforms.validates(&snapshots));
        assert_eq!(
            transforms.records()[0].profile,
            TransformProfile::ZstdRfc8878SingleFrameV1
        );
        let derived = snapshots.domain(SnapshotDomainId::FIRST_DERIVED).unwrap();
        assert_eq!(derived.len(), content.len() as u64);
        assert_eq!(
            derived.digest().sha256(),
            Some(transformed.output_sha256.as_str())
        );
    }
}
