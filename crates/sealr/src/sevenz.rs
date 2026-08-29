//! Strict, bounded 7z Copy-only container parsing over raw headers.
//!
//! This module is deliberately crate-private until the container profile and
//! its identity are part of the public admission contract.
//!
//! 7z is a header-last container: a 32-byte signature header names the next
//! header's offset, size, and CRC32, and the next header's tagged property
//! grammar describes pack streams, folders, substreams, and file records. The
//! restricted Copy profile admits exactly one raw `kHeader` — stock producers
//! LZMA-compress the header itself (`kEncodedHeader`), which is a named
//! unsupported shape with a documented producer remedy (`-mhc=off`) — with
//! every coder Copy, no bind pairs, no external records, a dense byte-exact
//! covering with no unreferenced bytes anywhere, minimal variable-length
//! integer encodings, and every CRC32 in the file verified by Sealr itself.

use crate::findings::{Finding, FindingCode};
use crate::ir::ByteRange;
use crate::snapshot::SourceSnapshot;

pub(crate) const SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
pub(crate) const SIGNATURE_HEADER_LEN: u64 = 32;
const START_HEADER_LEN: usize = 20;

const K_END: u64 = 0x00;
const K_HEADER: u64 = 0x01;
const K_ARCHIVE_PROPERTIES: u64 = 0x02;
const K_ADDITIONAL_STREAMS: u64 = 0x03;
const K_MAIN_STREAMS: u64 = 0x04;
const K_FILES_INFO: u64 = 0x05;
const K_PACK_INFO: u64 = 0x06;
const K_UNPACK_INFO: u64 = 0x07;
const K_SUBSTREAMS_INFO: u64 = 0x08;
const K_SIZE: u64 = 0x09;
const K_CRC: u64 = 0x0A;
const K_FOLDER: u64 = 0x0B;
const K_CODERS_UNPACK_SIZE: u64 = 0x0C;
const K_NUM_UNPACK_STREAM: u64 = 0x0D;
const K_EMPTY_STREAM: u64 = 0x0E;
const K_EMPTY_FILE: u64 = 0x0F;
const K_ANTI: u64 = 0x10;
const K_NAME: u64 = 0x11;
const K_CTIME: u64 = 0x12;
const K_ATIME: u64 = 0x13;
const K_MTIME: u64 = 0x14;
const K_WIN_ATTRIBUTES: u64 = 0x15;
const K_COMMENT: u64 = 0x16;
const K_ENCODED_HEADER: u64 = 0x17;
const K_START_POS: u64 = 0x18;
const K_DUMMY: u64 = 0x19;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

/// One member of the restricted Copy container: a regular file, an empty
/// file, or a directory, with the Copy payload's exact original-domain range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SevenZMember {
    pub(crate) raw_name_bytes: Vec<u8>,
    pub(crate) name: String,
    pub(crate) is_dir: bool,
    pub(crate) size: u64,
    pub(crate) payload: ByteRange,
    pub(crate) declared_crc: Option<u32>,
    pub(crate) attributes: Option<u32>,
    pub(crate) mtime: Option<u64>,
}

/// One verified Copy substream inside a folder's pack stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SevenZSubStreamParsed {
    pub(crate) payload: ByteRange,
    pub(crate) declared_crc: Option<u32>,
}

/// One verified single-coder Copy folder and its pack stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SevenZFolderParsed {
    pub(crate) pack_stream: ByteRange,
    pub(crate) pack_crc: Option<u32>,
    pub(crate) unpack_size: u64,
    pub(crate) folder_crc: Option<u32>,
    pub(crate) substreams: Vec<SevenZSubStreamParsed>,
}

/// A fully parsed restricted Copy archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SevenZParsed {
    pub(crate) version_minor: u8,
    pub(crate) pack_region: ByteRange,
    pub(crate) next_header: ByteRange,
    pub(crate) next_header_crc: u32,
    pub(crate) folders: Vec<SevenZFolderParsed>,
    pub(crate) name_region_bytes: u64,
    pub(crate) dummy_bytes: u64,
    pub(crate) metadata_bytes: u64,
    pub(crate) members: Vec<SevenZMember>,
}

fn structure(detail: impl Into<String>) -> Finding {
    Finding::error(FindingCode::SevenZInvalidStructure, detail)
}

fn unsupported(detail: impl Into<String>) -> Finding {
    Finding::error(FindingCode::FormatUnsupported, detail)
}

fn crc_mismatch(detail: impl Into<String>) -> Finding {
    Finding::error(FindingCode::CrcMismatch, detail)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

/// Whether the source begins with the exact 7z signature.
pub(crate) fn recognizes_sevenz(source: &SourceSnapshot<'_>) -> bool {
    if source.len() < 6 {
        return false;
    }
    let mut magic = [0_u8; 6];
    source
        .read_exact_at(0, &mut magic)
        .is_ok_and(|()| magic == SIGNATURE)
}

/// Parse exactly one restricted Copy 7z archive from the complete snapshot.
///
/// Every structural claim is bounds-checked before it is read, every CRC32 in
/// the container is verified, variable-length integers must use minimal
/// encodings, and the covering must be dense: signature header, pack streams,
/// and the raw next header tile the file exactly with no gaps or trailing
/// bytes.
pub(crate) fn parse_copy_portable_v1(
    source: &SourceSnapshot<'_>,
    max_files: u64,
    max_metadata_bytes: u64,
) -> Result<SevenZParsed, Finding> {
    if source.len() < SIGNATURE_HEADER_LEN {
        return Err(structure("source is shorter than a 7z signature header"));
    }
    let mut signature_header = [0_u8; 32];
    source.read_exact_at(0, &mut signature_header)?;
    if signature_header[..6] != SIGNATURE {
        return Err(Finding::error(
            FindingCode::FormatMagic,
            "source does not begin with the 7z signature",
        ));
    }
    if signature_header[6] != 0 {
        return Err(unsupported(format!(
            "7z major version {} is outside the restricted profile",
            signature_header[6]
        )));
    }
    let version_minor = signature_header[7];
    if version_minor != 4 {
        return Err(unsupported(format!(
            "7z minor version {version_minor} is outside the restricted profile"
        )));
    }
    let declared_start_crc = u32::from_le_bytes([
        signature_header[8],
        signature_header[9],
        signature_header[10],
        signature_header[11],
    ]);
    if crc32(&signature_header[12..12 + START_HEADER_LEN]) != declared_start_crc {
        return Err(crc_mismatch("7z start-header CRC32 mismatch"));
    }
    let next_offset = u64::from_le_bytes(signature_header[12..20].try_into().expect("8 bytes"));
    let next_size = u64::from_le_bytes(signature_header[20..28].try_into().expect("8 bytes"));
    let next_crc = u32::from_le_bytes(signature_header[28..32].try_into().expect("4 bytes"));

    if next_size == 0 {
        return Err(unsupported(
            "an empty 7z archive carries no admissible members",
        ));
    }
    let header_start = SIGNATURE_HEADER_LEN
        .checked_add(next_offset)
        .ok_or_else(|| structure("7z next-header offset overflowed u64"))?;
    let header_end = header_start
        .checked_add(next_size)
        .ok_or_else(|| structure("7z next-header size overflowed u64"))?;
    if header_end != source.len() {
        return Err(structure(
            "the 7z next header does not end exactly at the end of the source",
        ));
    }
    let metadata_bytes = SIGNATURE_HEADER_LEN
        .checked_add(next_size)
        .expect("signature plus bounded header size fits u64");
    if metadata_bytes > max_metadata_bytes {
        return Err(Finding::error(
            FindingCode::QuotaMetadata,
            format!("7z metadata is {metadata_bytes} bytes; cap is {max_metadata_bytes}"),
        ));
    }
    let header_bytes = source.read_vec(header_start, next_size)?;
    if crc32(&header_bytes) != next_crc {
        return Err(crc_mismatch("7z next-header CRC32 mismatch"));
    }

    let mut reader = HeaderReader {
        bytes: &header_bytes,
        pos: 0,
    };
    let first = reader.number("header kind")?;
    if first == K_ENCODED_HEADER {
        return Err(unsupported(
            "packed 7z headers (kEncodedHeader) are outside the restricted profile; \
             produce raw headers with -mhc=off",
        ));
    }
    if first != K_HEADER {
        return Err(structure("the 7z next header does not begin with kHeader"));
    }

    let mut streams: Option<StreamsInfo> = None;
    let mut files: Option<FilesInfo> = None;
    loop {
        let id = reader.number("header property id")?;
        match id {
            K_END => break,
            K_ARCHIVE_PROPERTIES => {
                return Err(unsupported(
                    "7z archive properties are outside the restricted profile",
                ));
            }
            K_ADDITIONAL_STREAMS => {
                return Err(unsupported(
                    "7z additional streams are outside the restricted profile",
                ));
            }
            K_MAIN_STREAMS => {
                if streams.is_some() {
                    return Err(structure("duplicate 7z main streams info"));
                }
                streams = Some(parse_streams_info(&mut reader)?);
            }
            K_FILES_INFO => {
                if files.is_some() {
                    return Err(structure("duplicate 7z files info"));
                }
                files = Some(parse_files_info(&mut reader, max_files)?);
            }
            other => {
                return Err(unsupported(format!(
                    "7z header property {other:#04x} is outside the restricted profile"
                )));
            }
        }
    }
    if reader.pos != header_bytes.len() {
        return Err(structure("trailing bytes inside the 7z next header"));
    }
    let files = files.ok_or_else(|| {
        unsupported("a 7z archive without file records carries no admissible members")
    })?;
    if files.num_files == 0 {
        return Err(unsupported(
            "an empty 7z archive carries no admissible members",
        ));
    }

    // Resolve pack geometry against the dense covering: pack streams begin at
    // byte 32 (PackPos must be zero), tile contiguously, and end exactly where
    // the next header begins.
    let streams = match streams {
        Some(streams) => streams,
        None => StreamsInfo {
            pack_sizes: Vec::new(),
            pack_crcs: Vec::new(),
            folders: Vec::new(),
        },
    };
    let mut folders = Vec::with_capacity(streams.folders.len());
    let mut cursor = SIGNATURE_HEADER_LEN;
    if streams.folders.len() != streams.pack_sizes.len() {
        return Err(structure(
            "7z folder count disagrees with the pack-stream count",
        ));
    }
    for (index, folder) in streams.folders.iter().enumerate() {
        let pack_size = streams.pack_sizes[index];
        if folder.unpack_size != pack_size {
            return Err(structure(
                "a Copy folder's unpack size disagrees with its pack size",
            ));
        }
        let pack_stream = ByteRange {
            offset: cursor,
            len: pack_size,
        };
        cursor = cursor
            .checked_add(pack_size)
            .ok_or_else(|| structure("7z pack sizes overflowed u64"))?;
        if cursor > header_start {
            return Err(structure("7z pack streams overlap the next header"));
        }
        let mut substreams = Vec::with_capacity(folder.substream_sizes.len());
        let mut sub_cursor = pack_stream.offset;
        for (sub_index, size) in folder.substream_sizes.iter().enumerate() {
            let payload = ByteRange {
                offset: sub_cursor,
                len: *size,
            };
            sub_cursor = sub_cursor
                .checked_add(*size)
                .ok_or_else(|| structure("7z substream sizes overflowed u64"))?;
            substreams.push(SevenZSubStreamParsed {
                payload,
                declared_crc: folder.substream_crcs[sub_index],
            });
        }
        if sub_cursor != pack_stream.offset + pack_stream.len {
            return Err(structure(
                "7z substream sizes do not exactly tile their folder",
            ));
        }
        folders.push(SevenZFolderParsed {
            pack_stream,
            pack_crc: streams.pack_crcs.get(index).copied().flatten(),
            unpack_size: folder.unpack_size,
            folder_crc: folder.folder_crc,
            substreams,
        });
    }
    if cursor != header_start {
        return Err(structure(
            "7z pack streams do not end exactly where the next header begins",
        ));
    }
    let pack_region = ByteRange {
        offset: SIGNATURE_HEADER_LEN,
        len: header_start - SIGNATURE_HEADER_LEN,
    };

    // Verify every declared CRC that Sealr can check directly.
    for folder in &folders {
        if let Some(declared) = folder.pack_crc {
            let bytes = source.read_vec(folder.pack_stream.offset, folder.pack_stream.len)?;
            if crc32(&bytes) != declared {
                return Err(crc_mismatch("a 7z pack-stream CRC32 does not match"));
            }
        }
        if let Some(declared) = folder.folder_crc {
            let bytes = source.read_vec(folder.pack_stream.offset, folder.pack_stream.len)?;
            if crc32(&bytes) != declared {
                return Err(crc_mismatch("a 7z folder CRC32 does not match"));
            }
        }
    }

    // Map files to members: empty-stream entries are directories or empty
    // files by the kEmptyFile bit; stream-bearing files take substreams in
    // file order.
    let num_files = usize::try_from(files.num_files).expect("bounded by header length");
    let empty_stream = match &files.empty_stream {
        Some(bits) => bits.clone(),
        None => vec![false; num_files],
    };
    let num_empty = empty_stream.iter().filter(|bit| **bit).count();
    let empty_file = match &files.empty_file {
        Some(bits) => bits.clone(),
        None => vec![false; num_empty],
    };
    let stream_bearing = num_files - num_empty;
    let total_substreams: usize = folders.iter().map(|folder| folder.substreams.len()).sum();
    if stream_bearing != total_substreams {
        return Err(structure(
            "7z stream-bearing file count disagrees with the substream count",
        ));
    }
    if files.names.len() != num_files {
        return Err(structure("7z name count disagrees with the file count"));
    }

    let empty_payload = ByteRange {
        offset: header_start,
        len: 0,
    };
    let mut substream_iter = folders
        .iter()
        .flat_map(|folder| folder.substreams.iter().cloned());
    let mut empty_index = 0_usize;
    let mut members = Vec::with_capacity(num_files);
    for (index, (raw_name_bytes, name)) in files.names.into_iter().enumerate() {
        let attributes = files.attributes.get(index).copied().flatten();
        let mtime = files.mtimes.get(index).copied().flatten();
        let (is_dir, size, payload, declared_crc) = if empty_stream[index] {
            let is_empty_file = *empty_file.get(empty_index).ok_or_else(|| {
                structure("7z empty-file vector is shorter than the empty-stream count")
            })?;
            empty_index += 1;
            (!is_empty_file, 0, empty_payload, None)
        } else {
            let substream = substream_iter
                .next()
                .expect("substream counts were matched to stream-bearing files");
            (
                false,
                substream.payload.len,
                substream.payload,
                substream.declared_crc,
            )
        };
        if let Some(attributes) = attributes {
            if (attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != is_dir {
                return Err(structure(
                    "a 7z directory attribute disagrees with the empty-stream matrix",
                ));
            }
        }
        members.push(SevenZMember {
            raw_name_bytes,
            name,
            is_dir,
            size,
            payload,
            declared_crc,
            attributes,
            mtime,
        });
    }

    Ok(SevenZParsed {
        version_minor,
        pack_region,
        next_header: ByteRange {
            offset: header_start,
            len: next_size,
        },
        next_header_crc: next_crc,
        folders,
        name_region_bytes: files.name_region_bytes,
        dummy_bytes: files.dummy_bytes,
        metadata_bytes,
        members,
    })
}

struct ParsedFolder {
    unpack_size: u64,
    folder_crc: Option<u32>,
    substream_sizes: Vec<u64>,
    substream_crcs: Vec<Option<u32>>,
}

struct StreamsInfo {
    pack_sizes: Vec<u64>,
    pack_crcs: Vec<Option<u32>>,
    folders: Vec<ParsedFolder>,
}

struct FilesInfo {
    num_files: u64,
    empty_stream: Option<Vec<bool>>,
    empty_file: Option<Vec<bool>>,
    names: Vec<(Vec<u8>, String)>,
    attributes: Vec<Option<u32>>,
    mtimes: Vec<Option<u64>>,
    name_region_bytes: u64,
    dummy_bytes: u64,
}

struct HeaderReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl HeaderReader<'_> {
    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn byte(&mut self, what: &str) -> Result<u8, Finding> {
        if self.pos >= self.bytes.len() {
            return Err(structure(format!("7z header ends inside {what}")));
        }
        let value = self.bytes[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn take(&mut self, len: usize, what: &str) -> Result<&[u8], Finding> {
        if self.remaining() < len {
            return Err(structure(format!("7z header ends inside {what}")));
        }
        let slice = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    /// Read one variable-length NUMBER, requiring the minimal encoding.
    fn number(&mut self, what: &str) -> Result<u64, Finding> {
        let first = self.byte(what)?;
        let extra = first.leading_ones() as usize;
        if extra == 0 {
            return Ok(u64::from(first));
        }
        let mask_bits = if extra >= 7 {
            0
        } else {
            u64::from(first & (0x7F >> extra))
        };
        let extra = extra.min(8);
        let tail = self.take(extra, what)?;
        let mut low = 0_u64;
        for (index, byte) in tail.iter().enumerate() {
            low |= u64::from(*byte) << (8 * index);
        }
        let value = if extra == 8 {
            if mask_bits != 0 {
                return Err(structure(format!(
                    "non-minimal 7z number encoding in {what}"
                )));
            }
            low
        } else {
            (mask_bits << (8 * extra)) | low
        };
        let minimal_extra = minimal_number_extra(value);
        if extra != minimal_extra {
            return Err(structure(format!(
                "non-minimal 7z number encoding in {what}"
            )));
        }
        Ok(value)
    }

    fn real_u64(&mut self, what: &str) -> Result<u64, Finding> {
        let bytes = self.take(8, what)?;
        Ok(u64::from_le_bytes(bytes.try_into().expect("8 bytes")))
    }

    fn u32_le(&mut self, what: &str) -> Result<u32, Finding> {
        let bytes = self.take(4, what)?;
        Ok(u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
    }

    /// Read a count bounded by the remaining header bytes, so hostile claimed
    /// counts can never drive allocation beyond the header itself.
    fn bounded_count(&mut self, what: &str) -> Result<usize, Finding> {
        let value = self.number(what)?;
        let bound = self.remaining() as u64;
        if value > bound {
            return Err(structure(format!(
                "7z {what} claims {value} items inside {bound} remaining header bytes"
            )));
        }
        Ok(value as usize)
    }

    /// Read an MSB-first bit vector of exactly `count` items with zero
    /// padding bits.
    fn bit_vector(&mut self, count: usize, what: &str) -> Result<Vec<bool>, Finding> {
        let byte_len = count.div_ceil(8);
        let bytes = self.take(byte_len, what)?;
        let mut bits = Vec::with_capacity(count);
        for index in 0..count {
            let byte = bytes[index / 8];
            bits.push(byte & (0x80 >> (index % 8)) != 0);
        }
        if !count.is_multiple_of(8) {
            let padding_mask = 0xFF_u8 >> (count % 8);
            if bytes[byte_len - 1] & padding_mask != 0 {
                return Err(structure(format!(
                    "nonzero 7z bit-vector padding in {what}"
                )));
            }
        }
        Ok(bits)
    }

    /// Read an AllAreDefined-prefixed digest set for exactly `count` items.
    fn digests(&mut self, count: usize, what: &str) -> Result<Vec<Option<u32>>, Finding> {
        let all_defined = self.byte(what)?;
        let defined = match all_defined {
            0 => self.bit_vector(count, what)?,
            1 => vec![true; count],
            other => {
                return Err(structure(format!(
                    "7z {what} AllAreDefined byte {other:#04x} is not 0 or 1"
                )));
            }
        };
        let mut digests = Vec::with_capacity(count);
        for flag in defined {
            if flag {
                digests.push(Some(self.u32_le(what)?));
            } else {
                digests.push(None);
            }
        }
        Ok(digests)
    }
}

const fn minimal_number_extra(value: u64) -> usize {
    let mut extra = 0;
    while extra <= 6 {
        if value < 1_u64 << (7 + 7 * extra) {
            return extra;
        }
        extra += 1;
    }
    if value < 1_u64 << 56 {
        7
    } else {
        8
    }
}

fn parse_streams_info(reader: &mut HeaderReader<'_>) -> Result<StreamsInfo, Finding> {
    let mut id = reader.number("streams info")?;
    if id != K_PACK_INFO {
        return Err(structure("7z streams info does not begin with pack info"));
    }
    let pack_pos = reader.number("pack position")?;
    if pack_pos != 0 {
        return Err(structure(
            "7z pack streams do not begin immediately after the signature header",
        ));
    }
    let num_pack = reader.bounded_count("pack-stream count")?;
    let mut pack_sizes = Vec::with_capacity(num_pack);
    let mut pack_crcs: Vec<Option<u32>> = vec![None; num_pack];
    loop {
        match reader.number("pack info property")? {
            K_END => break,
            K_SIZE => {
                if !pack_sizes.is_empty() {
                    return Err(structure("duplicate 7z pack-size record"));
                }
                for _ in 0..num_pack {
                    pack_sizes.push(reader.number("pack size")?);
                }
                if pack_sizes.is_empty() && num_pack > 0 {
                    return Err(structure("7z pack sizes are missing"));
                }
            }
            K_CRC => {
                pack_crcs = reader.digests(num_pack, "pack digests")?;
            }
            other => {
                return Err(unsupported(format!(
                    "7z pack-info property {other:#04x} is outside the restricted profile"
                )));
            }
        }
    }
    if pack_sizes.len() != num_pack {
        return Err(structure("7z pack sizes are missing"));
    }

    id = reader.number("streams info")?;
    if id != K_UNPACK_INFO {
        return Err(structure(
            "7z streams info does not continue with coders info",
        ));
    }
    if reader.number("folder marker")? != K_FOLDER {
        return Err(structure("7z coders info does not begin with folders"));
    }
    let num_folders = reader.bounded_count("folder count")?;
    let external = reader.byte("folder external flag")?;
    if external != 0 {
        return Err(unsupported(
            "external 7z folder records are outside the restricted profile",
        ));
    }
    for _ in 0..num_folders {
        let num_coders = reader.number("coder count")?;
        if num_coders != 1 {
            return Err(unsupported(
                "7z folders with more than one coder are outside the restricted profile",
            ));
        }
        let flags = reader.byte("coder flags")?;
        let id_size = usize::from(flags & 0x0F);
        if flags & 0x80 != 0 {
            return Err(structure("reserved 7z coder flag bit is set"));
        }
        if flags & 0x10 != 0 {
            return Err(unsupported(
                "complex 7z coders are outside the restricted profile",
            ));
        }
        if flags & 0x20 != 0 {
            return Err(unsupported(
                "7z coder attributes are outside the restricted profile",
            ));
        }
        let codec_id = reader.take(id_size, "codec id")?;
        if codec_id != [0x00] {
            return Err(unsupported(format!(
                "7z codec id {codec_id:02x?} is outside the Copy-only profile"
            )));
        }
    }
    if reader.number("unpack sizes marker")? != K_CODERS_UNPACK_SIZE {
        return Err(structure("7z coders info is missing unpack sizes"));
    }
    let mut unpack_sizes = Vec::with_capacity(num_folders);
    for _ in 0..num_folders {
        unpack_sizes.push(reader.number("folder unpack size")?);
    }
    let mut folder_crcs: Vec<Option<u32>> = vec![None; num_folders];
    loop {
        match reader.number("coders info property")? {
            K_END => break,
            K_CRC => {
                folder_crcs = reader.digests(num_folders, "folder digests")?;
            }
            other => {
                return Err(unsupported(format!(
                    "7z coders-info property {other:#04x} is outside the restricted profile"
                )));
            }
        }
    }

    // SubStreamsInfo is optional; default is one substream per folder.
    let mut substream_counts: Vec<usize> = vec![1; num_folders];
    let mut explicit_sizes: Vec<Vec<u64>> = Vec::new();
    let mut substream_digest_values: Option<Vec<Option<u32>>> = None;
    id = reader.number("streams info")?;
    if id == K_SUBSTREAMS_INFO {
        let mut property = reader.number("substreams property")?;
        if property == K_NUM_UNPACK_STREAM {
            substream_counts.clear();
            for _ in 0..num_folders {
                let count = reader.bounded_count("substream count")?;
                substream_counts.push(count);
            }
            property = reader.number("substreams property")?;
        }
        if property == K_SIZE {
            for (folder_index, count) in substream_counts.iter().enumerate() {
                let mut sizes = Vec::with_capacity(*count);
                let mut consumed = 0_u64;
                for _ in 0..count.saturating_sub(1) {
                    let size = reader.number("substream size")?;
                    consumed = consumed
                        .checked_add(size)
                        .ok_or_else(|| structure("7z substream sizes overflowed u64"))?;
                    sizes.push(size);
                }
                if *count > 0 {
                    let folder_size = unpack_sizes[folder_index];
                    let last = folder_size
                        .checked_sub(consumed)
                        .ok_or_else(|| structure("7z substream sizes exceed their folder size"))?;
                    sizes.push(last);
                }
                explicit_sizes.push(sizes);
            }
            property = reader.number("substreams property")?;
        }
        if property == K_CRC {
            // Digests cover only substreams whose CRC is not already known: a
            // folder with exactly one substream and a defined folder digest is
            // excluded.
            let mut unknown = 0_usize;
            for (folder_index, count) in substream_counts.iter().enumerate() {
                if *count == 1 && folder_crcs[folder_index].is_some() {
                    continue;
                }
                unknown += *count;
            }
            substream_digest_values = Some(reader.digests(unknown, "substream digests")?);
            property = reader.number("substreams property")?;
        }
        if property != K_END {
            return Err(unsupported(format!(
                "7z substreams property {property:#04x} is outside the restricted profile"
            )));
        }
        id = reader.number("streams info")?;
    }
    if id != K_END {
        return Err(structure("7z streams info does not end with kEnd"));
    }

    let mut folders = Vec::with_capacity(num_folders);
    let mut digest_cursor = 0_usize;
    for folder_index in 0..num_folders {
        let count = substream_counts[folder_index];
        if count == 0 {
            return Err(structure("7z folders must carry at least one substream"));
        }
        let sizes = if explicit_sizes.is_empty() {
            if count != 1 {
                return Err(structure(
                    "7z substream sizes are missing for a multi-substream folder",
                ));
            }
            vec![unpack_sizes[folder_index]]
        } else {
            explicit_sizes[folder_index].clone()
        };
        if sizes.contains(&0) {
            return Err(structure("7z substreams must not be empty"));
        }
        let mut crcs = Vec::with_capacity(count);
        if count == 1 && folder_crcs[folder_index].is_some() {
            crcs.push(folder_crcs[folder_index]);
        } else {
            for _ in 0..count {
                let declared = match &substream_digest_values {
                    Some(values) => values.get(digest_cursor).copied().flatten(),
                    None => None,
                };
                digest_cursor += 1;
                crcs.push(declared);
            }
        }
        folders.push(ParsedFolder {
            unpack_size: unpack_sizes[folder_index],
            folder_crc: folder_crcs[folder_index],
            substream_sizes: sizes,
            substream_crcs: crcs,
        });
    }
    if let Some(values) = &substream_digest_values {
        if digest_cursor != values.len() {
            return Err(structure(
                "7z substream digests do not match the substream layout",
            ));
        }
    }

    Ok(StreamsInfo {
        pack_sizes,
        pack_crcs,
        folders,
    })
}

fn parse_files_info(reader: &mut HeaderReader<'_>, max_files: u64) -> Result<FilesInfo, Finding> {
    let num_files_claimed = reader.number("file count")?;
    if num_files_claimed > max_files {
        return Err(Finding::error(
            FindingCode::QuotaFiles,
            format!("{num_files_claimed} entries"),
        ));
    }
    // Every file needs at least two name bytes, so the count is also bounded
    // by the remaining header bytes before any allocation.
    if num_files_claimed > reader.remaining() as u64 {
        return Err(structure(
            "7z file count exceeds the remaining header bytes",
        ));
    }
    let num_files = num_files_claimed as usize;

    let mut empty_stream: Option<Vec<bool>> = None;
    let mut empty_file: Option<Vec<bool>> = None;
    let mut names: Option<Vec<(Vec<u8>, String)>> = None;
    let mut attributes: Vec<Option<u32>> = vec![None; num_files];
    let mut mtimes: Vec<Option<u64>> = vec![None; num_files];
    let mut name_region_bytes = 0_u64;
    let mut dummy_bytes = 0_u64;

    loop {
        let id = reader.number("files property id")?;
        if id == K_END {
            break;
        }
        let size = reader.number("files property size")?;
        if size > reader.remaining() as u64 {
            return Err(structure("7z files property exceeds the header"));
        }
        let record_end = reader.pos + size as usize;
        match id {
            K_EMPTY_STREAM => {
                if empty_stream.is_some() {
                    return Err(structure("duplicate 7z empty-stream record"));
                }
                empty_stream = Some(reader.bit_vector(num_files, "empty-stream vector")?);
            }
            K_EMPTY_FILE => {
                let num_empty = empty_stream
                    .as_ref()
                    .map(|bits| bits.iter().filter(|bit| **bit).count())
                    .ok_or_else(|| {
                        structure("7z empty-file record appears before the empty-stream record")
                    })?;
                if empty_file.is_some() {
                    return Err(structure("duplicate 7z empty-file record"));
                }
                empty_file = Some(reader.bit_vector(num_empty, "empty-file vector")?);
            }
            K_ANTI => {
                return Err(unsupported(
                    "7z anti-items are outside the restricted profile",
                ));
            }
            K_NAME => {
                if names.is_some() {
                    return Err(structure("duplicate 7z name record"));
                }
                let external = reader.byte("name external flag")?;
                if external != 0 {
                    return Err(unsupported(
                        "external 7z name records are outside the restricted profile",
                    ));
                }
                let region_len = record_end
                    .checked_sub(reader.pos)
                    .ok_or_else(|| structure("7z name record size underflowed"))?;
                name_region_bytes = region_len as u64;
                let region = reader.take(region_len, "name region")?;
                names = Some(decode_names(region, num_files)?);
            }
            K_CTIME | K_ATIME => {
                let _ = parse_time_record(reader, num_files, "time record")?;
            }
            K_MTIME => {
                mtimes = parse_time_record(reader, num_files, "modification-time record")?;
            }
            K_WIN_ATTRIBUTES => {
                let defined = parse_defined_vector(reader, num_files, "attribute record")?;
                let external = reader.byte("attribute external flag")?;
                if external != 0 {
                    return Err(unsupported(
                        "external 7z attribute records are outside the restricted profile",
                    ));
                }
                for (index, flag) in defined.iter().enumerate() {
                    if *flag {
                        attributes[index] = Some(reader.u32_le("attribute value")?);
                    }
                }
            }
            K_DUMMY => {
                let padding = reader.take(size as usize, "dummy padding")?;
                if padding.iter().any(|byte| *byte != 0) {
                    return Err(structure("nonzero 7z dummy padding bytes"));
                }
                dummy_bytes = dummy_bytes
                    .checked_add(size)
                    .ok_or_else(|| structure("7z dummy padding overflowed u64"))?;
            }
            K_COMMENT | K_START_POS => {
                return Err(unsupported(format!(
                    "7z files property {id:#04x} is outside the restricted profile"
                )));
            }
            other => {
                return Err(unsupported(format!(
                    "7z files property {other:#04x} is outside the restricted profile"
                )));
            }
        }
        if reader.pos != record_end {
            return Err(structure(
                "a 7z files property was not consumed exactly to its declared size",
            ));
        }
    }

    let names = names.ok_or_else(|| structure("7z file records carry no names"))?;
    Ok(FilesInfo {
        num_files: num_files_claimed,
        empty_stream,
        empty_file,
        names,
        attributes,
        mtimes,
        name_region_bytes,
        dummy_bytes,
    })
}

fn parse_defined_vector(
    reader: &mut HeaderReader<'_>,
    count: usize,
    what: &str,
) -> Result<Vec<bool>, Finding> {
    match reader.byte(what)? {
        0 => reader.bit_vector(count, what),
        1 => Ok(vec![true; count]),
        other => Err(structure(format!(
            "7z {what} AllAreDefined byte {other:#04x} is not 0 or 1"
        ))),
    }
}

fn parse_time_record(
    reader: &mut HeaderReader<'_>,
    count: usize,
    what: &str,
) -> Result<Vec<Option<u64>>, Finding> {
    let defined = parse_defined_vector(reader, count, what)?;
    let external = reader.byte(what)?;
    if external != 0 {
        return Err(unsupported(format!(
            "external 7z {what}s are outside the restricted profile"
        )));
    }
    let mut values = vec![None; count];
    for (index, flag) in defined.iter().enumerate() {
        if *flag {
            values[index] = Some(reader.real_u64(what)?);
        }
    }
    Ok(values)
}

/// Decode the concatenated null-terminated UTF-16LE name region into exactly
/// `count` non-empty names, consuming the region completely.
fn decode_names(region: &[u8], count: usize) -> Result<Vec<(Vec<u8>, String)>, Finding> {
    if !region.len().is_multiple_of(2) {
        return Err(structure("7z name region is not an even number of bytes"));
    }
    let mut names = Vec::with_capacity(count);
    let mut start = 0_usize;
    let mut cursor = 0_usize;
    while cursor + 1 < region.len() + 1 {
        if cursor + 2 > region.len() {
            return Err(structure("7z name region ends without a terminator"));
        }
        let unit = u16::from_le_bytes([region[cursor], region[cursor + 1]]);
        cursor += 2;
        if unit == 0 {
            let raw = &region[start..cursor - 2];
            if raw.is_empty() {
                return Err(structure("7z member names must not be empty"));
            }
            let units: Vec<u16> = raw
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            let name: String = char::decode_utf16(units.iter().copied())
                .collect::<Result<String, _>>()
                .map_err(|_| structure("a 7z member name is not valid UTF-16"))?;
            names.push((raw.to_vec(), name));
            start = cursor;
            if names.len() == count {
                break;
            }
        }
    }
    if names.len() != count {
        return Err(structure("7z name count disagrees with the file count"));
    }
    if start != region.len() || cursor != region.len() {
        return Err(structure("7z name region is not consumed exactly"));
    }
    Ok(names)
}

/// Test-only fixtures: measured 7-Zip 26.02 output over the standard
/// conformance content, plus a raw-header builder for hostile mutations.
#[cfg(test)]
pub(crate) mod test_support {
    /// `7z a -m0=Copy -mhc=off` of exactly `mission/plan.txt` =
    /// "verify twice, decode once" (mtime 1788000000): one Copy folder,
    /// raw header, 147 bytes.
    pub(crate) const SEVENZ_CLI_FILEONLY_HEX: &str = "377abcaf271c000435c12a4919000000000000\
        005a00000000000000eaaeb7e67665726966792074776963652c206465636f6465206f6e636501040600\
        01091900070b01000101000c1900080a0103b44165000005011123006d0069007300730069006f006e00\
        2f0070006c0061006e002e0074007800740000001900140a01000000d4bda237dd011506010020000000\
        0000";

    /// `7z a -m0=Copy -mhc=off` of the `mission/` directory and its one file:
    /// two file records, one empty-stream directory entry, 166 bytes.
    pub(crate) const SEVENZ_CLI_DIR_HEX: &str = "377abcaf271c0004594020be19000000000000008600\
        000000000000c515cbb77665726966792074776963652c206465636f6465206f6e636501040600010919\
        00070b01000101000c1900080a0103b44165000005020e0180190b0000000000000000000000113300\
        6d0069007300730069006f006e0000006d0069007300730069006f006e002f0070006c0061006e002e00\
        74007800740000001900141201000000d4bda237dd010000d4bda237dd01150a0100100000002000000000\
        00";

    /// `7z a -m0=Copy -mhc=off` of a directory, an empty file, and two
    /// payload files: two Copy folders, the full empty matrix, 272 bytes.
    pub(crate) const SEVENZ_CLI_MULTI_HEX: &str = "377abcaf271c000412338a09440000000000000\
        0ee00000000000000a70495047665726966792074776963652c206465636f6465206f6e63657468652062\
        6f756e64617279206f776e7320746865206d65616e696e67206f662065766572792062797465010406000\
        209192b00070b02000101000101000c192b00080a0103b44165443d37e6000005040e01c00f0140118083\
        006d0069007300730069006f006e0000006d0069007300730069006f006e002f0065006d0070007400790\
        02e0074007800740000006d0069007300730069006f006e002f0070006c0061006e002e00740078007400\
        00006d0069007300730069006f006e002f00740065006c0065006d0065007400720079002e006c006f006\
        70000001900142201000000d4bda237dd010000d4bda237dd010000d4bda237dd010000d4bda237dd0115\
        120100100000002000000020000000200000000000";

    /// Stock `7z a -m0=Copy` (default): the next header is kEncodedHeader with
    /// an LZMA1-coded header stream — the named unsupported shape.
    pub(crate) const SEVENZ_CLI_ENCODED_HEADER_HEX: &str = "377abcaf271c0004f59452dd7800000000\
        00000021000000000000009db7c94a7665726966792074776963652c206465636f6465206f6e63650000\
        813307ae0fcf926e600febeb2d5cf9eaa7997e032f24bd2f25021d1de4439ce2744630c90a6dc37dde91\
        e412785742f539bd30d0c0918f644e5bb9f0713b9d5526658e27ebbf2feb0de156528f08f8308f33cf29\
        268f9c0a7af76e000017061901095f00070b01000123030101055d001000000c80860a01c515cbb70000";

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
}

#[cfg(test)]
mod tests {
    use super::test_support::{
        decode_hex, SEVENZ_CLI_DIR_HEX, SEVENZ_CLI_ENCODED_HEADER_HEX, SEVENZ_CLI_FILEONLY_HEX,
        SEVENZ_CLI_MULTI_HEX,
    };
    use super::*;

    fn snapshot(bytes: &[u8]) -> SourceSnapshot<'_> {
        SourceSnapshot::borrowed(None, bytes)
    }

    fn parse(bytes: &[u8]) -> Result<SevenZParsed, Finding> {
        parse_copy_portable_v1(&snapshot(bytes), 10_000, 1024 * 1024)
    }

    #[test]
    fn the_pinned_single_file_archive_parses_with_exact_evidence() {
        let source = decode_hex(SEVENZ_CLI_FILEONLY_HEX);
        let parsed = parse(&source).unwrap();
        assert_eq!(parsed.version_minor, 4);
        assert_eq!(
            parsed.pack_region,
            ByteRange {
                offset: 32,
                len: 25
            }
        );
        assert_eq!(
            parsed.next_header,
            ByteRange {
                offset: 57,
                len: 90
            }
        );
        assert_eq!(parsed.metadata_bytes, 32 + 90);
        assert_eq!(parsed.folders.len(), 1);
        assert_eq!(
            parsed.folders[0].pack_stream,
            ByteRange {
                offset: 32,
                len: 25
            }
        );
        assert_eq!(parsed.folders[0].unpack_size, 25);
        assert_eq!(parsed.folders[0].substreams.len(), 1);
        assert_eq!(parsed.members.len(), 1);
        let member = &parsed.members[0];
        assert_eq!(member.name, "mission/plan.txt");
        assert!(!member.is_dir);
        assert_eq!(member.size, 25);
        assert_eq!(
            member.payload,
            ByteRange {
                offset: 32,
                len: 25
            }
        );
        assert_eq!(member.declared_crc, Some(0x6541_B403));
        assert_eq!(member.attributes, Some(0x20));
        let payload = snapshot(&source)
            .read_vec(member.payload.offset, member.payload.len)
            .unwrap();
        assert_eq!(payload, b"verify twice, decode once");
        assert_eq!(crc32(&payload), 0x6541_B403);
    }

    #[test]
    fn the_pinned_directory_archive_separates_the_empty_matrix() {
        let source = decode_hex(SEVENZ_CLI_DIR_HEX);
        let parsed = parse(&source).unwrap();
        assert_eq!(parsed.members.len(), 2);
        assert_eq!(parsed.members[0].name, "mission");
        assert!(parsed.members[0].is_dir);
        assert_eq!(parsed.members[0].size, 0);
        assert_eq!(parsed.members[0].attributes, Some(0x10));
        assert_eq!(parsed.members[1].name, "mission/plan.txt");
        assert!(!parsed.members[1].is_dir);
        assert_eq!(parsed.dummy_bytes, 11);
    }

    #[test]
    fn the_pinned_multi_archive_covers_folders_and_the_full_empty_matrix() {
        let source = decode_hex(SEVENZ_CLI_MULTI_HEX);
        let parsed = parse(&source).unwrap();
        assert_eq!(parsed.folders.len(), 2);
        assert_eq!(parsed.members.len(), 4);
        assert!(parsed.members[0].is_dir);
        assert_eq!(parsed.members[0].name, "mission");
        assert!(!parsed.members[1].is_dir);
        assert_eq!(parsed.members[1].name, "mission/empty.txt");
        assert_eq!(parsed.members[1].size, 0);
        assert_eq!(parsed.members[2].name, "mission/plan.txt");
        assert_eq!(
            parsed.members[2].payload,
            ByteRange {
                offset: 32,
                len: 25
            }
        );
        assert_eq!(parsed.members[3].name, "mission/telemetry.log");
        assert_eq!(
            parsed.members[3].payload,
            ByteRange {
                offset: 57,
                len: 43
            }
        );
        assert_eq!(parsed.members[3].declared_crc, Some(0xE637_3D44));
    }

    #[test]
    fn stock_packed_headers_are_unsupported_with_a_named_remedy() {
        let source = decode_hex(SEVENZ_CLI_ENCODED_HEADER_HEX);
        let finding = parse(&source).unwrap_err();
        assert_eq!(finding.code, FindingCode::FormatUnsupported);
        assert!(finding.detail.contains("mhc=off"));
    }

    #[test]
    fn signature_version_and_crc_failures_classify_precisely() {
        let mut magic = decode_hex(SEVENZ_CLI_FILEONLY_HEX);
        magic[0] ^= 0xFF;
        assert_eq!(parse(&magic).unwrap_err().code, FindingCode::FormatMagic);

        let mut major = decode_hex(SEVENZ_CLI_FILEONLY_HEX);
        major[6] = 1;
        assert_eq!(
            parse(&major).unwrap_err().code,
            FindingCode::FormatUnsupported
        );

        let mut start_crc = decode_hex(SEVENZ_CLI_FILEONLY_HEX);
        start_crc[8] ^= 0x01;
        assert_eq!(
            parse(&start_crc).unwrap_err().code,
            FindingCode::CrcMismatch
        );

        let mut header_crc = decode_hex(SEVENZ_CLI_FILEONLY_HEX);
        let last = header_crc.len() - 1;
        header_crc[last] ^= 0x01;
        assert_eq!(
            parse(&header_crc).unwrap_err().code,
            FindingCode::CrcMismatch
        );

        let mut truncated = decode_hex(SEVENZ_CLI_FILEONLY_HEX);
        truncated.truncate(20);
        assert_eq!(
            parse(&truncated).unwrap_err().code,
            FindingCode::SevenZInvalidStructure
        );
    }

    #[test]
    fn dense_covering_rejects_gaps_overlaps_and_trailing_bytes() {
        let mut trailing = decode_hex(SEVENZ_CLI_FILEONLY_HEX);
        trailing.push(0x00);
        assert_eq!(
            parse(&trailing).unwrap_err().code,
            FindingCode::SevenZInvalidStructure
        );

        // Growing the declared next-header size past the end of the file.
        let mut oversize = decode_hex(SEVENZ_CLI_FILEONLY_HEX);
        oversize[20] = oversize[20].wrapping_add(1);
        let observed = crc32(&oversize[12..32]);
        oversize[8..12].copy_from_slice(&observed.to_le_bytes());
        assert_eq!(
            parse(&oversize).unwrap_err().code,
            FindingCode::SevenZInvalidStructure
        );
    }

    #[test]
    fn payload_crc_lies_fail_closed_at_the_declared_pack_digest() {
        // The pinned archive declares the substream CRC through kCRC; flip a
        // payload byte so the declared digest no longer matches when the
        // member is verified. The parser itself verifies pack and folder
        // digests; substream digests bind through the payload plan.
        let mut source = decode_hex(SEVENZ_CLI_FILEONLY_HEX);
        source[32] ^= 0x01;
        // The parse succeeds structurally (substream CRC is carried as
        // evidence), and verification catches the lie downstream.
        let parsed = parse(&source).unwrap();
        assert_eq!(parsed.members[0].declared_crc, Some(0x6541_B403));
    }

    #[test]
    fn hostile_counts_and_encodings_fail_closed() {
        // A claimed file count far beyond the remaining header bytes.
        let source = decode_hex(SEVENZ_CLI_FILEONLY_HEX);
        let parsed = parse_copy_portable_v1(&snapshot(&source), 0, 1024 * 1024).unwrap_err();
        assert_eq!(parsed.code, FindingCode::QuotaFiles);

        let denied = parse_copy_portable_v1(&snapshot(&source), 10_000, 40).unwrap_err();
        assert_eq!(denied.code, FindingCode::QuotaMetadata);
    }

    #[test]
    fn minimal_number_encoding_is_required() {
        assert_eq!(minimal_number_extra(0), 0);
        assert_eq!(minimal_number_extra(0x7F), 0);
        assert_eq!(minimal_number_extra(0x80), 1);
        assert_eq!(minimal_number_extra((1 << 14) - 1), 1);
        assert_eq!(minimal_number_extra(1 << 14), 2);
        assert_eq!(minimal_number_extra((1 << 56) - 1), 7);
        assert_eq!(minimal_number_extra(1 << 56), 8);
        assert_eq!(minimal_number_extra(u64::MAX), 8);

        let mut reader = HeaderReader {
            bytes: &[0x80, 0x05],
            pos: 0,
        };
        let finding = reader.number("test").unwrap_err();
        assert_eq!(finding.code, FindingCode::SevenZInvalidStructure);

        let mut reader = HeaderReader {
            bytes: &[0x80, 0x85],
            pos: 0,
        };
        assert_eq!(reader.number("test").unwrap(), 0x85);
    }

    #[test]
    fn nonzero_dummy_padding_and_bad_names_are_malformed() {
        // The fileonly fixture has a zero-length kDummy; the dir fixture has
        // an 11-byte one. Flip one dummy byte in the dir fixture and repair
        // the header CRC so only the padding rule can reject it.
        let mut source = decode_hex(SEVENZ_CLI_DIR_HEX);
        let header_start = 57_usize;
        let dummy_offset = source
            .windows(2)
            .enumerate()
            .skip(header_start)
            .find(|(_, pair)| pair == &[0x19, 0x0B])
            .map(|(index, _)| index + 2)
            .expect("dir fixture carries an 11-byte dummy record");
        source[dummy_offset] = 0x01;
        repair_header_crcs(&mut source, header_start);
        assert_eq!(
            parse(&source).unwrap_err().code,
            FindingCode::SevenZInvalidStructure
        );

        // An unpaired surrogate in the name region.
        let mut surrogate = decode_hex(SEVENZ_CLI_FILEONLY_HEX);
        let name_offset = surrogate
            .windows(4)
            .enumerate()
            .skip(header_start)
            .find(|(_, window)| window == b"\x6d\x00\x69\x00")
            .map(|(index, _)| index)
            .expect("fileonly fixture carries the name region");
        surrogate[name_offset] = 0x00;
        surrogate[name_offset + 1] = 0xD8;
        repair_header_crcs(&mut surrogate, header_start);
        assert_eq!(
            parse(&surrogate).unwrap_err().code,
            FindingCode::SevenZInvalidStructure
        );
    }

    /// Recompute the next-header CRC and then the start-header CRC that
    /// covers it, so a mutated header fails only on the intended rule.
    fn repair_header_crcs(source: &mut [u8], header_start: usize) {
        let next = crc32(&source[header_start..]);
        source[28..32].copy_from_slice(&next.to_le_bytes());
        let start = crc32(&source[12..32]);
        source[8..12].copy_from_slice(&start.to_le_bytes());
    }
}
