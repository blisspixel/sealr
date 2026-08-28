use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use crate::jail::{PORTABLE_PATH_GRAMMAR_ID, PORTABLE_RESERVED_NAMES_ID};
use crate::outcome::SourceDigest;
use crate::policy::hex_sha256;
use crate::tar::TarMember;
use crate::tar_gnu::GnuLongNameMember;
use crate::zip::{
    DataDescriptorWidth, Zip64LocalValueShape as ParsedZip64LocalValueShape, ZipMember,
};

pub const ARCHIVE_IR_SCHEMA: &str = "sealr.archive-ir.v1";
pub const ZIP64_ARCHIVE_IR_SCHEMA: &str = "sealr.archive-ir.zip64.v1";
pub const TAR_ARCHIVE_IR_SCHEMA: &str = "sealr.archive-ir.tar-ustar.v1";
pub const TAR_GZIP_ARCHIVE_IR_SCHEMA: &str = "sealr.archive-ir.tar-gzip-ustar.v1";
pub const TAR_PAX_ARCHIVE_IR_SCHEMA: &str = "sealr.archive-ir.tar-pax.v1";
pub const TAR_GNU_LONGNAME_ARCHIVE_IR_SCHEMA: &str = "sealr.archive-ir.tar-gnu-longname.v1";
pub const ZIP_STRICT_ASCII_V1: &str = "sealr.profile.zip.strict-ascii.v1";
pub const ZIP_STRICT_ASCII_V2: &str = "sealr.profile.zip.strict-ascii.v2";
pub const ZIP_PORTABLE_UTF8_V1: &str = "sealr.profile.zip.portable-utf8.v1";
pub const ZIP_WHEEL_UTF8_V1: &str = "sealr.profile.zip.wheel-utf8.v1";
pub const ZIP64_STRICT_ASCII_V1: &str = "sealr.profile.zip64.strict-ascii.v1";
pub const TAR_USTAR_PORTABLE_V1: &str = "sealr.profile.tar.ustar-portable.v1";
pub const TAR_GZIP_USTAR_PORTABLE_V1: &str = "sealr.profile.tar-gzip.ustar-portable.v1";
pub const TAR_PAX_PORTABLE_V1: &str = "sealr.profile.tar.pax-portable.v1";
pub const TAR_GNU_LONGNAME_PORTABLE_V1: &str = "sealr.profile.tar.gnu-longname-portable.v1";

const DENIED_EXTRA_ZIP64: u16 = 0x0001;
const DENIED_EXTRA_UNICODE_PATH: u16 = 0x7075;

/// ZIP interpretation selected for one operation.
///
/// `StrictAsciiV1` preserves the Alpha.3 compatibility language. It accepts
/// unknown flag bits and records unknown extra fields as ignored. New callers
/// that need a closed interpretation contract should select `StrictAsciiV2`,
/// which permits only flag bit 3 and denies every extra field.
/// `PortableUtf8V1` is the supported preview Unicode language. It accepts
/// strict UTF-8 names, requires bit 11 for non-ASCII names, permits data
/// descriptors, denies every extra field, and requires canonical portable
/// paths under fixed component limits.
/// `WheelUtf8V1` is a closed, research-only wheel container language. It
/// permits only the UTF-8 flag, requires that flag for non-ASCII names, denies
/// data descriptors and every extra field, and requires NFC paths.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZipInterpretationProfile {
    #[default]
    StrictAsciiV1,
    StrictAsciiV2,
    PortableUtf8V1,
    WheelUtf8V1,
    /// Closed ZIP64 language for ASCII Store and Deflate members, fixed
    /// single-disk end records, and producer-compatible size and offset forms.
    Zip64StrictAsciiV1,
}

impl ZipInterpretationProfile {
    pub const fn id(self) -> &'static str {
        match self {
            Self::StrictAsciiV1 => ZIP_STRICT_ASCII_V1,
            Self::StrictAsciiV2 => ZIP_STRICT_ASCII_V2,
            Self::PortableUtf8V1 => ZIP_PORTABLE_UTF8_V1,
            Self::WheelUtf8V1 => ZIP_WHEEL_UTF8_V1,
            Self::Zip64StrictAsciiV1 => ZIP64_STRICT_ASCII_V1,
        }
    }

    pub fn digest(self) -> String {
        match self {
            Self::StrictAsciiV1 => zip_strict_ascii_v1_digest(),
            Self::StrictAsciiV2 => zip_strict_ascii_v2_digest(),
            Self::PortableUtf8V1 => zip_portable_utf8_v1_digest(),
            Self::WheelUtf8V1 => zip_wheel_utf8_v1_digest(),
            Self::Zip64StrictAsciiV1 => zip64_strict_ascii_v1_digest(),
        }
    }

    pub const fn archive_format(self) -> ArchiveFormat {
        match self {
            Self::Zip64StrictAsciiV1 => ArchiveFormat::Zip64,
            Self::StrictAsciiV1
            | Self::StrictAsciiV2
            | Self::PortableUtf8V1
            | Self::WheelUtf8V1 => ArchiveFormat::Zip32,
        }
    }

    pub const fn policy_format(self) -> &'static str {
        match self {
            Self::Zip64StrictAsciiV1 => crate::policy::POLICY_FORMAT_ZIP64,
            Self::StrictAsciiV1
            | Self::StrictAsciiV2
            | Self::PortableUtf8V1
            | Self::WheelUtf8V1 => crate::policy::POLICY_FORMAT_ZIP,
        }
    }

    pub const fn is_zip64(self) -> bool {
        matches!(self, Self::Zip64StrictAsciiV1)
    }
}

/// TAR interpretation selected for one operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum TarInterpretationProfile {
    /// Exact POSIX ustar regular files and directories under Sealr's portable
    /// UTF-8 path contract. PAX, GNU extensions, links, sparse entries,
    /// special files, base-256 numbers, and concatenation are denied.
    #[default]
    UstarPortableV1,
}

impl TarInterpretationProfile {
    pub const fn id(self) -> &'static str {
        match self {
            Self::UstarPortableV1 => TAR_USTAR_PORTABLE_V1,
        }
    }

    pub fn digest(self) -> String {
        match self {
            Self::UstarPortableV1 => tar_ustar_portable_v1_digest(),
        }
    }
}

/// POSIX PAX interpretation selected for one operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum TarPaxInterpretationProfile {
    /// Exact POSIX ustar regular files and directories extended only by
    /// bounded `path` and `size` records in local or global PAX headers.
    #[default]
    PortableV1,
}

impl TarPaxInterpretationProfile {
    pub const fn id(self) -> &'static str {
        match self {
            Self::PortableV1 => TAR_PAX_PORTABLE_V1,
        }
    }

    pub fn digest(self) -> String {
        match self {
            Self::PortableV1 => tar_pax_portable_v1_digest(),
        }
    }
}

/// Old-GNU TAR interpretation selected for one operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum TarGnuLongNameInterpretationProfile {
    /// Exact old-GNU regular files and directories extended only by one
    /// bounded pathname-only `L` carrier consumed by the following member.
    #[default]
    PortableV1,
}

impl TarGnuLongNameInterpretationProfile {
    pub const fn id(self) -> &'static str {
        match self {
            Self::PortableV1 => TAR_GNU_LONGNAME_PORTABLE_V1,
        }
    }

    pub fn digest(self) -> String {
        match self {
            Self::PortableV1 => tar_gnu_longname_portable_v1_digest(),
        }
    }
}

/// Gzip-wrapped TAR interpretation selected for one operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum TarGzipInterpretationProfile {
    /// Exactly one strict RFC 1952 member whose bounded output is exact
    /// portable POSIX ustar.
    #[default]
    UstarPortableV1,
}

impl TarGzipInterpretationProfile {
    pub const fn id(self) -> &'static str {
        match self {
            Self::UstarPortableV1 => TAR_GZIP_USTAR_PORTABLE_V1,
        }
    }

    pub fn digest(self) -> String {
        match self {
            Self::UstarPortableV1 => tar_gzip_ustar_portable_v1_digest(),
        }
    }
}

/// Container format represented by an [`ArchiveIR`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ArchiveFormat {
    Zip32,
    Zip64,
    TarUstar,
    TarGzipUstar,
    TarPax,
    #[serde(rename = "tar-gnu-longname")]
    TarGnuLongName,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum MemberKind {
    File,
    Directory,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum MemberVerification {
    Pending,
    Verified,
    Failed { cause: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ByteRange {
    pub offset: u64,
    pub len: u64,
}

impl ByteRange {
    pub fn end(self) -> u64 {
        self.offset.saturating_add(self.len)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ExtraSite {
    Local,
    Central,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ExtraDisposition {
    Semantic,
    Ignored,
    Denied,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ExtraFieldRecord {
    pub site: ExtraSite,
    pub id: u16,
    pub header_range: ByteRange,
    pub data_range: ByteRange,
    pub disposition: ExtraDisposition,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct MemberSourceRanges {
    pub local_header: ByteRange,
    pub compressed_payload: ByteRange,
    pub data_descriptor: Option<ByteRange>,
    pub central_header: ByteRange,
}

/// Exact source evidence for one portable POSIX ustar member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct TarMemberEvidence {
    pub header: ByteRange,
    pub payload: ByteRange,
    pub padding: ByteRange,
    pub mode: u32,
    pub mtime: u64,
    pub header_checksum: u32,
    pub header_sha256: String,
}

/// PAX extension-header type admitted by the portable PAX profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PaxExtensionKind {
    Global,
    Local,
}

/// Semantic keyword admitted by the portable PAX profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PaxKeyword {
    Path,
    Size,
}

/// Exact source of an effective PAX member value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PaxValueSource {
    Ustar,
    Global {
        extension_index: u32,
        record_index: u32,
    },
    Local {
        extension_index: u32,
        record_index: u32,
    },
}

/// Ordered evidence for one completely consumed PAX record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct PaxRecordEvidence {
    /// Absolute range of the complete `<length> <keyword>=<value>\n` record.
    pub record: ByteRange,
    /// Absolute range of the raw value bytes inside `record`.
    pub value: ByteRange,
    pub keyword: PaxKeyword,
    pub raw_value_bytes: Vec<u8>,
    /// Canonical parsed decimal value for `size`; always `None` for `path`.
    pub parsed_size: Option<u64>,
}

/// Exact source evidence for one non-materialized PAX extension header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct PaxExtensionEvidence {
    pub raw_name_bytes: Vec<u8>,
    pub kind: PaxExtensionKind,
    pub header: ByteRange,
    pub payload: ByteRange,
    pub padding: ByteRange,
    pub mode: u32,
    pub mtime: u64,
    pub header_checksum: u32,
    pub header_sha256: String,
    pub payload_sha256: String,
    /// Records in exact payload order.
    pub records: Vec<PaxRecordEvidence>,
}

/// Exact structural and precedence evidence for one materialized PAX member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct TarPaxMemberEvidence {
    pub tar: TarMemberEvidence,
    /// Underlying ustar name before a PAX `path` value is applied.
    pub base_name_bytes: Vec<u8>,
    /// Underlying checksum-covered ustar size before a PAX `size` value is applied.
    pub base_size: u64,
    pub path_source: PaxValueSource,
    pub size_source: PaxValueSource,
}

/// Exact source of an effective old-GNU member pathname.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum GnuLongNamePathSource {
    Header,
    Carrier { carrier_index: u32 },
}

/// Exact source evidence for one non-materialized GNU `L` carrier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct GnuLongNameCarrierEvidence {
    pub raw_name_bytes: Vec<u8>,
    /// Complete effective pathname bytes, excluding the final carrier NUL.
    pub path_bytes: Vec<u8>,
    pub header: ByteRange,
    pub payload: ByteRange,
    /// Exact pathname bytes inside `payload`, excluding the final NUL.
    pub path: ByteRange,
    pub padding: ByteRange,
    pub mode: u32,
    pub mtime: u64,
    pub header_checksum: u32,
    pub header_sha256: String,
    pub payload_sha256: String,
}

/// Exact structural and precedence evidence for one old-GNU member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct TarGnuLongNameMemberEvidence {
    pub tar: TarMemberEvidence,
    /// Physical 1 through 100-byte name from the ordinary header.
    pub base_name_bytes: Vec<u8>,
    pub path_source: GnuLongNamePathSource,
}

/// Exact RFC 1952 wrapper evidence for a gzip-derived archive domain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct GzipWrapperEvidence {
    pub flags: u8,
    pub modification_time: u32,
    pub extra_flags: u8,
    pub operating_system: u8,
    pub header: ByteRange,
    pub extra: Option<ByteRange>,
    pub extra_subfield_count: u32,
    pub original_name: Option<ByteRange>,
    pub comment: Option<ByteRange>,
    pub header_crc16: Option<ByteRange>,
    pub compressed_payload: ByteRange,
    pub trailer: ByteRange,
    pub declared_crc32: u32,
    pub declared_isize: u32,
    pub derived_output_len: u64,
    pub derived_output_sha256: String,
}

/// Exact ZIP-specific evidence for one interpreted member.
///
/// These fields remain serialized at their historical top-level member keys so
/// the ZIP preview JSON and `sealrTreeV1` encodings stay byte-for-byte stable.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ZipMemberEvidence {
    pub method: u16,
    pub flags: u16,
    pub declared_crc: u32,
    pub declared_comp_size: u64,
    pub source_ranges: MemberSourceRanges,
    pub extra_fields: Vec<ExtraFieldRecord>,
    pub(crate) creator_system: u8,
    pub(crate) external_attributes: u32,
}

/// Width selected for a signed ZIP64-profile data descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Zip64DataDescriptorWidth {
    Zip32,
    Zip64,
}

/// Admitted semantic shape of the local ZIP64 size values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Zip64LocalValueShape {
    Absent,
    Exact,
    StreamingZeros,
    StreamingMaxima,
}

/// Exact ZIP64-specific evidence layered over the common ZIP member facts.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Zip64MemberEvidence {
    pub zip: ZipMemberEvidence,
    pub local_version_needed: u16,
    pub central_version_needed: u16,
    /// Unique `U,C,O` presence mask selected for the central ZIP64 extra.
    pub central_presence_mask: u8,
    pub central_legacy_sentinel_mask: u8,
    pub local_legacy_sentinel_mask: u8,
    pub local_value_shape: Zip64LocalValueShape,
    pub local_zip64_extra: Option<ByteRange>,
    pub central_zip64_extra: Option<ByteRange>,
    pub descriptor_width: Option<Zip64DataDescriptorWidth>,
}

#[derive(Serialize)]
struct Zip64SpecificEvidence {
    local_version_needed: u16,
    central_version_needed: u16,
    central_presence_mask: u8,
    central_legacy_sentinel_mask: u8,
    local_legacy_sentinel_mask: u8,
    local_value_shape: Zip64LocalValueShape,
    local_zip64_extra: Option<ByteRange>,
    central_zip64_extra: Option<ByteRange>,
    descriptor_width: Option<Zip64DataDescriptorWidth>,
}

impl Zip64MemberEvidence {
    fn specific(&self) -> Zip64SpecificEvidence {
        Zip64SpecificEvidence {
            local_version_needed: self.local_version_needed,
            central_version_needed: self.central_version_needed,
            central_presence_mask: self.central_presence_mask,
            central_legacy_sentinel_mask: self.central_legacy_sentinel_mask,
            local_legacy_sentinel_mask: self.local_legacy_sentinel_mask,
            local_value_shape: self.local_value_shape,
            local_zip64_extra: self.local_zip64_extra,
            central_zip64_extra: self.central_zip64_extra,
            descriptor_width: self.descriptor_width,
        }
    }
}

/// Format-native structural evidence for one interpreted member.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemberEvidence {
    Zip(ZipMemberEvidence),
    Zip64(Zip64MemberEvidence),
    Tar(TarMemberEvidence),
    TarGzip(TarMemberEvidence),
    TarPax(TarPaxMemberEvidence),
    TarGnuLongName(TarGnuLongNameMemberEvidence),
}

impl MemberSourceRanges {
    pub fn record_end(&self) -> u64 {
        self.data_descriptor
            .map(ByteRange::end)
            .unwrap_or_else(|| self.compressed_payload.end())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum NormalizationAction {
    StripDirectoryTrailingSlash,
    DropDotComponent { component_index: u32 },
}

/// Read-only central-directory facts bound to one verified member.
///
/// These facts are intentionally outside sealrTreeV1. Adding them does not
/// change Alpha.6 layout or content roots. Consumer identities that interpret
/// mode bits must bind their derived disposition separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemberContainerFacts {
    pub creator_system: u8,
    pub external_attributes: u32,
}

impl MemberContainerFacts {
    /// Unix mode when the ZIP creator system explicitly identifies Unix.
    pub fn unix_mode(self) -> Option<u16> {
        (self.creator_system == 3).then_some((self.external_attributes >> 16) as u16)
    }

    /// Whether Unix creator metadata describes an executable regular file.
    pub fn unix_regular_executable(self) -> bool {
        let Some(mode) = self.unix_mode() else {
            return false;
        };
        mode & 0o170000 == 0o100000 && mode & 0o111 != 0
    }

    /// Executable disposition used by PyPA installer 0.7.0 WheelFile.
    pub fn pypa_installer_0_7_executable(self) -> bool {
        let mode = (self.external_attributes >> 16) as u16;
        mode & 0o170000 == 0o100000 && mode & 0o111 != 0
    }
}

/// Hashed description of the current ZIP interpretation. The digest covers the
/// actual method, flag, extra-field, and name rules, not only the profile name.
#[derive(Clone, Debug, Serialize)]
struct ZipStrictAsciiProfile {
    schema: &'static str,
    format: &'static str,
    methods: [u16; 2],
    extra_fields_denied: [u16; 2],
    extra_fields_other: &'static str,
    gp_encryption_bit: u16,
    gp_data_descriptor_bit: u16,
    gp_utf8_bit: u16,
    gp_other_bits: &'static str,
    names: &'static str,
    directories: &'static str,
    redundant_metadata: &'static str,
}

fn zip_strict_ascii_profile() -> ZipStrictAsciiProfile {
    ZipStrictAsciiProfile {
        schema: ZIP_STRICT_ASCII_V1,
        format: "zip32",
        methods: [0, 8],
        extra_fields_denied: [DENIED_EXTRA_ZIP64, DENIED_EXTRA_UNICODE_PATH],
        extra_fields_other: "ignored",
        gp_encryption_bit: 0,
        gp_data_descriptor_bit: 3,
        gp_utf8_bit: 11,
        gp_other_bits: "accepted",
        names: "ascii-or-utf8-flag-reject-non-ascii-cp437",
        directories: "trailing-slash-store-empty-crc32-zero",
        redundant_metadata: "exact-lfh-cdh-descriptor",
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
struct GeneralPurposeBitRule {
    bit: u8,
    mask: u16,
    disposition: &'static str,
    meaning: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct ZipStrictAsciiV2Profile {
    schema: &'static str,
    format: &'static str,
    methods: [u16; 2],
    general_purpose_bits: [GeneralPurposeBitRule; 16],
    extra_fields_semantic: [u16; 0],
    extra_fields_permitted_nonsemantic: [u16; 0],
    extra_fields_other: &'static str,
    names: &'static str,
    directories: &'static str,
    redundant_metadata: &'static str,
}

fn zip_strict_ascii_v2_profile() -> ZipStrictAsciiV2Profile {
    ZipStrictAsciiV2Profile {
        schema: ZIP_STRICT_ASCII_V2,
        format: "zip32",
        methods: [0, 8],
        general_purpose_bits: [
            GeneralPurposeBitRule {
                bit: 0,
                mask: 0x0001,
                disposition: "denied",
                meaning: "traditional-encryption",
            },
            GeneralPurposeBitRule {
                bit: 1,
                mask: 0x0002,
                disposition: "denied",
                meaning: "method-dependent-option-1",
            },
            GeneralPurposeBitRule {
                bit: 2,
                mask: 0x0004,
                disposition: "denied",
                meaning: "method-dependent-option-2",
            },
            GeneralPurposeBitRule {
                bit: 3,
                mask: 0x0008,
                disposition: "semantic",
                meaning: "data-descriptor",
            },
            GeneralPurposeBitRule {
                bit: 4,
                mask: 0x0010,
                disposition: "denied",
                meaning: "enhanced-deflating",
            },
            GeneralPurposeBitRule {
                bit: 5,
                mask: 0x0020,
                disposition: "denied",
                meaning: "compressed-patched-data",
            },
            GeneralPurposeBitRule {
                bit: 6,
                mask: 0x0040,
                disposition: "denied",
                meaning: "strong-encryption",
            },
            GeneralPurposeBitRule {
                bit: 7,
                mask: 0x0080,
                disposition: "denied",
                meaning: "unused",
            },
            GeneralPurposeBitRule {
                bit: 8,
                mask: 0x0100,
                disposition: "denied",
                meaning: "unused",
            },
            GeneralPurposeBitRule {
                bit: 9,
                mask: 0x0200,
                disposition: "denied",
                meaning: "unused",
            },
            GeneralPurposeBitRule {
                bit: 10,
                mask: 0x0400,
                disposition: "denied",
                meaning: "unused",
            },
            GeneralPurposeBitRule {
                bit: 11,
                mask: 0x0800,
                disposition: "denied",
                meaning: "utf8-name",
            },
            GeneralPurposeBitRule {
                bit: 12,
                mask: 0x1000,
                disposition: "denied",
                meaning: "reserved-enhanced-compression",
            },
            GeneralPurposeBitRule {
                bit: 13,
                mask: 0x2000,
                disposition: "denied",
                meaning: "masked-local-header",
            },
            GeneralPurposeBitRule {
                bit: 14,
                mask: 0x4000,
                disposition: "denied",
                meaning: "alternate-streams",
            },
            GeneralPurposeBitRule {
                bit: 15,
                mask: 0x8000,
                disposition: "denied",
                meaning: "reserved",
            },
        ],
        extra_fields_semantic: [],
        extra_fields_permitted_nonsemantic: [],
        extra_fields_other: "denied",
        names: "ascii-only-utf8-flag-denied",
        directories: "trailing-slash-store-empty-crc32-zero",
        redundant_metadata: "exact-lfh-cdh-descriptor",
    }
}

#[derive(Clone, Debug, Serialize)]
struct Zip64StrictAsciiV1Profile {
    schema: &'static str,
    format: &'static str,
    methods: [u16; 2],
    general_purpose_bits: [GeneralPurposeBitRule; 16],
    names: &'static str,
    extra_fields: &'static str,
    local_zip64: &'static str,
    central_zip64: &'static str,
    descriptor_width: &'static str,
    descriptors: &'static str,
    global_end_records: &'static str,
    spanning: &'static str,
    directories: &'static str,
    redundant_metadata: &'static str,
}

fn zip64_strict_ascii_v1_profile() -> Zip64StrictAsciiV1Profile {
    Zip64StrictAsciiV1Profile {
        schema: ZIP64_STRICT_ASCII_V1,
        format: "zip64",
        methods: [0, 8],
        general_purpose_bits: zip_strict_ascii_v2_profile().general_purpose_bits,
        names: "strict-ascii",
        extra_fields: "exactly-one-semantic-zip64-per-site-or-none-all-other-ids-denied",
        local_zip64: "exact-u-c-or-cpython-zero-pair-or-zip-rs-max-pair",
        central_zip64: "unique-fixed-order-u-c-o-mask-with-exact-redundancy",
        descriptor_width: "zip64-iff-local-zip64-or-resolved-size-at-least-u32-max",
        descriptors: "signed-only-exact-crc-compressed-uncompressed",
        global_end_records: "optional-fixed-56-byte-eocd-plus-adjacent-20-byte-locator",
        spanning: "denied-single-disk-only",
        directories: "trailing-slash-store-empty-crc32-zero",
        redundant_metadata: "exact-producer-compatible-lfh-cdh-descriptor-and-end-records",
    }
}

#[derive(Clone, Debug, Serialize)]
struct ZipWheelUtf8V1Profile {
    schema: &'static str,
    status: &'static str,
    format: &'static str,
    methods: [u16; 2],
    general_purpose_bits: [GeneralPurposeBitRule; 16],
    extra_fields_semantic: [u16; 0],
    extra_fields_permitted_nonsemantic: [u16; 0],
    extra_fields_other: &'static str,
    names: &'static str,
    normalization: &'static str,
    case_collision: &'static str,
    directories: &'static str,
    redundant_metadata: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct ZipPortableUtf8V1Profile {
    schema: &'static str,
    status: &'static str,
    format: &'static str,
    methods: [u16; 2],
    general_purpose_bits: [GeneralPurposeBitRule; 16],
    extra_fields_semantic: [u16; 0],
    extra_fields_permitted_nonsemantic: [u16; 0],
    extra_fields_other: &'static str,
    names: &'static str,
    legacy_encoding: &'static str,
    unicode_repertoire_version: &'static str,
    unicode_repertoire: &'static str,
    unicode_repertoire_implementation: &'static str,
    character_restrictions: &'static str,
    path_grammar: &'static str,
    reserved_names: &'static str,
    normalization_unicode_version: &'static str,
    normalization_implementation: &'static str,
    case_folding_unicode_version: &'static str,
    case_folding_implementation: &'static str,
    normalization: &'static str,
    case_collision: &'static str,
    component_limit: &'static str,
    directories: &'static str,
    redundant_metadata: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct TarUstarPortableV1Profile {
    schema: &'static str,
    status: &'static str,
    format: &'static str,
    block_bytes: u16,
    header_magic: &'static str,
    header_version: &'static str,
    accepted_types: [&'static str; 2],
    numeric_encoding: &'static str,
    checksum: &'static str,
    fixed_text_fields: &'static str,
    owner_names: &'static str,
    mode: &'static str,
    linkname: &'static str,
    device_numbers: &'static str,
    reserved_bytes: &'static str,
    member_padding: &'static str,
    termination: &'static str,
    destination_metadata: &'static str,
    names: &'static str,
    unicode_repertoire_version: &'static str,
    unicode_repertoire: &'static str,
    unicode_repertoire_implementation: &'static str,
    character_restrictions: &'static str,
    path_grammar: &'static str,
    reserved_names: &'static str,
    normalization_unicode_version: &'static str,
    normalization_implementation: &'static str,
    case_folding_unicode_version: &'static str,
    case_folding_implementation: &'static str,
    normalization: &'static str,
    case_collision: &'static str,
    component_limit: &'static str,
    denied_features: [&'static str; 10],
}

#[derive(Clone, Debug, Serialize)]
struct TarGzipUstarPortableV1Profile {
    schema: &'static str,
    status: &'static str,
    format: &'static str,
    wrapper_profile: &'static str,
    wrapper_profile_sha256: &'static str,
    decoder_parameters_sha256: &'static str,
    gzip_members: &'static str,
    gzip_optional_fields: &'static str,
    gzip_integrity: &'static str,
    gzip_trailing_input: &'static str,
    derived_output: &'static str,
    inner_profile: &'static str,
    inner_profile_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
struct TarPaxPortableV1Profile {
    schema: &'static str,
    status: &'static str,
    format: &'static str,
    base_profile: &'static str,
    base_profile_sha256: String,
    extension_types: [&'static str; 2],
    extension_carrier_names: &'static str,
    underlying_member_names: &'static str,
    extension_materialization: &'static str,
    record_encoding: &'static str,
    length_encoding: &'static str,
    record_consumption: &'static str,
    keywords: [&'static str; 2],
    duplicate_keywords: &'static str,
    unknown_keywords: &'static str,
    empty_values: &'static str,
    path_values: &'static str,
    size_values: &'static str,
    precedence: &'static str,
    global_state: &'static str,
    local_state: &'static str,
    max_extension_payload_bytes: u32,
    max_extension_headers: u16,
    max_records_per_extension: u8,
    max_keyword_scan_bytes: u8,
    max_effective_path_bytes: &'static str,
    denied_features: [&'static str; 10],
}

#[derive(Clone, Debug, Serialize)]
struct TarGnuLongNamePortableV1Profile {
    schema: &'static str,
    status: &'static str,
    format: &'static str,
    block_bytes: u16,
    header_magic_and_version: &'static str,
    accepted_types: [&'static str; 3],
    numeric_encoding: &'static str,
    checksum: &'static str,
    fixed_text_fields: &'static str,
    owner_names: &'static str,
    mode: &'static str,
    linkname: &'static str,
    device_numbers: &'static str,
    gnu_tail: &'static str,
    carrier_names: &'static str,
    carrier_payload: &'static str,
    carrier_state: &'static str,
    physical_name_binding: &'static str,
    min_effective_path_bytes: u8,
    max_effective_path_bytes: &'static str,
    max_carrier_payload_bytes: u16,
    max_carrier_headers: u16,
    carrier_materialization: &'static str,
    member_padding: &'static str,
    termination: &'static str,
    destination_metadata: &'static str,
    names: &'static str,
    unicode_repertoire_version: &'static str,
    unicode_repertoire: &'static str,
    unicode_repertoire_implementation: &'static str,
    character_restrictions: &'static str,
    path_grammar: &'static str,
    reserved_names: &'static str,
    normalization_unicode_version: &'static str,
    normalization_implementation: &'static str,
    case_folding_unicode_version: &'static str,
    case_folding_implementation: &'static str,
    normalization: &'static str,
    case_collision: &'static str,
    component_limit: &'static str,
    denied_features: [&'static str; 13],
}

fn tar_ustar_portable_v1_profile() -> TarUstarPortableV1Profile {
    TarUstarPortableV1Profile {
        schema: TAR_USTAR_PORTABLE_V1,
        status: "supported-preview",
        format: "posix-ustar",
        block_bytes: 512,
        header_magic: "757374617200",
        header_version: "3030",
        accepted_types: ["regular-0-or-nul", "directory-5-size-zero"],
        numeric_encoding: "one-or-more-ascii-octal-digits;one-or-more-nul-or-space-terminators;no-leading-space;gnu-base256-denied",
        checksum: "six-octal-digits-nul-space;unsigned-byte-sum-with-spaces",
        fixed_text_fields: "name-and-prefix-may-fill-field;after-first-nul-all-bytes-zero",
        owner_names: "nul-terminated-printable-ascii;remaining-bytes-zero",
        mode: "ascii-octal-permission-bits<=07777",
        linkname: "all-zero",
        device_numbers: "all-zero-bytes-or-ascii-octal-zero;never-applied",
        reserved_bytes: "header-500-through-511-all-zero",
        member_padding: "zero-to-512-byte-boundary",
        termination: "two-zero-blocks;remaining-complete-blocks-zero",
        destination_metadata: "uid-gid-uname-gname-mtime-not-applied;mode-recorded-not-applied;setid-and-special-effects-never-applied",
        names: "strict-utf8-name-plus-optional-prefix",
        unicode_repertoire_version: "16.0.0",
        unicode_repertoire: "public-assigned-no-private-use",
        unicode_repertoire_implementation: "unicode-general-category-1.1.0-exact",
        character_restrictions: "unicode-16-general-category-cc;white-space-0085-00a0-1680-2000..200a-2028-2029-202f-205f-3000;bidi-control-061c-200e-200f-202a..202e-2066..2069",
        path_grammar: PORTABLE_PATH_GRAMMAR_ID,
        reserved_names: PORTABLE_RESERVED_NAMES_ID,
        normalization_unicode_version: "17.0.0-stable-for-16.0.0-repertoire",
        normalization_implementation: "unicode-normalization-0.1.25-exact",
        case_folding_unicode_version: "16.0.0",
        case_folding_implementation: "caseless-0.2.2-exact",
        normalization: "unicode-17-full-nfc-over-unicode-16-repertoire-no-dot-component",
        case_collision: "unicode-16-full-default-case-fold-then-nfc",
        component_limit: "utf8-bytes<=255-and-utf16-code-units<=255",
        denied_features: [
            "pax-local-header",
            "pax-global-header",
            "gnu-long-name",
            "gnu-long-link",
            "sparse-file",
            "hard-link",
            "symbolic-link",
            "device-or-fifo",
            "multi-volume",
            "concatenated-archive",
        ],
    }
}

fn tar_gzip_ustar_portable_v1_profile() -> TarGzipUstarPortableV1Profile {
    TarGzipUstarPortableV1Profile {
        schema: TAR_GZIP_USTAR_PORTABLE_V1,
        status: "supported-preview",
        format: "tar-gzip-ustar",
        wrapper_profile: "sealr.transform.gzip.rfc1952-single-member.v1",
        wrapper_profile_sha256: "795a124c278eacf1fb9b4fc3825a74240d6d0e89c29ffdfe6118ff6db53c0a45",
        decoder_parameters_sha256:
            "c835627b01c4b54041c627319fab4d5af294a203ac26fbe91cadb6d1f17cd5e1",
        gzip_members: "exactly-one",
        gzip_optional_fields: "bounded-exact-rfc1952-framing-si2-nonzero-unique-ids",
        gzip_integrity: "fhcrc-when-present-and-crc32-and-isize",
        gzip_trailing_input: "denied-including-zero-padding-and-concatenation",
        derived_output: "private-immutable-bounded-and-sha256-bound",
        inner_profile: TAR_USTAR_PORTABLE_V1,
        inner_profile_sha256: tar_ustar_portable_v1_digest(),
    }
}

fn tar_pax_portable_v1_profile() -> TarPaxPortableV1Profile {
    TarPaxPortableV1Profile {
        schema: TAR_PAX_PORTABLE_V1,
        status: "supported-preview",
        format: "posix-pax",
        base_profile: TAR_USTAR_PORTABLE_V1,
        base_profile_sha256: tar_ustar_portable_v1_digest(),
        extension_types: ["global-g", "local-x"],
        extension_carrier_names: "structurally-valid-ustar-text-not-destination-validated",
        underlying_member_names:
            "structurally-valid-ustar-text-destination-validated-only-when-effective",
        extension_materialization: "metadata-only-never-a-member",
        record_encoding: "decimal-length-space-keyword-equals-value-newline",
        length_encoding: "canonical-ascii-decimal-no-leading-zero-max-20-digits",
        record_consumption: "declared-length-exact-and-entire-payload-consumed",
        keywords: ["path", "size"],
        duplicate_keywords: "denied-within-one-extension",
        unknown_keywords: "denied",
        empty_values: "denied",
        path_values: "strict-utf8-portable-path-v1",
        size_values: "canonical-ascii-decimal-u64",
        precedence: "local-over-global-over-ustar",
        global_state: "fixed-path-and-size-fields-last-global-value-persists",
        local_state: "at-most-one-pending-header-consumed-by-exactly-one-file-or-directory",
        max_extension_payload_bytes: 64 * 1024,
        max_extension_headers: 1024,
        max_records_per_extension: 2,
        max_keyword_scan_bytes: 16,
        max_effective_path_bytes: "min-8191-and-256-times-policy-max-path-depth-minus-1",
        denied_features: [
            "gnu-long-name",
            "gnu-long-link",
            "sparse-file",
            "hard-link",
            "symbolic-link",
            "device-or-fifo",
            "base-256-numbers",
            "mixed-pax-and-gnu-state",
            "orphan-local-header",
            "concatenated-archive",
        ],
    }
}

fn tar_gnu_longname_portable_v1_profile() -> TarGnuLongNamePortableV1Profile {
    TarGnuLongNamePortableV1Profile {
        schema: TAR_GNU_LONGNAME_PORTABLE_V1,
        status: "supported-preview",
        format: "old-gnu-tar-long-name-only",
        block_bytes: 512,
        header_magic_and_version: "7573746172202000",
        accepted_types: ["regular-0-or-nul", "directory-5-size-zero", "long-name-L"],
        numeric_encoding: "one-or-more-ascii-octal-digits;one-or-more-nul-or-space-terminators;no-leading-space;base256-denied",
        checksum: "six-octal-digits-nul-space;unsigned-byte-sum-with-spaces",
        fixed_text_fields: "name-may-fill-field;after-first-nul-all-bytes-zero",
        owner_names: "nul-terminated-printable-ascii;remaining-bytes-zero",
        mode: "ascii-octal-permission-bits<=07777",
        linkname: "all-zero",
        device_numbers: "all-zero-bytes-or-ascii-octal-zero;never-applied",
        gnu_tail: "header-345-through-511-all-zero",
        carrier_names: "structurally-valid-oldgnu-text-not-destination-validated-and-bound-as-evidence",
        carrier_payload: "strict-utf8-effective-path-followed-by-exactly-one-final-nul;no-embedded-nul",
        carrier_state: "at-most-one-pending-L-consumed-by-exactly-one-following-file-or-directory",
        physical_name_binding: "ordinary-header-name-bound-as-overridden-evidence-without-equality-rule",
        min_effective_path_bytes: 1,
        max_effective_path_bytes: "min-8191-and-256-times-policy-max-path-depth-minus-1",
        max_carrier_payload_bytes: 8192,
        max_carrier_headers: 1024,
        carrier_materialization: "metadata-only-never-a-member",
        member_padding: "zero-to-512-byte-boundary",
        termination: "two-zero-blocks;remaining-complete-blocks-zero",
        destination_metadata: "uid-gid-uname-gname-mtime-not-applied;mode-recorded-not-applied;setid-and-special-effects-never-applied",
        names: "strict-utf8-oldgnu-name-or-L-value",
        unicode_repertoire_version: "16.0.0",
        unicode_repertoire: "public-assigned-no-private-use",
        unicode_repertoire_implementation: "unicode-general-category-1.1.0-exact",
        character_restrictions: "unicode-16-general-category-cc;white-space-0085-00a0-1680-2000..200a-2028-2029-202f-205f-3000;bidi-control-061c-200e-200f-202a..202e-2066..2069",
        path_grammar: PORTABLE_PATH_GRAMMAR_ID,
        reserved_names: PORTABLE_RESERVED_NAMES_ID,
        normalization_unicode_version: "17.0.0-stable-for-16.0.0-repertoire",
        normalization_implementation: "unicode-normalization-0.1.25-exact",
        case_folding_unicode_version: "16.0.0",
        case_folding_implementation: "caseless-0.2.2-exact",
        normalization: "unicode-17-full-nfc-over-unicode-16-repertoire-no-dot-component",
        case_collision: "unicode-16-full-default-case-fold-then-nfc",
        component_limit: "utf8-bytes<=255-and-utf16-code-units<=255",
        denied_features: [
            "pax-local-header",
            "pax-global-header",
            "gnu-long-link",
            "gnu-sparse",
            "gnu-incremental",
            "hard-link",
            "symbolic-link",
            "device-or-fifo",
            "base-256-numbers",
            "mixed-dialect-state",
            "orphan-or-chained-carrier",
            "multi-volume",
            "concatenated-archive",
        ],
    }
}

fn zip_portable_utf8_v1_profile() -> ZipPortableUtf8V1Profile {
    ZipPortableUtf8V1Profile {
        schema: ZIP_PORTABLE_UTF8_V1,
        status: "supported-preview",
        format: "zip32",
        methods: [0, 8],
        general_purpose_bits: [
            GeneralPurposeBitRule {
                bit: 0,
                mask: 0x0001,
                disposition: "denied",
                meaning: "traditional-encryption",
            },
            GeneralPurposeBitRule {
                bit: 1,
                mask: 0x0002,
                disposition: "denied",
                meaning: "method-dependent-option-1",
            },
            GeneralPurposeBitRule {
                bit: 2,
                mask: 0x0004,
                disposition: "denied",
                meaning: "method-dependent-option-2",
            },
            GeneralPurposeBitRule {
                bit: 3,
                mask: 0x0008,
                disposition: "semantic",
                meaning: "data-descriptor",
            },
            GeneralPurposeBitRule {
                bit: 4,
                mask: 0x0010,
                disposition: "denied",
                meaning: "enhanced-deflating",
            },
            GeneralPurposeBitRule {
                bit: 5,
                mask: 0x0020,
                disposition: "denied",
                meaning: "compressed-patched-data",
            },
            GeneralPurposeBitRule {
                bit: 6,
                mask: 0x0040,
                disposition: "denied",
                meaning: "strong-encryption",
            },
            GeneralPurposeBitRule {
                bit: 7,
                mask: 0x0080,
                disposition: "denied",
                meaning: "unused",
            },
            GeneralPurposeBitRule {
                bit: 8,
                mask: 0x0100,
                disposition: "denied",
                meaning: "unused",
            },
            GeneralPurposeBitRule {
                bit: 9,
                mask: 0x0200,
                disposition: "denied",
                meaning: "unused",
            },
            GeneralPurposeBitRule {
                bit: 10,
                mask: 0x0400,
                disposition: "denied",
                meaning: "unused",
            },
            GeneralPurposeBitRule {
                bit: 11,
                mask: 0x0800,
                disposition: "semantic",
                meaning: "utf8-name",
            },
            GeneralPurposeBitRule {
                bit: 12,
                mask: 0x1000,
                disposition: "denied",
                meaning: "reserved-enhanced-compression",
            },
            GeneralPurposeBitRule {
                bit: 13,
                mask: 0x2000,
                disposition: "denied",
                meaning: "masked-local-header",
            },
            GeneralPurposeBitRule {
                bit: 14,
                mask: 0x4000,
                disposition: "denied",
                meaning: "alternate-streams",
            },
            GeneralPurposeBitRule {
                bit: 15,
                mask: 0x8000,
                disposition: "denied",
                meaning: "reserved",
            },
        ],
        extra_fields_semantic: [],
        extra_fields_permitted_nonsemantic: [],
        extra_fields_other: "denied",
        names: "strict-utf8-nonascii-requires-bit11",
        legacy_encoding: "nonascii-without-bit11-denied-cp437-separate-profile",
        unicode_repertoire_version: "16.0.0",
        unicode_repertoire: "public-assigned-no-private-use",
        unicode_repertoire_implementation: "unicode-general-category-1.1.0-exact",
        character_restrictions: "unicode-16-general-category-cc;white-space-0085-00a0-1680-2000..200a-2028-2029-202f-205f-3000;bidi-control-061c-200e-200f-202a..202e-2066..2069",
        path_grammar: PORTABLE_PATH_GRAMMAR_ID,
        reserved_names: PORTABLE_RESERVED_NAMES_ID,
        normalization_unicode_version: "17.0.0-stable-for-16.0.0-repertoire",
        normalization_implementation: "unicode-normalization-0.1.25-exact",
        case_folding_unicode_version: "16.0.0",
        case_folding_implementation: "caseless-0.2.2-exact",
        normalization: "unicode-17-full-nfc-over-unicode-16-repertoire-no-dot-component",
        case_collision: "unicode-16-full-default-case-fold-then-nfc",
        component_limit: "utf8-bytes<=255-and-utf16-code-units<=255",
        directories: "trailing-slash-store-empty-crc32-zero",
        redundant_metadata: "exact-lfh-cdh-optional-descriptor",
    }
}

fn zip_wheel_utf8_v1_profile() -> ZipWheelUtf8V1Profile {
    ZipWheelUtf8V1Profile {
        schema: ZIP_WHEEL_UTF8_V1,
        status: "nonshipping-research",
        format: "zip32",
        methods: [0, 8],
        general_purpose_bits: [
            GeneralPurposeBitRule {
                bit: 0,
                mask: 0x0001,
                disposition: "denied",
                meaning: "traditional-encryption",
            },
            GeneralPurposeBitRule {
                bit: 1,
                mask: 0x0002,
                disposition: "denied",
                meaning: "method-dependent-option-1",
            },
            GeneralPurposeBitRule {
                bit: 2,
                mask: 0x0004,
                disposition: "denied",
                meaning: "method-dependent-option-2",
            },
            GeneralPurposeBitRule {
                bit: 3,
                mask: 0x0008,
                disposition: "denied",
                meaning: "data-descriptor",
            },
            GeneralPurposeBitRule {
                bit: 4,
                mask: 0x0010,
                disposition: "denied",
                meaning: "enhanced-deflating",
            },
            GeneralPurposeBitRule {
                bit: 5,
                mask: 0x0020,
                disposition: "denied",
                meaning: "compressed-patched-data",
            },
            GeneralPurposeBitRule {
                bit: 6,
                mask: 0x0040,
                disposition: "denied",
                meaning: "strong-encryption",
            },
            GeneralPurposeBitRule {
                bit: 7,
                mask: 0x0080,
                disposition: "denied",
                meaning: "unused",
            },
            GeneralPurposeBitRule {
                bit: 8,
                mask: 0x0100,
                disposition: "denied",
                meaning: "unused",
            },
            GeneralPurposeBitRule {
                bit: 9,
                mask: 0x0200,
                disposition: "denied",
                meaning: "unused",
            },
            GeneralPurposeBitRule {
                bit: 10,
                mask: 0x0400,
                disposition: "denied",
                meaning: "unused",
            },
            GeneralPurposeBitRule {
                bit: 11,
                mask: 0x0800,
                disposition: "semantic",
                meaning: "utf8-name",
            },
            GeneralPurposeBitRule {
                bit: 12,
                mask: 0x1000,
                disposition: "denied",
                meaning: "reserved-enhanced-compression",
            },
            GeneralPurposeBitRule {
                bit: 13,
                mask: 0x2000,
                disposition: "denied",
                meaning: "masked-local-header",
            },
            GeneralPurposeBitRule {
                bit: 14,
                mask: 0x4000,
                disposition: "denied",
                meaning: "alternate-streams",
            },
            GeneralPurposeBitRule {
                bit: 15,
                mask: 0x8000,
                disposition: "denied",
                meaning: "reserved",
            },
        ],
        extra_fields_semantic: [],
        extra_fields_permitted_nonsemantic: [],
        extra_fields_other: "denied",
        names: "strict-utf8-nonascii-requires-bit11",
        normalization: "nfc-no-dot-component",
        case_collision: "rust-1.98-lowercase-then-nfc",
        directories: "trailing-slash-store-empty-crc32-zero",
        redundant_metadata: "exact-lfh-cdh-no-descriptor",
    }
}

pub fn zip_strict_ascii_v1_digest() -> String {
    hex_sha256(&zip_strict_ascii_v1_canonical_bytes())
}

pub fn zip_strict_ascii_v2_digest() -> String {
    hex_sha256(&zip_strict_ascii_v2_canonical_bytes())
}

pub fn zip_portable_utf8_v1_digest() -> String {
    hex_sha256(&zip_portable_utf8_v1_canonical_bytes())
}

pub fn zip_wheel_utf8_v1_digest() -> String {
    hex_sha256(&zip_wheel_utf8_v1_canonical_bytes())
}

pub fn zip64_strict_ascii_v1_digest() -> String {
    hex_sha256(&zip64_strict_ascii_v1_canonical_bytes())
}

pub fn tar_ustar_portable_v1_digest() -> String {
    hex_sha256(&tar_ustar_portable_v1_canonical_bytes())
}

pub fn tar_gzip_ustar_portable_v1_digest() -> String {
    hex_sha256(&tar_gzip_ustar_portable_v1_canonical_bytes())
}

pub fn tar_pax_portable_v1_digest() -> String {
    hex_sha256(&tar_pax_portable_v1_canonical_bytes())
}

pub fn tar_gnu_longname_portable_v1_digest() -> String {
    hex_sha256(&tar_gnu_longname_portable_v1_canonical_bytes())
}

/// Canonical JSON bytes hashed by the v1 interpretation identity.
pub fn zip_strict_ascii_v1_canonical_bytes() -> Vec<u8> {
    serde_json::to_vec(&zip_strict_ascii_profile()).expect("profile serializes")
}

/// Canonical JSON bytes hashed by the v2 interpretation identity.
pub fn zip_strict_ascii_v2_canonical_bytes() -> Vec<u8> {
    serde_json::to_vec(&zip_strict_ascii_v2_profile()).expect("profile serializes")
}

/// Canonical JSON bytes hashed by the portable UTF-8 interpretation.
pub fn zip_portable_utf8_v1_canonical_bytes() -> Vec<u8> {
    serde_json::to_vec(&zip_portable_utf8_v1_profile()).expect("profile serializes")
}

/// Canonical JSON bytes hashed by the research wheel UTF-8 interpretation.
pub fn zip_wheel_utf8_v1_canonical_bytes() -> Vec<u8> {
    serde_json::to_vec(&zip_wheel_utf8_v1_profile()).expect("profile serializes")
}

/// Canonical JSON bytes hashed by the strict ZIP64 interpretation.
pub fn zip64_strict_ascii_v1_canonical_bytes() -> Vec<u8> {
    serde_json::to_vec(&zip64_strict_ascii_v1_profile()).expect("profile serializes")
}

/// Canonical JSON bytes hashed by the portable POSIX ustar interpretation.
pub fn tar_ustar_portable_v1_canonical_bytes() -> Vec<u8> {
    serde_json::to_vec(&tar_ustar_portable_v1_profile()).expect("profile serializes")
}

/// Canonical JSON bytes hashed by the gzip-wrapped portable ustar interpretation.
pub fn tar_gzip_ustar_portable_v1_canonical_bytes() -> Vec<u8> {
    serde_json::to_vec(&tar_gzip_ustar_portable_v1_profile()).expect("profile serializes")
}

/// Canonical JSON bytes hashed by the portable POSIX PAX interpretation.
pub fn tar_pax_portable_v1_canonical_bytes() -> Vec<u8> {
    serde_json::to_vec(&tar_pax_portable_v1_profile()).expect("profile serializes")
}

/// Canonical JSON bytes hashed by the old-GNU long-name interpretation.
pub fn tar_gnu_longname_portable_v1_canonical_bytes() -> Vec<u8> {
    serde_json::to_vec(&tar_gnu_longname_portable_v1_profile()).expect("profile serializes")
}

pub fn is_denied_extra_id(id: u16) -> bool {
    id == DENIED_EXTRA_ZIP64 || id == DENIED_EXTRA_UNICODE_PATH
}

/// One member of a versioned, effect-independent archive interpretation.
///
/// Names, destination meaning, declared output size, and measured verification
/// are common. Container-specific structure is carried only by [`MemberEvidence`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct IrMember {
    pub raw_name_bytes: Vec<u8>,
    pub decoded_name: String,
    pub canonical_path: String,
    pub components: Vec<String>,
    pub kind: MemberKind,
    pub declared_uncomp_size: u64,
    pub evidence: MemberEvidence,
    pub actual_uncomp_size: Option<u64>,
    pub actual_crc: Option<u32>,
    pub content_sha256: Option<String>,
    pub verification: MemberVerification,
    pub normalization_actions: Vec<NormalizationAction>,
}

impl IrMember {
    pub(crate) fn from_planned(
        zip: ZipMember,
        components: Vec<String>,
        normalization_actions: Vec<NormalizationAction>,
    ) -> Self {
        let kind = if zip.is_dir {
            MemberKind::Directory
        } else {
            MemberKind::File
        };
        Self {
            raw_name_bytes: zip.raw_name,
            decoded_name: zip.name,
            canonical_path: components.join("/"),
            components,
            kind,
            declared_uncomp_size: zip.uncomp_size,
            evidence: MemberEvidence::Zip(ZipMemberEvidence {
                method: zip.method,
                flags: zip.flags,
                declared_crc: zip.crc,
                declared_comp_size: zip.comp_size,
                source_ranges: zip.source_ranges,
                extra_fields: zip.extra_fields,
                creator_system: zip.creator_system,
                external_attributes: zip.external_attributes,
            }),
            actual_uncomp_size: None,
            actual_crc: None,
            content_sha256: None,
            verification: MemberVerification::Pending,
            normalization_actions,
        }
    }

    pub(crate) fn from_zip64_planned(
        zip: ZipMember,
        components: Vec<String>,
        normalization_actions: Vec<NormalizationAction>,
    ) -> Self {
        let kind = if zip.is_dir {
            MemberKind::Directory
        } else {
            MemberKind::File
        };
        let local_zip64_extra = zip
            .extra_fields
            .iter()
            .find(|field| field.site == ExtraSite::Local && field.id == DENIED_EXTRA_ZIP64)
            .map(|field| field.data_range);
        let central_zip64_extra = zip
            .extra_fields
            .iter()
            .find(|field| field.site == ExtraSite::Central && field.id == DENIED_EXTRA_ZIP64)
            .map(|field| field.data_range);
        let parsed = zip
            .zip64_evidence
            .expect("ZIP64 planning requires parser-native ZIP64 evidence");
        let descriptor_width = parsed.descriptor_width.map(|width| match width {
            DataDescriptorWidth::Zip32 => Zip64DataDescriptorWidth::Zip32,
            DataDescriptorWidth::Zip64 => Zip64DataDescriptorWidth::Zip64,
        });
        let local_value_shape = match parsed.local_value_shape {
            ParsedZip64LocalValueShape::Absent => Zip64LocalValueShape::Absent,
            ParsedZip64LocalValueShape::Exact => Zip64LocalValueShape::Exact,
            ParsedZip64LocalValueShape::StreamingZeros => Zip64LocalValueShape::StreamingZeros,
            ParsedZip64LocalValueShape::StreamingMaxima => Zip64LocalValueShape::StreamingMaxima,
        };
        Self {
            raw_name_bytes: zip.raw_name,
            decoded_name: zip.name,
            canonical_path: components.join("/"),
            components,
            kind,
            declared_uncomp_size: zip.uncomp_size,
            evidence: MemberEvidence::Zip64(Zip64MemberEvidence {
                zip: ZipMemberEvidence {
                    method: zip.method,
                    flags: zip.flags,
                    declared_crc: zip.crc,
                    declared_comp_size: zip.comp_size,
                    source_ranges: zip.source_ranges,
                    extra_fields: zip.extra_fields,
                    creator_system: zip.creator_system,
                    external_attributes: zip.external_attributes,
                },
                local_version_needed: parsed.local_version_needed,
                central_version_needed: parsed.central_version_needed,
                central_presence_mask: parsed.central_presence_mask,
                central_legacy_sentinel_mask: parsed.central_legacy_sentinel_mask,
                local_legacy_sentinel_mask: parsed.local_legacy_sentinel_mask,
                local_value_shape,
                local_zip64_extra,
                central_zip64_extra,
                descriptor_width,
            }),
            actual_uncomp_size: None,
            actual_crc: None,
            content_sha256: None,
            verification: MemberVerification::Pending,
            normalization_actions,
        }
    }

    pub(crate) fn from_tar_planned(
        tar: TarMember,
        components: Vec<String>,
        normalization_actions: Vec<NormalizationAction>,
    ) -> Self {
        Self::from_tar_planned_for_format(tar, components, normalization_actions, false)
    }

    pub(crate) fn from_tar_gzip_planned(
        tar: TarMember,
        components: Vec<String>,
        normalization_actions: Vec<NormalizationAction>,
    ) -> Self {
        Self::from_tar_planned_for_format(tar, components, normalization_actions, true)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_tar_pax_planned(
        tar: TarMember,
        base_size: u64,
        effective_raw_name_bytes: Vec<u8>,
        effective_name: String,
        components: Vec<String>,
        normalization_actions: Vec<NormalizationAction>,
        path_source: PaxValueSource,
        size_source: PaxValueSource,
    ) -> Self {
        let kind = if tar.is_dir {
            MemberKind::Directory
        } else {
            MemberKind::File
        };
        let base_name_bytes = tar.raw_name;
        Self {
            raw_name_bytes: effective_raw_name_bytes,
            decoded_name: effective_name,
            canonical_path: components.join("/"),
            components,
            kind,
            declared_uncomp_size: tar.size,
            evidence: MemberEvidence::TarPax(TarPaxMemberEvidence {
                tar: TarMemberEvidence {
                    header: tar.header,
                    payload: tar.payload,
                    padding: tar.padding,
                    mode: tar.mode,
                    mtime: tar.mtime,
                    header_checksum: tar.header_checksum,
                    header_sha256: tar.header_sha256,
                },
                base_name_bytes,
                base_size,
                path_source,
                size_source,
            }),
            actual_uncomp_size: None,
            actual_crc: None,
            content_sha256: None,
            verification: MemberVerification::Pending,
            normalization_actions,
        }
    }

    pub(crate) fn from_tar_gnu_longname_planned(
        tar: GnuLongNameMember,
        components: Vec<String>,
        normalization_actions: Vec<NormalizationAction>,
    ) -> Self {
        let kind = if tar.is_dir {
            MemberKind::Directory
        } else {
            MemberKind::File
        };
        let effective_name_bytes = tar.name.as_bytes().to_vec();
        let base_name_bytes = tar.raw_name;
        let path_source = tar
            .carrier_index
            .map_or(GnuLongNamePathSource::Header, |carrier_index| {
                GnuLongNamePathSource::Carrier { carrier_index }
            });
        Self {
            raw_name_bytes: effective_name_bytes,
            decoded_name: tar.name,
            canonical_path: components.join("/"),
            components,
            kind,
            declared_uncomp_size: tar.size,
            evidence: MemberEvidence::TarGnuLongName(TarGnuLongNameMemberEvidence {
                tar: TarMemberEvidence {
                    header: tar.header,
                    payload: tar.payload,
                    padding: tar.padding,
                    mode: tar.mode,
                    mtime: tar.mtime,
                    header_checksum: tar.header_checksum,
                    header_sha256: tar.header_sha256,
                },
                base_name_bytes,
                path_source,
            }),
            actual_uncomp_size: None,
            actual_crc: None,
            content_sha256: None,
            verification: MemberVerification::Pending,
            normalization_actions,
        }
    }

    fn from_tar_planned_for_format(
        tar: TarMember,
        components: Vec<String>,
        normalization_actions: Vec<NormalizationAction>,
        gzip_wrapped: bool,
    ) -> Self {
        let kind = if tar.is_dir {
            MemberKind::Directory
        } else {
            MemberKind::File
        };
        let evidence = TarMemberEvidence {
            header: tar.header,
            payload: tar.payload,
            padding: tar.padding,
            mode: tar.mode,
            mtime: tar.mtime,
            header_checksum: tar.header_checksum,
            header_sha256: tar.header_sha256,
        };
        Self {
            raw_name_bytes: tar.raw_name,
            decoded_name: tar.name,
            canonical_path: components.join("/"),
            components,
            kind,
            declared_uncomp_size: tar.size,
            evidence: if gzip_wrapped {
                MemberEvidence::TarGzip(evidence)
            } else {
                MemberEvidence::Tar(evidence)
            },
            actual_uncomp_size: None,
            actual_crc: None,
            content_sha256: None,
            verification: MemberVerification::Pending,
            normalization_actions,
        }
    }

    pub(crate) fn mark_directory_verified(&mut self) {
        self.actual_uncomp_size = Some(0);
        self.actual_crc = Some(
            self.zip_evidence()
                .map_or(0, |evidence| evidence.declared_crc),
        );
        self.content_sha256 = Some(hex_sha256(&[]));
        self.verification = MemberVerification::Verified;
    }

    pub(crate) fn mark_file_verified(&mut self, actual: u64, crc: u32, sha256: String) {
        self.actual_uncomp_size = Some(actual);
        self.actual_crc = Some(crc);
        self.content_sha256 = Some(sha256);
        self.verification = MemberVerification::Verified;
    }

    pub(crate) fn mark_failed(&mut self, cause: &str) {
        self.verification = MemberVerification::Failed {
            cause: cause.to_owned(),
        };
    }

    /// Return the format whose evidence this member carries.
    pub fn format(&self) -> ArchiveFormat {
        match &self.evidence {
            MemberEvidence::Zip(_) => ArchiveFormat::Zip32,
            MemberEvidence::Zip64(_) => ArchiveFormat::Zip64,
            MemberEvidence::Tar(_) => ArchiveFormat::TarUstar,
            MemberEvidence::TarGzip(_) => ArchiveFormat::TarGzipUstar,
            MemberEvidence::TarPax(_) => ArchiveFormat::TarPax,
            MemberEvidence::TarGnuLongName(_) => ArchiveFormat::TarGnuLongName,
        }
    }

    /// Return exact ZIP evidence, or `None` for a non-ZIP member.
    pub fn zip_evidence(&self) -> Option<&ZipMemberEvidence> {
        match &self.evidence {
            MemberEvidence::Zip(evidence) => Some(evidence),
            MemberEvidence::Zip64(evidence) => Some(&evidence.zip),
            MemberEvidence::Tar(_)
            | MemberEvidence::TarGzip(_)
            | MemberEvidence::TarPax(_)
            | MemberEvidence::TarGnuLongName(_) => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn zip_evidence_mut(&mut self) -> Option<&mut ZipMemberEvidence> {
        match &mut self.evidence {
            MemberEvidence::Zip(evidence) => Some(evidence),
            MemberEvidence::Zip64(evidence) => Some(&mut evidence.zip),
            MemberEvidence::Tar(_)
            | MemberEvidence::TarGzip(_)
            | MemberEvidence::TarPax(_)
            | MemberEvidence::TarGnuLongName(_) => None,
        }
    }

    /// Return exact portable-ustar evidence, or `None` for a ZIP member.
    pub fn tar_evidence(&self) -> Option<&TarMemberEvidence> {
        match &self.evidence {
            MemberEvidence::Zip(_) => None,
            MemberEvidence::Zip64(_) => None,
            MemberEvidence::Tar(evidence) | MemberEvidence::TarGzip(evidence) => Some(evidence),
            MemberEvidence::TarPax(evidence) => Some(&evidence.tar),
            MemberEvidence::TarGnuLongName(evidence) => Some(&evidence.tar),
        }
    }

    /// Return exact ZIP64-specific evidence, or `None` for another format.
    pub fn zip64_evidence(&self) -> Option<&Zip64MemberEvidence> {
        match &self.evidence {
            MemberEvidence::Zip64(evidence) => Some(evidence),
            MemberEvidence::Zip(_)
            | MemberEvidence::Tar(_)
            | MemberEvidence::TarGzip(_)
            | MemberEvidence::TarPax(_)
            | MemberEvidence::TarGnuLongName(_) => None,
        }
    }

    /// Return exact PAX-specific evidence, or `None` for another format.
    pub fn tar_pax_evidence(&self) -> Option<&TarPaxMemberEvidence> {
        match &self.evidence {
            MemberEvidence::TarPax(evidence) => Some(evidence),
            MemberEvidence::Zip(_)
            | MemberEvidence::Zip64(_)
            | MemberEvidence::Tar(_)
            | MemberEvidence::TarGzip(_)
            | MemberEvidence::TarGnuLongName(_) => None,
        }
    }

    /// Return exact old-GNU long-name evidence, or `None` for another format.
    pub fn tar_gnu_longname_evidence(&self) -> Option<&TarGnuLongNameMemberEvidence> {
        match &self.evidence {
            MemberEvidence::TarGnuLongName(evidence) => Some(evidence),
            MemberEvidence::Zip(_)
            | MemberEvidence::Zip64(_)
            | MemberEvidence::Tar(_)
            | MemberEvidence::TarGzip(_)
            | MemberEvidence::TarPax(_) => None,
        }
    }

    /// Return ZIP creator and external-attribute facts when ZIP supplied them.
    pub fn container_facts(&self) -> Option<MemberContainerFacts> {
        self.zip_evidence().map(|evidence| MemberContainerFacts {
            creator_system: evidence.creator_system,
            external_attributes: evidence.external_attributes,
        })
    }
}

impl Serialize for IrMember {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(
            "IrMember",
            match &self.evidence {
                MemberEvidence::Zip(_) => 17,
                MemberEvidence::Zip64(_) => 18,
                MemberEvidence::Tar(_)
                | MemberEvidence::TarGzip(_)
                | MemberEvidence::TarPax(_)
                | MemberEvidence::TarGnuLongName(_) => 12,
            },
        )?;
        state.serialize_field("raw_name_bytes", &self.raw_name_bytes)?;
        state.serialize_field("decoded_name", &self.decoded_name)?;
        state.serialize_field("canonical_path", &self.canonical_path)?;
        state.serialize_field("components", &self.components)?;
        state.serialize_field("kind", &self.kind)?;
        if let Some(evidence) = self.zip_evidence() {
            state.serialize_field("method", &evidence.method)?;
            state.serialize_field("flags", &evidence.flags)?;
            state.serialize_field("declared_crc", &evidence.declared_crc)?;
            state.serialize_field("declared_comp_size", &evidence.declared_comp_size)?;
        }
        state.serialize_field("declared_uncomp_size", &self.declared_uncomp_size)?;
        match &self.evidence {
            MemberEvidence::Zip(evidence) => {
                state.serialize_field("source_ranges", &evidence.source_ranges)?;
                state.serialize_field("extra_fields", &evidence.extra_fields)?;
            }
            MemberEvidence::Zip64(evidence) => {
                state.serialize_field("source_ranges", &evidence.zip.source_ranges)?;
                state.serialize_field("extra_fields", &evidence.zip.extra_fields)?;
                state.serialize_field("zip64", &evidence.specific())?;
            }
            MemberEvidence::Tar(evidence) | MemberEvidence::TarGzip(evidence) => {
                state.serialize_field("tar", evidence)?;
            }
            MemberEvidence::TarPax(evidence) => {
                state.serialize_field("tar_pax", evidence)?;
            }
            MemberEvidence::TarGnuLongName(evidence) => {
                state.serialize_field("tar_gnu_longname", evidence)?;
            }
        }
        state.serialize_field("actual_uncomp_size", &self.actual_uncomp_size)?;
        state.serialize_field("actual_crc", &self.actual_crc)?;
        state.serialize_field("content_sha256", &self.content_sha256)?;
        state.serialize_field("verification", &self.verification)?;
        state.serialize_field("normalization_actions", &self.normalization_actions)?;
        state.end()
    }
}

/// Labeled partition of the source interval under a ZIP32 profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ArchiveCovering {
    pub local_records: ByteRange,
    pub central_directory: ByteRange,
    pub eocd: ByteRange,
    pub comment: ByteRange,
}

/// Exact partition of a source interpreted by the strict ZIP64 profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Zip64ArchiveCovering {
    pub local_records: ByteRange,
    pub central_directory: ByteRange,
    pub zip64_eocd: Option<ByteRange>,
    pub zip64_locator: Option<ByteRange>,
    pub eocd: ByteRange,
    pub comment: ByteRange,
}

/// Exact partition of a portable POSIX ustar source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct TarArchiveCovering {
    pub member_records: ByteRange,
    pub terminator: ByteRange,
    pub trailing_zeros: ByteRange,
}

/// Exact original-wrapper and derived-TAR evidence for one gzip-wrapped ustar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct TarGzipArchiveEvidence {
    pub gzip: GzipWrapperEvidence,
    pub tar: TarArchiveCovering,
}

/// Exact source covering and ordered extension evidence for portable PAX.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct TarPaxArchiveEvidence {
    pub tar: TarArchiveCovering,
    pub extensions: Vec<PaxExtensionEvidence>,
}

/// Exact source covering and ordered carrier evidence for old-GNU long names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct TarGnuLongNameArchiveEvidence {
    pub tar: TarArchiveCovering,
    pub carriers: Vec<GnuLongNameCarrierEvidence>,
}

/// Format-native source covering for one interpreted archive.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveEvidence {
    Zip(ArchiveCovering),
    Zip64(Zip64ArchiveCovering),
    Tar(TarArchiveCovering),
    TarGzip(TarGzipArchiveEvidence),
    TarPax(TarPaxArchiveEvidence),
    TarGnuLongName(TarGnuLongNameArchiveEvidence),
}

impl ArchiveCovering {
    #[cfg(test)]
    pub(crate) fn synthetic() -> Self {
        Self {
            local_records: ByteRange { offset: 0, len: 0 },
            central_directory: ByteRange { offset: 0, len: 0 },
            eocd: ByteRange { offset: 0, len: 0 },
            comment: ByteRange { offset: 0, len: 0 },
        }
    }

    pub(crate) fn from_zip32(
        cd_offset: u64,
        cd_size: u64,
        eocd_offset: u64,
        comment_len: u64,
    ) -> Self {
        Self {
            local_records: ByteRange {
                offset: 0,
                len: cd_offset,
            },
            central_directory: ByteRange {
                offset: cd_offset,
                len: cd_size,
            },
            eocd: ByteRange {
                offset: eocd_offset,
                len: 22,
            },
            comment: ByteRange {
                offset: eocd_offset + 22,
                len: comment_len,
            },
        }
    }
}

impl Zip64ArchiveCovering {
    pub(crate) fn from_parsed(
        cd_offset: u64,
        cd_size: u64,
        zip64_eocd: Option<ByteRange>,
        zip64_locator: Option<ByteRange>,
        eocd_offset: u64,
        comment_len: u64,
    ) -> Self {
        Self {
            local_records: ByteRange {
                offset: 0,
                len: cd_offset,
            },
            central_directory: ByteRange {
                offset: cd_offset,
                len: cd_size,
            },
            zip64_eocd,
            zip64_locator,
            eocd: ByteRange {
                offset: eocd_offset,
                len: 22,
            },
            comment: ByteRange {
                offset: eocd_offset + 22,
                len: comment_len,
            },
        }
    }
}

/// Effect-independent interpretation of one archive snapshot under a named profile.
///
/// The value is produced only by Sealr. Callers can inspect and serialize it,
/// but cannot construct or mutate an object that purports to be Sealr's
/// interpretation.
///
/// ```compile_fail
/// use sealr::{ArchiveIR, SourceDigest};
///
/// let _forged = ArchiveIR::new(SourceDigest::available("not-an-archive"), Vec::new());
/// ```
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ArchiveIR {
    pub(crate) schema: &'static str,
    pub(crate) profile: &'static str,
    pub(crate) profile_digest: String,
    pub(crate) source_digest: SourceDigest,
    pub(crate) evidence: ArchiveEvidence,
    pub(crate) members: Vec<IrMember>,
}

impl ArchiveIR {
    #[cfg(test)]
    pub(crate) fn new(source_digest: SourceDigest, members: Vec<IrMember>) -> Self {
        Self::with_covering(
            ZipInterpretationProfile::StrictAsciiV1,
            source_digest,
            ArchiveCovering::synthetic(),
            members,
        )
    }

    pub(crate) fn with_covering(
        profile: ZipInterpretationProfile,
        source_digest: SourceDigest,
        covering: ArchiveCovering,
        members: Vec<IrMember>,
    ) -> Self {
        Self {
            schema: ARCHIVE_IR_SCHEMA,
            profile: profile.id(),
            profile_digest: profile.digest(),
            source_digest,
            evidence: ArchiveEvidence::Zip(covering),
            members,
        }
    }

    pub(crate) fn with_tar(
        profile: TarInterpretationProfile,
        source_digest: SourceDigest,
        covering: TarArchiveCovering,
        members: Vec<IrMember>,
    ) -> Self {
        Self {
            schema: TAR_ARCHIVE_IR_SCHEMA,
            profile: profile.id(),
            profile_digest: profile.digest(),
            source_digest,
            evidence: ArchiveEvidence::Tar(covering),
            members,
        }
    }

    pub(crate) fn with_tar_gzip(
        profile: TarGzipInterpretationProfile,
        source_digest: SourceDigest,
        gzip: GzipWrapperEvidence,
        tar: TarArchiveCovering,
        members: Vec<IrMember>,
    ) -> Self {
        Self {
            schema: TAR_GZIP_ARCHIVE_IR_SCHEMA,
            profile: profile.id(),
            profile_digest: profile.digest(),
            source_digest,
            evidence: ArchiveEvidence::TarGzip(TarGzipArchiveEvidence { gzip, tar }),
            members,
        }
    }

    pub(crate) fn with_tar_pax(
        profile: TarPaxInterpretationProfile,
        source_digest: SourceDigest,
        tar: TarArchiveCovering,
        extensions: Vec<PaxExtensionEvidence>,
        members: Vec<IrMember>,
    ) -> Self {
        Self {
            schema: TAR_PAX_ARCHIVE_IR_SCHEMA,
            profile: profile.id(),
            profile_digest: profile.digest(),
            source_digest,
            evidence: ArchiveEvidence::TarPax(TarPaxArchiveEvidence { tar, extensions }),
            members,
        }
    }

    pub(crate) fn with_tar_gnu_longname(
        profile: TarGnuLongNameInterpretationProfile,
        source_digest: SourceDigest,
        tar: TarArchiveCovering,
        carriers: Vec<GnuLongNameCarrierEvidence>,
        members: Vec<IrMember>,
    ) -> Self {
        Self {
            schema: TAR_GNU_LONGNAME_ARCHIVE_IR_SCHEMA,
            profile: profile.id(),
            profile_digest: profile.digest(),
            source_digest,
            evidence: ArchiveEvidence::TarGnuLongName(TarGnuLongNameArchiveEvidence {
                tar,
                carriers,
            }),
            members,
        }
    }

    pub(crate) fn with_zip64(
        profile: ZipInterpretationProfile,
        source_digest: SourceDigest,
        covering: Zip64ArchiveCovering,
        members: Vec<IrMember>,
    ) -> Self {
        debug_assert_eq!(profile, ZipInterpretationProfile::Zip64StrictAsciiV1);
        Self {
            schema: ZIP64_ARCHIVE_IR_SCHEMA,
            profile: profile.id(),
            profile_digest: profile.digest(),
            source_digest,
            evidence: ArchiveEvidence::Zip64(covering),
            members,
        }
    }

    pub fn schema(&self) -> &'static str {
        self.schema
    }

    pub fn profile(&self) -> &'static str {
        self.profile
    }

    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    pub fn format(&self) -> ArchiveFormat {
        match &self.evidence {
            ArchiveEvidence::Zip(_) => ArchiveFormat::Zip32,
            ArchiveEvidence::Zip64(_) => ArchiveFormat::Zip64,
            ArchiveEvidence::Tar(_) => ArchiveFormat::TarUstar,
            ArchiveEvidence::TarGzip(_) => ArchiveFormat::TarGzipUstar,
            ArchiveEvidence::TarPax(_) => ArchiveFormat::TarPax,
            ArchiveEvidence::TarGnuLongName(_) => ArchiveFormat::TarGnuLongName,
        }
    }

    pub fn source_digest(&self) -> &SourceDigest {
        &self.source_digest
    }

    /// Return exact format-native archive evidence.
    pub fn evidence(&self) -> &ArchiveEvidence {
        &self.evidence
    }

    /// Return historical ZIP32 covering evidence, or `None` for another format.
    pub fn covering(&self) -> Option<&ArchiveCovering> {
        self.zip_covering()
    }

    /// Return exact ZIP32 covering evidence, or `None` for ZIP64 or TAR.
    pub fn zip_covering(&self) -> Option<&ArchiveCovering> {
        match &self.evidence {
            ArchiveEvidence::Zip(covering) => Some(covering),
            ArchiveEvidence::Zip64(_)
            | ArchiveEvidence::Tar(_)
            | ArchiveEvidence::TarGzip(_)
            | ArchiveEvidence::TarPax(_)
            | ArchiveEvidence::TarGnuLongName(_) => None,
        }
    }

    /// Return exact ZIP64 covering evidence, or `None` for another format.
    pub fn zip64_covering(&self) -> Option<&Zip64ArchiveCovering> {
        match &self.evidence {
            ArchiveEvidence::Zip64(covering) => Some(covering),
            ArchiveEvidence::Zip(_)
            | ArchiveEvidence::Tar(_)
            | ArchiveEvidence::TarGzip(_)
            | ArchiveEvidence::TarPax(_)
            | ArchiveEvidence::TarGnuLongName(_) => None,
        }
    }

    pub fn tar_covering(&self) -> Option<&TarArchiveCovering> {
        match &self.evidence {
            ArchiveEvidence::Zip(_) | ArchiveEvidence::Zip64(_) => None,
            ArchiveEvidence::Tar(covering) => Some(covering),
            ArchiveEvidence::TarGzip(evidence) => Some(&evidence.tar),
            ArchiveEvidence::TarPax(evidence) => Some(&evidence.tar),
            ArchiveEvidence::TarGnuLongName(evidence) => Some(&evidence.tar),
        }
    }

    /// Return exact RFC 1952 evidence for a gzip-wrapped TAR, if selected.
    pub fn gzip_evidence(&self) -> Option<&GzipWrapperEvidence> {
        match &self.evidence {
            ArchiveEvidence::TarGzip(evidence) => Some(&evidence.gzip),
            ArchiveEvidence::Zip(_)
            | ArchiveEvidence::Zip64(_)
            | ArchiveEvidence::Tar(_)
            | ArchiveEvidence::TarPax(_)
            | ArchiveEvidence::TarGnuLongName(_) => None,
        }
    }

    /// Return exact ordered PAX extension evidence, if selected.
    pub fn pax_extensions(&self) -> Option<&[PaxExtensionEvidence]> {
        self.tar_pax_evidence()
            .map(|evidence| evidence.extensions.as_slice())
    }

    /// Return exact portable PAX archive evidence, if selected.
    pub fn tar_pax_evidence(&self) -> Option<&TarPaxArchiveEvidence> {
        match &self.evidence {
            ArchiveEvidence::TarPax(evidence) => Some(evidence),
            ArchiveEvidence::Zip(_)
            | ArchiveEvidence::Zip64(_)
            | ArchiveEvidence::Tar(_)
            | ArchiveEvidence::TarGzip(_)
            | ArchiveEvidence::TarGnuLongName(_) => None,
        }
    }

    /// Return exact ordered GNU long-name carrier evidence, if selected.
    pub fn gnu_longname_carriers(&self) -> Option<&[GnuLongNameCarrierEvidence]> {
        self.tar_gnu_longname_evidence()
            .map(|evidence| evidence.carriers.as_slice())
    }

    /// Return exact old-GNU long-name archive evidence, if selected.
    pub fn tar_gnu_longname_evidence(&self) -> Option<&TarGnuLongNameArchiveEvidence> {
        match &self.evidence {
            ArchiveEvidence::TarGnuLongName(evidence) => Some(evidence),
            ArchiveEvidence::Zip(_)
            | ArchiveEvidence::Zip64(_)
            | ArchiveEvidence::Tar(_)
            | ArchiveEvidence::TarGzip(_)
            | ArchiveEvidence::TarPax(_) => None,
        }
    }

    pub fn members(&self) -> &[IrMember] {
        &self.members
    }
}

impl Serialize for ArchiveIR {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(
            "ArchiveIR",
            match &self.evidence {
                ArchiveEvidence::Zip(_) => 6,
                ArchiveEvidence::Zip64(_) => 7,
                ArchiveEvidence::Tar(_) => 7,
                ArchiveEvidence::TarGzip(_) => 8,
                ArchiveEvidence::TarPax(_) => 8,
                ArchiveEvidence::TarGnuLongName(_) => 8,
            },
        )?;
        state.serialize_field("schema", self.schema)?;
        state.serialize_field("profile", self.profile)?;
        state.serialize_field("profile_digest", &self.profile_digest)?;
        state.serialize_field("source_digest", &self.source_digest)?;
        match &self.evidence {
            ArchiveEvidence::Zip(covering) => {
                state.serialize_field("covering", covering)?;
            }
            ArchiveEvidence::Zip64(covering) => {
                state.serialize_field("format", &ArchiveFormat::Zip64)?;
                state.serialize_field("zip64_covering", covering)?;
            }
            ArchiveEvidence::Tar(covering) => {
                state.serialize_field("format", &ArchiveFormat::TarUstar)?;
                state.serialize_field("tar_covering", covering)?;
            }
            ArchiveEvidence::TarGzip(evidence) => {
                state.serialize_field("format", &ArchiveFormat::TarGzipUstar)?;
                state.serialize_field("gzip", &evidence.gzip)?;
                state.serialize_field("tar_covering", &evidence.tar)?;
            }
            ArchiveEvidence::TarPax(evidence) => {
                state.serialize_field("format", &ArchiveFormat::TarPax)?;
                state.serialize_field("tar_covering", &evidence.tar)?;
                state.serialize_field("pax_extensions", &evidence.extensions)?;
            }
            ArchiveEvidence::TarGnuLongName(evidence) => {
                state.serialize_field("format", &ArchiveFormat::TarGnuLongName)?;
                state.serialize_field("tar_covering", &evidence.tar)?;
                state.serialize_field("gnu_longname_carriers", &evidence.carriers)?;
            }
        }
        state.serialize_field("members", &self.members)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_and_profile_are_stable() {
        let ir = ArchiveIR::new(SourceDigest::available("abc"), Vec::new());
        assert_eq!(ir.schema, "sealr.archive-ir.v1");
        assert_eq!(ir.profile, "sealr.profile.zip.strict-ascii.v1");
        assert_eq!(
            serde_json::to_value(ir.schema).unwrap(),
            serde_json::json!("sealr.archive-ir.v1")
        );
        assert_eq!(ir.profile_digest, zip_strict_ascii_v1_digest());
        assert_eq!(ir.profile_digest.len(), 64);
    }

    #[test]
    fn profile_digest_covers_extra_field_denylist() {
        let digest = zip_strict_ascii_v1_digest();
        let json = serde_json::to_vec(&zip_strict_ascii_profile()).unwrap();
        assert!(String::from_utf8_lossy(&json).contains("28789")); // 0x7075
        assert_eq!(digest, hex_sha256(&json));
    }

    #[test]
    fn strict_ascii_v2_profile_is_exhaustive_and_distinct() {
        let profile = zip_strict_ascii_v2_profile();
        assert_eq!(profile.general_purpose_bits.len(), 16);
        for (bit, rule) in profile.general_purpose_bits.iter().enumerate() {
            assert_eq!(usize::from(rule.bit), bit);
            assert_eq!(rule.mask, 1_u16 << bit);
        }
        assert_eq!(profile.general_purpose_bits[3].disposition, "semantic");
        assert!(profile
            .general_purpose_bits
            .iter()
            .enumerate()
            .all(|(bit, rule)| bit == 3 || rule.disposition == "denied"));
        assert!(profile.extra_fields_semantic.is_empty());
        assert!(profile.extra_fields_permitted_nonsemantic.is_empty());
        assert_eq!(profile.extra_fields_other, "denied");
        assert_ne!(zip_strict_ascii_v2_digest(), zip_strict_ascii_v1_digest());
    }

    #[test]
    fn portable_utf8_v1_profile_is_exhaustive_and_pinned() {
        let profile = zip_portable_utf8_v1_profile();
        assert_eq!(profile.general_purpose_bits.len(), 16);
        for (bit, rule) in profile.general_purpose_bits.iter().enumerate() {
            assert_eq!(usize::from(rule.bit), bit);
            assert_eq!(rule.mask, 1_u16 << bit);
        }
        assert!(profile
            .general_purpose_bits
            .iter()
            .enumerate()
            .all(|(bit, rule)| matches!(bit, 3 | 11) || rule.disposition == "denied"));
        assert_eq!(profile.general_purpose_bits[3].disposition, "semantic");
        assert_eq!(profile.general_purpose_bits[11].disposition, "semantic");
        assert!(profile.extra_fields_semantic.is_empty());
        assert!(profile.extra_fields_permitted_nonsemantic.is_empty());
        assert_eq!(profile.extra_fields_other, "denied");
        assert_eq!(profile.unicode_repertoire_version, "16.0.0");
        assert_eq!(
            profile.unicode_repertoire_implementation,
            "unicode-general-category-1.1.0-exact"
        );
        assert_eq!(
            profile.normalization_unicode_version,
            "17.0.0-stable-for-16.0.0-repertoire"
        );
        assert_eq!(profile.case_folding_unicode_version, "16.0.0");
        assert!(profile.character_restrictions.contains("bidi-control-061c"));
        assert_eq!(profile.path_grammar, PORTABLE_PATH_GRAMMAR_ID);
        assert_eq!(profile.reserved_names, PORTABLE_RESERVED_NAMES_ID);
        assert_eq!(
            zip_portable_utf8_v1_digest(),
            "acee86158d481adff96da0277a470ba753d6208ede74bc48586bb0134db5152e"
        );
    }

    #[test]
    fn portable_pax_v1_profile_is_closed_and_pinned() {
        let profile = tar_pax_portable_v1_profile();
        let canonical = tar_pax_portable_v1_canonical_bytes();
        let vector = include_bytes!("../tests/conformance/tar-pax-profile-v1.json");
        assert_eq!(profile.extension_types, ["global-g", "local-x"]);
        assert_eq!(
            profile.extension_carrier_names,
            "structurally-valid-ustar-text-not-destination-validated"
        );
        assert_eq!(
            profile.underlying_member_names,
            "structurally-valid-ustar-text-destination-validated-only-when-effective"
        );
        assert_eq!(profile.keywords, ["path", "size"]);
        assert_eq!(profile.max_extension_payload_bytes, 64 * 1024);
        assert_eq!(profile.max_extension_headers, 1024);
        assert_eq!(profile.max_records_per_extension, 2);
        assert_eq!(profile.max_keyword_scan_bytes, 16);
        assert_eq!(
            profile.base_profile_sha256,
            "3c87c5ec4c1ad5377eb60ebb308e9e394aaf7a4133dddf5587829b4510af1700"
        );
        assert_eq!(
            tar_pax_portable_v1_digest(),
            "db951f620acf54e67845144e138f9f16994439847a97601e20a424dfea7f4445"
        );
        assert_eq!(&canonical, &vector[..vector.len() - 1]);
    }

    #[test]
    fn portable_gnu_longname_v1_profile_is_closed_and_pinned() {
        let profile = tar_gnu_longname_portable_v1_profile();
        let canonical = tar_gnu_longname_portable_v1_canonical_bytes();
        let vector = include_bytes!("../tests/conformance/tar-gnu-longname-profile-v1.json");
        assert_eq!(profile.header_magic_and_version, "7573746172202000");
        assert_eq!(
            profile.accepted_types,
            ["regular-0-or-nul", "directory-5-size-zero", "long-name-L"]
        );
        assert_eq!(profile.min_effective_path_bytes, 1);
        assert_eq!(profile.max_carrier_payload_bytes, 8192);
        assert_eq!(profile.max_carrier_headers, 1024);
        assert_eq!(
            tar_gnu_longname_portable_v1_digest(),
            "08fe2698806da997bc42e7e13a45cbf412a4a7056dec39c62456202680b91fa4"
        );
        assert_eq!(&canonical, &vector[..vector.len() - 1]);
    }
}
