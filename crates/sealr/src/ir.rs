use serde::Serialize;

use crate::outcome::SourceDigest;
use crate::policy::hex_sha256;
use crate::zip::ZipMember;

pub const ARCHIVE_IR_SCHEMA: &str = "sealr.archive-ir.v1";
pub const ZIP_STRICT_ASCII_V1: &str = "sealr.profile.zip.strict-ascii.v1";
pub const ZIP_STRICT_ASCII_V2: &str = "sealr.profile.zip.strict-ascii.v2";

const DENIED_EXTRA_ZIP64: u16 = 0x0001;
const DENIED_EXTRA_UNICODE_PATH: u16 = 0x7075;

/// ZIP interpretation selected for one operation.
///
/// `StrictAsciiV1` preserves the Alpha.3 compatibility language. It accepts
/// unknown flag bits and records unknown extra fields as ignored. New callers
/// that need a closed interpretation contract should select `StrictAsciiV2`,
/// which permits only flag bit 3 and denies every extra field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZipInterpretationProfile {
    #[default]
    StrictAsciiV1,
    StrictAsciiV2,
}

impl ZipInterpretationProfile {
    pub const fn id(self) -> &'static str {
        match self {
            Self::StrictAsciiV1 => ZIP_STRICT_ASCII_V1,
            Self::StrictAsciiV2 => ZIP_STRICT_ASCII_V2,
        }
    }

    pub fn digest(self) -> String {
        match self {
            Self::StrictAsciiV1 => zip_strict_ascii_v1_digest(),
            Self::StrictAsciiV2 => zip_strict_ascii_v2_digest(),
        }
    }
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

pub fn zip_strict_ascii_v1_digest() -> String {
    hex_sha256(&zip_strict_ascii_v1_canonical_bytes())
}

pub fn zip_strict_ascii_v2_digest() -> String {
    hex_sha256(&zip_strict_ascii_v2_canonical_bytes())
}

/// Canonical JSON bytes hashed by the v1 interpretation identity.
pub fn zip_strict_ascii_v1_canonical_bytes() -> Vec<u8> {
    serde_json::to_vec(&zip_strict_ascii_profile()).expect("profile serializes")
}

/// Canonical JSON bytes hashed by the v2 interpretation identity.
pub fn zip_strict_ascii_v2_canonical_bytes() -> Vec<u8> {
    serde_json::to_vec(&zip_strict_ascii_v2_profile()).expect("profile serializes")
}

pub fn is_denied_extra_id(id: u16) -> bool {
    id == DENIED_EXTRA_ZIP64 || id == DENIED_EXTRA_UNICODE_PATH
}

/// One member of a versioned, effect-independent ZIP interpretation.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct IrMember {
    pub raw_name_bytes: Vec<u8>,
    pub decoded_name: String,
    pub canonical_path: String,
    pub components: Vec<String>,
    pub kind: MemberKind,
    pub method: u16,
    pub flags: u16,
    pub declared_crc: u32,
    pub declared_comp_size: u64,
    pub declared_uncomp_size: u64,
    pub source_ranges: MemberSourceRanges,
    pub extra_fields: Vec<ExtraFieldRecord>,
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
            method: zip.method,
            flags: zip.flags,
            declared_crc: zip.crc,
            declared_comp_size: zip.comp_size,
            declared_uncomp_size: zip.uncomp_size,
            source_ranges: zip.source_ranges,
            extra_fields: zip.extra_fields,
            actual_uncomp_size: None,
            actual_crc: None,
            content_sha256: None,
            verification: MemberVerification::Pending,
            normalization_actions,
        }
    }

    pub(crate) fn mark_directory_verified(&mut self) {
        self.actual_uncomp_size = Some(0);
        self.actual_crc = Some(self.declared_crc);
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
}

/// Labeled partition of the source interval under the current ZIP32 profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ArchiveCovering {
    pub local_records: ByteRange,
    pub central_directory: ByteRange,
    pub eocd: ByteRange,
    pub comment: ByteRange,
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

/// Effect-independent interpretation of one ZIP snapshot under a named profile.
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
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct ArchiveIR {
    pub(crate) schema: &'static str,
    pub(crate) profile: &'static str,
    pub(crate) profile_digest: String,
    pub(crate) source_digest: SourceDigest,
    pub(crate) covering: ArchiveCovering,
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
            covering,
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

    pub fn source_digest(&self) -> &SourceDigest {
        &self.source_digest
    }

    pub fn covering(&self) -> &ArchiveCovering {
        &self.covering
    }

    pub fn members(&self) -> &[IrMember] {
        &self.members
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
}
