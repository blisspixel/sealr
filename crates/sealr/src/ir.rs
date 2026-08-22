use serde::Serialize;

use crate::outcome::SourceDigest;
use crate::policy::hex_sha256;
use crate::zip::ZipMember;

pub const ARCHIVE_IR_SCHEMA: &str = "sealr.archive-ir.v1";
pub const ZIP_STRICT_ASCII_V1: &str = "sealr.profile.zip.strict-ascii.v1";

const DENIED_EXTRA_ZIP64: u16 = 0x0001;
const DENIED_EXTRA_UNICODE_PATH: u16 = 0x7075;

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

pub fn zip_strict_ascii_v1_digest() -> String {
    let json = serde_json::to_vec(&zip_strict_ascii_profile()).expect("profile serializes");
    hex_sha256(&json)
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

    pub(crate) fn as_zip_member(&self) -> ZipMember {
        ZipMember {
            raw_name: self.raw_name_bytes.clone(),
            name: self.decoded_name.clone(),
            method: self.method,
            flags: self.flags,
            crc: self.declared_crc,
            comp_size: self.declared_comp_size,
            uncomp_size: self.declared_uncomp_size,
            lfh_offset: self.source_ranges.local_header.offset,
            data_offset: self.source_ranges.compressed_payload.offset,
            record_end: self.source_ranges.record_end(),
            is_dir: matches!(self.kind, MemberKind::Directory),
            extra_fields: self.extra_fields.clone(),
            source_ranges: self.source_ranges.clone(),
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
        Self::with_covering(source_digest, ArchiveCovering::synthetic(), members)
    }

    pub(crate) fn with_covering(
        source_digest: SourceDigest,
        covering: ArchiveCovering,
        members: Vec<IrMember>,
    ) -> Self {
        Self {
            schema: ARCHIVE_IR_SCHEMA,
            profile: ZIP_STRICT_ASCII_V1,
            profile_digest: zip_strict_ascii_v1_digest(),
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
}
