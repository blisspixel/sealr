use serde::Serialize;

use crate::outcome::SourceDigest;
use crate::policy::hex_sha256;
use crate::zip::ZipMember;

pub const ARCHIVE_IR_SCHEMA: &str = "sealr.archive-ir.v1";
pub const ZIP_STRICT_ASCII_V1: &str = "sealr.profile.zip.strict-ascii.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemberKind {
    File,
    Directory,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum MemberVerification {
    Pending,
    Verified,
    Failed { cause: String },
}

/// One member of a versioned, effect-independent ZIP interpretation.
#[derive(Clone, Debug, Serialize)]
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
    pub lfh_offset: u64,
    pub data_offset: u64,
    pub record_end: u64,
    pub actual_uncomp_size: Option<u64>,
    pub actual_crc: Option<u32>,
    pub content_sha256: Option<String>,
    pub verification: MemberVerification,
}

impl IrMember {
    pub fn from_planned(zip: ZipMember, components: Vec<String>) -> Self {
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
            lfh_offset: zip.lfh_offset,
            data_offset: zip.data_offset,
            record_end: zip.record_end,
            actual_uncomp_size: None,
            actual_crc: None,
            content_sha256: None,
            verification: MemberVerification::Pending,
        }
    }

    pub fn as_zip_member(&self) -> ZipMember {
        ZipMember {
            raw_name: self.raw_name_bytes.clone(),
            name: self.decoded_name.clone(),
            method: self.method,
            flags: self.flags,
            crc: self.declared_crc,
            comp_size: self.declared_comp_size,
            uncomp_size: self.declared_uncomp_size,
            lfh_offset: self.lfh_offset,
            data_offset: self.data_offset,
            record_end: self.record_end,
            is_dir: matches!(self.kind, MemberKind::Directory),
        }
    }

    pub fn mark_directory_verified(&mut self) {
        self.actual_uncomp_size = Some(0);
        self.actual_crc = Some(self.declared_crc);
        self.content_sha256 = Some(hex_sha256(&[]));
        self.verification = MemberVerification::Verified;
    }

    pub fn mark_file_verified(&mut self, actual: u64, crc: u32, sha256: String) {
        self.actual_uncomp_size = Some(actual);
        self.actual_crc = Some(crc);
        self.content_sha256 = Some(sha256);
        self.verification = MemberVerification::Verified;
    }

    pub fn mark_failed(&mut self, cause: &str) {
        self.verification = MemberVerification::Failed {
            cause: cause.to_owned(),
        };
    }
}

/// Effect-independent interpretation of one ZIP snapshot under a named profile.
#[derive(Clone, Debug, Serialize)]
pub struct ArchiveIR {
    pub schema: &'static str,
    pub profile: &'static str,
    pub source_digest: SourceDigest,
    pub members: Vec<IrMember>,
}

impl ArchiveIR {
    pub fn new(source_digest: SourceDigest, members: Vec<IrMember>) -> Self {
        Self {
            schema: ARCHIVE_IR_SCHEMA,
            profile: ZIP_STRICT_ASCII_V1,
            source_digest,
            members,
        }
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
    }
}
