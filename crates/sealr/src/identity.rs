//! Canonical `sealrTreeV1` layout and content-tree identities.
//!
//! Each root is SHA-256 of a Git-style preimage:
//! `label SP decimal_len NUL body`. Integers in the body are little-endian and
//! length-prefixed. The interpretation profile is a sibling identity, not part
//! of the tree bytes. The encoding does not use JSON, so tree identity is
//! independent of `view_digest` and of later RFC 8785 canonicalization.

use serde::ser::{SerializeMap, Serializer};
use serde::Serialize;

use crate::ir::{
    ArchiveFormat, ArchiveIR, ExtraDisposition, ExtraSite, IrMember, MemberKind,
    MemberVerification, NormalizationAction, PaxExtensionKind, PaxKeyword, PaxValueSource,
    TarGzipInterpretationProfile, TarInterpretationProfile, TarPaxInterpretationProfile,
    ZipInterpretationProfile,
};
use crate::outcome::{DigestHex, SourceDigest, VerificationStatus};
use crate::policy::hex_sha256;
use crate::snapshot::TransformProfile;

pub const TREE_ENCODING_ID: &str = "sealrTreeV1";
pub const TREE_ENCODING_V2_ID: &str = "sealrTreeV2";
pub const TREE_ENCODING_V3_ID: &str = "sealrTreeV3";
pub const TREE_ENCODING_V4_ID: &str = "sealrTreeV4";
pub const TREE_ENCODING_V5_ID: &str = "sealrTreeV5";
const LAYOUT_LABEL: &str = "sealr.tree.layout.v1";
const TAR_LAYOUT_LABEL: &str = "sealr.tree.layout.tar-ustar.v1";
const ZIP64_LAYOUT_LABEL: &str = "sealr.tree.layout.zip64.v1";
const TAR_GZIP_LAYOUT_LABEL: &str = "sealr.tree.layout.tar-gzip-ustar.v1";
const TAR_PAX_LAYOUT_LABEL: &str = "sealr.tree.layout.tar-pax.v1";
const CONTENT_LABEL: &str = "sealr.tree.content.v1";
const FILE: u8 = 1;
const DIRECTORY: u8 = 2;
const SITE_LOCAL: u8 = 1;
const SITE_CENTRAL: u8 = 2;
const DISP_IGNORED: u8 = 1;
const DISP_SEMANTIC: u8 = 2;
const DISP_DENIED: u8 = 3;
const NORM_STRIP_DIR_SLASH: u8 = 1;
const NORM_DROP_DOT: u8 = 2;
const PAX_EXTENSION_GLOBAL: u8 = 1;
const PAX_EXTENSION_LOCAL: u8 = 2;
const PAX_KEYWORD_PATH: u8 = 1;
const PAX_KEYWORD_SIZE: u8 = 2;
const PAX_SOURCE_USTAR: u8 = 0;
const PAX_SOURCE_GLOBAL: u8 = 1;
const PAX_SOURCE_LOCAL: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TreeRoot {
    SealrTreeV1 { hex: String },
    SealrTreeV2 { hex: String },
    SealrTreeV3 { hex: String },
    SealrTreeV4 { hex: String },
    SealrTreeV5 { hex: String },
    Unavailable,
}

impl TreeRoot {
    pub fn unavailable() -> Self {
        Self::Unavailable
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::SealrTreeV1 {
            hex: hex_sha256(bytes),
        }
    }

    pub fn from_v2_bytes(bytes: &[u8]) -> Self {
        Self::SealrTreeV2 {
            hex: hex_sha256(bytes),
        }
    }

    pub fn from_v3_bytes(bytes: &[u8]) -> Self {
        Self::SealrTreeV3 {
            hex: hex_sha256(bytes),
        }
    }

    pub fn from_v4_bytes(bytes: &[u8]) -> Self {
        Self::SealrTreeV4 {
            hex: hex_sha256(bytes),
        }
    }

    pub fn from_v5_bytes(bytes: &[u8]) -> Self {
        Self::SealrTreeV5 {
            hex: hex_sha256(bytes),
        }
    }

    pub fn hex(&self) -> Option<&str> {
        match self {
            Self::SealrTreeV1 { hex } => Some(hex),
            Self::SealrTreeV2 { hex } => Some(hex),
            Self::SealrTreeV3 { hex } => Some(hex),
            Self::SealrTreeV4 { hex } => Some(hex),
            Self::SealrTreeV5 { hex } => Some(hex),
            Self::Unavailable => None,
        }
    }
}

impl Serialize for TreeRoot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::SealrTreeV1 { hex } => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(TREE_ENCODING_ID, hex)?;
                map.end()
            }
            Self::SealrTreeV2 { hex } => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(TREE_ENCODING_V2_ID, hex)?;
                map.end()
            }
            Self::SealrTreeV3 { hex } => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(TREE_ENCODING_V3_ID, hex)?;
                map.end()
            }
            Self::SealrTreeV4 { hex } => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(TREE_ENCODING_V4_ID, hex)?;
                map.end()
            }
            Self::SealrTreeV5 { hex } => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(TREE_ENCODING_V5_ID, hex)?;
                map.end()
            }
            Self::Unavailable => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("status", "unavailable")?;
                map.end()
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct InterpretationIdentity {
    pub id: String,
    pub digest: DigestHex,
}

#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct OutcomeIdentities {
    pub source: SourceDigest,
    pub interpretation: InterpretationIdentity,
    pub layout: TreeRoot,
    pub content: TreeRoot,
}

impl OutcomeIdentities {
    pub fn unavailable(source: SourceDigest) -> Self {
        Self::unavailable_for(source, ZipInterpretationProfile::StrictAsciiV1)
    }

    pub fn unavailable_for(source: SourceDigest, profile: ZipInterpretationProfile) -> Self {
        Self::unavailable_for_named(source, profile.id(), profile.digest())
    }

    pub fn unavailable_for_tar(source: SourceDigest, profile: TarInterpretationProfile) -> Self {
        Self::unavailable_for_named(source, profile.id(), profile.digest())
    }

    pub fn unavailable_for_tar_gzip(
        source: SourceDigest,
        profile: TarGzipInterpretationProfile,
    ) -> Self {
        Self::unavailable_for_named(source, profile.id(), profile.digest())
    }

    pub fn unavailable_for_tar_pax(
        source: SourceDigest,
        profile: TarPaxInterpretationProfile,
    ) -> Self {
        Self::unavailable_for_named(source, profile.id(), profile.digest())
    }

    fn unavailable_for_named(source: SourceDigest, id: &'static str, digest: String) -> Self {
        Self {
            source,
            interpretation: InterpretationIdentity {
                id: id.into(),
                digest: DigestHex { sha256: digest },
            },
            layout: TreeRoot::unavailable(),
            content: TreeRoot::unavailable(),
        }
    }

    pub fn without_source() -> Self {
        Self::unavailable(SourceDigest::unavailable())
    }

    pub fn without_source_for(profile: ZipInterpretationProfile) -> Self {
        Self::unavailable_for(SourceDigest::unavailable(), profile)
    }

    pub fn from_ir(
        _source: SourceDigest,
        ir: &ArchiveIR,
        verification: &VerificationStatus,
    ) -> Self {
        let source = ir.source_digest().clone();
        let interpretation = InterpretationIdentity {
            id: ir.profile.to_string(),
            digest: DigestHex {
                sha256: ir.profile_digest.clone(),
            },
        };
        let layout = layout_root(ir);
        let content = if matches!(verification, VerificationStatus::Complete)
            && ir
                .members
                .iter()
                .all(|member| matches!(member.verification, MemberVerification::Verified))
        {
            content_root(ir)
        } else {
            TreeRoot::unavailable()
        };
        Self {
            source,
            interpretation,
            layout,
            content,
        }
    }
}

/// Git-style domain-separated preimage: `label SP decimal_len NUL body`.
fn preimage(label: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len() + 24 + body.len());
    out.extend_from_slice(label.as_bytes());
    out.push(b' ');
    out.extend_from_slice(body.len().to_string().as_bytes());
    out.push(0);
    out.extend_from_slice(body);
    out
}

fn sorted_members(ir: &ArchiveIR) -> Vec<&IrMember> {
    let mut members: Vec<&IrMember> = ir.members.iter().collect();
    members.sort_by(|a, b| a.canonical_path.as_bytes().cmp(b.canonical_path.as_bytes()));
    members
}

pub fn encode_layout(ir: &ArchiveIR) -> Vec<u8> {
    let members = sorted_members(ir);
    let covering = ir
        .zip_covering()
        .expect("ZIP layout encoding requires ZIP archive evidence");
    let mut body = Vec::new();
    encode_range(&mut body, covering.local_records);
    encode_range(&mut body, covering.central_directory);
    encode_range(&mut body, covering.eocd);
    encode_range(&mut body, covering.comment);
    push_u32(
        &mut body,
        u32::try_from(members.len()).expect("planned member count is bounded by policy"),
    );
    for member in members {
        encode_layout_member(&mut body, member);
    }
    preimage(LAYOUT_LABEL, &body)
}

pub fn encode_content(ir: &ArchiveIR) -> Vec<u8> {
    let members = sorted_members(ir);
    let mut body = Vec::new();
    push_u32(
        &mut body,
        u32::try_from(members.len()).expect("planned member count is bounded by policy"),
    );
    for member in members {
        encode_content_member(&mut body, member);
    }
    preimage(CONTENT_LABEL, &body)
}

pub fn encode_tar_layout(ir: &ArchiveIR) -> Option<Vec<u8>> {
    if ir.format() != ArchiveFormat::TarUstar {
        return None;
    }
    tar_layout_body(ir, ArchiveFormat::TarUstar).map(|body| preimage(TAR_LAYOUT_LABEL, &body))
}

/// Canonical physical-layout encoding for the restricted POSIX PAX profile.
pub fn encode_tar_pax_layout(ir: &ArchiveIR) -> Option<Vec<u8>> {
    if ir.format() != ArchiveFormat::TarPax {
        return None;
    }
    let covering = ir.tar_covering()?;
    let extensions = ir.pax_extensions()?;
    let members = sorted_members(ir);
    let mut body = Vec::new();
    encode_range(&mut body, covering.member_records);
    encode_range(&mut body, covering.terminator);
    encode_range(&mut body, covering.trailing_zeros);
    push_u32(&mut body, u32::try_from(extensions.len()).ok()?);
    for extension in extensions {
        body.push(match extension.kind {
            PaxExtensionKind::Global => PAX_EXTENSION_GLOBAL,
            PaxExtensionKind::Local => PAX_EXTENSION_LOCAL,
        });
        push_bytes(&mut body, &extension.raw_name_bytes);
        encode_range(&mut body, extension.header);
        encode_range(&mut body, extension.payload);
        encode_range(&mut body, extension.padding);
        push_u32(&mut body, extension.mode);
        push_u64(&mut body, extension.mtime);
        push_u32(&mut body, extension.header_checksum);
        body.extend_from_slice(&parse_hex32(&extension.header_sha256)?);
        body.extend_from_slice(&parse_hex32(&extension.payload_sha256)?);
        push_u32(&mut body, u32::try_from(extension.records.len()).ok()?);
        for record in &extension.records {
            body.push(match record.keyword {
                PaxKeyword::Path => PAX_KEYWORD_PATH,
                PaxKeyword::Size => PAX_KEYWORD_SIZE,
            });
            encode_range(&mut body, record.record);
            encode_range(&mut body, record.value);
            push_bytes(&mut body, &record.raw_value_bytes);
            match record.parsed_size {
                Some(size) => {
                    body.push(1);
                    push_u64(&mut body, size);
                }
                None => body.push(0),
            }
        }
    }
    push_u32(&mut body, u32::try_from(members.len()).ok()?);
    for member in members {
        if member.format() != ArchiveFormat::TarPax {
            return None;
        }
        let evidence = member.tar_pax_evidence()?;
        push_bytes(&mut body, member.canonical_path.as_bytes());
        body.push(match member.kind {
            MemberKind::File => FILE,
            MemberKind::Directory => DIRECTORY,
        });
        push_bytes(&mut body, &member.raw_name_bytes);
        push_bytes(&mut body, &evidence.base_name_bytes);
        push_u64(&mut body, member.declared_uncomp_size);
        push_u64(&mut body, evidence.base_size);
        encode_range(&mut body, evidence.tar.header);
        encode_range(&mut body, evidence.tar.payload);
        encode_range(&mut body, evidence.tar.padding);
        push_u32(&mut body, evidence.tar.mode);
        push_u64(&mut body, evidence.tar.mtime);
        push_u32(&mut body, evidence.tar.header_checksum);
        body.extend_from_slice(&parse_hex32(&evidence.tar.header_sha256)?);
        encode_pax_value_source(&mut body, evidence.path_source);
        encode_pax_value_source(&mut body, evidence.size_source);
        push_u32(
            &mut body,
            u32::try_from(member.normalization_actions.len()).ok()?,
        );
        for action in &member.normalization_actions {
            match action {
                NormalizationAction::StripDirectoryTrailingSlash => {
                    body.push(NORM_STRIP_DIR_SLASH);
                }
                NormalizationAction::DropDotComponent { component_index } => {
                    body.push(NORM_DROP_DOT);
                    push_u32(&mut body, *component_index);
                }
            }
        }
    }
    Some(preimage(TAR_PAX_LAYOUT_LABEL, &body))
}

fn tar_layout_body(ir: &ArchiveIR, expected_format: ArchiveFormat) -> Option<Vec<u8>> {
    let covering = ir.tar_covering()?;
    let members = sorted_members(ir);
    let mut body = Vec::new();
    encode_range(&mut body, covering.member_records);
    encode_range(&mut body, covering.terminator);
    encode_range(&mut body, covering.trailing_zeros);
    push_u32(
        &mut body,
        u32::try_from(members.len()).expect("planned member count is bounded by policy"),
    );
    for member in members {
        if member.format() != expected_format {
            return None;
        }
        let evidence = member.tar_evidence()?;
        push_bytes(&mut body, member.canonical_path.as_bytes());
        body.push(match member.kind {
            MemberKind::File => FILE,
            MemberKind::Directory => DIRECTORY,
        });
        push_bytes(&mut body, &member.raw_name_bytes);
        push_u64(&mut body, member.declared_uncomp_size);
        encode_range(&mut body, evidence.header);
        encode_range(&mut body, evidence.payload);
        encode_range(&mut body, evidence.padding);
        push_u32(&mut body, evidence.mode);
        push_u64(&mut body, evidence.mtime);
        push_u32(&mut body, evidence.header_checksum);
        body.extend_from_slice(&parse_hex32(&evidence.header_sha256)?);
        push_u32(&mut body, member.normalization_actions.len() as u32);
        for action in &member.normalization_actions {
            match action {
                NormalizationAction::StripDirectoryTrailingSlash => {
                    body.push(NORM_STRIP_DIR_SLASH);
                }
                NormalizationAction::DropDotComponent { component_index } => {
                    body.push(NORM_DROP_DOT);
                    push_u32(&mut body, *component_index);
                }
            }
        }
    }
    Some(body)
}

/// Canonical wrapper-plus-inner-layout encoding for strict gzip-wrapped ustar.
pub fn encode_tar_gzip_layout(ir: &ArchiveIR) -> Option<Vec<u8>> {
    if ir.format() != ArchiveFormat::TarGzipUstar {
        return None;
    }
    let gzip = ir.gzip_evidence()?;
    let transform = TransformProfile::GzipRfc1952SingleMemberV1;
    let mut body = Vec::new();
    push_bytes(&mut body, transform.id().as_bytes());
    body.extend_from_slice(&parse_hex32(transform.digest())?);
    body.extend_from_slice(&parse_hex32(transform.decoder_parameters_digest())?);
    push_u16(&mut body, 0);
    encode_range(
        &mut body,
        crate::ir::ByteRange {
            offset: 0,
            len: gzip.trailer.offset.checked_add(gzip.trailer.len)?,
        },
    );
    body.extend_from_slice(&parse_hex32(ir.source_digest().sha256()?)?);
    push_u16(&mut body, 1);
    push_u64(&mut body, gzip.derived_output_len);
    body.extend_from_slice(&parse_hex32(&gzip.derived_output_sha256)?);
    body.push(gzip.flags);
    push_u32(&mut body, gzip.modification_time);
    body.push(gzip.extra_flags);
    body.push(gzip.operating_system);
    encode_range(&mut body, gzip.header);
    encode_optional_range(&mut body, gzip.extra);
    push_u32(&mut body, gzip.extra_subfield_count);
    encode_optional_range(&mut body, gzip.original_name);
    encode_optional_range(&mut body, gzip.comment);
    encode_optional_range(&mut body, gzip.header_crc16);
    encode_range(&mut body, gzip.compressed_payload);
    encode_range(&mut body, gzip.trailer);
    push_u32(&mut body, gzip.declared_crc32);
    push_u32(&mut body, gzip.declared_isize);
    push_u64(&mut body, gzip.derived_output_len);
    body.extend_from_slice(&parse_hex32(&gzip.derived_output_sha256)?);
    push_bytes(
        &mut body,
        &tar_layout_body(ir, ArchiveFormat::TarGzipUstar)?,
    );
    Some(preimage(TAR_GZIP_LAYOUT_LABEL, &body))
}

pub fn encode_zip64_layout(ir: &ArchiveIR) -> Option<Vec<u8>> {
    let covering = ir.zip64_covering()?;
    let members = sorted_members(ir);
    let mut body = Vec::new();
    encode_range(&mut body, covering.local_records);
    encode_range(&mut body, covering.central_directory);
    encode_optional_range(&mut body, covering.zip64_eocd);
    encode_optional_range(&mut body, covering.zip64_locator);
    encode_range(&mut body, covering.eocd);
    encode_range(&mut body, covering.comment);
    push_u32(
        &mut body,
        u32::try_from(members.len()).expect("planned member count is bounded by policy"),
    );
    for member in members {
        encode_layout_member(&mut body, member);
        let evidence = member.zip64_evidence()?;
        push_u16(&mut body, evidence.local_version_needed);
        push_u16(&mut body, evidence.central_version_needed);
        body.push(evidence.central_presence_mask);
        body.push(evidence.central_legacy_sentinel_mask);
        body.push(evidence.local_legacy_sentinel_mask);
        body.push(match evidence.local_value_shape {
            crate::ir::Zip64LocalValueShape::Absent => 0,
            crate::ir::Zip64LocalValueShape::Exact => 1,
            crate::ir::Zip64LocalValueShape::StreamingZeros => 2,
            crate::ir::Zip64LocalValueShape::StreamingMaxima => 3,
        });
        encode_optional_range(&mut body, evidence.local_zip64_extra);
        encode_optional_range(&mut body, evidence.central_zip64_extra);
        body.push(match evidence.descriptor_width {
            None => 0,
            Some(crate::ir::Zip64DataDescriptorWidth::Zip32) => 1,
            Some(crate::ir::Zip64DataDescriptorWidth::Zip64) => 2,
        });
    }
    Some(preimage(ZIP64_LAYOUT_LABEL, &body))
}

fn encode_range(out: &mut Vec<u8>, range: crate::ir::ByteRange) {
    push_u64(out, range.offset);
    push_u64(out, range.len);
}

fn encode_optional_range(out: &mut Vec<u8>, range: Option<crate::ir::ByteRange>) {
    match range {
        Some(range) => {
            out.push(1);
            encode_range(out, range);
        }
        None => out.push(0),
    }
}

fn encode_pax_value_source(out: &mut Vec<u8>, source: PaxValueSource) {
    match source {
        PaxValueSource::Ustar => out.push(PAX_SOURCE_USTAR),
        PaxValueSource::Global {
            extension_index,
            record_index,
        } => {
            out.push(PAX_SOURCE_GLOBAL);
            push_u32(out, extension_index);
            push_u32(out, record_index);
        }
        PaxValueSource::Local {
            extension_index,
            record_index,
        } => {
            out.push(PAX_SOURCE_LOCAL);
            push_u32(out, extension_index);
            push_u32(out, record_index);
        }
    }
}

fn encode_layout_member(out: &mut Vec<u8>, member: &IrMember) {
    let evidence = member
        .zip_evidence()
        .expect("ZIP layout member encoding requires ZIP evidence");
    push_bytes(out, member.canonical_path.as_bytes());
    out.push(match member.kind {
        MemberKind::File => FILE,
        MemberKind::Directory => DIRECTORY,
    });
    push_bytes(out, &member.raw_name_bytes);
    push_u16(out, evidence.method);
    push_u16(out, evidence.flags);
    push_u64(out, evidence.declared_comp_size);
    push_u64(out, member.declared_uncomp_size);
    push_u32(out, evidence.declared_crc);
    encode_range(out, evidence.source_ranges.local_header);
    encode_range(out, evidence.source_ranges.compressed_payload);
    if let Some(descriptor) = evidence.source_ranges.data_descriptor {
        out.push(1);
        encode_range(out, descriptor);
    } else {
        out.push(0);
    }
    encode_range(out, evidence.source_ranges.central_header);
    let mut extras = evidence.extra_fields.clone();
    extras.sort_by(|a, b| {
        (site_tag(a.site), a.id, a.data_range.offset).cmp(&(
            site_tag(b.site),
            b.id,
            b.data_range.offset,
        ))
    });
    push_u32(out, extras.len() as u32);
    for extra in extras {
        out.push(site_tag(extra.site));
        push_u16(out, extra.id);
        out.push(match extra.disposition {
            ExtraDisposition::Ignored => DISP_IGNORED,
            ExtraDisposition::Semantic => DISP_SEMANTIC,
            ExtraDisposition::Denied => DISP_DENIED,
        });
        push_u64(out, extra.data_range.offset);
        push_u16(out, extra.data_range.len as u16);
    }
    push_u32(out, member.normalization_actions.len() as u32);
    for action in &member.normalization_actions {
        match action {
            NormalizationAction::StripDirectoryTrailingSlash => {
                out.push(NORM_STRIP_DIR_SLASH);
            }
            NormalizationAction::DropDotComponent { component_index } => {
                out.push(NORM_DROP_DOT);
                push_u32(out, *component_index);
            }
        }
    }
}

fn encode_content_member(out: &mut Vec<u8>, member: &IrMember) {
    push_bytes(out, member.canonical_path.as_bytes());
    out.push(match member.kind {
        MemberKind::File => FILE,
        MemberKind::Directory => DIRECTORY,
    });
    push_u64(out, member.actual_uncomp_size.unwrap_or(0));
    let digest = member
        .content_sha256
        .as_deref()
        .and_then(parse_hex32)
        .unwrap_or([0; 32]);
    out.extend_from_slice(&digest);
}

fn site_tag(site: ExtraSite) -> u8 {
    match site {
        ExtraSite::Local => SITE_LOCAL,
        ExtraSite::Central => SITE_CENTRAL,
    }
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    push_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn parse_hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        out[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(out)
}

/// SHA-256 of canonical layout bytes. Distinct from `view_digest`.
pub fn layout_root(ir: &ArchiveIR) -> TreeRoot {
    match ir.format() {
        ArchiveFormat::Zip32 => TreeRoot::from_bytes(&encode_layout(ir)),
        ArchiveFormat::Zip64 => encode_zip64_layout(ir)
            .map(|bytes| TreeRoot::from_v3_bytes(&bytes))
            .unwrap_or_else(TreeRoot::unavailable),
        ArchiveFormat::TarUstar => encode_tar_layout(ir)
            .map(|bytes| TreeRoot::from_v2_bytes(&bytes))
            .unwrap_or_else(TreeRoot::unavailable),
        ArchiveFormat::TarGzipUstar => encode_tar_gzip_layout(ir)
            .map(|bytes| TreeRoot::from_v4_bytes(&bytes))
            .unwrap_or_else(TreeRoot::unavailable),
        ArchiveFormat::TarPax => encode_tar_pax_layout(ir)
            .map(|bytes| TreeRoot::from_v5_bytes(&bytes))
            .unwrap_or_else(TreeRoot::unavailable),
    }
}

/// SHA-256 of canonical content-tree bytes. Requires verified members.
pub fn content_root(ir: &ArchiveIR) -> TreeRoot {
    if ir.members.iter().all(|member| {
        matches!(member.verification, MemberVerification::Verified)
            && member.actual_uncomp_size.is_some()
            && member
                .content_sha256
                .as_deref()
                .and_then(parse_hex32)
                .is_some()
    }) {
        TreeRoot::from_bytes(&encode_content(ir))
    } else {
        TreeRoot::unavailable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ByteRange, MemberEvidence, MemberSourceRanges, ZipMemberEvidence};
    use crate::outcome::SourceDigest;

    fn empty_ir() -> ArchiveIR {
        ArchiveIR::new(SourceDigest::available("abc"), Vec::new())
    }

    #[test]
    fn empty_layout_encoding_is_pinned() {
        let encoded = encode_layout(&empty_ir());
        let mut body = Vec::new();
        for _ in 0..8 {
            body.extend_from_slice(&0_u64.to_le_bytes());
        }
        body.extend_from_slice(&0_u32.to_le_bytes());
        let mut expected = format!("sealr.tree.layout.v1 {}", body.len()).into_bytes();
        expected.push(0);
        expected.extend_from_slice(&body);
        assert_eq!(encoded, expected);
        assert_eq!(
            layout_root(&empty_ir()).hex(),
            Some(hex_sha256(&expected).as_str())
        );
    }

    #[test]
    fn layout_and_content_use_distinct_domain_labels() {
        let layout = encode_layout(&empty_ir());
        let content = encode_content(&empty_ir());
        assert_ne!(layout, content);
        assert!(layout.starts_with(b"sealr.tree.layout.v1 "));
        assert!(content.starts_with(b"sealr.tree.content.v1 "));
    }

    #[test]
    fn member_order_does_not_change_roots() {
        let a = sample_member("b.txt", 10);
        let b = sample_member("a.txt", 20);
        let mut first = empty_ir();
        first.members = vec![a.clone(), b.clone()];
        let mut second = empty_ir();
        second.members = vec![b, a];
        assert_eq!(encode_layout(&first), encode_layout(&second));
        assert_eq!(encode_content(&first), encode_content(&second));
    }

    #[test]
    fn layout_binds_the_central_header_range() {
        let mut first = empty_ir();
        first.members = vec![sample_member("a.txt", 10)];
        let mut second = first.clone();
        second.members[0]
            .zip_evidence_mut()
            .expect("sample member is ZIP")
            .source_ranges
            .central_header
            .offset += 1;
        assert_ne!(layout_root(&first), layout_root(&second));
    }

    #[test]
    fn content_root_requires_verified_members_and_valid_digests() {
        let mut ir = empty_ir();
        let mut member = sample_member("a.txt", 10);
        member.verification = MemberVerification::Pending;
        ir.members = vec![member];
        assert_eq!(content_root(&ir), TreeRoot::Unavailable);

        ir.members[0].verification = MemberVerification::Verified;
        ir.members[0].content_sha256 = Some("not-a-sha256".into());
        assert_eq!(content_root(&ir), TreeRoot::Unavailable);
    }

    fn sample_member(path: &str, offset: u64) -> IrMember {
        IrMember {
            raw_name_bytes: path.as_bytes().to_vec(),
            decoded_name: path.to_string(),
            canonical_path: path.to_string(),
            components: vec![path.to_string()],
            kind: MemberKind::File,
            declared_uncomp_size: 1,
            evidence: MemberEvidence::Zip(ZipMemberEvidence {
                method: 0,
                flags: 0,
                creator_system: 0,
                external_attributes: 0,
                declared_crc: 0,
                declared_comp_size: 1,
                source_ranges: MemberSourceRanges {
                    local_header: ByteRange {
                        offset,
                        len: 30 + path.len() as u64,
                    },
                    compressed_payload: ByteRange {
                        offset: offset + 30 + path.len() as u64,
                        len: 1,
                    },
                    data_descriptor: None,
                    central_header: ByteRange {
                        offset: 100 + offset,
                        len: 46 + path.len() as u64,
                    },
                },
                extra_fields: Vec::new(),
            }),
            actual_uncomp_size: Some(1),
            actual_crc: Some(0),
            content_sha256: Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ),
            verification: MemberVerification::Verified,
            normalization_actions: Vec::new(),
        }
    }
}
