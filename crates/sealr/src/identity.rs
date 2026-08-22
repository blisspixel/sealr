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
    ArchiveIR, ExtraDisposition, ExtraSite, IrMember, MemberKind, MemberVerification,
    NormalizationAction, ZIP_STRICT_ASCII_V1,
};
use crate::outcome::{DigestHex, SourceDigest, VerificationStatus};
use crate::policy::hex_sha256;

pub const TREE_ENCODING_ID: &str = "sealrTreeV1";
const LAYOUT_LABEL: &str = "sealr.tree.layout.v1";
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TreeRoot {
    SealrTreeV1 { hex: String },
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

    pub fn hex(&self) -> Option<&str> {
        match self {
            Self::SealrTreeV1 { hex } => Some(hex),
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
            Self::Unavailable => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("status", "unavailable")?;
                map.end()
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InterpretationIdentity {
    pub id: String,
    pub digest: DigestHex,
}

#[derive(Clone, Debug, Serialize)]
pub struct OutcomeIdentities {
    pub source: SourceDigest,
    pub interpretation: InterpretationIdentity,
    pub layout: TreeRoot,
    pub content: TreeRoot,
}

impl OutcomeIdentities {
    pub fn unavailable(source: SourceDigest) -> Self {
        Self {
            source,
            interpretation: InterpretationIdentity {
                id: ZIP_STRICT_ASCII_V1.into(),
                digest: DigestHex {
                    sha256: crate::ir::zip_strict_ascii_v1_digest(),
                },
            },
            layout: TreeRoot::unavailable(),
            content: TreeRoot::unavailable(),
        }
    }

    pub fn without_source() -> Self {
        Self::unavailable(SourceDigest::unavailable())
    }

    pub fn from_ir(
        source: SourceDigest,
        ir: &ArchiveIR,
        verification: &VerificationStatus,
    ) -> Self {
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
    let mut body = Vec::new();
    encode_range(&mut body, ir.covering.local_records);
    encode_range(&mut body, ir.covering.central_directory);
    encode_range(&mut body, ir.covering.eocd);
    encode_range(&mut body, ir.covering.comment);
    push_u32(&mut body, members.len() as u32);
    for member in members {
        encode_layout_member(&mut body, member);
    }
    preimage(LAYOUT_LABEL, &body)
}

pub fn encode_content(ir: &ArchiveIR) -> Vec<u8> {
    let members = sorted_members(ir);
    let mut body = Vec::new();
    push_u32(&mut body, members.len() as u32);
    for member in members {
        encode_content_member(&mut body, member);
    }
    preimage(CONTENT_LABEL, &body)
}

fn encode_range(out: &mut Vec<u8>, range: crate::ir::ByteRange) {
    push_u64(out, range.offset);
    push_u64(out, range.len);
}

fn encode_layout_member(out: &mut Vec<u8>, member: &IrMember) {
    push_bytes(out, member.canonical_path.as_bytes());
    out.push(match member.kind {
        MemberKind::File => FILE,
        MemberKind::Directory => DIRECTORY,
    });
    push_bytes(out, &member.raw_name_bytes);
    push_u16(out, member.method);
    push_u16(out, member.flags);
    push_u64(out, member.declared_comp_size);
    push_u64(out, member.declared_uncomp_size);
    push_u32(out, member.declared_crc);
    encode_range(out, member.source_ranges.local_header);
    encode_range(out, member.source_ranges.compressed_payload);
    if let Some(descriptor) = member.source_ranges.data_descriptor {
        out.push(1);
        encode_range(out, descriptor);
    } else {
        out.push(0);
    }
    encode_range(out, member.source_ranges.central_header);
    let mut extras = member.extra_fields.clone();
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
    TreeRoot::from_bytes(&encode_layout(ir))
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
    use crate::ir::{ByteRange, MemberSourceRanges};
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
        second.members[0].source_ranges.central_header.offset += 1;
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
            method: 0,
            flags: 0,
            declared_crc: 0,
            declared_comp_size: 1,
            declared_uncomp_size: 1,
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
