//! Independent verifier for Sealr identity conformance manifests.
//!
//! This crate deliberately does not depend on `sealr`. It reads committed
//! evidence facts, validates their semantic coherence, and independently
//! reproduces profile, layout, and content digests. It never parses or inflates
//! an archive.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_CASES: usize = 10_000;
const MAX_MEMBERS_PER_CASE: usize = 100_000;
const MANIFEST_SCHEMA: &str = "sealr.identity-conformance.v1";
const IR_SCHEMA: &str = "sealr.archive-ir.v1";
const TREE_ENCODING: &str = "sealrTreeV1";
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationSummary {
    pub profiles: usize,
    pub cases: usize,
    pub layout_roots: usize,
    pub content_roots: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyError(String);

impl VerifyError {
    fn new(detail: impl Into<String>) -> Self {
        Self(detail.into())
    }

    fn context(self, context: &str) -> Self {
        Self(format!("{context}: {}", self.0))
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for VerifyError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    tree_encoding: String,
    profiles: Vec<ProfileVector>,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileVector {
    id: String,
    digest: DigestHex,
    canonical_bytes_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestHex {
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InterpretationIdentity {
    id: String,
    digest: DigestHex,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    source_bytes_hex: String,
    source: DigestHex,
    interpretation: InterpretationIdentity,
    axes: Axes,
    findings: Vec<Finding>,
    archive_ir: Option<ArchiveIr>,
    layout_root: Root,
    content_root: Root,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Axes {
    interpretation: InterpretationStatus,
    admission: AdmissionStatus,
    verification: VerificationStatus,
    effect: EffectStatus,
    view_completeness: ViewCompleteness,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum InterpretationStatus {
    Interpreted,
    Malformed,
    Unsupported,
    Indeterminate,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum AdmissionStatus {
    Admitted,
    Denied,
    NotEvaluated,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum VerificationStatus {
    StructureOnly,
    Partial {
        verified_members: u64,
        pending_members: u64,
    },
    Complete,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum EffectStatus {
    NotRequested,
    Committed,
    Failed,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum ViewCompleteness {
    Complete,
    Partial { phase: StoppingPhase, cause: String },
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum StoppingPhase {
    Source,
    Structure,
    Admission,
    Verification,
    Effect,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Finding {
    code: String,
    severity: Severity,
    #[serde(default)]
    member: Option<String>,
    detail: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Error,
    Deny,
    Warn,
    Info,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Root {
    Available(AvailableRoot),
    Unavailable(UnavailableRoot),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AvailableRoot {
    #[serde(rename = "sealrTreeV1")]
    sealr_tree_v1: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnavailableRoot {
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveIr {
    schema: String,
    profile: String,
    profile_digest: String,
    source_digest: DigestHex,
    covering: ArchiveCovering,
    members: Vec<Member>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ByteRange {
    offset: u64,
    len: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveCovering {
    local_records: ByteRange,
    central_directory: ByteRange,
    eocd: ByteRange,
    comment: ByteRange,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    raw_name_bytes: Vec<u8>,
    decoded_name: String,
    canonical_path: String,
    components: Vec<String>,
    kind: MemberKind,
    method: u16,
    flags: u16,
    declared_crc: u32,
    declared_comp_size: u64,
    declared_uncomp_size: u64,
    source_ranges: MemberSourceRanges,
    extra_fields: Vec<ExtraField>,
    actual_uncomp_size: Option<u64>,
    actual_crc: Option<u32>,
    content_sha256: Option<String>,
    verification: MemberVerification,
    normalization_actions: Vec<NormalizationAction>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum MemberKind {
    File,
    Directory,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum MemberVerification {
    Pending,
    Verified,
    Failed { cause: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberSourceRanges {
    local_header: ByteRange,
    compressed_payload: ByteRange,
    data_descriptor: Option<ByteRange>,
    central_header: ByteRange,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtraField {
    site: ExtraSite,
    id: u16,
    header_range: ByteRange,
    data_range: ByteRange,
    disposition: ExtraDisposition,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
enum ExtraSite {
    Local,
    Central,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ExtraDisposition {
    Semantic,
    Ignored,
    Denied,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum NormalizationAction {
    StripDirectoryTrailingSlash,
    DropDotComponent { component_index: u32 },
}

pub fn verify_manifest_json(bytes: &[u8]) -> Result<VerificationSummary, VerifyError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(VerifyError::new(format!(
            "manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let manifest: Manifest = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::new(format!("JSON: {error}")))?;
    verify_manifest(&manifest)
}

fn verify_manifest(manifest: &Manifest) -> Result<VerificationSummary, VerifyError> {
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(VerifyError::new(format!(
            "unsupported schema {:?}",
            manifest.schema
        )));
    }
    if manifest.tree_encoding != TREE_ENCODING {
        return Err(VerifyError::new(format!(
            "unsupported tree encoding {:?}",
            manifest.tree_encoding
        )));
    }
    if manifest.profiles.is_empty() {
        return Err(VerifyError::new("manifest has no profile vectors"));
    }
    if manifest.cases.is_empty() {
        return Err(VerifyError::new("manifest has no cases"));
    }
    if manifest.cases.len() > MAX_CASES {
        return Err(VerifyError::new(format!(
            "manifest exceeds the {MAX_CASES}-case limit"
        )));
    }

    let mut profiles = HashMap::new();
    for profile in &manifest.profiles {
        verify_profile(profile)
            .map_err(|error| error.context(&format!("profile {}", profile.id)))?;
        if profiles.insert(profile.id.as_str(), profile).is_some() {
            return Err(VerifyError::new(format!(
                "duplicate profile id {:?}",
                profile.id
            )));
        }
    }

    let mut case_ids = HashSet::new();
    let mut layout_roots = 0;
    let mut content_roots = 0;
    for case in &manifest.cases {
        if case.id.is_empty() {
            return Err(VerifyError::new("case id is empty"));
        }
        if !case_ids.insert(case.id.as_str()) {
            return Err(VerifyError::new(format!("duplicate case id {:?}", case.id)));
        }
        let (has_layout, has_content) = verify_case(case, &profiles)
            .map_err(|error| error.context(&format!("case {}", case.id)))?;
        layout_roots += usize::from(has_layout);
        content_roots += usize::from(has_content);
    }

    Ok(VerificationSummary {
        profiles: manifest.profiles.len(),
        cases: manifest.cases.len(),
        layout_roots,
        content_roots,
    })
}

fn verify_profile(profile: &ProfileVector) -> Result<(), VerifyError> {
    if profile.id.is_empty() {
        return Err(VerifyError::new("profile id is empty"));
    }
    let canonical = decode_hex(&profile.canonical_bytes_hex, "canonical_bytes_hex")?;
    if canonical.is_empty() {
        return Err(VerifyError::new("canonical profile bytes are empty"));
    }
    verify_digest(&profile.digest.sha256, "profile digest")?;
    if sha256_hex(&canonical) != profile.digest.sha256 {
        return Err(VerifyError::new(
            "canonical profile bytes do not match digest",
        ));
    }
    let definition: serde_json::Value = serde_json::from_slice(&canonical)
        .map_err(|error| VerifyError::new(format!("canonical profile JSON: {error}")))?;
    if definition.get("schema").and_then(serde_json::Value::as_str) != Some(&profile.id) {
        return Err(VerifyError::new(
            "canonical profile schema does not match profile id",
        ));
    }
    Ok(())
}

fn verify_case(
    case: &Case,
    profiles: &HashMap<&str, &ProfileVector>,
) -> Result<(bool, bool), VerifyError> {
    let source_bytes = decode_hex(&case.source_bytes_hex, "source_bytes_hex")?;
    verify_digest(&case.source.sha256, "source digest")?;
    if sha256_hex(&source_bytes) != case.source.sha256 {
        return Err(VerifyError::new("source bytes do not match source digest"));
    }

    let profile = profiles
        .get(case.interpretation.id.as_str())
        .ok_or_else(|| VerifyError::new("case references an unknown profile"))?;
    verify_digest(&case.interpretation.digest.sha256, "interpretation digest")?;
    if case.interpretation.digest.sha256 != profile.digest.sha256 {
        return Err(VerifyError::new(
            "case interpretation digest does not match profile vector",
        ));
    }
    verify_axes(&case.axes, &case.findings)?;

    for finding in &case.findings {
        if finding.code.is_empty() || finding.detail.is_empty() {
            return Err(VerifyError::new("finding code and detail must be nonempty"));
        }
        let _ = (&finding.severity, &finding.member);
    }

    match &case.archive_ir {
        Some(ir) => {
            if ir.schema != IR_SCHEMA {
                return Err(VerifyError::new(format!(
                    "unsupported IR schema {:?}",
                    ir.schema
                )));
            }
            if ir.profile != case.interpretation.id
                || ir.profile_digest != case.interpretation.digest.sha256
                || ir.source_digest.sha256 != case.source.sha256
            {
                return Err(VerifyError::new(
                    "IR source or interpretation identity does not match case",
                ));
            }
            validate_ir(ir)?;
            verify_covering(&source_bytes, ir)?;

            let expected_layout = available_root(&case.layout_root, "layout root")?
                .ok_or_else(|| VerifyError::new("IR case has no layout root"))?;
            let actual_layout = sha256_hex(&encode_layout(ir)?);
            if actual_layout != expected_layout {
                return Err(VerifyError::new(format!(
                    "layout root mismatch: expected {expected_layout}, calculated {actual_layout}"
                )));
            }

            let verification_complete =
                matches!(case.axes.verification, VerificationStatus::Complete);
            if verification_complete {
                let expected_content = available_root(&case.content_root, "content root")?
                    .ok_or_else(|| VerifyError::new("complete case has no content root"))?;
                let actual_content = sha256_hex(&encode_content(ir)?);
                if actual_content != expected_content {
                    return Err(VerifyError::new(format!(
                        "content root mismatch: expected {expected_content}, calculated {actual_content}"
                    )));
                }
                Ok((true, true))
            } else {
                if available_root(&case.content_root, "content root")?.is_some() {
                    return Err(VerifyError::new(
                        "incomplete verification carries a content root",
                    ));
                }
                Ok((true, false))
            }
        }
        None => {
            if available_root(&case.layout_root, "layout root")?.is_some()
                || available_root(&case.content_root, "content root")?.is_some()
            {
                return Err(VerifyError::new("case without IR carries a tree root"));
            }
            if matches!(case.axes.verification, VerificationStatus::Complete) {
                return Err(VerifyError::new("complete case has no IR"));
            }
            Ok((false, false))
        }
    }
}

fn verify_axes(axes: &Axes, findings: &[Finding]) -> Result<(), VerifyError> {
    if matches!(axes.verification, VerificationStatus::Complete)
        && (!matches!(axes.interpretation, InterpretationStatus::Interpreted)
            || !matches!(axes.admission, AdmissionStatus::Admitted)
            || !matches!(axes.view_completeness, ViewCompleteness::Complete))
    {
        return Err(VerifyError::new(
            "complete verification requires interpreted, admitted, complete evidence",
        ));
    }
    if matches!(axes.effect, EffectStatus::Committed)
        && (!matches!(axes.admission, AdmissionStatus::Admitted)
            || !matches!(axes.verification, VerificationStatus::Complete))
    {
        return Err(VerifyError::new(
            "committed effect requires admission and complete verification",
        ));
    }
    if matches!(axes.admission, AdmissionStatus::Denied)
        && !matches!(axes.effect, EffectStatus::NotRequested)
    {
        return Err(VerifyError::new("denied case carries an effect outcome"));
    }
    if let VerificationStatus::Partial {
        verified_members,
        pending_members,
    } = axes.verification
    {
        if verified_members.checked_add(pending_members).is_none() || pending_members == 0 {
            return Err(VerifyError::new("invalid partial verification counts"));
        }
    }
    if let ViewCompleteness::Partial { phase, cause } = &axes.view_completeness {
        if cause.is_empty() || !findings.iter().any(|finding| finding.code == *cause) {
            return Err(VerifyError::new(
                "partial evidence cause is not present in findings",
            ));
        }
        let _ = phase;
    }
    Ok(())
}

fn validate_ir(ir: &ArchiveIr) -> Result<(), VerifyError> {
    if ir.members.len() > MAX_MEMBERS_PER_CASE {
        return Err(VerifyError::new(format!(
            "IR exceeds the {MAX_MEMBERS_PER_CASE}-member limit"
        )));
    }
    u32::try_from(ir.members.len()).map_err(|_| VerifyError::new("member count exceeds u32"))?;
    validate_range(ir.covering.local_records, "covering.local_records")?;
    validate_range(ir.covering.central_directory, "covering.central_directory")?;
    validate_range(ir.covering.eocd, "covering.eocd")?;
    validate_range(ir.covering.comment, "covering.comment")?;

    let mut paths = HashSet::new();
    for member in &ir.members {
        if member.canonical_path.is_empty() || !paths.insert(member.canonical_path.as_str()) {
            return Err(VerifyError::new(format!(
                "empty or duplicate canonical path {:?}",
                member.canonical_path
            )));
        }
        if member.components.join("/") != member.canonical_path {
            return Err(VerifyError::new(format!(
                "components do not reproduce canonical path {:?}",
                member.canonical_path
            )));
        }
        u32::try_from(member.canonical_path.len())
            .map_err(|_| VerifyError::new("canonical path exceeds u32"))?;
        u32::try_from(member.raw_name_bytes.len())
            .map_err(|_| VerifyError::new("raw name exceeds u32"))?;
        u32::try_from(member.extra_fields.len())
            .map_err(|_| VerifyError::new("extra-field count exceeds u32"))?;
        u32::try_from(member.normalization_actions.len())
            .map_err(|_| VerifyError::new("normalization count exceeds u32"))?;

        validate_range(member.source_ranges.local_header, "member.local_header")?;
        validate_range(
            member.source_ranges.compressed_payload,
            "member.compressed_payload",
        )?;
        if let Some(descriptor) = member.source_ranges.data_descriptor {
            validate_range(descriptor, "member.data_descriptor")?;
        }
        validate_range(member.source_ranges.central_header, "member.central_header")?;
        let mut extra_ids = HashSet::new();
        for extra in &member.extra_fields {
            validate_range(extra.header_range, "extra.header_range")?;
            validate_range(extra.data_range, "extra.data_range")?;
            u16::try_from(extra.data_range.len)
                .map_err(|_| VerifyError::new("extra data length exceeds u16"))?;
            if !extra_ids.insert((extra.site, extra.id)) {
                return Err(VerifyError::new("duplicate extra-field id at one site"));
            }
            if extra.header_range.len != 4
                || checked_range_end(extra.header_range, "extra header")? != extra.data_range.offset
            {
                return Err(VerifyError::new(
                    "extra header does not exactly precede its data",
                ));
            }
            let enclosing_header = match extra.site {
                ExtraSite::Local => member.source_ranges.local_header,
                ExtraSite::Central => member.source_ranges.central_header,
            };
            if !contains_range(enclosing_header, extra.header_range)?
                || !contains_range(enclosing_header, extra.data_range)?
            {
                return Err(VerifyError::new(
                    "extra field is outside its claimed ZIP header",
                ));
            }
        }

        if let MemberVerification::Failed { cause } = &member.verification {
            if cause.is_empty() {
                return Err(VerifyError::new("failed member has an empty cause"));
            }
        }
        if matches!(member.verification, MemberVerification::Verified) {
            let actual_size = member
                .actual_uncomp_size
                .ok_or_else(|| VerifyError::new("verified member has no actual size"))?;
            let actual_crc = member
                .actual_crc
                .ok_or_else(|| VerifyError::new("verified member has no actual CRC"))?;
            let content_digest = member
                .content_sha256
                .as_deref()
                .ok_or_else(|| VerifyError::new("verified member has no content digest"))?;
            verify_digest(content_digest, "member content digest")?;
            if actual_size != member.declared_uncomp_size || actual_crc != member.declared_crc {
                return Err(VerifyError::new(
                    "verified member actual size or CRC differs from declaration",
                ));
            }
        }
        let _ = (
            &member.decoded_name,
            member.declared_comp_size,
            member.method,
            member.flags,
        );
    }
    Ok(())
}

fn validate_range(range: ByteRange, label: &str) -> Result<(), VerifyError> {
    range
        .offset
        .checked_add(range.len)
        .ok_or_else(|| VerifyError::new(format!("{label} overflows u64")))?;
    Ok(())
}

fn verify_covering(source: &[u8], ir: &ArchiveIr) -> Result<(), VerifyError> {
    const LFH: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
    const CDH: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
    const EOCD: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const DESCRIPTOR: [u8; 4] = [0x50, 0x4b, 0x07, 0x08];

    let covering = &ir.covering;
    let source_len =
        u64::try_from(source.len()).map_err(|_| VerifyError::new("source length exceeds u64"))?;
    if covering.local_records.offset != 0
        || checked_range_end(covering.local_records, "local covering")?
            != covering.central_directory.offset
        || checked_range_end(covering.central_directory, "central covering")?
            != covering.eocd.offset
        || checked_range_end(covering.eocd, "EOCD covering")? != covering.comment.offset
        || checked_range_end(covering.comment, "comment covering")? != source_len
    {
        return Err(VerifyError::new(
            "covering ranges do not form an exact source partition",
        ));
    }
    if covering.eocd.len != 22 {
        return Err(VerifyError::new("EOCD covering length is not 22"));
    }
    let eocd = range_bytes(source, covering.eocd, "EOCD")?;
    if eocd[0..4] != EOCD {
        return Err(VerifyError::new(
            "EOCD signature is absent at claimed offset",
        ));
    }
    if le_u16(eocd, 4) != 0 || le_u16(eocd, 6) != 0 {
        return Err(VerifyError::new("EOCD claims a spanned archive"));
    }
    if le_u16(eocd, 8) != le_u16(eocd, 10)
        || usize::from(le_u16(eocd, 10)) != ir.members.len()
        || u64::from(le_u32(eocd, 12)) != covering.central_directory.len
        || u64::from(le_u32(eocd, 16)) != covering.central_directory.offset
        || u64::from(le_u16(eocd, 20)) != covering.comment.len
    {
        return Err(VerifyError::new(
            "EOCD fields do not match the covering certificate",
        ));
    }

    let mut local_ranges = Vec::with_capacity(ir.members.len());
    let mut central_ranges = Vec::with_capacity(ir.members.len());
    for member in &ir.members {
        let ranges = &member.source_ranges;
        if ranges.local_header.len < 30 || ranges.central_header.len < 46 {
            return Err(VerifyError::new(
                "member header range is shorter than its fixed ZIP32 header",
            ));
        }
        if range_bytes(
            source,
            ByteRange {
                offset: ranges.local_header.offset,
                len: 4,
            },
            "local-header signature",
        )? != LFH
        {
            return Err(VerifyError::new(
                "local-header signature is absent at claimed offset",
            ));
        }
        if range_bytes(
            source,
            ByteRange {
                offset: ranges.central_header.offset,
                len: 4,
            },
            "central-header signature",
        )? != CDH
        {
            return Err(VerifyError::new(
                "central-header signature is absent at claimed offset",
            ));
        }
        if checked_range_end(ranges.local_header, "local header")?
            != ranges.compressed_payload.offset
        {
            return Err(VerifyError::new("local header does not abut its payload"));
        }
        let payload_end = checked_range_end(ranges.compressed_payload, "payload")?;
        let local_end = if let Some(descriptor) = ranges.data_descriptor {
            if payload_end != descriptor.offset {
                return Err(VerifyError::new(
                    "payload does not abut its data descriptor",
                ));
            }
            let descriptor_bytes = range_bytes(source, descriptor, "data descriptor")?;
            match descriptor_bytes.len() {
                12 if descriptor_bytes[0..4] != DESCRIPTOR => {}
                16 if descriptor_bytes[0..4] == DESCRIPTOR => {}
                _ => {
                    return Err(VerifyError::new(
                        "data descriptor is neither the 12-byte nor signed 16-byte form",
                    ));
                }
            }
            checked_range_end(descriptor, "data descriptor")?
        } else {
            payload_end
        };
        let local_record = ByteRange {
            offset: ranges.local_header.offset,
            len: local_end
                .checked_sub(ranges.local_header.offset)
                .ok_or_else(|| VerifyError::new("local record range underflows"))?,
        };
        if local_record.len == 0
            || !contains_range(covering.local_records, local_record)?
            || !contains_range(local_record, ranges.compressed_payload)?
        {
            return Err(VerifyError::new(
                "member local record is outside the local covering",
            ));
        }
        if !contains_range(covering.central_directory, ranges.central_header)? {
            return Err(VerifyError::new(
                "member central header is outside the central covering",
            ));
        }
        local_ranges.push((local_record.offset, local_end));
        central_ranges.push((
            ranges.central_header.offset,
            checked_range_end(ranges.central_header, "central header")?,
        ));
    }

    local_ranges.sort_unstable_by_key(|range| range.0);
    central_ranges.sort_unstable_by_key(|range| range.0);
    verify_partition(
        &local_ranges,
        covering.local_records,
        "local record partition",
    )?;
    verify_partition(
        &central_ranges,
        covering.central_directory,
        "central header partition",
    )?;
    Ok(())
}

fn verify_partition(
    ranges: &[(u64, u64)],
    covering: ByteRange,
    label: &str,
) -> Result<(), VerifyError> {
    if ranges.is_empty() {
        if covering.len == 0 {
            return Ok(());
        }
        return Err(VerifyError::new(format!(
            "empty {label} has a nonempty covering"
        )));
    }
    if ranges[0].0 != covering.offset
        || ranges.windows(2).any(|window| window[0].1 != window[1].0)
        || ranges.last().map(|range| range.1) != Some(checked_range_end(covering, label)?)
    {
        return Err(VerifyError::new(format!(
            "{label} does not exactly fill its covering"
        )));
    }
    Ok(())
}

fn contains_range(outer: ByteRange, inner: ByteRange) -> Result<bool, VerifyError> {
    Ok(inner.offset >= outer.offset
        && checked_range_end(inner, "inner range")? <= checked_range_end(outer, "outer range")?)
}

fn range_bytes<'a>(
    source: &'a [u8],
    range: ByteRange,
    label: &str,
) -> Result<&'a [u8], VerifyError> {
    let start = usize::try_from(range.offset)
        .map_err(|_| VerifyError::new(format!("{label} offset exceeds usize")))?;
    let end = usize::try_from(checked_range_end(range, label)?)
        .map_err(|_| VerifyError::new(format!("{label} end exceeds usize")))?;
    source
        .get(start..end)
        .ok_or_else(|| VerifyError::new(format!("{label} is outside source bytes")))
}

fn checked_range_end(range: ByteRange, label: &str) -> Result<u64, VerifyError> {
    range
        .offset
        .checked_add(range.len)
        .ok_or_else(|| VerifyError::new(format!("{label} overflows u64")))
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn available_root<'a>(root: &'a Root, label: &str) -> Result<Option<&'a str>, VerifyError> {
    match root {
        Root::Available(root) => {
            verify_digest(&root.sealr_tree_v1, label)?;
            Ok(Some(&root.sealr_tree_v1))
        }
        Root::Unavailable(root) if root.status == "unavailable" => Ok(None),
        Root::Unavailable(root) => Err(VerifyError::new(format!(
            "{label} has unsupported status {:?}",
            root.status
        ))),
    }
}

fn encode_layout(ir: &ArchiveIr) -> Result<Vec<u8>, VerifyError> {
    let members = sorted_members(ir);
    let mut body = Vec::new();
    encode_range(&mut body, ir.covering.local_records);
    encode_range(&mut body, ir.covering.central_directory);
    encode_range(&mut body, ir.covering.eocd);
    encode_range(&mut body, ir.covering.comment);
    push_u32(
        &mut body,
        u32::try_from(members.len()).map_err(|_| VerifyError::new("member count exceeds u32"))?,
    );
    for member in members {
        encode_layout_member(&mut body, member)?;
    }
    Ok(preimage(LAYOUT_LABEL, &body))
}

fn encode_content(ir: &ArchiveIr) -> Result<Vec<u8>, VerifyError> {
    let members = sorted_members(ir);
    let mut body = Vec::new();
    push_u32(
        &mut body,
        u32::try_from(members.len()).map_err(|_| VerifyError::new("member count exceeds u32"))?,
    );
    for member in members {
        if !matches!(member.verification, MemberVerification::Verified) {
            return Err(VerifyError::new(
                "complete content case contains an unverified member",
            ));
        }
        push_bytes(&mut body, member.canonical_path.as_bytes())?;
        body.push(kind_tag(&member.kind));
        push_u64(
            &mut body,
            member
                .actual_uncomp_size
                .ok_or_else(|| VerifyError::new("verified member has no actual size"))?,
        );
        let digest = decode_digest(
            member
                .content_sha256
                .as_deref()
                .ok_or_else(|| VerifyError::new("verified member has no content digest"))?,
            "member content digest",
        )?;
        body.extend_from_slice(&digest);
    }
    Ok(preimage(CONTENT_LABEL, &body))
}

fn sorted_members(ir: &ArchiveIr) -> Vec<&Member> {
    let mut members: Vec<_> = ir.members.iter().collect();
    members.sort_by(|left, right| {
        left.canonical_path
            .as_bytes()
            .cmp(right.canonical_path.as_bytes())
    });
    members
}

fn encode_layout_member(output: &mut Vec<u8>, member: &Member) -> Result<(), VerifyError> {
    push_bytes(output, member.canonical_path.as_bytes())?;
    output.push(kind_tag(&member.kind));
    push_bytes(output, &member.raw_name_bytes)?;
    push_u16(output, member.method);
    push_u16(output, member.flags);
    push_u64(output, member.declared_comp_size);
    push_u64(output, member.declared_uncomp_size);
    push_u32(output, member.declared_crc);
    encode_range(output, member.source_ranges.local_header);
    encode_range(output, member.source_ranges.compressed_payload);
    if let Some(descriptor) = member.source_ranges.data_descriptor {
        output.push(1);
        encode_range(output, descriptor);
    } else {
        output.push(0);
    }
    encode_range(output, member.source_ranges.central_header);

    let mut extras: Vec<_> = member.extra_fields.iter().collect();
    extras.sort_by_key(|extra| (site_tag(extra.site), extra.id, extra.data_range.offset));
    push_u32(
        output,
        u32::try_from(extras.len())
            .map_err(|_| VerifyError::new("extra-field count exceeds u32"))?,
    );
    for extra in extras {
        output.push(site_tag(extra.site));
        push_u16(output, extra.id);
        output.push(match extra.disposition {
            ExtraDisposition::Ignored => DISP_IGNORED,
            ExtraDisposition::Semantic => DISP_SEMANTIC,
            ExtraDisposition::Denied => DISP_DENIED,
        });
        push_u64(output, extra.data_range.offset);
        push_u16(
            output,
            u16::try_from(extra.data_range.len)
                .map_err(|_| VerifyError::new("extra data length exceeds u16"))?,
        );
    }

    push_u32(
        output,
        u32::try_from(member.normalization_actions.len())
            .map_err(|_| VerifyError::new("normalization count exceeds u32"))?,
    );
    for action in &member.normalization_actions {
        match action {
            NormalizationAction::StripDirectoryTrailingSlash => {
                output.push(NORM_STRIP_DIR_SLASH);
            }
            NormalizationAction::DropDotComponent { component_index } => {
                output.push(NORM_DROP_DOT);
                push_u32(output, *component_index);
            }
        }
    }
    Ok(())
}

fn kind_tag(kind: &MemberKind) -> u8 {
    match kind {
        MemberKind::File => FILE,
        MemberKind::Directory => DIRECTORY,
    }
}

fn site_tag(site: ExtraSite) -> u8 {
    match site {
        ExtraSite::Local => SITE_LOCAL,
        ExtraSite::Central => SITE_CENTRAL,
    }
}

fn encode_range(output: &mut Vec<u8>, range: ByteRange) {
    push_u64(output, range.offset);
    push_u64(output, range.len);
}

fn push_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), VerifyError> {
    push_u32(
        output,
        u32::try_from(bytes.len()).map_err(|_| VerifyError::new("byte string exceeds u32"))?,
    );
    output.extend_from_slice(bytes);
    Ok(())
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn preimage(label: &str, body: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(label.as_bytes());
    output.push(b' ');
    output.extend_from_slice(body.len().to_string().as_bytes());
    output.push(0);
    output.extend_from_slice(body);
    output
}

fn verify_digest(value: &str, label: &str) -> Result<(), VerifyError> {
    decode_digest(value, label).map(|_| ())
}

fn decode_digest(value: &str, label: &str) -> Result<[u8; 32], VerifyError> {
    if value.len() != 64 {
        return Err(VerifyError::new(format!(
            "{label} must contain 64 lowercase hexadecimal characters"
        )));
    }
    let decoded = decode_hex(value, label)?;
    decoded
        .try_into()
        .map_err(|_| VerifyError::new(format!("{label} is not 32 bytes")))
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>, VerifyError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VerifyError::new(format!(
            "{label} must be lowercase, even-length hexadecimal"
        )));
    }
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(VerifyError::new(format!(
            "{label} must have even hexadecimal length"
        )));
    }
    pairs
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|_| VerifyError::new(format!("{label} is not UTF-8")))?;
            u8::from_str_radix(text, 16)
                .map_err(|_| VerifyError::new(format!("{label} contains invalid hexadecimal")))
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &[u8] =
        include_bytes!("../../../crates/sealr/tests/conformance/identity-v1.json");

    #[test]
    fn committed_vectors_verify_independently() {
        let summary = verify_manifest_json(VECTORS).expect("committed vectors");
        assert_eq!(summary.profiles, 1);
        assert_eq!(summary.cases, 4);
        assert_eq!(summary.layout_roots, 3);
        assert_eq!(summary.content_roots, 3);
    }

    #[test]
    fn tampered_layout_root_is_rejected() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["cases"][1]["layout_root"][TREE_ENCODING] =
            serde_json::Value::String("0".repeat(64));
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error.to_string().contains("layout root mismatch"));
    }

    #[test]
    fn tampered_source_is_rejected() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["cases"][0]["source_bytes_hex"] = serde_json::Value::String(String::new());
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error.to_string().contains("source bytes do not match"));
    }

    #[test]
    fn tampered_profile_bytes_are_rejected() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["profiles"][0]["canonical_bytes_hex"] = serde_json::Value::String(String::new());
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error.to_string().contains("profile bytes are empty"));
    }

    #[test]
    fn tampered_covering_is_rejected_before_root_comparison() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["cases"][1]["archive_ir"]["covering"]["local_records"]["len"] =
            serde_json::json!(126);
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error.to_string().contains("covering ranges"));
    }

    #[test]
    fn tampered_extra_range_is_rejected_before_root_comparison() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["cases"][2]["archive_ir"]["members"][0]["extra_fields"][0]["header_range"]
            ["len"] = serde_json::json!(3);
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error
            .to_string()
            .contains("extra header does not exactly precede"));
    }

    #[test]
    fn root_objects_reject_unknown_fields() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["cases"][0]["layout_root"]["unexpected"] = serde_json::json!(true);
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error.to_string().contains("JSON"));
    }

    #[test]
    fn unavailable_ir_cannot_carry_a_root() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["cases"][3]["layout_root"] = serde_json::json!({
            TREE_ENCODING: "0".repeat(64)
        });
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error.to_string().contains("without IR carries a tree root"));
    }

    #[test]
    fn duplicate_case_ids_are_rejected() {
        let mut manifest: serde_json::Value = serde_json::from_slice(VECTORS).unwrap();
        manifest["cases"][1]["id"] = manifest["cases"][0]["id"].clone();
        let error = verify_manifest_json(&serde_json::to_vec(&manifest).unwrap()).unwrap_err();
        assert!(error.to_string().contains("duplicate case id"));
    }
}
