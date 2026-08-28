//! Independent verifier for Sealr identity conformance manifests.
//!
//! This crate deliberately does not depend on `sealr`. It reads committed
//! evidence facts, validates their semantic coherence, and independently
//! reproduces profile, layout, and content digests. It never parses or inflates
//! an archive.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_CASES: usize = 10_000;
const MAX_MEMBERS_PER_CASE: usize = 100_000;
const MANIFEST_SCHEMA: &str = "sealr.identity-conformance.v1";
const IR_SCHEMA: &str = "sealr.archive-ir.v1";
const TREE_ENCODING: &str = "sealrTreeV1";
const LAYOUT_LABEL: &str = "sealr.tree.layout.v1";
const CONTENT_LABEL: &str = "sealr.tree.content.v1";
const TAR_LAYOUT_VECTOR_SCHEMA: &str = "sealr.tar-layout-conformance.v1";
const TAR_TREE_ENCODING: &str = "sealrTreeV2";
const TAR_LAYOUT_LABEL: &str = "sealr.tree.layout.tar-ustar.v1";
const ZIP64_MANIFEST_SCHEMA: &str = "sealr.zip64-identity-conformance.v1";
const ZIP64_IR_SCHEMA: &str = "sealr.archive-ir.zip64.v1";
const ZIP64_PROFILE_SCHEMA: &str = "sealr.profile.zip64.strict-ascii.v1";
const ZIP64_TREE_ENCODING: &str = "sealrTreeV3";
const ZIP64_LAYOUT_LABEL: &str = "sealr.tree.layout.zip64.v1";

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TarVerificationSummary {
    pub members: usize,
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
struct ManifestEnvelope {
    schema: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64Manifest {
    schema: String,
    profile: Zip64ProfileVector,
    layout_encoding: String,
    layout_label: String,
    content_encoding: String,
    content_label: String,
    cases: Vec<Zip64Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64ProfileVector {
    id: String,
    digest: DigestHex,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64Case {
    id: String,
    source_bytes_hex: String,
    source: DigestHex,
    archive_ir: Zip64ArchiveIr,
    layout_preimage_hex: String,
    layout_root: Zip64LayoutRoot,
    content_root: Zip64ContentRoot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64ArchiveIr {
    schema: String,
    profile: String,
    profile_digest: String,
    source_digest: DigestHex,
    format: String,
    zip64_covering: Zip64Covering,
    members: Vec<Zip64Member>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64Covering {
    local_records: ByteRange,
    central_directory: ByteRange,
    zip64_eocd: Option<ByteRange>,
    zip64_locator: Option<ByteRange>,
    eocd: ByteRange,
    comment: ByteRange,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64Member {
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
    zip64: Zip64MemberEvidence,
    actual_uncomp_size: Option<u64>,
    actual_crc: Option<u32>,
    content_sha256: Option<String>,
    verification: MemberVerification,
    normalization_actions: Vec<NormalizationAction>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64MemberEvidence {
    local_version_needed: u16,
    central_version_needed: u16,
    central_presence_mask: u8,
    central_legacy_sentinel_mask: u8,
    local_legacy_sentinel_mask: u8,
    local_value_shape: Zip64LocalValueShape,
    local_zip64_extra: Option<ByteRange>,
    central_zip64_extra: Option<ByteRange>,
    descriptor_width: Option<Zip64DescriptorWidth>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Zip64LocalValueShape {
    Absent,
    Exact,
    StreamingZeros,
    StreamingMaxima,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Zip64DescriptorWidth {
    Zip32,
    Zip64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64LayoutRoot {
    #[serde(rename = "sealrTreeV3")]
    sealr_tree_v3: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Zip64ContentRoot {
    #[serde(rename = "sealrTreeV1")]
    sealr_tree_v1: String,
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

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ByteRange {
    offset: u64,
    len: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarLayoutVector {
    schema: String,
    tree_encoding: String,
    layout_label: String,
    content_encoding: String,
    content_label: String,
    source: DigestHex,
    covering: TarCovering,
    members: Vec<TarVectorMember>,
    layout_root: TarLayoutRoot,
    content_root: TarContentRoot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarCovering {
    member_records: ByteRange,
    terminator: ByteRange,
    trailing_zeros: ByteRange,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarVectorMember {
    canonical_path: String,
    kind: MemberKind,
    raw_name_bytes: Vec<u8>,
    declared_uncomp_size: u64,
    header: ByteRange,
    payload: ByteRange,
    padding: ByteRange,
    mode: u32,
    mtime: u64,
    header_checksum: u32,
    header_sha256: String,
    normalization_actions: Vec<NormalizationAction>,
    actual_uncomp_size: u64,
    content_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarLayoutRoot {
    #[serde(rename = "sealrTreeV2")]
    sealr_tree_v2: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TarContentRoot {
    #[serde(rename = "sealrTreeV1")]
    sealr_tree_v1: String,
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

#[derive(Clone, Copy, Serialize)]
struct Zip64ProfileBitRule {
    bit: u8,
    mask: u16,
    disposition: &'static str,
    meaning: &'static str,
}

#[derive(Serialize)]
struct Zip64ProfileDefinition {
    schema: &'static str,
    format: &'static str,
    methods: [u16; 2],
    general_purpose_bits: [Zip64ProfileBitRule; 16],
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

pub fn verify_manifest_json(bytes: &[u8]) -> Result<VerificationSummary, VerifyError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(VerifyError::new(format!(
            "manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let envelope: ManifestEnvelope = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::new(format!("JSON: {error}")))?;
    match envelope.schema.as_str() {
        MANIFEST_SCHEMA => {
            let manifest: Manifest = serde_json::from_slice(bytes)
                .map_err(|error| VerifyError::new(format!("JSON: {error}")))?;
            verify_manifest(&manifest)
        }
        ZIP64_MANIFEST_SCHEMA => verify_zip64_identity_vector_json(bytes),
        schema => Err(VerifyError::new(format!("unsupported schema {schema:?}"))),
    }
}

pub fn verify_zip64_identity_vector_json(bytes: &[u8]) -> Result<VerificationSummary, VerifyError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(VerifyError::new(format!(
            "ZIP64 manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let manifest: Zip64Manifest = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::new(format!("ZIP64 JSON: {error}")))?;
    verify_zip64_manifest(&manifest)
}

pub fn verify_tar_layout_vector_json(bytes: &[u8]) -> Result<TarVerificationSummary, VerifyError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(VerifyError::new(format!(
            "TAR vector exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let vector: TarLayoutVector = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::new(format!("TAR vector JSON: {error}")))?;
    verify_tar_layout_vector(&vector)?;
    Ok(TarVerificationSummary {
        members: vector.members.len(),
    })
}

fn verify_tar_layout_vector(vector: &TarLayoutVector) -> Result<(), VerifyError> {
    if vector.schema != TAR_LAYOUT_VECTOR_SCHEMA
        || vector.tree_encoding != TAR_TREE_ENCODING
        || vector.layout_label != TAR_LAYOUT_LABEL
        || vector.content_encoding != TREE_ENCODING
        || vector.content_label != CONTENT_LABEL
    {
        return Err(VerifyError::new("unsupported TAR vector contract"));
    }
    verify_digest(&vector.source.sha256, "TAR source digest")?;
    verify_digest(&vector.layout_root.sealr_tree_v2, "TAR layout root")?;
    verify_digest(&vector.content_root.sealr_tree_v1, "TAR content root")?;
    if vector.members.len() > MAX_MEMBERS_PER_CASE {
        return Err(VerifyError::new("TAR vector member limit exceeded"));
    }
    validate_tar_covering(vector)?;
    let actual_layout = sha256_hex(&encode_tar_layout_vector(vector)?);
    if actual_layout != vector.layout_root.sealr_tree_v2 {
        return Err(VerifyError::new(format!(
            "TAR layout root mismatch: expected {}, calculated {actual_layout}",
            vector.layout_root.sealr_tree_v2
        )));
    }
    let actual_content = sha256_hex(&encode_tar_content_vector(vector)?);
    if actual_content != vector.content_root.sealr_tree_v1 {
        return Err(VerifyError::new(format!(
            "TAR content root mismatch: expected {}, calculated {actual_content}",
            vector.content_root.sealr_tree_v1
        )));
    }
    Ok(())
}

fn validate_tar_covering(vector: &TarLayoutVector) -> Result<(), VerifyError> {
    let covering = &vector.covering;
    let records_end = range_end(covering.member_records, "TAR member covering")?;
    let terminator_end = range_end(covering.terminator, "TAR terminator")?;
    let source_end = range_end(covering.trailing_zeros, "TAR trailing zeros")?;
    if covering.member_records.offset != 0
        || covering.terminator.offset != records_end
        || covering.terminator.len != 1024
        || covering.trailing_zeros.offset != terminator_end
        || !source_end.is_multiple_of(512)
    {
        return Err(VerifyError::new(
            "TAR covering does not form one complete 512-byte-block source",
        ));
    }
    let mut paths = HashSet::new();
    let mut records: Vec<&TarVectorMember> = vector.members.iter().collect();
    records.sort_by_key(|member| member.header.offset);
    let mut expected_header = 0_u64;
    for member in records {
        if member.canonical_path.is_empty() || !paths.insert(member.canonical_path.as_str()) {
            return Err(VerifyError::new("TAR member paths are empty or duplicate"));
        }
        if member.raw_name_bytes.is_empty() {
            return Err(VerifyError::new("TAR raw member name is empty"));
        }
        verify_digest(&member.header_sha256, "TAR header digest")?;
        verify_digest(&member.content_sha256, "TAR content digest")?;
        let header_end = range_end(member.header, "TAR member header")?;
        let payload_end = range_end(member.payload, "TAR member payload")?;
        let padding_end = range_end(member.padding, "TAR member padding")?;
        let expected_padding = (512 - (member.payload.len % 512)) % 512;
        if member.header.offset != expected_header
            || member.header.len != 512
            || member.payload.offset != header_end
            || member.payload.len != member.declared_uncomp_size
            || member.padding.offset != payload_end
            || member.padding.len != expected_padding
            || !padding_end.is_multiple_of(512)
            || member.actual_uncomp_size != member.declared_uncomp_size
        {
            return Err(VerifyError::new("TAR member record geometry is invalid"));
        }
        expected_header = padding_end;
    }
    if expected_header != records_end {
        return Err(VerifyError::new(
            "TAR member records do not fill their covering",
        ));
    }
    Ok(())
}

fn encode_tar_layout_vector(vector: &TarLayoutVector) -> Result<Vec<u8>, VerifyError> {
    let mut body = Vec::new();
    encode_range(&mut body, vector.covering.member_records);
    encode_range(&mut body, vector.covering.terminator);
    encode_range(&mut body, vector.covering.trailing_zeros);
    let mut members: Vec<&TarVectorMember> = vector.members.iter().collect();
    members.sort_by(|left, right| left.canonical_path.cmp(&right.canonical_path));
    push_u32(
        &mut body,
        u32::try_from(members.len())
            .map_err(|_| VerifyError::new("TAR member count exceeds u32"))?,
    );
    for member in members {
        push_bytes(&mut body, member.canonical_path.as_bytes())?;
        body.push(kind_tag(&member.kind));
        push_bytes(&mut body, &member.raw_name_bytes)?;
        push_u64(&mut body, member.declared_uncomp_size);
        encode_range(&mut body, member.header);
        encode_range(&mut body, member.payload);
        encode_range(&mut body, member.padding);
        push_u32(&mut body, member.mode);
        push_u64(&mut body, member.mtime);
        push_u32(&mut body, member.header_checksum);
        body.extend_from_slice(&decode_digest(&member.header_sha256, "TAR header digest")?);
        push_u32(
            &mut body,
            u32::try_from(member.normalization_actions.len())
                .map_err(|_| VerifyError::new("TAR normalization count exceeds u32"))?,
        );
        encode_normalization_actions(&mut body, &member.normalization_actions);
    }
    Ok(preimage(TAR_LAYOUT_LABEL, &body))
}

fn encode_tar_content_vector(vector: &TarLayoutVector) -> Result<Vec<u8>, VerifyError> {
    let mut body = Vec::new();
    let mut members: Vec<&TarVectorMember> = vector.members.iter().collect();
    members.sort_by(|left, right| left.canonical_path.cmp(&right.canonical_path));
    push_u32(
        &mut body,
        u32::try_from(members.len())
            .map_err(|_| VerifyError::new("TAR member count exceeds u32"))?,
    );
    for member in members {
        push_bytes(&mut body, member.canonical_path.as_bytes())?;
        body.push(kind_tag(&member.kind));
        push_u64(&mut body, member.actual_uncomp_size);
        body.extend_from_slice(&decode_digest(
            &member.content_sha256,
            "TAR content digest",
        )?);
    }
    Ok(preimage(CONTENT_LABEL, &body))
}

fn encode_normalization_actions(output: &mut Vec<u8>, actions: &[NormalizationAction]) {
    for action in actions {
        match action {
            NormalizationAction::StripDirectoryTrailingSlash => output.push(NORM_STRIP_DIR_SLASH),
            NormalizationAction::DropDotComponent { component_index } => {
                output.push(NORM_DROP_DOT);
                push_u32(output, *component_index);
            }
        }
    }
}

fn range_end(range: ByteRange, label: &str) -> Result<u64, VerifyError> {
    range
        .offset
        .checked_add(range.len)
        .ok_or_else(|| VerifyError::new(format!("{label} overflows u64")))
}

fn verify_zip64_manifest(manifest: &Zip64Manifest) -> Result<VerificationSummary, VerifyError> {
    if manifest.schema != ZIP64_MANIFEST_SCHEMA
        || manifest.layout_encoding != ZIP64_TREE_ENCODING
        || manifest.layout_label != ZIP64_LAYOUT_LABEL
        || manifest.content_encoding != TREE_ENCODING
        || manifest.content_label != CONTENT_LABEL
    {
        return Err(VerifyError::new("unsupported ZIP64 manifest contract"));
    }
    verify_zip64_profile(&manifest.profile)?;
    if manifest.cases.is_empty() {
        return Err(VerifyError::new("ZIP64 manifest has no cases"));
    }
    if manifest.cases.len() > MAX_CASES {
        return Err(VerifyError::new(format!(
            "ZIP64 manifest exceeds the {MAX_CASES}-case limit"
        )));
    }

    let mut case_ids = HashSet::new();
    for case in &manifest.cases {
        if case.id.is_empty() || !case_ids.insert(case.id.as_str()) {
            return Err(VerifyError::new("ZIP64 case ids are empty or duplicate"));
        }
        verify_zip64_case(case, &manifest.profile)
            .map_err(|error| error.context(&format!("ZIP64 case {}", case.id)))?;
    }

    Ok(VerificationSummary {
        profiles: 1,
        cases: manifest.cases.len(),
        layout_roots: manifest.cases.len(),
        content_roots: manifest.cases.len(),
    })
}

fn verify_zip64_profile(profile: &Zip64ProfileVector) -> Result<(), VerifyError> {
    if profile.id != ZIP64_PROFILE_SCHEMA {
        return Err(VerifyError::new("unsupported ZIP64 profile id"));
    }
    verify_digest(&profile.digest.sha256, "ZIP64 profile digest")?;
    let canonical = zip64_profile_canonical_bytes()?;
    if sha256_hex(&canonical) != profile.digest.sha256 {
        return Err(VerifyError::new(
            "ZIP64 profile digest does not match the independently reconstructed profile",
        ));
    }
    Ok(())
}

fn zip64_profile_canonical_bytes() -> Result<Vec<u8>, VerifyError> {
    const fn rule(
        bit: u8,
        disposition: &'static str,
        meaning: &'static str,
    ) -> Zip64ProfileBitRule {
        Zip64ProfileBitRule {
            bit,
            mask: 1_u16 << bit,
            disposition,
            meaning,
        }
    }
    let definition = Zip64ProfileDefinition {
        schema: ZIP64_PROFILE_SCHEMA,
        format: "zip64",
        methods: [0, 8],
        general_purpose_bits: [
            rule(0, "denied", "traditional-encryption"),
            rule(1, "denied", "method-dependent-option-1"),
            rule(2, "denied", "method-dependent-option-2"),
            rule(3, "semantic", "data-descriptor"),
            rule(4, "denied", "enhanced-deflating"),
            rule(5, "denied", "compressed-patched-data"),
            rule(6, "denied", "strong-encryption"),
            rule(7, "denied", "unused"),
            rule(8, "denied", "unused"),
            rule(9, "denied", "unused"),
            rule(10, "denied", "unused"),
            rule(11, "denied", "utf8-name"),
            rule(12, "denied", "reserved-enhanced-compression"),
            rule(13, "denied", "masked-local-header"),
            rule(14, "denied", "alternate-streams"),
            rule(15, "denied", "reserved"),
        ],
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
    };
    serde_json::to_vec(&definition)
        .map_err(|error| VerifyError::new(format!("ZIP64 profile serialization: {error}")))
}

fn verify_zip64_case(case: &Zip64Case, profile: &Zip64ProfileVector) -> Result<(), VerifyError> {
    let source = decode_hex(&case.source_bytes_hex, "ZIP64 source_bytes_hex")?;
    verify_digest(&case.source.sha256, "ZIP64 source digest")?;
    if sha256_hex(&source) != case.source.sha256 {
        return Err(VerifyError::new(
            "ZIP64 source bytes do not match source digest",
        ));
    }
    let ir = &case.archive_ir;
    if ir.schema != ZIP64_IR_SCHEMA
        || ir.profile != profile.id
        || ir.profile_digest != profile.digest.sha256
        || ir.source_digest.sha256 != case.source.sha256
        || ir.format != "zip64"
    {
        return Err(VerifyError::new(
            "ZIP64 IR source, format, or profile identity does not match the case",
        ));
    }
    validate_zip64_ir(ir)?;
    verify_zip64_covering(&source, ir)?;

    verify_digest(&case.layout_root.sealr_tree_v3, "ZIP64 layout root")?;
    let expected_preimage = decode_hex(&case.layout_preimage_hex, "ZIP64 layout preimage")?;
    let actual_preimage = encode_zip64_layout(ir)?;
    if actual_preimage != expected_preimage {
        return Err(VerifyError::new(
            "ZIP64 layout preimage does not match reconstructed evidence",
        ));
    }
    let actual_layout = sha256_hex(&actual_preimage);
    if actual_layout != case.layout_root.sealr_tree_v3 {
        return Err(VerifyError::new(format!(
            "ZIP64 layout root mismatch: expected {}, calculated {actual_layout}",
            case.layout_root.sealr_tree_v3
        )));
    }

    verify_digest(&case.content_root.sealr_tree_v1, "ZIP64 content root")?;
    let actual_content = sha256_hex(&encode_zip64_content(ir)?);
    if actual_content != case.content_root.sealr_tree_v1 {
        return Err(VerifyError::new(format!(
            "ZIP64 content root mismatch: expected {}, calculated {actual_content}",
            case.content_root.sealr_tree_v1
        )));
    }
    Ok(())
}

fn validate_zip64_ir(ir: &Zip64ArchiveIr) -> Result<(), VerifyError> {
    if ir.members.len() > MAX_MEMBERS_PER_CASE {
        return Err(VerifyError::new("ZIP64 IR member limit exceeded"));
    }
    u32::try_from(ir.members.len())
        .map_err(|_| VerifyError::new("ZIP64 member count exceeds u32"))?;
    let mut paths = HashSet::new();
    for member in &ir.members {
        if member.canonical_path.is_empty() || !paths.insert(member.canonical_path.as_str()) {
            return Err(VerifyError::new(
                "ZIP64 canonical paths are empty or duplicate",
            ));
        }
        if member.raw_name_bytes.is_empty()
            || !member.raw_name_bytes.is_ascii()
            || member.decoded_name.as_bytes() != member.raw_name_bytes
            || member.components.join("/") != member.canonical_path
        {
            return Err(VerifyError::new("ZIP64 member name evidence is invalid"));
        }
        if !matches!(member.method, 0 | 8) || !matches!(member.flags, 0 | 0x0008) {
            return Err(VerifyError::new("ZIP64 member method or flags are denied"));
        }
        for (range, label) in [
            (member.source_ranges.local_header, "ZIP64 local header"),
            (
                member.source_ranges.compressed_payload,
                "ZIP64 compressed payload",
            ),
            (member.source_ranges.central_header, "ZIP64 central header"),
        ] {
            validate_range(range, label)?;
        }
        if let Some(range) = member.source_ranges.data_descriptor {
            validate_range(range, "ZIP64 data descriptor")?;
        }
        let mut sites = HashSet::new();
        for extra in &member.extra_fields {
            validate_range(extra.header_range, "ZIP64 extra header")?;
            validate_range(extra.data_range, "ZIP64 extra data")?;
            if extra.id != 1
                || !matches!(extra.disposition, ExtraDisposition::Semantic)
                || extra.header_range.len != 4
                || checked_range_end(extra.header_range, "ZIP64 extra header")?
                    != extra.data_range.offset
                || !sites.insert(extra.site)
            {
                return Err(VerifyError::new(
                    "ZIP64 extra evidence is outside the closed semantic language",
                ));
            }
        }
        if member.zip64.central_presence_mask > 0b111
            || member.zip64.central_legacy_sentinel_mask > 0b111
            || member.zip64.local_legacy_sentinel_mask > 0b11
        {
            return Err(VerifyError::new("ZIP64 evidence mask is invalid"));
        }
        if !matches!(member.verification, MemberVerification::Verified) {
            return Err(VerifyError::new(
                "ZIP64 conformance content requires verified members",
            ));
        }
        let actual_size = member
            .actual_uncomp_size
            .ok_or_else(|| VerifyError::new("ZIP64 verified member has no actual size"))?;
        let actual_crc = member
            .actual_crc
            .ok_or_else(|| VerifyError::new("ZIP64 verified member has no actual CRC"))?;
        let content_digest = member
            .content_sha256
            .as_deref()
            .ok_or_else(|| VerifyError::new("ZIP64 verified member has no content digest"))?;
        verify_digest(content_digest, "ZIP64 member content digest")?;
        if actual_size != member.declared_uncomp_size || actual_crc != member.declared_crc {
            return Err(VerifyError::new(
                "ZIP64 verified member facts differ from their declarations",
            ));
        }
    }
    Ok(())
}

fn verify_zip64_covering(source: &[u8], ir: &Zip64ArchiveIr) -> Result<(), VerifyError> {
    const LFH: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
    const CDH: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
    const ZIP64_EOCD: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
    const ZIP64_LOCATOR: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
    const EOCD: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];

    let covering = &ir.zip64_covering;
    let source_len =
        u64::try_from(source.len()).map_err(|_| VerifyError::new("source exceeds u64"))?;
    for (range, label) in [
        (covering.local_records, "ZIP64 local covering"),
        (covering.central_directory, "ZIP64 central covering"),
        (covering.eocd, "ZIP64 EOCD covering"),
        (covering.comment, "ZIP64 comment covering"),
    ] {
        validate_range(range, label)?;
    }
    let pair = match (covering.zip64_eocd, covering.zip64_locator) {
        (None, None) => None,
        (Some(record), Some(locator)) => {
            validate_range(record, "ZIP64 EOCD record")?;
            validate_range(locator, "ZIP64 locator")?;
            Some((record, locator))
        }
        _ => {
            return Err(VerifyError::new(
                "ZIP64 end-record evidence is only partially present",
            ));
        }
    };
    if pair.is_none()
        && !ir.members.iter().any(|member| {
            member.zip64.local_zip64_extra.is_some()
                || member.zip64.central_zip64_extra.is_some()
                || matches!(
                    member.zip64.descriptor_width,
                    Some(Zip64DescriptorWidth::Zip64)
                )
        })
    {
        return Err(VerifyError::new(
            "ZIP64 profile evidence contains no ZIP64 construct",
        ));
    }
    let after_central = pair.map_or(covering.eocd.offset, |(record, _)| record.offset);
    if covering.local_records.offset != 0
        || checked_range_end(covering.local_records, "ZIP64 local covering")?
            != covering.central_directory.offset
        || checked_range_end(covering.central_directory, "ZIP64 central covering")? != after_central
        || covering.eocd.len != 22
        || checked_range_end(covering.eocd, "ZIP64 EOCD covering")? != covering.comment.offset
        || checked_range_end(covering.comment, "ZIP64 comment covering")? != source_len
    {
        return Err(VerifyError::new(
            "ZIP64 top-level covering does not exactly partition the source",
        ));
    }

    let eocd = range_bytes(source, covering.eocd, "ZIP64 classic EOCD")?;
    if eocd[0..4] != EOCD || le_u16(eocd, 4) != 0 || le_u16(eocd, 6) != 0 {
        return Err(VerifyError::new(
            "ZIP64 classic EOCD is absent, invalid, or spanned",
        ));
    }
    if u64::from(le_u16(eocd, 20)) != covering.comment.len {
        return Err(VerifyError::new(
            "ZIP64 classic EOCD comment length disagrees with covering",
        ));
    }
    reject_zip64_structural_metadata(
        range_bytes(source, covering.comment, "ZIP64 global EOCD comment")?,
        "global EOCD comment",
    )?;
    let classic_count_disk = le_u16(eocd, 8);
    let classic_count_total = le_u16(eocd, 10);
    let classic_cd_size = le_u32(eocd, 12);
    let classic_cd_offset = le_u32(eocd, 16);
    let member_count = u64::try_from(ir.members.len())
        .map_err(|_| VerifyError::new("ZIP64 member count exceeds u64"))?;
    let mut end_version_needed = None;

    if let Some((record_range, locator_range)) = pair {
        if record_range.len != 56
            || locator_range.len != 20
            || checked_range_end(record_range, "ZIP64 EOCD record")? != locator_range.offset
            || checked_range_end(locator_range, "ZIP64 locator")? != covering.eocd.offset
        {
            return Err(VerifyError::new(
                "ZIP64 end pair does not have fixed adjacent geometry",
            ));
        }
        let record = range_bytes(source, record_range, "ZIP64 EOCD record")?;
        let locator = range_bytes(source, locator_range, "ZIP64 locator")?;
        if record[0..4] != ZIP64_EOCD
            || le_u64(record, 4) != 44
            || le_u32(record, 16) != 0
            || le_u32(record, 20) != 0
            || le_u64(record, 24) != member_count
            || le_u64(record, 32) != member_count
            || le_u64(record, 40) != covering.central_directory.len
            || le_u64(record, 48) != covering.central_directory.offset
        {
            return Err(VerifyError::new(
                "ZIP64 EOCD disagrees with represented archive geometry",
            ));
        }
        end_version_needed = Some(le_u16(record, 14));
        if locator[0..4] != ZIP64_LOCATOR
            || le_u32(locator, 4) != 0
            || le_u64(locator, 8) != record_range.offset
            || le_u32(locator, 16) != 1
        {
            return Err(VerifyError::new(
                "ZIP64 locator disagrees with represented archive geometry",
            ));
        }
        let has_sentinel = classic_count_disk == u16::MAX
            || classic_count_total == u16::MAX
            || classic_cd_size == u32::MAX
            || classic_cd_offset == u32::MAX;
        if !has_sentinel
            || !canonical_zip64_end_u16(classic_count_disk, member_count)
            || !canonical_zip64_end_u16(classic_count_total, member_count)
            || !canonical_zip64_end_u32(classic_cd_size, covering.central_directory.len)
            || !canonical_zip64_end_u32(classic_cd_offset, covering.central_directory.offset)
        {
            return Err(VerifyError::new(
                "classic EOCD is not canonical for the ZIP64 end record",
            ));
        }
    } else if u64::from(classic_count_disk) != member_count
        || u64::from(classic_count_total) != member_count
        || u64::from(classic_cd_size) != covering.central_directory.len
        || u64::from(classic_cd_offset) != covering.central_directory.offset
    {
        return Err(VerifyError::new(
            "classic EOCD disagrees with member-only ZIP64 evidence",
        ));
    }

    let mut local_ranges = Vec::with_capacity(ir.members.len());
    let mut central_ranges = Vec::with_capacity(ir.members.len());
    for member in &ir.members {
        let ranges = &member.source_ranges;
        if ranges.local_header.len < 30 || ranges.central_header.len < 46 {
            return Err(VerifyError::new("ZIP64 member header is too short"));
        }
        let local = range_bytes(
            source,
            ByteRange {
                offset: ranges.local_header.offset,
                len: 30,
            },
            "ZIP64 local fixed header",
        )?;
        let central = range_bytes(
            source,
            ByteRange {
                offset: ranges.central_header.offset,
                len: 46,
            },
            "ZIP64 central fixed header",
        )?;
        if local[0..4] != LFH || central[0..4] != CDH {
            return Err(VerifyError::new("ZIP64 member signature is invalid"));
        }
        let local_name_len = u64::from(le_u16(local, 26));
        let local_extra_len = u64::from(le_u16(local, 28));
        let central_name_len = u64::from(le_u16(central, 28));
        let central_extra_len = u64::from(le_u16(central, 30));
        let central_comment_len = u64::from(le_u16(central, 32));
        if ranges.local_header.len != 30 + local_name_len + local_extra_len
            || ranges.central_header.len
                != 46 + central_name_len + central_extra_len + central_comment_len
            || checked_range_end(ranges.local_header, "ZIP64 local header")?
                != ranges.compressed_payload.offset
            || ranges.compressed_payload.len != member.declared_comp_size
            || !contains_range(covering.local_records, ranges.local_header)?
            || !contains_range(covering.central_directory, ranges.central_header)?
        {
            return Err(VerifyError::new(
                "ZIP64 member ranges disagree with encoded header lengths",
            ));
        }
        let central_comment_offset = ranges
            .central_header
            .offset
            .checked_add(46 + central_name_len + central_extra_len)
            .ok_or_else(|| VerifyError::new("ZIP64 central comment offset overflows"))?;
        reject_zip64_structural_metadata(
            range_bytes(
                source,
                ByteRange {
                    offset: central_comment_offset,
                    len: central_comment_len,
                },
                "ZIP64 central member comment",
            )?,
            "central member comment",
        )?;
        let local_name = range_bytes(
            source,
            ByteRange {
                offset: ranges.local_header.offset + 30,
                len: local_name_len,
            },
            "ZIP64 local name",
        )?;
        let central_name = range_bytes(
            source,
            ByteRange {
                offset: ranges.central_header.offset + 46,
                len: central_name_len,
            },
            "ZIP64 central name",
        )?;
        if local_name != member.raw_name_bytes || central_name != member.raw_name_bytes {
            return Err(VerifyError::new(
                "ZIP64 member names disagree with source bytes",
            ));
        }
        verify_zip64_common_member(member, local, central, pair.is_some())?;
        verify_zip64_extras(source, member, local, central)?;
        if member.method == 0 && member.flags & 0x0008 != 0 {
            reject_zip64_stream_signatures(
                range_bytes(
                    source,
                    ranges.compressed_payload,
                    "ZIP64 stored descriptor payload",
                )?,
                "stored descriptor payload",
            )?;
        }
        verify_zip64_descriptor(source, member)?;

        let payload_end = checked_range_end(ranges.compressed_payload, "ZIP64 payload")?;
        let local_end = if let Some(descriptor) = ranges.data_descriptor {
            if payload_end != descriptor.offset {
                return Err(VerifyError::new(
                    "ZIP64 payload does not abut its descriptor",
                ));
            }
            checked_range_end(descriptor, "ZIP64 descriptor")?
        } else {
            payload_end
        };
        local_ranges.push((ranges.local_header.offset, local_end));
        central_ranges.push((
            ranges.central_header.offset,
            checked_range_end(ranges.central_header, "ZIP64 central header")?,
        ));
    }

    if let Some(version_needed) = end_version_needed {
        let maximum_member_version = ir
            .members
            .iter()
            .map(|member| member.zip64.central_version_needed)
            .max()
            .unwrap_or(0);
        if version_needed != 45
            && (maximum_member_version == 0 || version_needed != maximum_member_version)
        {
            return Err(VerifyError::new(
                "ZIP64 EOCD extraction version is not canonical",
            ));
        }
    }

    local_ranges.sort_unstable_by_key(|range| range.0);
    central_ranges.sort_unstable_by_key(|range| range.0);
    verify_partition(
        &local_ranges,
        covering.local_records,
        "ZIP64 local record partition",
    )?;
    verify_partition(
        &central_ranges,
        covering.central_directory,
        "ZIP64 central header partition",
    )?;
    Ok(())
}

fn reject_zip64_structural_metadata(data: &[u8], context: &str) -> Result<(), VerifyError> {
    const SIGNATURES: [[u8; 4]; 6] = [
        [0x50, 0x4b, 0x06, 0x06],
        [0x50, 0x4b, 0x06, 0x07],
        [0x50, 0x4b, 0x05, 0x06],
        [0x50, 0x4b, 0x03, 0x04],
        [0x50, 0x4b, 0x01, 0x02],
        [0x50, 0x4b, 0x07, 0x08],
    ];
    if SIGNATURES
        .iter()
        .any(|signature| data.windows(4).any(|window| window == signature))
    {
        return Err(VerifyError::new(format!(
            "ZIP64 structural signature is denied in {context}"
        )));
    }
    Ok(())
}

fn reject_zip64_stream_signatures(data: &[u8], context: &str) -> Result<(), VerifyError> {
    const SIGNATURES: [[u8; 4]; 3] = [
        [0x50, 0x4b, 0x03, 0x04],
        [0x50, 0x4b, 0x01, 0x02],
        [0x50, 0x4b, 0x07, 0x08],
    ];
    if SIGNATURES
        .iter()
        .any(|signature| data.windows(4).any(|window| window == signature))
    {
        return Err(VerifyError::new(format!(
            "ZIP64 stream signature is denied in {context}"
        )));
    }
    Ok(())
}

fn verify_zip64_common_member(
    member: &Zip64Member,
    local: &[u8],
    central: &[u8],
    has_global_end_pair: bool,
) -> Result<(), VerifyError> {
    if le_u16(local, 4) != member.zip64.local_version_needed
        || le_u16(central, 6) != member.zip64.central_version_needed
        || le_u16(local, 6) != member.flags
        || le_u16(central, 8) != member.flags
        || le_u16(local, 8) != member.method
        || le_u16(central, 10) != member.method
        || le_u32(central, 16) != member.declared_crc
        || le_u16(central, 34) != 0
    {
        return Err(VerifyError::new(
            "ZIP64 common member evidence disagrees with source bytes",
        ));
    }
    let source_is_directory = member.raw_name_bytes.ends_with(b"/");
    if source_is_directory != matches!(member.kind, MemberKind::Directory) {
        return Err(VerifyError::new(
            "ZIP64 member kind disagrees with source name",
        ));
    }
    let attributes = le_u32(central, 38);
    let dos_directory = attributes & 0x10 != 0;
    let unix_kind = (attributes >> 16) & 0xf000;
    let attribute_is_directory = dos_directory || unix_kind == 0x4000;
    let attribute_is_regular = unix_kind == 0x8000;
    let attribute_is_special = unix_kind != 0 && unix_kind != 0x4000 && unix_kind != 0x8000;
    if attribute_is_special
        || (attribute_is_directory && attribute_is_regular)
        || (attribute_is_directory != source_is_directory
            && (attribute_is_directory || attribute_is_regular))
        || (source_is_directory
            && (member.declared_comp_size != 0
                || member.declared_uncomp_size != 0
                || member.method != 0
                || member.declared_crc != 0))
    {
        return Err(VerifyError::new("ZIP64 member attributes are invalid"));
    }

    let central_legacy_mask = u8::from(le_u32(central, 24) == u32::MAX)
        | (u8::from(le_u32(central, 20) == u32::MAX) << 1)
        | (u8::from(le_u32(central, 42) == u32::MAX) << 2);
    let local_legacy_mask =
        u8::from(le_u32(local, 22) == u32::MAX) | (u8::from(le_u32(local, 18) == u32::MAX) << 1);
    if central_legacy_mask != member.zip64.central_legacy_sentinel_mask
        || local_legacy_mask != member.zip64.local_legacy_sentinel_mask
    {
        return Err(VerifyError::new(
            "ZIP64 legacy sentinel evidence disagrees with source bytes",
        ));
    }

    let local_crc = le_u32(local, 14);
    let local_comp = le_u32(local, 18);
    let local_uncomp = le_u32(local, 22);
    let uses_descriptor = member.flags & 0x0008 != 0;
    if (!uses_descriptor && local_crc != member.declared_crc)
        || (uses_descriptor && local_crc != 0 && local_crc != member.declared_crc)
    {
        return Err(VerifyError::new("ZIP64 local CRC disagrees with evidence"));
    }
    match member.zip64.local_value_shape {
        Zip64LocalValueShape::Absent => {
            let sizes_match = if uses_descriptor {
                (local_comp == 0 || u64::from(local_comp) == member.declared_comp_size)
                    && (local_uncomp == 0 || u64::from(local_uncomp) == member.declared_uncomp_size)
            } else {
                u64::from(local_comp) == member.declared_comp_size
                    && u64::from(local_uncomp) == member.declared_uncomp_size
            };
            if member.zip64.local_zip64_extra.is_some() || !sizes_match {
                return Err(VerifyError::new(
                    "ZIP64 absent local value shape is invalid",
                ));
            }
        }
        Zip64LocalValueShape::Exact => {
            let forced = local_uncomp == u32::MAX && local_comp == u32::MAX;
            let canonical = canonical_zip64_member_u32(local_uncomp, member.declared_uncomp_size)
                && canonical_zip64_member_u32(local_comp, member.declared_comp_size);
            if member.zip64.local_zip64_extra.is_none() || (!forced && !canonical) {
                return Err(VerifyError::new("ZIP64 exact local value shape is invalid"));
            }
        }
        Zip64LocalValueShape::StreamingZeros => {
            if !uses_descriptor
                || member.zip64.local_zip64_extra.is_none()
                || local_uncomp != u32::MAX
                || local_comp != u32::MAX
            {
                return Err(VerifyError::new(
                    "ZIP64 zero-streaming local value shape is invalid",
                ));
            }
        }
        Zip64LocalValueShape::StreamingMaxima => {
            if !uses_descriptor
                || member.zip64.local_zip64_extra.is_none()
                || local_uncomp != 0
                || local_comp != 0
            {
                return Err(VerifyError::new(
                    "ZIP64 maximum-streaming local value shape is invalid",
                ));
            }
        }
    }
    if member.zip64.local_zip64_extra.is_some() && member.zip64.local_version_needed < 45 {
        return Err(VerifyError::new(
            "ZIP64 local extra requires extraction version 4.5",
        ));
    }
    let standard_offset_only = member.zip64.central_presence_mask == 0b100
        && u64::from(le_u32(central, 24)) == member.declared_uncomp_size
        && u64::from(le_u32(central, 20)) == member.declared_comp_size
        && matches!(
            (member.method, member.zip64.central_version_needed),
            (0, 10) | (8, 20)
        );
    let go_offset_only = member.zip64.central_presence_mask == 0b111
        && le_u32(central, 24) == u32::MAX
        && le_u32(central, 20) == u32::MAX
        && member.zip64.central_version_needed == 20
        && matches!(member.method, 0 | 8);
    let offset_only = has_global_end_pair
        && (standard_offset_only || go_offset_only)
        && le_u32(central, 42) == u32::MAX
        && member.declared_uncomp_size < u64::from(u32::MAX)
        && member.declared_comp_size < u64::from(u32::MAX)
        && member.source_ranges.local_header.offset >= u64::from(u32::MAX);
    if member.zip64.central_zip64_extra.is_some()
        && member.zip64.central_version_needed < 45
        && !offset_only
    {
        return Err(VerifyError::new(
            "ZIP64 central extra has an invalid extraction version",
        ));
    }
    let expected_width = uses_descriptor.then_some(
        if member.zip64.local_zip64_extra.is_some()
            || member.declared_comp_size >= u64::from(u32::MAX)
            || member.declared_uncomp_size >= u64::from(u32::MAX)
        {
            Zip64DescriptorWidth::Zip64
        } else {
            Zip64DescriptorWidth::Zip32
        },
    );
    if member.zip64.descriptor_width != expected_width {
        return Err(VerifyError::new(
            "ZIP64 descriptor width evidence is not canonical",
        ));
    }
    Ok(())
}

fn verify_zip64_extras(
    source: &[u8],
    member: &Zip64Member,
    local: &[u8],
    central: &[u8],
) -> Result<(), VerifyError> {
    for (site, expected) in [
        (ExtraSite::Local, member.zip64.local_zip64_extra),
        (ExtraSite::Central, member.zip64.central_zip64_extra),
    ] {
        let mut matching = member
            .extra_fields
            .iter()
            .filter(|field| field.site == site);
        let actual = matching.next().map(|field| field.data_range);
        if matching.next().is_some() || actual != expected {
            return Err(VerifyError::new(
                "ZIP64 site-specific extra evidence is inconsistent",
            ));
        }
        if let Some(data_range) = expected {
            let header_offset = data_range
                .offset
                .checked_sub(4)
                .ok_or_else(|| VerifyError::new("ZIP64 extra header underflows"))?;
            let header = range_bytes(
                source,
                ByteRange {
                    offset: header_offset,
                    len: 4,
                },
                "ZIP64 extra header",
            )?;
            if le_u16(header, 0) != 1 || u64::from(le_u16(header, 2)) != data_range.len {
                return Err(VerifyError::new(
                    "ZIP64 extra header disagrees with evidence",
                ));
            }
        }
    }

    let local_extra_start = member
        .source_ranges
        .local_header
        .offset
        .checked_add(30 + u64::from(le_u16(local, 26)))
        .ok_or_else(|| VerifyError::new("ZIP64 local extra offset overflows"))?;
    let local_extra_end = local_extra_start
        .checked_add(u64::from(le_u16(local, 28)))
        .ok_or_else(|| VerifyError::new("ZIP64 local extra range overflows"))?;
    let central_extra_start = member
        .source_ranges
        .central_header
        .offset
        .checked_add(46 + u64::from(le_u16(central, 28)))
        .ok_or_else(|| VerifyError::new("ZIP64 central extra offset overflows"))?;
    let central_extra_end = central_extra_start
        .checked_add(u64::from(le_u16(central, 30)))
        .ok_or_else(|| VerifyError::new("ZIP64 central extra range overflows"))?;
    for (range, start, end) in [
        (
            member.zip64.local_zip64_extra,
            local_extra_start,
            local_extra_end,
        ),
        (
            member.zip64.central_zip64_extra,
            central_extra_start,
            central_extra_end,
        ),
    ] {
        if let Some(range) = range {
            let header_start = range
                .offset
                .checked_sub(4)
                .ok_or_else(|| VerifyError::new("ZIP64 extra range underflows"))?;
            if header_start != start || checked_range_end(range, "ZIP64 extra data")? != end {
                return Err(VerifyError::new(
                    "ZIP64 extra does not exactly fill its header extra area",
                ));
            }
        } else if start != end {
            return Err(VerifyError::new(
                "unrepresented ZIP64 header extra bytes remain",
            ));
        }
    }

    match member.zip64.local_zip64_extra {
        None => {
            if member.zip64.local_value_shape != Zip64LocalValueShape::Absent {
                return Err(VerifyError::new(
                    "absent ZIP64 local extra has a non-absent shape",
                ));
            }
        }
        Some(range) => {
            if range.len != 16 || member.zip64.local_value_shape == Zip64LocalValueShape::Absent {
                return Err(VerifyError::new(
                    "ZIP64 local extra has an invalid semantic shape",
                ));
            }
            let data = range_bytes(source, range, "ZIP64 local extra data")?;
            let values = [le_u64(data, 0), le_u64(data, 8)];
            let valid = match member.zip64.local_value_shape {
                Zip64LocalValueShape::Absent => false,
                Zip64LocalValueShape::Exact => {
                    values == [member.declared_uncomp_size, member.declared_comp_size]
                }
                Zip64LocalValueShape::StreamingZeros => values == [0, 0],
                Zip64LocalValueShape::StreamingMaxima => values == [u64::MAX, u64::MAX],
            };
            if !valid {
                return Err(VerifyError::new(
                    "ZIP64 local value shape disagrees with source bytes",
                ));
            }
        }
    }

    match member.zip64.central_zip64_extra {
        None => {
            if member.zip64.central_presence_mask != 0
                || member.zip64.central_legacy_sentinel_mask != 0
                || u64::from(le_u32(central, 24)) != member.declared_uncomp_size
                || u64::from(le_u32(central, 20)) != member.declared_comp_size
                || u64::from(le_u32(central, 42)) != member.source_ranges.local_header.offset
            {
                return Err(VerifyError::new(
                    "absent ZIP64 central extra disagrees with legacy fields",
                ));
            }
        }
        Some(range) => {
            let mask = member.zip64.central_presence_mask;
            if mask == 0
                || mask > 0b111
                || range.len != u64::from(mask.count_ones()) * 8
                || mask & member.zip64.central_legacy_sentinel_mask
                    != member.zip64.central_legacy_sentinel_mask
            {
                return Err(VerifyError::new("ZIP64 central presence mask is invalid"));
            }
            let data = range_bytes(source, range, "ZIP64 central extra data")?;
            let legacy = [
                le_u32(central, 24),
                le_u32(central, 20),
                le_u32(central, 42),
            ];
            let resolved = [
                member.declared_uncomp_size,
                member.declared_comp_size,
                member.source_ranges.local_header.offset,
            ];
            let required_mask = legacy
                .iter()
                .enumerate()
                .fold(0_u8, |required, (index, value)| {
                    required | (u8::from(*value == u32::MAX) << index)
                });
            let mut matching_masks = 0_u8;
            let mut unique_mask = 0_u8;
            for candidate in 1_u8..8 {
                if candidate.count_ones() != mask.count_ones()
                    || candidate & required_mask != required_mask
                {
                    continue;
                }
                let mut candidate_values = legacy.map(u64::from);
                let mut cursor = 0_usize;
                let mut valid = true;
                for (index, value) in candidate_values.iter_mut().enumerate() {
                    if candidate & (1 << index) == 0 {
                        continue;
                    }
                    let encoded = le_u64(data, cursor);
                    cursor += 8;
                    if legacy[index] == u32::MAX {
                        *value = encoded;
                    } else if encoded != u64::from(legacy[index]) {
                        valid = false;
                        break;
                    }
                }
                if valid && candidate_values == resolved {
                    matching_masks = matching_masks.saturating_add(1);
                    unique_mask = candidate;
                }
            }
            if matching_masks != 1 || unique_mask != mask {
                return Err(VerifyError::new(
                    "ZIP64 central values lack one evidence-selected interpretation",
                ));
            }
        }
    }
    Ok(())
}

fn verify_zip64_descriptor(source: &[u8], member: &Zip64Member) -> Result<(), VerifyError> {
    const DESCRIPTOR: [u8; 4] = [0x50, 0x4b, 0x07, 0x08];
    match (
        member.zip64.descriptor_width,
        member.source_ranges.data_descriptor,
    ) {
        (None, None) if member.flags & 0x0008 == 0 => Ok(()),
        (Some(width), Some(range)) if member.flags & 0x0008 != 0 => {
            let expected_len = match width {
                Zip64DescriptorWidth::Zip32 => 16,
                Zip64DescriptorWidth::Zip64 => 24,
            };
            if range.len != expected_len {
                return Err(VerifyError::new(
                    "ZIP64 descriptor range has the wrong width",
                ));
            }
            let data = range_bytes(source, range, "ZIP64 data descriptor")?;
            if data[0..4] != DESCRIPTOR || le_u32(data, 4) != member.declared_crc {
                return Err(VerifyError::new(
                    "ZIP64 descriptor signature or CRC disagrees with evidence",
                ));
            }
            let (compressed, uncompressed) = match width {
                Zip64DescriptorWidth::Zip32 => {
                    (u64::from(le_u32(data, 8)), u64::from(le_u32(data, 12)))
                }
                Zip64DescriptorWidth::Zip64 => (le_u64(data, 8), le_u64(data, 16)),
            };
            if compressed != member.declared_comp_size
                || uncompressed != member.declared_uncomp_size
            {
                return Err(VerifyError::new(
                    "ZIP64 descriptor sizes disagree with evidence",
                ));
            }
            Ok(())
        }
        _ => Err(VerifyError::new(
            "ZIP64 descriptor evidence disagrees with flag bit 3",
        )),
    }
}

fn canonical_zip64_member_u32(legacy: u32, resolved: u64) -> bool {
    if resolved < u64::from(u32::MAX) {
        u64::from(legacy) == resolved
    } else {
        legacy == u32::MAX
    }
}

fn canonical_zip64_end_u16(legacy: u16, resolved: u64) -> bool {
    if resolved < u64::from(u16::MAX) {
        u64::from(legacy) == resolved || legacy == u16::MAX
    } else {
        legacy == u16::MAX
    }
}

fn canonical_zip64_end_u32(legacy: u32, resolved: u64) -> bool {
    if resolved < u64::from(u32::MAX) {
        u64::from(legacy) == resolved || legacy == u32::MAX
    } else {
        legacy == u32::MAX
    }
}

fn encode_zip64_layout(ir: &Zip64ArchiveIr) -> Result<Vec<u8>, VerifyError> {
    let covering = &ir.zip64_covering;
    let members = sorted_zip64_members(ir);
    let mut body = Vec::new();
    encode_range(&mut body, covering.local_records);
    encode_range(&mut body, covering.central_directory);
    encode_optional_range(&mut body, covering.zip64_eocd);
    encode_optional_range(&mut body, covering.zip64_locator);
    encode_range(&mut body, covering.eocd);
    encode_range(&mut body, covering.comment);
    push_u32(
        &mut body,
        u32::try_from(members.len())
            .map_err(|_| VerifyError::new("ZIP64 member count exceeds u32"))?,
    );
    for member in members {
        encode_zip64_layout_member(&mut body, member)?;
        push_u16(&mut body, member.zip64.local_version_needed);
        push_u16(&mut body, member.zip64.central_version_needed);
        body.push(member.zip64.central_presence_mask);
        body.push(member.zip64.central_legacy_sentinel_mask);
        body.push(member.zip64.local_legacy_sentinel_mask);
        body.push(match member.zip64.local_value_shape {
            Zip64LocalValueShape::Absent => 0,
            Zip64LocalValueShape::Exact => 1,
            Zip64LocalValueShape::StreamingZeros => 2,
            Zip64LocalValueShape::StreamingMaxima => 3,
        });
        encode_optional_range(&mut body, member.zip64.local_zip64_extra);
        encode_optional_range(&mut body, member.zip64.central_zip64_extra);
        body.push(match member.zip64.descriptor_width {
            None => 0,
            Some(Zip64DescriptorWidth::Zip32) => 1,
            Some(Zip64DescriptorWidth::Zip64) => 2,
        });
    }
    Ok(preimage(ZIP64_LAYOUT_LABEL, &body))
}

fn encode_zip64_layout_member(
    output: &mut Vec<u8>,
    member: &Zip64Member,
) -> Result<(), VerifyError> {
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
            .map_err(|_| VerifyError::new("ZIP64 extra-field count exceeds u32"))?,
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
                .map_err(|_| VerifyError::new("ZIP64 extra data length exceeds u16"))?,
        );
    }
    push_u32(
        output,
        u32::try_from(member.normalization_actions.len())
            .map_err(|_| VerifyError::new("ZIP64 normalization count exceeds u32"))?,
    );
    encode_normalization_actions(output, &member.normalization_actions);
    Ok(())
}

fn encode_zip64_content(ir: &Zip64ArchiveIr) -> Result<Vec<u8>, VerifyError> {
    let members = sorted_zip64_members(ir);
    let mut body = Vec::new();
    push_u32(
        &mut body,
        u32::try_from(members.len())
            .map_err(|_| VerifyError::new("ZIP64 member count exceeds u32"))?,
    );
    for member in members {
        push_bytes(&mut body, member.canonical_path.as_bytes())?;
        body.push(kind_tag(&member.kind));
        push_u64(
            &mut body,
            member
                .actual_uncomp_size
                .ok_or_else(|| VerifyError::new("ZIP64 verified member has no actual size"))?,
        );
        body.extend_from_slice(&decode_digest(
            member
                .content_sha256
                .as_deref()
                .ok_or_else(|| VerifyError::new("ZIP64 verified member has no content digest"))?,
            "ZIP64 member content digest",
        )?);
    }
    Ok(preimage(CONTENT_LABEL, &body))
}

fn sorted_zip64_members(ir: &Zip64ArchiveIr) -> Vec<&Zip64Member> {
    let mut members: Vec<_> = ir.members.iter().collect();
    members.sort_by(|left, right| {
        left.canonical_path
            .as_bytes()
            .cmp(right.canonical_path.as_bytes())
    });
    members
}

fn encode_optional_range(output: &mut Vec<u8>, range: Option<ByteRange>) {
    if let Some(range) = range {
        output.push(1);
        encode_range(output, range);
    } else {
        output.push(0);
    }
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

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
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

    #[test]
    fn portable_ustar_profile_vector_verifies_without_sealr() {
        let vector =
            include_bytes!("../../../crates/sealr/tests/conformance/tar-ustar-portable-v1.json");
        let canonical = &vector[..vector.len() - 1];
        assert_eq!(
            sha256_hex(canonical),
            "3c87c5ec4c1ad5377eb60ebb308e9e394aaf7a4133dddf5587829b4510af1700"
        );
        let value: serde_json::Value = serde_json::from_slice(canonical).unwrap();
        assert_eq!(value["schema"], "sealr.profile.tar.ustar-portable.v1");
    }

    const VECTORS: &[u8] =
        include_bytes!("../../../crates/sealr/tests/conformance/identity-v1.json");
    const ZIP64_VECTORS: &[u8] =
        include_bytes!("../../../crates/sealr/tests/conformance/zip64-identity-v1.json");
    const TAR_LAYOUT_VECTOR: &[u8] =
        include_bytes!("../../../crates/sealr/tests/conformance/tar-layout-v2.json");

    #[test]
    fn zip64_profile_digest_is_reconstructed_without_sealr() {
        assert_eq!(
            sha256_hex(&zip64_profile_canonical_bytes().unwrap()),
            "167a6d226bbe74e88189ec61c61df10ae5ed35c0294ad0cf3b5194d2f0bc23e2"
        );
    }

    #[test]
    fn committed_zip64_vectors_verify_independently() {
        let expected = VerificationSummary {
            profiles: 1,
            cases: 2,
            layout_roots: 2,
            content_roots: 2,
        };
        assert_eq!(
            verify_zip64_identity_vector_json(ZIP64_VECTORS).unwrap(),
            expected
        );
        assert_eq!(verify_manifest_json(ZIP64_VECTORS).unwrap(), expected);
    }

    #[test]
    fn zip64_covering_is_bound_to_source_records_and_semantic_extra_values() {
        let manifest: Zip64Manifest = serde_json::from_slice(ZIP64_VECTORS).unwrap();

        let case = &manifest.cases[0];
        let mut source = decode_hex(&case.source_bytes_hex, "test source").unwrap();
        source[0] ^= 1;
        assert!(verify_zip64_covering(&source, &case.archive_ir)
            .unwrap_err()
            .to_string()
            .contains("signature"));

        let mut source = decode_hex(&case.source_bytes_hex, "test source").unwrap();
        source[35] ^= 1;
        assert!(verify_zip64_covering(&source, &case.archive_ir)
            .unwrap_err()
            .to_string()
            .contains("value shape"));

        let case = &manifest.cases[1];
        let mut source = decode_hex(&case.source_bytes_hex, "test source").unwrap();
        source[0] ^= 1;
        assert!(verify_zip64_covering(&source, &case.archive_ir)
            .unwrap_err()
            .to_string()
            .contains("EOCD"));
    }

    const ZIP64_STRUCTURAL_SIGNATURES: [[u8; 4]; 6] = [
        [0x50, 0x4b, 0x06, 0x06],
        [0x50, 0x4b, 0x06, 0x07],
        [0x50, 0x4b, 0x05, 0x06],
        [0x50, 0x4b, 0x03, 0x04],
        [0x50, 0x4b, 0x01, 0x02],
        [0x50, 0x4b, 0x07, 0x08],
    ];

    const ZIP64_STREAM_SIGNATURES: [[u8; 4]; 3] = [
        [0x50, 0x4b, 0x03, 0x04],
        [0x50, 0x4b, 0x01, 0x02],
        [0x50, 0x4b, 0x07, 0x08],
    ];

    fn zip64_case_with_global_comment(comment: [u8; 4]) -> (Vec<u8>, Zip64ArchiveIr) {
        let manifest: Zip64Manifest = serde_json::from_slice(ZIP64_VECTORS).unwrap();
        let case = &manifest.cases[1];
        let mut source = decode_hex(&case.source_bytes_hex, "test source").unwrap();
        let eocd = usize::try_from(case.archive_ir.zip64_covering.eocd.offset).unwrap();
        source[eocd + 20..eocd + 22].copy_from_slice(&4_u16.to_le_bytes());
        source.extend_from_slice(&comment);
        let ir_value = serde_json::to_value(
            serde_json::from_slice::<serde_json::Value>(ZIP64_VECTORS).unwrap()["cases"][1]
                ["archive_ir"]
                .clone(),
        )
        .unwrap();
        let mut ir: Zip64ArchiveIr = serde_json::from_value(ir_value).unwrap();
        ir.zip64_covering.comment.len = 4;
        ir.source_digest.sha256 = sha256_hex(&source);
        (source, ir)
    }

    fn zip64_case_with_central_comment(comment: [u8; 4]) -> (Vec<u8>, Zip64ArchiveIr) {
        let manifest: Zip64Manifest = serde_json::from_slice(ZIP64_VECTORS).unwrap();
        let case = &manifest.cases[0];
        let mut source = decode_hex(&case.source_bytes_hex, "test source").unwrap();
        let central =
            usize::try_from(case.archive_ir.zip64_covering.central_directory.offset).unwrap();
        source[central + 32..central + 34].copy_from_slice(&4_u16.to_le_bytes());
        let old_eocd = usize::try_from(case.archive_ir.zip64_covering.eocd.offset).unwrap();
        source.splice(old_eocd..old_eocd, comment);
        let new_eocd = old_eocd + 4;
        source[new_eocd + 12..new_eocd + 16].copy_from_slice(&51_u32.to_le_bytes());
        let ir_value = serde_json::from_slice::<serde_json::Value>(ZIP64_VECTORS).unwrap()["cases"]
            [0]["archive_ir"]
            .clone();
        let mut ir: Zip64ArchiveIr = serde_json::from_value(ir_value).unwrap();
        ir.zip64_covering.central_directory.len = 51;
        ir.zip64_covering.eocd.offset += 4;
        ir.zip64_covering.comment.offset += 4;
        ir.members[0].source_ranges.central_header.len += 4;
        ir.source_digest.sha256 = sha256_hex(&source);
        (source, ir)
    }

    fn crc32_ieee(bytes: &[u8]) -> u32 {
        let mut crc = u32::MAX;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
            }
        }
        !crc
    }

    fn zip64_store_descriptor_case(payload: [u8; 4]) -> (Vec<u8>, Zip64ArchiveIr) {
        const LOCAL_HEADER_LEN: u64 = 51;
        const DESCRIPTOR_OFFSET: u64 = 55;
        const CENTRAL_OFFSET: u64 = 79;
        const EOCD_OFFSET: u64 = 126;
        const SOURCE_LEN: u64 = 148;

        let crc = crc32_ieee(&payload);
        let content_digest = sha256_hex(&payload);
        let mut source = Vec::new();
        source.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
        push_u16(&mut source, 45);
        push_u16(&mut source, 0x0008);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u32(&mut source, 0);
        push_u32(&mut source, u32::MAX);
        push_u32(&mut source, u32::MAX);
        push_u16(&mut source, 1);
        push_u16(&mut source, 20);
        source.push(b'a');
        push_u16(&mut source, 1);
        push_u16(&mut source, 16);
        push_u64(&mut source, 4);
        push_u64(&mut source, 4);
        assert_eq!(source.len(), usize::try_from(LOCAL_HEADER_LEN).unwrap());
        source.extend_from_slice(&payload);
        source.extend_from_slice(&[0x50, 0x4b, 0x07, 0x08]);
        push_u32(&mut source, crc);
        push_u64(&mut source, 4);
        push_u64(&mut source, 4);
        assert_eq!(source.len(), usize::try_from(CENTRAL_OFFSET).unwrap());
        source.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
        push_u16(&mut source, 45);
        push_u16(&mut source, 45);
        push_u16(&mut source, 0x0008);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u32(&mut source, crc);
        push_u32(&mut source, 4);
        push_u32(&mut source, 4);
        push_u16(&mut source, 1);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u32(&mut source, 0);
        push_u32(&mut source, 0);
        source.push(b'a');
        assert_eq!(source.len(), usize::try_from(EOCD_OFFSET).unwrap());
        source.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
        push_u16(&mut source, 0);
        push_u16(&mut source, 0);
        push_u16(&mut source, 1);
        push_u16(&mut source, 1);
        push_u32(&mut source, 47);
        push_u32(&mut source, u32::try_from(CENTRAL_OFFSET).unwrap());
        push_u16(&mut source, 0);
        assert_eq!(source.len(), usize::try_from(SOURCE_LEN).unwrap());

        let ir: Zip64ArchiveIr = serde_json::from_value(serde_json::json!({
            "schema": ZIP64_IR_SCHEMA,
            "profile": ZIP64_PROFILE_SCHEMA,
            "profile_digest": "167a6d226bbe74e88189ec61c61df10ae5ed35c0294ad0cf3b5194d2f0bc23e2",
            "source_digest": { "sha256": sha256_hex(&source) },
            "format": "zip64",
            "zip64_covering": {
                "local_records": { "offset": 0, "len": CENTRAL_OFFSET },
                "central_directory": { "offset": CENTRAL_OFFSET, "len": 47 },
                "zip64_eocd": null,
                "zip64_locator": null,
                "eocd": { "offset": EOCD_OFFSET, "len": 22 },
                "comment": { "offset": SOURCE_LEN, "len": 0 }
            },
            "members": [{
                "raw_name_bytes": [97],
                "decoded_name": "a",
                "canonical_path": "a",
                "components": ["a"],
                "kind": "file",
                "method": 0,
                "flags": 8,
                "declared_crc": crc,
                "declared_comp_size": 4,
                "declared_uncomp_size": 4,
                "source_ranges": {
                    "local_header": { "offset": 0, "len": LOCAL_HEADER_LEN },
                    "compressed_payload": { "offset": LOCAL_HEADER_LEN, "len": 4 },
                    "data_descriptor": { "offset": DESCRIPTOR_OFFSET, "len": 24 },
                    "central_header": { "offset": CENTRAL_OFFSET, "len": 47 }
                },
                "extra_fields": [{
                    "site": "local",
                    "id": 1,
                    "header_range": { "offset": 31, "len": 4 },
                    "data_range": { "offset": 35, "len": 16 },
                    "disposition": "semantic"
                }],
                "zip64": {
                    "local_version_needed": 45,
                    "central_version_needed": 45,
                    "central_presence_mask": 0,
                    "central_legacy_sentinel_mask": 0,
                    "local_legacy_sentinel_mask": 3,
                    "local_value_shape": "exact",
                    "local_zip64_extra": { "offset": 35, "len": 16 },
                    "central_zip64_extra": null,
                    "descriptor_width": "zip64"
                },
                "actual_uncomp_size": 4,
                "actual_crc": crc,
                "content_sha256": content_digest,
                "verification": { "status": "verified" },
                "normalization_actions": []
            }]
        }))
        .unwrap();
        (source, ir)
    }

    #[test]
    fn zip64_global_comment_rejects_every_production_structural_signature() {
        let (source, ir) = zip64_case_with_global_comment(*b"safe");
        verify_zip64_covering(&source, &ir).expect("safe global comment");
        for signature in ZIP64_STRUCTURAL_SIGNATURES {
            let (source, ir) = zip64_case_with_global_comment(signature);
            let error = verify_zip64_covering(&source, &ir).unwrap_err();
            assert!(
                error.to_string().contains("global EOCD comment"),
                "signature {signature:02x?}: {error}"
            );
        }
    }

    #[test]
    fn zip64_central_comment_rejects_every_production_structural_signature() {
        let (source, ir) = zip64_case_with_central_comment(*b"safe");
        verify_zip64_covering(&source, &ir).expect("safe central comment");
        for signature in ZIP64_STRUCTURAL_SIGNATURES {
            let (source, ir) = zip64_case_with_central_comment(signature);
            let error = verify_zip64_covering(&source, &ir).unwrap_err();
            assert!(
                error.to_string().contains("central member comment"),
                "signature {signature:02x?}: {error}"
            );
        }
    }

    #[test]
    fn zip64_store_descriptor_payload_rejects_every_stream_signature() {
        let (source, ir) = zip64_store_descriptor_case(*b"safe");
        validate_zip64_ir(&ir).expect("self-consistent stored member IR");
        verify_zip64_covering(&source, &ir).expect("safe stored descriptor payload");
        for signature in ZIP64_STREAM_SIGNATURES {
            let (source, ir) = zip64_store_descriptor_case(signature);
            validate_zip64_ir(&ir).expect("self-consistent stored member IR");
            let error = verify_zip64_covering(&source, &ir).unwrap_err();
            assert!(
                error.to_string().contains("stored descriptor payload"),
                "signature {signature:02x?}: {error}"
            );
        }
    }

    #[test]
    fn zip64_mutations_across_each_identity_family_are_rejected() {
        let mutations = [
            ("/schema", serde_json::json!("sealr.unknown")),
            ("/profile/id", serde_json::json!("sealr.profile.unknown")),
            ("/profile/digest/sha256", serde_json::json!("0".repeat(64))),
            ("/layout_encoding", serde_json::json!("sealrTreeV1")),
            ("/layout_label", serde_json::json!("sealr.tree.layout.v1")),
            ("/content_encoding", serde_json::json!("sealrTreeV3")),
            ("/content_label", serde_json::json!("sealr.tree.content.v2")),
            ("/cases/0/source_bytes_hex", serde_json::json!("00")),
            ("/cases/0/source/sha256", serde_json::json!("0".repeat(64))),
            (
                "/cases/0/archive_ir/schema",
                serde_json::json!("sealr.archive-ir.v1"),
            ),
            (
                "/cases/0/archive_ir/profile",
                serde_json::json!("sealr.profile.unknown"),
            ),
            (
                "/cases/0/archive_ir/profile_digest",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/cases/0/archive_ir/source_digest/sha256",
                serde_json::json!("0".repeat(64)),
            ),
            ("/cases/0/archive_ir/format", serde_json::json!("zip32")),
            (
                "/cases/0/archive_ir/zip64_covering/local_records/len",
                serde_json::json!(55),
            ),
            (
                "/cases/0/archive_ir/zip64_covering/central_directory/offset",
                serde_json::json!(57),
            ),
            (
                "/cases/0/archive_ir/zip64_covering/zip64_eocd",
                serde_json::json!({ "offset": 103, "len": 56 }),
            ),
            (
                "/cases/1/archive_ir/zip64_covering/zip64_locator/offset",
                serde_json::json!(57),
            ),
            (
                "/cases/0/archive_ir/zip64_covering/eocd/len",
                serde_json::json!(23),
            ),
            (
                "/cases/0/archive_ir/zip64_covering/comment/len",
                serde_json::json!(1),
            ),
            (
                "/cases/0/archive_ir/members/0/raw_name_bytes",
                serde_json::json!([98]),
            ),
            (
                "/cases/0/archive_ir/members/0/decoded_name",
                serde_json::json!("b"),
            ),
            (
                "/cases/0/archive_ir/members/0/canonical_path",
                serde_json::json!("b"),
            ),
            (
                "/cases/0/archive_ir/members/0/components",
                serde_json::json!(["b"]),
            ),
            (
                "/cases/0/archive_ir/members/0/kind",
                serde_json::json!("directory"),
            ),
            ("/cases/0/archive_ir/members/0/method", serde_json::json!(0)),
            ("/cases/0/archive_ir/members/0/flags", serde_json::json!(8)),
            (
                "/cases/0/archive_ir/members/0/declared_crc",
                serde_json::json!(3137623818_u32),
            ),
            (
                "/cases/0/archive_ir/members/0/declared_comp_size",
                serde_json::json!(6),
            ),
            (
                "/cases/0/archive_ir/members/0/declared_uncomp_size",
                serde_json::json!(17),
            ),
            (
                "/cases/0/archive_ir/members/0/source_ranges/local_header/len",
                serde_json::json!(50),
            ),
            (
                "/cases/0/archive_ir/members/0/source_ranges/compressed_payload/offset",
                serde_json::json!(50),
            ),
            (
                "/cases/0/archive_ir/members/0/source_ranges/data_descriptor",
                serde_json::json!({ "offset": 56, "len": 24 }),
            ),
            (
                "/cases/0/archive_ir/members/0/source_ranges/central_header/offset",
                serde_json::json!(57),
            ),
            (
                "/cases/0/archive_ir/members/0/extra_fields/0/id",
                serde_json::json!(2),
            ),
            (
                "/cases/0/archive_ir/members/0/extra_fields/0/header_range/offset",
                serde_json::json!(30),
            ),
            (
                "/cases/0/archive_ir/members/0/extra_fields/0/data_range/len",
                serde_json::json!(15),
            ),
            (
                "/cases/0/archive_ir/members/0/extra_fields/0/disposition",
                serde_json::json!("ignored"),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/local_version_needed",
                serde_json::json!(44),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/central_version_needed",
                serde_json::json!(44),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/central_presence_mask",
                serde_json::json!(1),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/central_legacy_sentinel_mask",
                serde_json::json!(1),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/local_legacy_sentinel_mask",
                serde_json::json!(2),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/local_value_shape",
                serde_json::json!("absent"),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/local_zip64_extra/offset",
                serde_json::json!(36),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/central_zip64_extra",
                serde_json::json!({ "offset": 103, "len": 8 }),
            ),
            (
                "/cases/0/archive_ir/members/0/zip64/descriptor_width",
                serde_json::json!("zip64"),
            ),
            (
                "/cases/0/archive_ir/members/0/actual_uncomp_size",
                serde_json::json!(17),
            ),
            (
                "/cases/0/archive_ir/members/0/actual_crc",
                serde_json::json!(3137623818_u32),
            ),
            (
                "/cases/0/archive_ir/members/0/content_sha256",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/cases/0/archive_ir/members/0/verification/status",
                serde_json::json!("pending"),
            ),
            (
                "/cases/0/archive_ir/members/0/normalization_actions",
                serde_json::json!([{ "action": "strip-directory-trailing-slash" }]),
            ),
            ("/cases/0/layout_preimage_hex", serde_json::json!("00")),
            (
                "/cases/0/layout_root/sealrTreeV3",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/cases/0/content_root/sealrTreeV1",
                serde_json::json!("0".repeat(64)),
            ),
        ];
        for (pointer, replacement) in mutations {
            let mut vector: serde_json::Value = serde_json::from_slice(ZIP64_VECTORS).unwrap();
            *vector
                .pointer_mut(pointer)
                .expect("known ZIP64 vector pointer") = replacement;
            assert!(
                verify_manifest_json(&serde_json::to_vec(&vector).unwrap()).is_err(),
                "ZIP64 mutation {pointer} must fail"
            );
        }
    }

    #[test]
    fn tar_layout_and_content_roots_verify_independently() {
        assert_eq!(
            verify_tar_layout_vector_json(TAR_LAYOUT_VECTOR).unwrap(),
            TarVerificationSummary { members: 3 }
        );
    }

    #[test]
    fn tar_covering_rejects_partial_trailing_record_padding() {
        let mut vector: TarLayoutVector = serde_json::from_slice(TAR_LAYOUT_VECTOR).unwrap();
        vector.covering.trailing_zeros.len = 1;
        let error = validate_tar_covering(&vector).unwrap_err();
        assert!(error.to_string().contains("complete 512-byte-block source"));
    }

    #[test]
    fn every_tar_layout_field_family_is_bound_or_structurally_checked() {
        let mutations = [
            ("/covering/member_records/len", serde_json::json!(2559)),
            ("/covering/terminator/offset", serde_json::json!(2559)),
            ("/covering/trailing_zeros/offset", serde_json::json!(3583)),
            ("/members/0/canonical_path", serde_json::json!("mission-x")),
            ("/members/0/kind", serde_json::json!("file")),
            ("/members/0/raw_name_bytes", serde_json::json!([109, 47])),
            ("/members/1/declared_uncomp_size", serde_json::json!(27)),
            ("/members/1/header/offset", serde_json::json!(511)),
            ("/members/1/header/len", serde_json::json!(511)),
            ("/members/1/payload/offset", serde_json::json!(1023)),
            ("/members/1/payload/len", serde_json::json!(27)),
            ("/members/1/padding/offset", serde_json::json!(1051)),
            ("/members/1/padding/len", serde_json::json!(483)),
            ("/members/1/mode", serde_json::json!(384)),
            ("/members/1/mtime", serde_json::json!(1788000001_u64)),
            ("/members/1/header_checksum", serde_json::json!(6294)),
            (
                "/members/1/header_sha256",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/members/1/normalization_actions",
                serde_json::json!([{ "action": "strip-directory-trailing-slash" }]),
            ),
            ("/members/1/actual_uncomp_size", serde_json::json!(27)),
            (
                "/members/1/content_sha256",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/layout_root/sealrTreeV2",
                serde_json::json!("0".repeat(64)),
            ),
            (
                "/content_root/sealrTreeV1",
                serde_json::json!("0".repeat(64)),
            ),
        ];
        for (pointer, replacement) in mutations {
            let mut vector: serde_json::Value = serde_json::from_slice(TAR_LAYOUT_VECTOR).unwrap();
            *vector.pointer_mut(pointer).expect("known vector pointer") = replacement;
            assert!(
                verify_tar_layout_vector_json(&serde_json::to_vec(&vector).unwrap()).is_err(),
                "mutation {pointer} must fail"
            );
        }
    }

    #[test]
    fn committed_vectors_verify_independently() {
        let summary = verify_manifest_json(VECTORS).expect("committed vectors");
        assert_eq!(summary.profiles, 4);
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
