//! Independent verification for live canonical view and receipt evidence.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::{decode_hex, preimage, sha256_hex, VerificationSummary, VerifyError};

pub const MAX_EVIDENCE_BYTES: usize = 16 * 1024 * 1024;
pub const EVIDENCE_CONFORMANCE_SCHEMA: &str = "sealr.evidence-conformance.v1";

const VIEW_SCHEMA: &str = "sealr.view.v2";
const RECEIPT_SCHEMA: &str = "sealr.receipt.v3";
const CANONICALIZATION: &str = "rfc8785";
const CONTENT_LABEL: &str = "sealr.tree.content.v1";
const MAX_CANONICAL_INTEGER: u64 = (1 << 53) - 1;
const MAX_MEMBERS: usize = 100_000;
const FILE: u8 = 1;
const DIRECTORY: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceVerificationSummary {
    pub view_digest: String,
    pub receipt_digest: String,
    pub source_digest: Option<String>,
    pub members: usize,
    pub content_root_verified: bool,
    pub source_checked: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceConformanceManifest {
    schema: String,
    cases: Vec<EvidenceConformanceCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceConformanceCase {
    id: String,
    view_bytes_hex: String,
    receipt_bytes_hex: String,
    #[serde(default)]
    source_bytes_hex: Option<String>,
    receipt_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceView {
    schema: String,
    source: SourceMeta,
    policy: PolicyMeta,
    interpretation: InterpretationStatus,
    admission: AdmissionStatus,
    verification: VerificationStatus,
    effect: EffectStatus,
    view_completeness: ViewCompleteness,
    verdict: String,
    wrote: bool,
    findings: Vec<Finding>,
    members: Vec<MemberView>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceReceipt {
    schema: String,
    verdict: String,
    wrote: bool,
    interpretation: InterpretationStatus,
    admission: AdmissionStatus,
    verification: VerificationStatus,
    effect: EffectStatus,
    view_completeness: ViewCompleteness,
    source: SourceDigest,
    source_snapshot: SnapshotKind,
    policy: PolicyMeta,
    identities: OutcomeIdentities,
    view_digest: DigestHex,
    canonicalization: String,
    view_schema: String,
    tool: ToolMeta,
    environment: EnvironmentMeta,
    materialization: MaterializationMeta,
    signed: bool,
    findings: Vec<Finding>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SourceMeta {
    path: Option<String>,
    digest: SourceDigest,
    magic: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
enum SourceDigest {
    Available(AvailableDigest),
    Unavailable(Unavailable),
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AvailableDigest {
    sha256: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Unavailable {
    status: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PolicyMeta {
    id: String,
    digest: DigestHex,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DigestHex {
    sha256: String,
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

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Finding {
    code: String,
    severity: Severity,
    #[serde(default)]
    member: Option<String>,
    detail: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Error,
    Deny,
    Warn,
    Info,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberView {
    path: String,
    kind: String,
    comp_bytes: u64,
    uncomp_bytes: u64,
    method: String,
    crc32: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeIdentities {
    source: SourceDigest,
    interpretation: InterpretationIdentity,
    layout: BTreeMap<String, String>,
    content: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InterpretationIdentity {
    id: String,
    digest: DigestHex,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SnapshotKind {
    MemoryOwned,
    MemoryBorrowed,
    PrivateFile,
    Unavailable,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolMeta {
    name: String,
    version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentMeta {
    os: String,
    arch: String,
    kernel_jail: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterializationMeta {
    schema: String,
    requested: bool,
    backend: String,
    stage_mode: String,
    stage_creation_primitive: String,
    member_resolution: String,
    durability: String,
    publication_primitive: String,
    outcome: String,
    cleanup: String,
    #[serde(default)]
    windows: Option<WindowsMaterializationEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsMaterializationEvidence {
    storage_policy: String,
    filesystem: Option<String>,
    device_scope: String,
    persistent_acls: Option<bool>,
    read_only: Option<bool>,
    stage_acl_policy: String,
    stage_acl: String,
}

#[derive(Debug)]
enum StrictValue {
    Null,
    Bool(bool),
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    String(String),
    Array(Vec<StrictValue>),
    Object(Vec<(String, StrictValue)>),
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one JSON value without duplicate object properties")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue::Bool(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue::Unsigned(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue::Signed(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E> {
        Ok(StrictValue::Float(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut values = Vec::new();
        while let Some((key, value)) = map.next_entry::<String, StrictValue>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate object property {key:?}"
                )));
            }
            values.push((key, value));
        }
        Ok(StrictValue::Object(values))
    }
}

pub fn verify_canonical_evidence(
    view_bytes: &[u8],
    receipt_bytes: &[u8],
    observed_source_sha256: Option<&str>,
) -> Result<EvidenceVerificationSummary, VerifyError> {
    verify_evidence_bound(view_bytes, "view")?;
    verify_evidence_bound(receipt_bytes, "receipt")?;
    verify_canonical_json(view_bytes, "view")?;
    verify_canonical_json(receipt_bytes, "receipt")?;

    let view: EvidenceView = serde_json::from_slice(view_bytes)
        .map_err(|error| VerifyError::new(format!("view schema: {error}")))?;
    let receipt: EvidenceReceipt = serde_json::from_slice(receipt_bytes)
        .map_err(|error| VerifyError::new(format!("receipt schema: {error}")))?;

    if view.schema != VIEW_SCHEMA {
        return Err(VerifyError::new(format!(
            "unsupported view schema {:?}",
            view.schema
        )));
    }
    if receipt.schema != RECEIPT_SCHEMA {
        return Err(VerifyError::new(format!(
            "unsupported receipt schema {:?}",
            receipt.schema
        )));
    }
    if receipt.canonicalization != CANONICALIZATION || receipt.view_schema != VIEW_SCHEMA {
        return Err(VerifyError::new(
            "receipt does not bind RFC 8785 and sealr.view.v2",
        ));
    }
    if receipt.signed {
        return Err(VerifyError::new(
            "sealr.receipt.v3 is unsigned evidence; signed=true is unsupported",
        ));
    }

    let view_digest = sha256_hex(view_bytes);
    verify_digest(&receipt.view_digest.sha256, "receipt view digest")?;
    if receipt.view_digest.sha256 != view_digest {
        return Err(VerifyError::new(
            "receipt view digest does not match the exact view bytes",
        ));
    }
    let receipt_digest = sha256_hex(receipt_bytes);

    verify_shared_claims(&view, &receipt)?;
    verify_source_claims(&view, &receipt, observed_source_sha256)?;
    verify_policy(&view.policy)?;
    verify_interpretation(&receipt.identities.interpretation)?;
    verify_root(&receipt.identities.layout, "layout root", false)?;
    let content_root = verify_content_root(&view, &receipt.identities.content)?;
    verify_outcome(&view, &receipt)?;
    verify_findings(&view.findings)?;
    verify_members(&view.members)?;
    verify_metadata(&view, &receipt)?;

    Ok(EvidenceVerificationSummary {
        view_digest,
        receipt_digest,
        source_digest: source_digest(&receipt.source).map(str::to_owned),
        members: view.members.len(),
        content_root_verified: content_root,
        source_checked: observed_source_sha256.is_some(),
    })
}

pub fn verify_evidence_conformance_json(bytes: &[u8]) -> Result<VerificationSummary, VerifyError> {
    verify_evidence_bound(bytes, "evidence conformance manifest")?;
    reject_duplicate_json_properties(bytes)?;
    let manifest: EvidenceConformanceManifest = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::new(format!("evidence conformance JSON: {error}")))?;
    if manifest.schema != EVIDENCE_CONFORMANCE_SCHEMA {
        return Err(VerifyError::new(format!(
            "unsupported evidence conformance schema {:?}",
            manifest.schema
        )));
    }
    if manifest.cases.is_empty() || manifest.cases.len() > 100 {
        return Err(VerifyError::new(
            "evidence conformance manifest must contain 1 through 100 cases",
        ));
    }

    let mut ids = HashSet::new();
    let mut content_roots = 0;
    for case in &manifest.cases {
        if case.id.is_empty() || !ids.insert(case.id.as_str()) {
            return Err(VerifyError::new(
                "evidence conformance case ids are empty or duplicate",
            ));
        }
        let view = decode_hex(&case.view_bytes_hex, "view_bytes_hex")?;
        let receipt = decode_hex(&case.receipt_bytes_hex, "receipt_bytes_hex")?;
        let source = case
            .source_bytes_hex
            .as_deref()
            .map(|value| decode_hex(value, "source_bytes_hex"))
            .transpose()?;
        let observed_source = source.as_deref().map(sha256_hex);
        let summary = verify_canonical_evidence(&view, &receipt, observed_source.as_deref())
            .map_err(|error| error.context(&format!("evidence case {}", case.id)))?;
        verify_digest(&case.receipt_digest, "expected receipt digest")?;
        if summary.receipt_digest != case.receipt_digest {
            return Err(VerifyError::new(format!(
                "evidence case {} receipt digest moved",
                case.id
            )));
        }
        content_roots += usize::from(summary.content_root_verified);
    }

    Ok(VerificationSummary {
        profiles: 0,
        cases: manifest.cases.len(),
        layout_roots: 0,
        content_roots,
    })
}

pub fn reject_duplicate_json_properties(bytes: &[u8]) -> Result<(), VerifyError> {
    let _: StrictValue = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::new(format!("JSON: {error}")))?;
    Ok(())
}

fn verify_evidence_bound(bytes: &[u8], label: &str) -> Result<(), VerifyError> {
    if bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(VerifyError::new(format!(
            "{label} exceeds the {MAX_EVIDENCE_BYTES}-byte limit"
        )));
    }
    if bytes.is_empty() {
        return Err(VerifyError::new(format!("{label} is empty")));
    }
    Ok(())
}

fn verify_canonical_json(bytes: &[u8], label: &str) -> Result<(), VerifyError> {
    let value: StrictValue = serde_json::from_slice(bytes)
        .map_err(|error| VerifyError::new(format!("{label} JSON: {error}")))?;
    let mut canonical = Vec::with_capacity(bytes.len());
    write_strict_value(&value, &mut canonical)?;
    if canonical != bytes {
        return Err(VerifyError::new(format!(
            "{label} bytes are not exact RFC 8785 canonical JSON"
        )));
    }
    Ok(())
}

fn write_strict_value(value: &StrictValue, out: &mut Vec<u8>) -> Result<(), VerifyError> {
    match value {
        StrictValue::Null => out.extend_from_slice(b"null"),
        StrictValue::Bool(true) => out.extend_from_slice(b"true"),
        StrictValue::Bool(false) => out.extend_from_slice(b"false"),
        StrictValue::Unsigned(value) => {
            if *value > MAX_CANONICAL_INTEGER {
                return Err(VerifyError::new(
                    "JSON integer exceeds the 2^53-1 canonical ceiling",
                ));
            }
            out.extend_from_slice(value.to_string().as_bytes());
        }
        StrictValue::Signed(value) => {
            if value.unsigned_abs() > MAX_CANONICAL_INTEGER {
                return Err(VerifyError::new(
                    "JSON integer exceeds the 2^53-1 canonical ceiling",
                ));
            }
            out.extend_from_slice(value.to_string().as_bytes());
        }
        StrictValue::Float(value) => {
            return Err(VerifyError::new(format!(
                "JSON number {value} is outside the integer-only evidence domain"
            )));
        }
        StrictValue::String(value) => write_string(value, out),
        StrictValue::Array(values) => {
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_strict_value(value, out)?;
            }
            out.push(b']');
        }
        StrictValue::Object(values) => {
            let mut values: Vec<_> = values.iter().collect();
            values.sort_by(|left, right| left.0.encode_utf16().cmp(right.0.encode_utf16()));
            out.push(b'{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write_strict_value(value, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{0008}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{000c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            control if (control as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", control as u32).as_bytes());
            }
            other => {
                let mut encoded = [0_u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn verify_shared_claims(view: &EvidenceView, receipt: &EvidenceReceipt) -> Result<(), VerifyError> {
    if view.source.digest != receipt.source
        || view.policy != receipt.policy
        || view.interpretation != receipt.interpretation
        || view.admission != receipt.admission
        || view.verification != receipt.verification
        || view.effect != receipt.effect
        || view.view_completeness != receipt.view_completeness
        || view.verdict != receipt.verdict
        || view.wrote != receipt.wrote
        || view.findings != receipt.findings
    {
        return Err(VerifyError::new(
            "view and receipt disagree on a shared evidence claim",
        ));
    }
    Ok(())
}

fn verify_source_claims(
    view: &EvidenceView,
    receipt: &EvidenceReceipt,
    observed_source_sha256: Option<&str>,
) -> Result<(), VerifyError> {
    if receipt.source != receipt.identities.source {
        return Err(VerifyError::new(
            "receipt source and outcome source identity disagree",
        ));
    }
    match &receipt.source {
        SourceDigest::Available(digest) => {
            verify_digest(&digest.sha256, "source digest")?;
            if matches!(receipt.source_snapshot, SnapshotKind::Unavailable) {
                return Err(VerifyError::new(
                    "available source identity carries an unavailable snapshot kind",
                ));
            }
        }
        SourceDigest::Unavailable(value) if value.status == "unavailable" => {
            if !matches!(receipt.source_snapshot, SnapshotKind::Unavailable) {
                return Err(VerifyError::new(
                    "unavailable source identity carries an available snapshot kind",
                ));
            }
        }
        SourceDigest::Unavailable(_) => {
            return Err(VerifyError::new(
                "unavailable source digest has an unknown status",
            ));
        }
    }
    if let Some(observed) = observed_source_sha256 {
        verify_digest(observed, "observed source digest")?;
        let claimed = source_digest(&receipt.source).ok_or_else(|| {
            VerifyError::new("source bytes were supplied for an unavailable source identity")
        })?;
        if claimed != observed {
            return Err(VerifyError::new(
                "source bytes do not match the claimed source digest",
            ));
        }
    }
    if view.source.magic.is_empty() {
        return Err(VerifyError::new("view source magic is empty"));
    }
    Ok(())
}

fn source_digest(source: &SourceDigest) -> Option<&str> {
    match source {
        SourceDigest::Available(digest) => Some(&digest.sha256),
        SourceDigest::Unavailable(_) => None,
    }
}

fn verify_policy(policy: &PolicyMeta) -> Result<(), VerifyError> {
    if policy.id.is_empty() {
        return Err(VerifyError::new("policy id is empty"));
    }
    verify_digest(&policy.digest.sha256, "policy digest")?;
    let known = match policy.id.as_str() {
        "sealr:policy/default/v1" => {
            Some("8298b205c981ed140a52ba555c0499712436969faf4ebc28d88d8d9e7024c340")
        }
        "sealr:policy/default/v2" => {
            Some("a02984fd88cb3fed1d60a339485eb0742da418681427dadcf699b4303f17d14a")
        }
        "sealr:policy/default/v3" => {
            Some("2cc96c7a2dd83617b3c80df7ec5ae7e4b92f74b0b391d70aa73f54f3f82068bd")
        }
        "sealr:policy/default/v4" => {
            Some("ecfca685a8f05c63fd12b7fd1c183a90a3fa705f801493fa4cb003cd57f1d601")
        }
        "sealr:policy/default/v5" => {
            Some("d1268c72f284f8f1b7ce5e06ada17ef7cbbbc5768a876ee93d103ad21e77d019")
        }
        "sealr:policy/default/v6" => {
            Some("aefc8a1baa113d7face30857ef64fe8f47c647fae863a72810b80380f8fd4178")
        }
        "sealr:policy/default/v7" => {
            Some("92d576984b718e8a02bc6044090f8e2b335dbd1abd136d53e5b02d0ffbd978ef")
        }
        "sealr:policy/default/v8" => {
            Some("d0cfdf4d40e3a88c8e80170494b23e91761802304265e41ce19cb616fa8a1c42")
        }
        "sealr:policy/default/v9" => {
            Some("c512895c09453f16c07ebeae94712099191b197ba9edaae384dba0fe7bb8b39e")
        }
        "sealr:policy/default/v10" => {
            Some("eada8150e14c0f05dcb25b6c9a90b87d3821fbb5f754192aceaea6d942e9f374")
        }
        "sealr:policy/default/v11" => {
            Some("afa0aeb04ceca00706b31dfd250216a87f2af0ada6e98d3815873de0d15172fc")
        }
        _ => None,
    };
    if let Some(expected) = known {
        if policy.digest.sha256 != expected {
            return Err(VerifyError::new(
                "known default policy id carries the wrong canonical digest",
            ));
        }
    }
    Ok(())
}

fn verify_interpretation(identity: &InterpretationIdentity) -> Result<(), VerifyError> {
    if identity.id.is_empty() {
        return Err(VerifyError::new("interpretation id is empty"));
    }
    verify_digest(&identity.digest.sha256, "interpretation digest")?;
    let expected = match identity.id.as_str() {
        "sealr.profile.7z.copy-portable.v1" => {
            "7b6604ad59b5aecf9ebdfa42d7d48d3df663813798992741dd6d74ea56f60b75"
        }
        "sealr.profile.tar-bzip2.ustar-portable.v1" => {
            "f6711c0c98cff6e3a2c6b266d159413ef891c202b4898b4e1665081dce0f29ee"
        }
        "sealr.profile.tar-gzip.gnu-longname-portable.v1" => {
            "622943e9629c4acc7cfeb446eb9f2d16bb245db589c1a200e885a9d69a02295a"
        }
        "sealr.profile.tar-gzip.pax-portable.v1" => {
            "6cc91b2b8563b5b070b44bf357a5c62e5d9dda0aedc374d7a08cd80da9c5434f"
        }
        "sealr.profile.tar-gzip.ustar-portable.v1" => {
            "914acdc0eab541483309a6838716fe837488ca80a1b7758383f28e47470925e1"
        }
        "sealr.profile.tar-xz.ustar-portable.v1" => {
            "16ec815ab3b2c3c5f877ec04e592d1dd1a6ec41f2c7d843dd7aa2bc6b50cfd05"
        }
        "sealr.profile.tar-zstd.ustar-portable.v1" => {
            "c7d2e708f2f5258eddfb99fbf13661bd2f671a2daa4a45bc1d9603d30d472ae7"
        }
        "sealr.profile.tar.gnu-longname-portable.v1" => {
            "08fe2698806da997bc42e7e13a45cbf412a4a7056dec39c62456202680b91fa4"
        }
        "sealr.profile.tar.pax-portable.v1" => {
            "db951f620acf54e67845144e138f9f16994439847a97601e20a424dfea7f4445"
        }
        "sealr.profile.tar.ustar-portable.v1" => {
            "3c87c5ec4c1ad5377eb60ebb308e9e394aaf7a4133dddf5587829b4510af1700"
        }
        "sealr.profile.zip.portable-utf8.v1" => {
            "acee86158d481adff96da0277a470ba753d6208ede74bc48586bb0134db5152e"
        }
        "sealr.profile.zip.strict-ascii.v1" => {
            "da3a2145d48decf8f8995ea01f1ddd0adb587f7f3544d4642bb8bb07b8f039f5"
        }
        "sealr.profile.zip.strict-ascii.v2" => {
            "384dceb8623a2b32d430034fefda2a9498439927285952c10a60c9f6caa51d45"
        }
        "sealr.profile.zip.wheel-utf8.v1" => {
            "757ead2782ab9f352fc1ff386733020e4cb114aa43aa1b756f6b7001d4c4cd5f"
        }
        "sealr.profile.zip64.strict-ascii.v1" => {
            "167a6d226bbe74e88189ec61c61df10ae5ed35c0294ad0cf3b5194d2f0bc23e2"
        }
        _ => return Err(VerifyError::new("interpretation profile is not registered")),
    };
    if identity.digest.sha256 != expected {
        return Err(VerifyError::new(
            "interpretation profile carries the wrong canonical digest",
        ));
    }
    Ok(())
}

fn verify_root<'a>(
    root: &'a BTreeMap<String, String>,
    label: &str,
    content_only: bool,
) -> Result<Option<&'a str>, VerifyError> {
    if root.len() != 1 {
        return Err(VerifyError::new(format!(
            "{label} must contain exactly one state"
        )));
    }
    let (kind, value) = root.iter().next().expect("one root entry");
    if kind == "status" {
        if value != "unavailable" {
            return Err(VerifyError::new(format!(
                "{label} has an unknown unavailable state"
            )));
        }
        return Ok(None);
    }
    let allowed = if content_only {
        kind == "sealrTreeV1"
    } else {
        matches!(
            kind.as_str(),
            "sealrTreeV1"
                | "sealrTreeV2"
                | "sealrTreeV3"
                | "sealrTreeV4"
                | "sealrTreeV5"
                | "sealrTreeV6"
                | "sealrTreeV7"
                | "sealrTreeV8"
                | "sealrTreeV9"
                | "sealrTreeV10"
                | "sealrTreeV11"
                | "sealrTreeV12"
        )
    };
    if !allowed {
        return Err(VerifyError::new(format!(
            "{label} uses an unknown tree encoding {kind:?}"
        )));
    }
    verify_digest(value, label)?;
    Ok(Some(value))
}

fn verify_content_root(
    view: &EvidenceView,
    root: &BTreeMap<String, String>,
) -> Result<bool, VerifyError> {
    let claimed = verify_root(root, "content root", true)?;
    if !matches!(view.verification, VerificationStatus::Complete) {
        if claimed.is_some() {
            return Err(VerifyError::new(
                "incomplete verification carries a content root",
            ));
        }
        return Ok(false);
    }
    let claimed = claimed
        .ok_or_else(|| VerifyError::new("complete verification does not carry a content root"))?;
    let calculated = calculate_content_root(&view.members)?;
    if calculated != claimed {
        return Err(VerifyError::new(
            "content root does not match the canonical member view",
        ));
    }
    Ok(true)
}

fn calculate_content_root(members: &[MemberView]) -> Result<String, VerifyError> {
    let mut members: Vec<_> = members.iter().collect();
    members.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let mut body = Vec::new();
    body.extend_from_slice(
        &u32::try_from(members.len())
            .map_err(|_| VerifyError::new("member count exceeds u32"))?
            .to_le_bytes(),
    );
    for member in members {
        push_bytes(&mut body, member.path.as_bytes())?;
        body.push(match member.kind.as_str() {
            "file" => FILE,
            "directory" => DIRECTORY,
            _ => return Err(VerifyError::new("member kind is not file or directory")),
        });
        body.extend_from_slice(&member.uncomp_bytes.to_le_bytes());
        body.extend_from_slice(&decode_digest(&member.sha256, "member SHA-256")?);
    }
    Ok(sha256_hex(&preimage(CONTENT_LABEL, &body)))
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), VerifyError> {
    out.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| VerifyError::new("member path exceeds u32"))?
            .to_le_bytes(),
    );
    out.extend_from_slice(value);
    Ok(())
}

fn verify_outcome(view: &EvidenceView, receipt: &EvidenceReceipt) -> Result<(), VerifyError> {
    if matches!(view.verification, VerificationStatus::Complete)
        && (!matches!(view.interpretation, InterpretationStatus::Interpreted)
            || !matches!(view.admission, AdmissionStatus::Admitted)
            || !matches!(view.view_completeness, ViewCompleteness::Complete))
    {
        return Err(VerifyError::new(
            "complete verification requires interpreted, admitted, complete evidence",
        ));
    }
    if matches!(view.effect, EffectStatus::Committed)
        && (!matches!(view.admission, AdmissionStatus::Admitted)
            || !matches!(view.verification, VerificationStatus::Complete))
    {
        return Err(VerifyError::new(
            "committed effect requires admission and complete verification",
        ));
    }
    if matches!(view.admission, AdmissionStatus::Denied)
        && !matches!(view.effect, EffectStatus::NotRequested)
    {
        return Err(VerifyError::new(
            "denied evidence carries an effect outcome",
        ));
    }
    if let VerificationStatus::Partial {
        verified_members,
        pending_members,
    } = view.verification
    {
        if verified_members.checked_add(pending_members).is_none()
            || pending_members == 0
            || usize::try_from(verified_members).ok() != Some(view.members.len())
        {
            return Err(VerifyError::new("invalid partial verification counts"));
        }
    }
    if matches!(view.view_completeness, ViewCompleteness::Complete)
        != matches!(view.verification, VerificationStatus::Complete)
    {
        return Err(VerifyError::new(
            "view completeness contradicts verification status",
        ));
    }
    if let ViewCompleteness::Partial { cause, .. } = &view.view_completeness {
        if cause.is_empty() || !view.findings.iter().any(|finding| finding.code == *cause) {
            return Err(VerifyError::new(
                "partial evidence cause is not present in findings",
            ));
        }
    }

    let expected_verdict = match (&view.admission, &view.verification, &view.effect) {
        (AdmissionStatus::Admitted, VerificationStatus::Complete, EffectStatus::Committed) => {
            ("allowed", true)
        }
        (AdmissionStatus::Admitted, VerificationStatus::Complete, EffectStatus::NotRequested) => {
            ("allowed", false)
        }
        _ => ("rejected", false),
    };
    if (view.verdict.as_str(), view.wrote) != expected_verdict {
        return Err(VerifyError::new(
            "compatibility verdict or wrote state contradicts the semantic axes",
        ));
    }
    if view.verdict == "rejected" && view.findings.is_empty() {
        return Err(VerifyError::new(
            "rejected evidence does not carry a finding",
        ));
    }

    let materialization_matches = matches!(
        (
            receipt.materialization.requested,
            receipt.materialization.outcome.as_str(),
            &view.effect,
        ),
        (false, "not-requested", EffectStatus::NotRequested)
            | (true, "not-started", EffectStatus::NotRequested)
            | (true, "committed", EffectStatus::Committed)
            | (
                true,
                "setup-failed" | "aborted" | "publication-failed",
                EffectStatus::Failed
            )
    );
    if !materialization_matches {
        return Err(VerifyError::new(
            "materialization evidence contradicts the effect status",
        ));
    }
    Ok(())
}

fn verify_findings(findings: &[Finding]) -> Result<(), VerifyError> {
    for finding in findings {
        if finding.code.is_empty() || finding.detail.is_empty() {
            return Err(VerifyError::new("finding code and detail must be nonempty"));
        }
        if finding.member.as_deref() == Some("") {
            return Err(VerifyError::new("finding member path is empty"));
        }
    }
    Ok(())
}

fn verify_members(members: &[MemberView]) -> Result<(), VerifyError> {
    if members.len() > MAX_MEMBERS {
        return Err(VerifyError::new(format!(
            "view exceeds the {MAX_MEMBERS}-member limit"
        )));
    }
    let mut paths = HashSet::new();
    let mut previous = None;
    for member in members {
        if member.path.is_empty() || !paths.insert(member.path.as_str()) {
            return Err(VerifyError::new("member paths are empty or duplicate"));
        }
        if previous.is_some_and(|path: &str| path.as_bytes() >= member.path.as_bytes()) {
            return Err(VerifyError::new(
                "members are not in canonical path-byte order",
            ));
        }
        previous = Some(member.path.as_str());
        if !matches!(member.kind.as_str(), "file" | "directory") {
            return Err(VerifyError::new("member kind is not file or directory"));
        }
        if member.method.is_empty() {
            return Err(VerifyError::new("member method is empty"));
        }
        if member.crc32.len() != 8
            || !member
                .crc32
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(VerifyError::new(
                "member CRC32 is not eight lowercase hexadecimal characters",
            ));
        }
        verify_digest(&member.sha256, "member SHA-256")?;
        let _ = member.comp_bytes;
    }
    Ok(())
}

fn verify_metadata(view: &EvidenceView, receipt: &EvidenceReceipt) -> Result<(), VerifyError> {
    if receipt.tool.name != "sealr" || receipt.tool.version.is_empty() {
        return Err(VerifyError::new("receipt tool identity is invalid"));
    }
    if receipt.environment.os.is_empty()
        || receipt.environment.arch.is_empty()
        || receipt.environment.kernel_jail.is_empty()
    {
        return Err(VerifyError::new(
            "receipt environment identity is incomplete",
        ));
    }
    if receipt.materialization.schema != "sealr.materialization.v2"
        || receipt.materialization.backend.is_empty()
        || receipt.materialization.stage_mode.is_empty()
        || receipt.materialization.stage_creation_primitive.is_empty()
        || receipt.materialization.member_resolution.is_empty()
        || receipt.materialization.durability.is_empty()
        || receipt.materialization.publication_primitive.is_empty()
        || receipt.materialization.cleanup.is_empty()
    {
        return Err(VerifyError::new("materialization evidence is incomplete"));
    }
    let materialization = &receipt.materialization;
    let common_fields = [
        materialization.backend.as_str(),
        materialization.stage_mode.as_str(),
        materialization.stage_creation_primitive.as_str(),
        materialization.member_resolution.as_str(),
        materialization.durability.as_str(),
        materialization.publication_primitive.as_str(),
    ];
    if !materialization.requested
        && (common_fields.iter().any(|field| *field != "none")
            || materialization.cleanup != "not-applicable"
            || materialization.windows.is_some())
    {
        return Err(VerifyError::new(
            "non-requested materialization carries execution metadata",
        ));
    }
    if materialization.requested && common_fields.contains(&"none") {
        return Err(VerifyError::new(
            "requested materialization omits execution metadata",
        ));
    }
    if materialization.windows.is_some()
        != (materialization.requested && receipt.environment.os == "windows")
    {
        return Err(VerifyError::new(
            "Windows materialization evidence contradicts the environment or request",
        ));
    }
    if let Some(windows) = &receipt.materialization.windows {
        if windows.storage_policy.is_empty()
            || windows.device_scope.is_empty()
            || windows.stage_acl_policy.is_empty()
            || windows.stage_acl.is_empty()
        {
            return Err(VerifyError::new(
                "Windows materialization evidence is incomplete",
            ));
        }
        let _ = (
            &windows.filesystem,
            windows.persistent_acls,
            windows.read_only,
        );
    }
    if view.source.path.as_deref() == Some("") {
        return Err(VerifyError::new("source path is empty"));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const COMMITTED_EVIDENCE: &[u8] =
        include_bytes!("../../../crates/sealr/tests/conformance/evidence-v1.json");

    fn canonical(value: &serde_json::Value) -> Vec<u8> {
        let loose = serde_json::to_vec(value).unwrap();
        let strict: StrictValue = serde_json::from_slice(&loose).unwrap();
        let mut bytes = Vec::new();
        write_strict_value(&strict, &mut bytes).unwrap();
        bytes
    }

    fn evidence_pair() -> (Vec<u8>, Vec<u8>) {
        let member_sha = sha256_hex(b"hello");
        let content = calculate_content_root(&[MemberView {
            path: "hello.txt".to_owned(),
            kind: "file".to_owned(),
            comp_bytes: 5,
            uncomp_bytes: 5,
            method: "store".to_owned(),
            crc32: "3610a686".to_owned(),
            sha256: member_sha.clone(),
        }])
        .unwrap();
        let source = sha256_hex(b"source");
        let policy = "8298b205c981ed140a52ba555c0499712436969faf4ebc28d88d8d9e7024c340";
        let interpretation = "da3a2145d48decf8f8995ea01f1ddd0adb587f7f3544d4642bb8bb07b8f039f5";
        let view = canonical(&json!({
            "schema": VIEW_SCHEMA,
            "source": {"path": "a.zip", "digest": {"sha256": source}, "magic": "zip"},
            "policy": {"id": "sealr:policy/default/v1", "digest": {"sha256": policy}},
            "interpretation": {"status": "interpreted"},
            "admission": {"status": "admitted"},
            "verification": {"status": "complete"},
            "effect": {"status": "not-requested"},
            "view_completeness": {"status": "complete"},
            "verdict": "allowed",
            "wrote": false,
            "findings": [],
            "members": [{
                "path": "hello.txt", "kind": "file", "comp_bytes": 5,
                "uncomp_bytes": 5, "method": "store", "crc32": "3610a686",
                "sha256": member_sha
            }]
        }));
        let view_digest = sha256_hex(&view);
        let receipt = canonical(&json!({
            "schema": RECEIPT_SCHEMA,
            "verdict": "allowed",
            "wrote": false,
            "interpretation": {"status": "interpreted"},
            "admission": {"status": "admitted"},
            "verification": {"status": "complete"},
            "effect": {"status": "not-requested"},
            "view_completeness": {"status": "complete"},
            "source": {"sha256": source},
            "source_snapshot": "private-file",
            "policy": {"id": "sealr:policy/default/v1", "digest": {"sha256": policy}},
            "identities": {
                "source": {"sha256": source},
                "interpretation": {"id": "sealr.profile.zip.strict-ascii.v1", "digest": {"sha256": interpretation}},
                "layout": {"sealrTreeV1": "b".repeat(64)},
                "content": {"sealrTreeV1": content}
            },
            "view_digest": {"sha256": view_digest},
            "canonicalization": CANONICALIZATION,
            "view_schema": VIEW_SCHEMA,
            "tool": {"name": "sealr", "version": "0.1.0-alpha.11"},
            "environment": {"os": "linux", "arch": "x86_64", "kernel_jail": "none"},
            "materialization": {
                "schema": "sealr.materialization.v2", "requested": false,
                "backend": "none", "stage_mode": "none",
                "stage_creation_primitive": "none", "member_resolution": "none",
                "durability": "none", "publication_primitive": "none",
                "outcome": "not-requested", "cleanup": "not-applicable"
            },
            "signed": false,
            "findings": []
        }));
        (view, receipt)
    }

    #[test]
    fn canonical_live_pair_verifies_independently() {
        let (view, receipt) = evidence_pair();
        let summary = verify_canonical_evidence(&view, &receipt, None).unwrap();
        assert_eq!(summary.members, 1);
        assert!(summary.content_root_verified);
        assert!(!summary.source_checked);
    }

    #[test]
    fn committed_evidence_vectors_verify_independently() {
        let summary = verify_evidence_conformance_json(COMMITTED_EVIDENCE).unwrap();
        assert_eq!(summary.cases, 5);
    }

    #[test]
    fn noncanonical_and_duplicate_json_are_rejected() {
        let (view, receipt) = evidence_pair();
        let mut whitespace = view.clone();
        whitespace.push(b'\n');
        assert!(verify_canonical_evidence(&whitespace, &receipt, None).is_err());

        let duplicate = br#"{"a":1,"a":2}"#;
        let error = verify_canonical_json(duplicate, "hostile").unwrap_err();
        assert!(error.to_string().contains("duplicate object property"));
    }

    #[test]
    fn every_shared_claim_and_digest_is_bound() {
        let (view, receipt) = evidence_pair();
        let mut changed: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        changed["effect"]["status"] = json!("failed");
        let changed = canonical(&changed);
        assert!(verify_canonical_evidence(&view, &changed, None).is_err());

        let mut changed: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        changed["view_digest"]["sha256"] = json!("0".repeat(64));
        let changed = canonical(&changed);
        assert!(verify_canonical_evidence(&view, &changed, None).is_err());
    }

    #[test]
    fn member_changes_move_the_independently_reconstructed_content_root() {
        let (view, receipt) = evidence_pair();
        let mut changed: serde_json::Value = serde_json::from_slice(&view).unwrap();
        changed["members"][0]["uncomp_bytes"] = json!(6);
        let changed = canonical(&changed);
        let mut changed_receipt: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        changed_receipt["view_digest"]["sha256"] = json!(sha256_hex(&changed));
        let changed_receipt = canonical(&changed_receipt);
        let error = verify_canonical_evidence(&changed, &changed_receipt, None).unwrap_err();
        assert!(error.to_string().contains("content root"));
    }

    #[test]
    fn observed_source_and_all_bound_claim_families_reject_tampering() {
        let (view, receipt) = evidence_pair();
        let wrong_source = sha256_hex(b"different source");
        assert!(verify_canonical_evidence(&view, &receipt, Some(&wrong_source)).is_err());

        for (pointer, value) in [
            ("/members/0/path", json!("changed.txt")),
            ("/members/0/kind", json!("directory")),
            ("/members/0/sha256", json!("0".repeat(64))),
        ] {
            let mut changed_view: serde_json::Value = serde_json::from_slice(&view).unwrap();
            *changed_view.pointer_mut(pointer).unwrap() = value;
            let changed_view = canonical(&changed_view);
            let mut changed_receipt: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
            changed_receipt["view_digest"]["sha256"] = json!(sha256_hex(&changed_view));
            let changed_receipt = canonical(&changed_receipt);
            assert!(verify_canonical_evidence(&changed_view, &changed_receipt, None).is_err());
        }

        for pointer in ["/policy/digest/sha256", "/verification/status", "/findings"] {
            let mut changed: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
            *changed.pointer_mut(pointer).unwrap() = match pointer {
                "/verification/status" => json!("partial"),
                "/findings" => json!([{"code": "changed", "detail": "changed"}]),
                _ => json!("0".repeat(64)),
            };
            assert!(verify_canonical_evidence(&view, &canonical(&changed), None).is_err());
        }
    }

    #[test]
    fn canonical_unknown_fields_are_rejected() {
        let (view, receipt) = evidence_pair();
        let mut changed: serde_json::Value = serde_json::from_slice(&view).unwrap();
        changed["unexpected"] = json!(true);
        let changed = canonical(&changed);
        let mut changed_receipt: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        changed_receipt["view_digest"]["sha256"] = json!(sha256_hex(&changed));
        assert!(verify_canonical_evidence(&changed, &canonical(&changed_receipt), None).is_err());
    }

    #[test]
    fn snapshot_and_materialization_metadata_drift_are_rejected() {
        let (view, receipt) = evidence_pair();

        let mut changed: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        changed["source_snapshot"] = json!("unavailable");
        assert!(verify_canonical_evidence(&view, &canonical(&changed), None).is_err());

        let mut changed: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        changed["materialization"]["backend"] = json!("cap-std");
        assert!(verify_canonical_evidence(&view, &canonical(&changed), None).is_err());

        let mut changed: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        changed["environment"]["os"] = json!("windows");
        changed["materialization"] = json!({
            "schema": "sealr.materialization.v2", "requested": true,
            "backend": "cap-std", "stage_mode": "private",
            "stage_creation_primitive": "private-directory",
            "member_resolution": "component-no-follow", "durability": "best-effort",
            "publication_primitive": "rename-no-replace", "outcome": "not-started",
            "cleanup": "not-created"
        });
        assert!(verify_canonical_evidence(&view, &canonical(&changed), None).is_err());
    }

    #[test]
    fn member_order_and_self_consistent_axis_or_policy_drift_are_rejected() {
        let manifest: EvidenceConformanceManifest =
            serde_json::from_slice(COMMITTED_EVIDENCE).unwrap();
        let case = &manifest.cases[0];
        let mut view: serde_json::Value =
            serde_json::from_slice(&decode_hex(&case.view_bytes_hex, "view").unwrap()).unwrap();
        view["members"].as_array_mut().unwrap().reverse();
        let changed_view = canonical(&view);
        let mut receipt: serde_json::Value =
            serde_json::from_slice(&decode_hex(&case.receipt_bytes_hex, "receipt").unwrap())
                .unwrap();
        receipt["view_digest"]["sha256"] = json!(sha256_hex(&changed_view));
        assert!(verify_canonical_evidence(&changed_view, &canonical(&receipt), None).is_err());

        let (view, receipt) = evidence_pair();
        let mut changed_view: serde_json::Value = serde_json::from_slice(&view).unwrap();
        let mut changed_receipt: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        changed_view["policy"]["digest"]["sha256"] = json!("0".repeat(64));
        changed_receipt["policy"]["digest"]["sha256"] = json!("0".repeat(64));
        let changed_view = canonical(&changed_view);
        changed_receipt["view_digest"]["sha256"] = json!(sha256_hex(&changed_view));
        assert!(
            verify_canonical_evidence(&changed_view, &canonical(&changed_receipt), None).is_err()
        );

        let mut changed_receipt: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        changed_receipt["identities"]["interpretation"]["digest"]["sha256"] = json!("0".repeat(64));
        assert!(verify_canonical_evidence(&view, &canonical(&changed_receipt), None).is_err());

        let mut changed_view: serde_json::Value = serde_json::from_slice(&view).unwrap();
        let mut changed_receipt: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        for changed in [&mut changed_view, &mut changed_receipt] {
            changed["verdict"] = json!("rejected");
            changed["findings"] = json!([{
                "code": "changed",
                "severity": "error",
                "detail": "changed"
            }]);
        }
        let changed_view = canonical(&changed_view);
        changed_receipt["view_digest"]["sha256"] = json!(sha256_hex(&changed_view));
        assert!(
            verify_canonical_evidence(&changed_view, &canonical(&changed_receipt), None).is_err()
        );
    }
}
