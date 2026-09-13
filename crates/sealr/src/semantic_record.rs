//! Crate-private semantic handoff for the explicit Linux supervisor.
//!
//! This bounded record codec carries validated plans and results for supervised
//! inspect, materialize, and later member-read operations. It remains
//! independent from worker protocol v1 and outside the supported public API.

use std::cmp::Ordering;
use std::fmt;

use sha2::{Digest, Sha256};

#[cfg(test)]
use crate::covering::audit_covering;
use crate::covering::{audit_covering_fallible, CoveringAuditError};
use crate::findings::{Finding, FindingCode, Severity};
use crate::ir::{
    ArchiveCovering, ArchiveEvidence, ArchiveIR, ByteRange, ExtraDisposition, ExtraFieldRecord,
    ExtraSite, IrMember, MemberEvidence, MemberKind, MemberSourceRanges, MemberVerification,
    NormalizationAction, ZipInterpretationProfile, ZipMemberEvidence,
};
use crate::jail::{
    jail_name_fallible, jail_name_fallible_for_profile, portable_name_violation, profile_case_fold,
    JailNameError, JailedName,
};
use crate::outcome::{
    AdmissionStatus, InterpretationStatus, SemanticAxes, SourceDigest, StoppingPhase,
    VerificationStatus, ViewCompleteness,
};
use crate::policy::{ratio_exceeds, ConsumerProfile, ResourceBudget, TargetModel};
use crate::snapshot::SourceSnapshot;
use crate::verified::{
    RetentionPlan, MAX_RETENTION_PATHS, MAX_RETENTION_PATH_BYTES, MAX_RETENTION_TOTAL_PATH_BYTES,
};

const MAGIC: [u8; 8] = *b"SEALRSEM";
const VERSION: u16 = 2;
const HEADER_BYTES: usize = 16;
const KIND_PLANNING: u8 = 1;
const KIND_COMPLETION: u8 = 2;
const KIND_RETAINED_CONTENT: u8 = 3;
const KIND_MEMBER_READ_REQUEST: u8 = 4;
const KIND_MEMBER_PREFIX_READ_REQUEST: u8 = 5;
const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_ISOLATED_READ_BYTES: u64 = 63 * 1024 * 1024;
const MAX_MEMBERS: usize = 65_535;
const MAX_FINDINGS: usize = 65_535;
const MAX_NAME_BYTES: usize = 65_535;
const MAX_COMPONENTS: usize = MAX_NAME_BYTES;
const MAX_EXTRA_FIELDS_PER_MEMBER: usize = 65_535;
const MAX_NORMALIZATIONS_PER_MEMBER: usize = MAX_NAME_BYTES;
const MAX_POLICY_ID_BYTES: usize = 256;
const MAX_FINDING_DETAIL_BYTES: usize = 1_024;
const MIN_MEMBER_BYTES: usize = 90;
const MIN_FINDING_BYTES: usize = 8;
const REQUEST_DOMAIN: &[u8] = b"sealr.semantic-request.experimental.v1\0";
const PLAN_DOMAIN: &[u8] = b"sealr.semantic-plan.experimental.v1\0";

mod executor;
mod member_read;
#[cfg(test)]
mod peak_live;
mod retained_content;
#[cfg(feature = "__internal-worker-lab")]
pub mod worker_lab;
#[cfg(any(target_os = "linux", feature = "__internal-worker-lab"))]
pub mod worker_runtime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestedEffect {
    Inspect,
    Materialize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RetentionBinding {
    None,
    Plan {
        paths: Vec<String>,
        max_member_bytes: u64,
        max_total_bytes: u64,
    },
}

impl RetentionBinding {
    fn from_plan(plan: Option<&RetentionPlan>) -> Self {
        match plan {
            None => Self::None,
            Some(plan) => Self::Plan {
                paths: plan.paths().map(str::to_owned).collect(),
                max_member_bytes: plan.max_member_bytes(),
                max_total_bytes: plan.max_total_bytes(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InvocationBinding {
    operation_id: [u8; 16],
    source_len: u64,
    source_sha256: [u8; 32],
    profile: ZipInterpretationProfile,
    profile_sha256: [u8; 32],
    policy_id: String,
    policy_sha256: [u8; 32],
    budget: ResourceBudget,
    target: TargetModel,
    consumer: ConsumerProfile,
    requested_effect: RequestedEffect,
    target_sha256: Option<[u8; 32]>,
    member_sync: bool,
    retention: RetentionBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TerminalPlanningAxes {
    interpretation: InterpretationStatus,
    admission: AdmissionStatus,
    verification: VerificationStatus,
    view_completeness: ViewCompleteness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PlanningDisposition {
    ReadyForVerification,
    Terminal(TerminalPlanningAxes),
}

#[derive(Clone, Debug)]
struct PlanningRecord {
    binding: InvocationBinding,
    disposition: PlanningDisposition,
    ir: Option<ArchiveIR>,
    findings: Vec<Finding>,
}

#[derive(Debug)]
struct ValidatedPlanningRecord {
    record: PlanningRecord,
    request_id: [u8; 32],
    plan_id: [u8; 32],
}

impl ValidatedPlanningRecord {
    fn setup_failure_axes(&self, finding: &Finding) -> Result<SemanticAxes, RecordError> {
        if !matches!(
            self.record.disposition,
            PlanningDisposition::ReadyForVerification
        ) {
            return Err(RecordError::new(
                RecordErrorKind::PhaseMismatch,
                0,
                "only a ready plan can merge a setup failure",
            ));
        }
        if self.record.binding.requested_effect != RequestedEffect::Materialize {
            return Err(RecordError::new(
                RecordErrorKind::PhaseMismatch,
                0,
                "inspect planning cannot merge a materialization setup failure",
            ));
        }
        if finding.severity != Severity::Error || !setup_failure_finding(finding.code) {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "setup failure is not an error authored by stage setup",
            ));
        }
        Ok(SemanticAxes::admitted_setup_failed(finding))
    }
}

fn setup_failure_finding(code: FindingCode) -> bool {
    matches!(
        code,
        FindingCode::MaterializeExists
            | FindingCode::MaterializeIo
            | FindingCode::MaterializeUnsafeParent
            | FindingCode::MaterializeUnsafeComponent
            | FindingCode::MaterializeUnsupported
            | FindingCode::MaterializeUnsupportedFilesystem
            | FindingCode::MaterializeUnsafeStage
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CompletionDisposition {
    Complete,
    Stopped {
        verified_members: u64,
        pending_members: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MemberCompletion {
    Pending,
    Verified {
        actual_uncomp_size: u64,
        actual_crc: u32,
        content_sha256: [u8; 32],
    },
    Failed {
        cause: FindingCode,
    },
}

#[derive(Clone, Debug)]
struct CompletionRecord {
    operation_id: [u8; 16],
    request_id: [u8; 32],
    plan_id: [u8; 32],
    disposition: CompletionDisposition,
    members: Vec<MemberCompletion>,
    findings: Vec<Finding>,
}

/// A canonically decoded, plan-bound worker proposal.
///
/// Correlation and semantic validation do not prove that the worker processed
/// file payloads. In particular, non-directory content digests remain
/// worker-supplied claims. This private type must not shape public semantic
/// state until a separate content-authority gate verifies the exact bytes.
#[must_use = "a bound completion proposal is not independently verified content authority"]
#[derive(Clone, Debug)]
struct BoundCompletionProposal {
    interpretation: InterpretationStatus,
    admission: AdmissionStatus,
    verification: VerificationStatus,
    view_completeness: ViewCompleteness,
    ir: ArchiveIR,
    findings: Vec<Finding>,
}

struct CompletionValidation<'plan> {
    interpretation: InterpretationStatus,
    admission: AdmissionStatus,
    verification: VerificationStatus,
    view_cause: Option<FindingCode>,
    ir: &'plan ArchiveIR,
}

#[cfg(test)]
thread_local! {
    static COMPLETION_IR_MATERIALIZATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static COMPLETION_ALLOCATION_FAIL_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static COMPLETION_ALLOCATION_BUDGET: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static ENCODER_RESERVATION_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
struct EncoderReservationFailureGuard {
    previous: bool,
}

#[cfg(test)]
impl Drop for EncoderReservationFailureGuard {
    fn drop(&mut self) {
        ENCODER_RESERVATION_FAILURE.with(|enabled| enabled.set(self.previous));
    }
}

#[cfg(test)]
fn fail_encoder_reservation() -> EncoderReservationFailureGuard {
    let previous = ENCODER_RESERVATION_FAILURE.with(|enabled| enabled.replace(true));
    EncoderReservationFailureGuard { previous }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordErrorKind {
    TooLarge,
    Truncated,
    TrailingBytes,
    InvalidMagic,
    UnsupportedVersion,
    UnexpectedKind,
    ReservedNonZero,
    LimitExceeded,
    InvalidEnum,
    InvalidUtf8,
    InvalidString,
    BindingMismatch,
    PhaseMismatch,
    NonCanonicalOrder,
    InvalidSemanticState,
    IntegerOverflow,
    AllocationFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecordError {
    kind: RecordErrorKind,
    offset: usize,
    detail: &'static str,
}

impl RecordError {
    const fn new(kind: RecordErrorKind, offset: usize, detail: &'static str) -> Self {
        Self {
            kind,
            offset,
            detail,
        }
    }
}

impl fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "semantic record error at byte {}: {}",
            self.offset, self.detail
        )
    }
}

impl std::error::Error for RecordError {}

struct Encoder {
    bytes: Vec<u8>,
    error: Option<RecordError>,
    limit: usize,
}

impl Encoder {
    fn new(kind: u8) -> Self {
        Self::new_with_limit(kind, MAX_RECORD_BYTES)
    }

    fn new_with_limit(kind: u8, limit: usize) -> Self {
        let mut encoder = Self {
            bytes: Vec::new(),
            error: None,
            limit,
        };
        encoder.append(&MAGIC);
        encoder.append(&VERSION.to_le_bytes());
        encoder.u8(kind);
        encoder.u8(0);
        encoder.append(&0_u32.to_le_bytes());
        encoder
    }

    fn body() -> Self {
        Self {
            bytes: Vec::new(),
            error: None,
            limit: MAX_RECORD_BYTES,
        }
    }

    fn finish(mut self) -> Result<Vec<u8>, RecordError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let body_len = self
            .bytes
            .len()
            .checked_sub(HEADER_BYTES)
            .and_then(|len| u32::try_from(len).ok())
            .ok_or_else(|| {
                RecordError::new(
                    RecordErrorKind::IntegerOverflow,
                    self.bytes.len(),
                    "record length cannot be represented",
                )
            })?;
        self.bytes[12..16].copy_from_slice(&body_len.to_le_bytes());
        Ok(self.bytes)
    }

    fn u8(&mut self, value: u8) {
        self.append(&[value]);
    }

    fn u16(&mut self, value: u16) {
        self.append(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.append(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.append(&value.to_le_bytes());
    }

    fn fixed<const N: usize>(&mut self, value: &[u8; N]) {
        self.append(value);
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), RecordError> {
        let len = u32::try_from(value.len()).map_err(|_| {
            RecordError::new(
                RecordErrorKind::LimitExceeded,
                self.bytes.len(),
                "byte string length exceeds the record integer limit",
            )
        })?;
        let Some(additional) = value.len().checked_add(std::mem::size_of::<u32>()) else {
            self.error = Some(RecordError::new(
                RecordErrorKind::IntegerOverflow,
                self.bytes.len(),
                "byte string field length calculation overflowed",
            ));
            return self.encoder_result();
        };
        if !self.prepare_append(additional) {
            return self.encoder_result();
        }
        self.bytes.extend_from_slice(&len.to_le_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<(), RecordError> {
        self.bytes(value.as_bytes())
    }

    fn append(&mut self, value: &[u8]) {
        if self.prepare_append(value.len()) {
            self.bytes.extend_from_slice(value);
        }
    }

    fn prepare_append(&mut self, additional: usize) -> bool {
        if self.error.is_some() {
            return false;
        }
        let Some(required) = self.bytes.len().checked_add(additional) else {
            self.error = Some(RecordError::new(
                RecordErrorKind::IntegerOverflow,
                self.bytes.len(),
                "record length calculation overflowed",
            ));
            return false;
        };
        if required > self.limit {
            self.error = Some(RecordError::new(
                RecordErrorKind::TooLarge,
                required,
                "record exceeds the hard byte limit",
            ));
            return false;
        }
        if required > self.bytes.capacity() {
            #[cfg(test)]
            if ENCODER_RESERVATION_FAILURE.with(std::cell::Cell::get) {
                self.error = Some(RecordError::new(
                    RecordErrorKind::AllocationFailed,
                    self.bytes.len(),
                    "bounded record allocation failed",
                ));
                return false;
            }
            let doubled = self.bytes.capacity().saturating_mul(2);
            let target = doubled.max(required).min(self.limit);
            if self
                .bytes
                .try_reserve_exact(target.saturating_sub(self.bytes.len()))
                .is_err()
            {
                self.error = Some(RecordError::new(
                    RecordErrorKind::AllocationFailed,
                    self.bytes.len(),
                    "bounded record allocation failed",
                ));
                return false;
            }
        }
        true
    }

    fn encoder_result(&self) -> Result<(), RecordError> {
        self.error.map_or(Ok(()), Err)
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn frame(input: &'a [u8], expected_kind: u8) -> Result<Self, RecordError> {
        if input.len() > MAX_RECORD_BYTES {
            return Err(RecordError::new(
                RecordErrorKind::TooLarge,
                input.len(),
                "record exceeds the hard byte limit",
            ));
        }
        if input.len() < HEADER_BYTES {
            return Err(RecordError::new(
                RecordErrorKind::Truncated,
                input.len(),
                "record header is truncated",
            ));
        }
        if input[..8] != MAGIC {
            return Err(RecordError::new(
                RecordErrorKind::InvalidMagic,
                0,
                "record magic is invalid",
            ));
        }
        let version = u16::from_le_bytes([input[8], input[9]]);
        if version != VERSION {
            return Err(RecordError::new(
                RecordErrorKind::UnsupportedVersion,
                8,
                "record version is unsupported",
            ));
        }
        if input[10] != expected_kind {
            return Err(RecordError::new(
                RecordErrorKind::UnexpectedKind,
                10,
                "record phase kind is unexpected",
            ));
        }
        if input[11] != 0 {
            return Err(RecordError::new(
                RecordErrorKind::ReservedNonZero,
                11,
                "record reserved byte is nonzero",
            ));
        }
        let body_len = u32::from_le_bytes([input[12], input[13], input[14], input[15]]) as usize;
        let total = HEADER_BYTES.checked_add(body_len).ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::IntegerOverflow,
                12,
                "record length overflows the host size",
            )
        })?;
        if total > input.len() {
            return Err(RecordError::new(
                RecordErrorKind::Truncated,
                input.len(),
                "record body is truncated",
            ));
        }
        if total < input.len() {
            return Err(RecordError::new(
                RecordErrorKind::TrailingBytes,
                total,
                "bytes follow the declared record body",
            ));
        }
        Ok(Self {
            input,
            pos: HEADER_BYTES,
        })
    }

    fn offset(&self) -> usize {
        self.pos
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], RecordError> {
        let end = self.pos.checked_add(len).ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::IntegerOverflow,
                self.pos,
                "field length overflows the host size",
            )
        })?;
        let value = self.input.get(self.pos..end).ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::Truncated,
                self.input.len(),
                "record field is truncated",
            )
        })?;
        self.pos = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RecordError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RecordError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, RecordError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, RecordError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], RecordError> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    fn bytes(&mut self, max: usize, detail: &'static str) -> Result<Vec<u8>, RecordError> {
        let source = self.bytes_ref(max, detail)?;
        let mut value = Vec::new();
        value.try_reserve_exact(source.len()).map_err(|_| {
            RecordError::new(
                RecordErrorKind::AllocationFailed,
                self.pos.saturating_sub(source.len()),
                "bounded byte allocation failed",
            )
        })?;
        value.extend_from_slice(source);
        Ok(value)
    }

    fn bytes_ref(&mut self, max: usize, detail: &'static str) -> Result<&'a [u8], RecordError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(RecordError::new(
                RecordErrorKind::LimitExceeded,
                self.pos.saturating_sub(4),
                detail,
            ));
        }
        self.take(len)
    }

    fn string(&mut self, max: usize, detail: &'static str) -> Result<String, RecordError> {
        let offset = self.pos;
        let bytes = self.bytes(max, detail)?;
        String::from_utf8(bytes).map_err(|_| {
            RecordError::new(
                RecordErrorKind::InvalidUtf8,
                offset,
                "record string is not valid UTF-8",
            )
        })
    }

    fn count(
        &mut self,
        max: usize,
        min_item_bytes: usize,
        detail: &'static str,
    ) -> Result<usize, RecordError> {
        let offset = self.pos;
        let count = self.u32()? as usize;
        if count > max || count > self.remaining() / min_item_bytes.max(1) {
            return Err(RecordError::new(
                RecordErrorKind::LimitExceeded,
                offset,
                detail,
            ));
        }
        Ok(count)
    }

    fn finish(self) -> Result<(), RecordError> {
        if self.pos == self.input.len() {
            Ok(())
        } else {
            Err(RecordError::new(
                RecordErrorKind::TrailingBytes,
                self.pos,
                "record body was not consumed exactly",
            ))
        }
    }
}

fn plan_id(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PLAN_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn request_id(binding: &InvocationBinding) -> Result<[u8; 32], RecordError> {
    let mut encoder = Encoder::body();
    encode_binding(&mut encoder, binding)?;
    encoder.encoder_result()?;
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DOMAIN);
    hasher.update(&encoder.bytes);
    Ok(hasher.finalize().into())
}

fn encode_binding(encoder: &mut Encoder, binding: &InvocationBinding) -> Result<(), RecordError> {
    validate_binding(binding)?;
    encode_binding_validated(encoder, binding)
}

fn encode_binding_validated(
    encoder: &mut Encoder,
    binding: &InvocationBinding,
) -> Result<(), RecordError> {
    encoder.fixed(&binding.operation_id);
    encoder.u64(binding.source_len);
    encoder.fixed(&binding.source_sha256);
    let profile_tag = match binding.profile {
        ZipInterpretationProfile::StrictAsciiV1 => 1,
        ZipInterpretationProfile::StrictAsciiV2 => 2,
        ZipInterpretationProfile::WheelUtf8V1 => 3,
        ZipInterpretationProfile::PortableUtf8V1 => 4,
        ZipInterpretationProfile::Zip64StrictAsciiV1 => {
            return Err(RecordError::new(
                RecordErrorKind::UnsupportedVersion,
                encoder.bytes.len(),
                "ZIP64 requires semantic-record v3",
            ));
        }
    };
    encoder.u8(profile_tag);
    encoder.fixed(&binding.profile_sha256);
    encoder.string(&binding.policy_id)?;
    encoder.fixed(&binding.policy_sha256);
    encoder.u8(0); // Compiled-controls identity is unavailable until its preimage is specified.
    encoder.u64(binding.budget.max_archive_bytes);
    encoder.u64(binding.budget.max_files);
    encoder.u64(binding.budget.max_member_bytes);
    encoder.u64(binding.budget.max_total_bytes);
    match binding.budget.max_ratio {
        None => {
            encoder.u8(0);
            encoder.u64(0);
        }
        Some(value) => {
            encoder.u8(1);
            encoder.u64(value);
        }
    }
    encoder.u32(binding.budget.max_path_depth);
    encoder.u64(binding.budget.max_metadata_bytes);
    encoder.u8(match binding.target {
        TargetModel::PortableV1 => 1,
    });
    encoder.u8(match binding.consumer {
        ConsumerProfile::GenericArchive => 1,
    });
    encoder.u8(match binding.requested_effect {
        RequestedEffect::Inspect => 0,
        RequestedEffect::Materialize => 1,
    });
    match binding.target_sha256 {
        None => encoder.u8(0),
        Some(digest) => {
            encoder.u8(1);
            encoder.fixed(&digest);
        }
    }
    encoder.u8(u8::from(binding.member_sync));
    match &binding.retention {
        RetentionBinding::None => encoder.u8(0),
        RetentionBinding::Plan {
            paths,
            max_member_bytes,
            max_total_bytes,
        } => {
            encoder.u8(1);
            encoder.u64(*max_member_bytes);
            encoder.u64(*max_total_bytes);
            encoder.u32(u32::try_from(paths.len()).map_err(|_| {
                RecordError::new(
                    RecordErrorKind::LimitExceeded,
                    encoder.bytes.len(),
                    "retention path count exceeds the record integer limit",
                )
            })?);
            for path in paths {
                encoder.string(path)?;
            }
        }
    }
    Ok(())
}

fn decode_binding(cursor: &mut Cursor<'_>) -> Result<InvocationBinding, RecordError> {
    let operation_id = cursor.fixed()?;
    let source_len = cursor.u64()?;
    let source_sha256 = cursor.fixed()?;
    let profile = match cursor.u8()? {
        1 => ZipInterpretationProfile::StrictAsciiV1,
        2 => ZipInterpretationProfile::StrictAsciiV2,
        3 => ZipInterpretationProfile::WheelUtf8V1,
        4 => ZipInterpretationProfile::PortableUtf8V1,
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidEnum,
                cursor.offset().saturating_sub(1),
                "interpretation profile tag is invalid",
            ));
        }
    };
    let profile_sha256 = cursor.fixed()?;
    let policy_id = cursor.string(
        MAX_POLICY_ID_BYTES,
        "policy identifier exceeds its byte limit",
    )?;
    let policy_sha256 = cursor.fixed()?;
    if cursor.u8()? != 0 {
        return Err(RecordError::new(
            RecordErrorKind::InvalidEnum,
            cursor.offset().saturating_sub(1),
            "compiled-controls identity must be unavailable",
        ));
    }
    let max_archive_bytes = cursor.u64()?;
    let max_files = cursor.u64()?;
    let max_member_bytes = cursor.u64()?;
    let max_total_bytes = cursor.u64()?;
    let max_ratio = match cursor.u8()? {
        0 => {
            if cursor.u64()? != 0 {
                return Err(RecordError::new(
                    RecordErrorKind::ReservedNonZero,
                    cursor.offset().saturating_sub(8),
                    "absent ratio has nonzero backing bytes",
                ));
            }
            None
        }
        1 => Some(cursor.u64()?),
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidEnum,
                cursor.offset().saturating_sub(1),
                "ratio presence tag is invalid",
            ));
        }
    };
    let max_path_depth = cursor.u32()?;
    let max_metadata_bytes = cursor.u64()?;
    let target = match cursor.u8()? {
        1 => TargetModel::PortableV1,
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidEnum,
                cursor.offset().saturating_sub(1),
                "target model tag is invalid",
            ));
        }
    };
    let consumer = match cursor.u8()? {
        1 => ConsumerProfile::GenericArchive,
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidEnum,
                cursor.offset().saturating_sub(1),
                "consumer profile tag is invalid",
            ));
        }
    };
    let requested_effect = match cursor.u8()? {
        0 => RequestedEffect::Inspect,
        1 => RequestedEffect::Materialize,
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidEnum,
                cursor.offset().saturating_sub(1),
                "requested effect tag is invalid",
            ));
        }
    };
    let target_sha256 = match cursor.u8()? {
        0 => None,
        1 => Some(cursor.fixed()?),
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidEnum,
                cursor.offset().saturating_sub(1),
                "target identity presence tag is invalid",
            ));
        }
    };
    let member_sync = decode_bool(cursor.u8()?, cursor.offset().saturating_sub(1))?;
    let retention = match cursor.u8()? {
        0 => RetentionBinding::None,
        1 => {
            let max_member_bytes = cursor.u64()?;
            let max_total_bytes = cursor.u64()?;
            let count = cursor.count(
                MAX_RETENTION_PATHS,
                4,
                "retention path count exceeds its bound or remaining bytes",
            )?;
            let mut paths = Vec::new();
            paths.try_reserve_exact(count).map_err(|_| {
                RecordError::new(
                    RecordErrorKind::AllocationFailed,
                    cursor.offset(),
                    "bounded retention-path allocation failed",
                )
            })?;
            for _ in 0..count {
                paths.push(cursor.string(
                    MAX_RETENTION_PATH_BYTES,
                    "retention path exceeds its byte limit",
                )?);
            }
            RetentionBinding::Plan {
                paths,
                max_member_bytes,
                max_total_bytes,
            }
        }
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidEnum,
                cursor.offset().saturating_sub(1),
                "retention presence tag is invalid",
            ));
        }
    };
    let binding = InvocationBinding {
        operation_id,
        source_len,
        source_sha256,
        profile,
        profile_sha256,
        policy_id,
        policy_sha256,
        budget: ResourceBudget {
            max_archive_bytes,
            max_derived_archive_bytes: 0,
            max_files,
            max_member_bytes,
            max_total_bytes,
            max_ratio,
            max_path_depth,
            max_metadata_bytes,
        },
        target,
        consumer,
        requested_effect,
        target_sha256,
        member_sync,
        retention,
    };
    validate_binding(&binding)?;
    Ok(binding)
}

fn validate_binding(binding: &InvocationBinding) -> Result<(), RecordError> {
    if binding.operation_id == [0; 16] {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "operation identifier must be nonzero",
        ));
    }
    if binding.source_len > binding.budget.max_archive_bytes {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "source length exceeds the bound resource budget",
        ));
    }
    if binding.policy_id.is_empty() || binding.policy_id.len() > MAX_POLICY_ID_BYTES {
        return Err(RecordError::new(
            RecordErrorKind::InvalidString,
            0,
            "policy identifier is empty or exceeds its byte limit",
        ));
    }
    let expected_profile = parse_hex_32(&binding.profile.digest()).ok_or_else(|| {
        RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "compiled profile digest is not a SHA-256 value",
        )
    })?;
    if binding.profile_sha256 != expected_profile {
        return Err(RecordError::new(
            RecordErrorKind::BindingMismatch,
            0,
            "profile digest does not match the selected profile",
        ));
    }
    match (binding.requested_effect, binding.target_sha256) {
        (RequestedEffect::Inspect, None) | (RequestedEffect::Materialize, Some(_)) => {}
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "target identity does not match the requested effect",
            ));
        }
    }
    if let RetentionBinding::Plan { paths, .. } = &binding.retention {
        if paths.len() > MAX_RETENTION_PATHS {
            return Err(RecordError::new(
                RecordErrorKind::LimitExceeded,
                0,
                "retention path count exceeds its bound",
            ));
        }
        let mut total = 0_usize;
        let mut previous: Option<&str> = None;
        for path in paths {
            if path.len() > MAX_RETENTION_PATH_BYTES {
                return Err(RecordError::new(
                    RecordErrorKind::LimitExceeded,
                    0,
                    "retention path exceeds its byte limit",
                ));
            }
            total = total.checked_add(path.len()).ok_or_else(|| {
                RecordError::new(
                    RecordErrorKind::IntegerOverflow,
                    0,
                    "retention path-byte total overflowed",
                )
            })?;
            if total > MAX_RETENTION_TOTAL_PATH_BYTES {
                return Err(RecordError::new(
                    RecordErrorKind::LimitExceeded,
                    0,
                    "retention path-byte total exceeds its bound",
                ));
            }
            if previous.is_some_and(|prior| prior >= path.as_str()) {
                return Err(RecordError::new(
                    RecordErrorKind::NonCanonicalOrder,
                    0,
                    "retention paths are not strictly byte-sorted",
                ));
            }
            let jailed = validate_jailed_name(path, u32::MAX, "retention path is not canonical")?;
            if !jailed.actions.is_empty() || !components_equal_path(&jailed.components, path) {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidString,
                    0,
                    "retention path is not canonical",
                ));
            }
            previous = Some(path);
        }
    }
    Ok(())
}

fn validate_jailed_name(
    raw: &str,
    max_depth: u32,
    invalid_detail: &'static str,
) -> Result<JailedName, RecordError> {
    jail_name_fallible(raw, max_depth).map_err(|error| match error {
        JailNameError::Invalid { .. } => {
            RecordError::new(RecordErrorKind::InvalidString, 0, invalid_detail)
        }
        JailNameError::AllocationFailed => RecordError::new(
            RecordErrorKind::AllocationFailed,
            0,
            "bounded path-validation allocation failed",
        ),
    })
}

fn components_equal_path(components: &[String], path: &str) -> bool {
    components.iter().map(String::as_str).eq(path.split('/'))
}

fn decode_bool(value: u8, offset: usize) -> Result<bool, RecordError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(RecordError::new(
            RecordErrorKind::InvalidEnum,
            offset,
            "Boolean tag is invalid",
        )),
    }
}

fn parse_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut result = [0_u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        result[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(result)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn hex_32(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for byte in value {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

fn digest_matches_hex(value: Option<&str>, expected: &[u8; 32]) -> bool {
    let Some(value) = value else {
        return false;
    };
    value.len() == 64
        && value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .zip(expected)
            .all(|(pair, byte)| {
                hex_nibble(pair[0]) == Some(byte >> 4) && hex_nibble(pair[1]) == Some(byte & 0x0f)
            })
}

fn encode_finding(encoder: &mut Encoder, finding: &Finding) -> Result<(), RecordError> {
    validate_finding(finding)?;
    encoder.u16(finding_code_tag(finding.code));
    encoder.u8(match finding.severity {
        Severity::Error => 0,
        Severity::Deny => 1,
        Severity::Warn => 2,
        Severity::Info => 3,
    });
    match &finding.member {
        None => encoder.u8(0),
        Some(member) => {
            encoder.u8(1);
            encoder.string(member)?;
        }
    }
    encoder.string(&finding.detail)
}

fn decode_finding(cursor: &mut Cursor<'_>) -> Result<Finding, RecordError> {
    let code = finding_code_from_tag(cursor.u16()?, cursor.offset().saturating_sub(2))?;
    let severity = match cursor.u8()? {
        0 => Severity::Error,
        1 => Severity::Deny,
        2 => Severity::Warn,
        3 => Severity::Info,
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidEnum,
                cursor.offset().saturating_sub(1),
                "finding severity tag is invalid",
            ));
        }
    };
    let member = match cursor.u8()? {
        0 => None,
        1 => Some(cursor.string(
            MAX_NAME_BYTES,
            "finding member label exceeds its byte limit",
        )?),
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidEnum,
                cursor.offset().saturating_sub(1),
                "finding member presence tag is invalid",
            ));
        }
    };
    let detail = cursor.string(
        MAX_FINDING_DETAIL_BYTES,
        "finding detail exceeds its byte limit",
    )?;
    let finding = Finding {
        code,
        severity,
        member,
        detail,
    };
    validate_finding(&finding)?;
    Ok(finding)
}

fn validate_finding(finding: &Finding) -> Result<(), RecordError> {
    if finding.detail.len() > MAX_FINDING_DETAIL_BYTES {
        return Err(RecordError::new(
            RecordErrorKind::LimitExceeded,
            0,
            "finding detail exceeds its byte limit",
        ));
    }
    if finding
        .member
        .as_ref()
        .is_some_and(|member| member.len() > MAX_NAME_BYTES)
    {
        return Err(RecordError::new(
            RecordErrorKind::LimitExceeded,
            0,
            "finding member label exceeds its byte limit",
        ));
    }
    Ok(())
}

fn finding_code_tag(code: FindingCode) -> u16 {
    match code {
        FindingCode::PathAbsolute => 0,
        FindingCode::PathDotDot => 1,
        FindingCode::PathEmpty => 2,
        FindingCode::PathAds => 3,
        FindingCode::PathReserved => 4,
        FindingCode::PathTrailing => 5,
        FindingCode::PathEscape => 6,
        FindingCode::PathDepth => 7,
        FindingCode::PathNul => 8,
        FindingCode::PathInvalidChar => 9,
        FindingCode::PathUnicode => 10,
        FindingCode::PathCaseFold => 11,
        FindingCode::PathConflict => 12,
        FindingCode::MaterializeExists => 13,
        FindingCode::MaterializeIo => 14,
        FindingCode::MaterializeCommit => 15,
        FindingCode::MaterializeUnsafeParent => 16,
        FindingCode::MaterializeUnsafeComponent => 17,
        FindingCode::MaterializeCleanup => 18,
        FindingCode::MaterializeUnsupported => 19,
        FindingCode::MaterializeUnsupportedFilesystem => 20,
        FindingCode::MaterializeUnsafeStage => 21,
        FindingCode::MaterializeAudit => 22,
        FindingCode::SourceIo => 23,
        FindingCode::QuotaArchive => 24,
        FindingCode::QuotaMetadata => 25,
        FindingCode::QuotaFiles => 26,
        FindingCode::QuotaMember => 27,
        FindingCode::QuotaTotal => 28,
        FindingCode::QuotaRatio => 29,
        FindingCode::QuotaOverflow => 30,
        FindingCode::QuotaDeclaredLie => 31,
        FindingCode::PolicyUnsupported => 32,
        FindingCode::ZipDiffA1Method => 33,
        FindingCode::ZipDiffA2Size => 34,
        FindingCode::ZipDiffA3Name => 35,
        FindingCode::ZipDiffA4Dir => 36,
        FindingCode::ZipDiffA5Crypt => 37,
        FindingCode::ZipDiffB1Dup => 38,
        FindingCode::ZipDiffB2Chars => 39,
        FindingCode::ZipDiffC1Stream => 40,
        FindingCode::ZipDiffC2Eocd => 41,
        FindingCode::ZipDiffC3Count => 42,
        FindingCode::ZipDiffC4Offset => 43,
        FindingCode::ZipDiffC5Zip64 => 44,
        FindingCode::ZipOverlap => 45,
        FindingCode::CoveringInconsistent => 46,
        FindingCode::ZipEncrypted => 47,
        FindingCode::ZipEncoding => 48,
        FindingCode::ZipExtra => 49,
        FindingCode::ZipFlags => 50,
        FindingCode::FormatUnsupported => 51,
        FindingCode::FormatMagic => 52,
        FindingCode::CodecDeflateInvalidStream => 53,
        FindingCode::CodecDeflateTrailingInput => 54,
        FindingCode::CrcMismatch => 55,
        FindingCode::MethodUnsupported => 56,
        FindingCode::TarChecksum => 57,
        FindingCode::TarDialect => 58,
        FindingCode::TarNumeric => 59,
        FindingCode::TarPadding => 60,
        FindingCode::TarTerminator => 61,
        FindingCode::TarTruncated => 62,
        FindingCode::TarType => 63,
        FindingCode::TarFeatureUnsupported => 64,
        FindingCode::GzipExtra => 65,
        FindingCode::QuotaDerived => 66,
        FindingCode::TarPaxRecord => 67,
        FindingCode::TarPaxState => 68,
        FindingCode::TarGnuLongName => 69,
        FindingCode::TarGnuState => 70,
        FindingCode::CodecZstdInvalidFrame => 71,
        FindingCode::CodecZstdTrailingInput => 72,
        FindingCode::CodecXzInvalidStream => 73,
        FindingCode::CodecXzTrailingInput => 74,
        FindingCode::CodecBzip2InvalidStream => 75,
        FindingCode::CodecBzip2TrailingInput => 76,
        FindingCode::SevenZInvalidStructure => 77,
        FindingCode::EvidenceCanonicalization => 78,
    }
}

fn finding_code_from_tag(tag: u16, offset: usize) -> Result<FindingCode, RecordError> {
    let code = match tag {
        0 => FindingCode::PathAbsolute,
        1 => FindingCode::PathDotDot,
        2 => FindingCode::PathEmpty,
        3 => FindingCode::PathAds,
        4 => FindingCode::PathReserved,
        5 => FindingCode::PathTrailing,
        6 => FindingCode::PathEscape,
        7 => FindingCode::PathDepth,
        8 => FindingCode::PathNul,
        9 => FindingCode::PathInvalidChar,
        10 => FindingCode::PathUnicode,
        11 => FindingCode::PathCaseFold,
        12 => FindingCode::PathConflict,
        13 => FindingCode::MaterializeExists,
        14 => FindingCode::MaterializeIo,
        15 => FindingCode::MaterializeCommit,
        16 => FindingCode::MaterializeUnsafeParent,
        17 => FindingCode::MaterializeUnsafeComponent,
        18 => FindingCode::MaterializeCleanup,
        19 => FindingCode::MaterializeUnsupported,
        20 => FindingCode::MaterializeUnsupportedFilesystem,
        21 => FindingCode::MaterializeUnsafeStage,
        22 => FindingCode::MaterializeAudit,
        23 => FindingCode::SourceIo,
        24 => FindingCode::QuotaArchive,
        25 => FindingCode::QuotaMetadata,
        26 => FindingCode::QuotaFiles,
        27 => FindingCode::QuotaMember,
        28 => FindingCode::QuotaTotal,
        29 => FindingCode::QuotaRatio,
        30 => FindingCode::QuotaOverflow,
        31 => FindingCode::QuotaDeclaredLie,
        32 => FindingCode::PolicyUnsupported,
        33 => FindingCode::ZipDiffA1Method,
        34 => FindingCode::ZipDiffA2Size,
        35 => FindingCode::ZipDiffA3Name,
        36 => FindingCode::ZipDiffA4Dir,
        37 => FindingCode::ZipDiffA5Crypt,
        38 => FindingCode::ZipDiffB1Dup,
        39 => FindingCode::ZipDiffB2Chars,
        40 => FindingCode::ZipDiffC1Stream,
        41 => FindingCode::ZipDiffC2Eocd,
        42 => FindingCode::ZipDiffC3Count,
        43 => FindingCode::ZipDiffC4Offset,
        44 => FindingCode::ZipDiffC5Zip64,
        45 => FindingCode::ZipOverlap,
        46 => FindingCode::CoveringInconsistent,
        47 => FindingCode::ZipEncrypted,
        48 => FindingCode::ZipEncoding,
        49 => FindingCode::ZipExtra,
        50 => FindingCode::ZipFlags,
        51 => FindingCode::FormatUnsupported,
        52 => FindingCode::FormatMagic,
        53 => FindingCode::CodecDeflateInvalidStream,
        54 => FindingCode::CodecDeflateTrailingInput,
        55 => FindingCode::CrcMismatch,
        56 => FindingCode::MethodUnsupported,
        57 => FindingCode::TarChecksum,
        58 => FindingCode::TarDialect,
        59 => FindingCode::TarNumeric,
        60 => FindingCode::TarPadding,
        61 => FindingCode::TarTerminator,
        62 => FindingCode::TarTruncated,
        63 => FindingCode::TarType,
        64 => FindingCode::TarFeatureUnsupported,
        65 => FindingCode::GzipExtra,
        66 => FindingCode::QuotaDerived,
        67 => FindingCode::TarPaxRecord,
        68 => FindingCode::TarPaxState,
        69 => FindingCode::TarGnuLongName,
        70 => FindingCode::TarGnuState,
        71 => FindingCode::CodecZstdInvalidFrame,
        72 => FindingCode::CodecZstdTrailingInput,
        73 => FindingCode::CodecXzInvalidStream,
        74 => FindingCode::CodecXzTrailingInput,
        75 => FindingCode::CodecBzip2InvalidStream,
        76 => FindingCode::CodecBzip2TrailingInput,
        77 => FindingCode::SevenZInvalidStructure,
        78 => FindingCode::EvidenceCanonicalization,
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidEnum,
                offset,
                "finding code tag is invalid",
            ));
        }
    };
    Ok(code)
}

fn encode_range(encoder: &mut Encoder, range: ByteRange) {
    encoder.u64(range.offset);
    encoder.u64(range.len);
}

fn decode_range(cursor: &mut Cursor<'_>) -> Result<ByteRange, RecordError> {
    Ok(ByteRange {
        offset: cursor.u64()?,
        len: cursor.u64()?,
    })
}

fn require_zip_covering(ir: &ArchiveIR) -> Result<&ArchiveCovering, RecordError> {
    ir.zip_covering().ok_or_else(|| {
        RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "semantic records require ZIP archive evidence",
        )
    })
}

fn require_zip_evidence(member: &IrMember) -> Result<&ZipMemberEvidence, RecordError> {
    member.zip_evidence().ok_or_else(|| {
        RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "semantic records require ZIP member evidence",
        )
    })
}

fn encode_ir(encoder: &mut Encoder, ir: &ArchiveIR) -> Result<(), RecordError> {
    let covering = require_zip_covering(ir)?;
    encode_range(encoder, covering.local_records);
    encode_range(encoder, covering.central_directory);
    encode_range(encoder, covering.eocd);
    encode_range(encoder, covering.comment);
    encoder.u32(u32::try_from(ir.members.len()).map_err(|_| {
        RecordError::new(
            RecordErrorKind::LimitExceeded,
            encoder.bytes.len(),
            "IR member count exceeds the record integer limit",
        )
    })?);
    for member in &ir.members {
        let zip = require_zip_evidence(member)?;
        encoder.bytes(&member.raw_name_bytes)?;
        encoder.string(&member.decoded_name)?;
        encoder.string(&member.canonical_path)?;
        encoder.u8(match member.kind {
            MemberKind::File => 0,
            MemberKind::Directory => 1,
        });
        encoder.u16(zip.method);
        encoder.u16(zip.flags);
        encoder.u8(zip.creator_system);
        encoder.u32(zip.external_attributes);
        encoder.u32(zip.declared_crc);
        encoder.u64(zip.declared_comp_size);
        encoder.u64(member.declared_uncomp_size);
        encode_range(encoder, zip.source_ranges.local_header);
        encode_range(encoder, zip.source_ranges.compressed_payload);
        match zip.source_ranges.data_descriptor {
            None => encoder.u8(0),
            Some(range) => {
                encoder.u8(1);
                encode_range(encoder, range);
            }
        }
        encode_range(encoder, zip.source_ranges.central_header);
        encoder.u32(u32::try_from(zip.extra_fields.len()).map_err(|_| {
            RecordError::new(
                RecordErrorKind::LimitExceeded,
                encoder.bytes.len(),
                "extra-field count exceeds the record integer limit",
            )
        })?);
        for extra in &zip.extra_fields {
            encoder.u8(match extra.site {
                ExtraSite::Central => 0,
                ExtraSite::Local => 1,
            });
            encoder.u16(extra.id);
            encode_range(encoder, extra.header_range);
            encode_range(encoder, extra.data_range);
            encoder.u8(match extra.disposition {
                ExtraDisposition::Semantic => 0,
                ExtraDisposition::Ignored => 1,
                ExtraDisposition::Denied => 2,
            });
        }
        encoder.u32(
            u32::try_from(member.normalization_actions.len()).map_err(|_| {
                RecordError::new(
                    RecordErrorKind::LimitExceeded,
                    encoder.bytes.len(),
                    "normalization count exceeds the record integer limit",
                )
            })?,
        );
        for action in &member.normalization_actions {
            match action {
                NormalizationAction::StripDirectoryTrailingSlash => encoder.u8(0),
                NormalizationAction::DropDotComponent { component_index } => {
                    encoder.u8(1);
                    encoder.u32(*component_index);
                }
            }
        }
    }
    Ok(())
}

fn decode_ir(
    cursor: &mut Cursor<'_>,
    binding: &InvocationBinding,
) -> Result<ArchiveIR, RecordError> {
    let covering = ArchiveCovering {
        local_records: decode_range(cursor)?,
        central_directory: decode_range(cursor)?,
        eocd: decode_range(cursor)?,
        comment: decode_range(cursor)?,
    };
    let max_members = usize::try_from(binding.budget.max_files)
        .unwrap_or(usize::MAX)
        .min(MAX_MEMBERS);
    let max_components = usize::try_from(binding.budget.max_path_depth)
        .unwrap_or(usize::MAX)
        .min(MAX_COMPONENTS);
    let count = cursor.count(
        max_members,
        MIN_MEMBER_BYTES,
        "IR member count exceeds its bound or remaining bytes",
    )?;
    let mut members = Vec::new();
    members.try_reserve_exact(count).map_err(|_| {
        RecordError::new(
            RecordErrorKind::AllocationFailed,
            cursor.offset(),
            "bounded IR member allocation failed",
        )
    })?;
    for _ in 0..count {
        let raw_name_bytes = cursor.bytes(
            MAX_NAME_BYTES,
            "raw member name exceeds the ZIP16 byte limit",
        )?;
        let decoded_name = cursor.string(
            MAX_NAME_BYTES,
            "decoded member name exceeds the ZIP16 byte limit",
        )?;
        let canonical_path = cursor.string(
            MAX_NAME_BYTES,
            "canonical member path exceeds the ZIP16 byte limit",
        )?;
        let kind = match cursor.u8()? {
            0 => MemberKind::File,
            1 => MemberKind::Directory,
            _ => {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidEnum,
                    cursor.offset().saturating_sub(1),
                    "member kind tag is invalid",
                ));
            }
        };
        let method = cursor.u16()?;
        let flags = cursor.u16()?;
        let creator_system = cursor.u8()?;
        let external_attributes = cursor.u32()?;
        let declared_crc = cursor.u32()?;
        let declared_comp_size = cursor.u64()?;
        let declared_uncomp_size = cursor.u64()?;
        let local_header = decode_range(cursor)?;
        let compressed_payload = decode_range(cursor)?;
        let data_descriptor = match cursor.u8()? {
            0 => None,
            1 => Some(decode_range(cursor)?),
            _ => {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidEnum,
                    cursor.offset().saturating_sub(1),
                    "data-descriptor presence tag is invalid",
                ));
            }
        };
        let central_header = decode_range(cursor)?;
        let extra_count = cursor.count(
            MAX_EXTRA_FIELDS_PER_MEMBER,
            36,
            "extra-field count exceeds its bound or remaining bytes",
        )?;
        let mut extra_fields = Vec::new();
        extra_fields.try_reserve_exact(extra_count).map_err(|_| {
            RecordError::new(
                RecordErrorKind::AllocationFailed,
                cursor.offset(),
                "bounded extra-field allocation failed",
            )
        })?;
        for _ in 0..extra_count {
            let site = match cursor.u8()? {
                0 => ExtraSite::Central,
                1 => ExtraSite::Local,
                _ => {
                    return Err(RecordError::new(
                        RecordErrorKind::InvalidEnum,
                        cursor.offset().saturating_sub(1),
                        "extra-field site tag is invalid",
                    ));
                }
            };
            let id = cursor.u16()?;
            let header_range = decode_range(cursor)?;
            let data_range = decode_range(cursor)?;
            let disposition = match cursor.u8()? {
                0 => ExtraDisposition::Semantic,
                1 => ExtraDisposition::Ignored,
                2 => ExtraDisposition::Denied,
                _ => {
                    return Err(RecordError::new(
                        RecordErrorKind::InvalidEnum,
                        cursor.offset().saturating_sub(1),
                        "extra-field disposition tag is invalid",
                    ));
                }
            };
            extra_fields.push(ExtraFieldRecord {
                site,
                id,
                header_range,
                data_range,
                disposition,
            });
        }
        let normalization_limit = decoded_name
            .split('/')
            .filter(|component| *component == ".")
            .count()
            .saturating_add(if matches!(kind, MemberKind::Directory) {
                1
            } else {
                0
            })
            .min(MAX_NORMALIZATIONS_PER_MEMBER);
        let normalization_count = cursor.count(
            normalization_limit,
            1,
            "normalization count exceeds its member-name-derived bound or remaining bytes",
        )?;
        let mut normalization_actions = Vec::new();
        normalization_actions
            .try_reserve_exact(normalization_count)
            .map_err(|_| {
                RecordError::new(
                    RecordErrorKind::AllocationFailed,
                    cursor.offset(),
                    "bounded normalization allocation failed",
                )
            })?;
        for _ in 0..normalization_count {
            normalization_actions.push(match cursor.u8()? {
                0 => NormalizationAction::StripDirectoryTrailingSlash,
                1 => NormalizationAction::DropDotComponent {
                    component_index: cursor.u32()?,
                },
                _ => {
                    return Err(RecordError::new(
                        RecordErrorKind::InvalidEnum,
                        cursor.offset().saturating_sub(1),
                        "normalization action tag is invalid",
                    ));
                }
            });
        }
        let components = split_components(&canonical_path, max_components, cursor.offset())?;
        members.push(IrMember {
            raw_name_bytes,
            decoded_name,
            canonical_path,
            components,
            kind,
            declared_uncomp_size,
            evidence: MemberEvidence::Zip(ZipMemberEvidence {
                method,
                flags,
                creator_system,
                external_attributes,
                declared_crc,
                declared_comp_size,
                source_ranges: MemberSourceRanges {
                    local_header,
                    compressed_payload,
                    data_descriptor,
                    central_header,
                },
                extra_fields,
            }),
            actual_uncomp_size: None,
            actual_crc: None,
            content_sha256: None,
            verification: MemberVerification::Pending,
            normalization_actions,
        });
    }
    Ok(ArchiveIR::with_covering(
        binding.profile,
        SourceDigest::available(try_record_hex_32(
            &binding.source_sha256,
            cursor.offset(),
            "bounded source-digest allocation failed",
        )?),
        covering,
        members,
    ))
}

fn split_components(
    path: &str,
    max_components: usize,
    offset: usize,
) -> Result<Vec<String>, RecordError> {
    let count = path.split('/').count();
    if count > max_components {
        return Err(RecordError::new(
            RecordErrorKind::LimitExceeded,
            offset,
            "canonical path component count exceeds the trusted depth bound",
        ));
    }
    let mut components = Vec::new();
    components.try_reserve_exact(count).map_err(|_| {
        RecordError::new(
            RecordErrorKind::AllocationFailed,
            offset,
            "bounded path-component allocation failed",
        )
    })?;
    for part in path.split('/') {
        let mut component = String::new();
        component.try_reserve_exact(part.len()).map_err(|_| {
            RecordError::new(
                RecordErrorKind::AllocationFailed,
                offset,
                "bounded path-component string allocation failed",
            )
        })?;
        component.push_str(part);
        components.push(component);
    }
    Ok(components)
}

fn validate_pending_ir(ir: &ArchiveIR, binding: &InvocationBinding) -> Result<(), RecordError> {
    if ir.schema() != crate::ir::ARCHIVE_IR_SCHEMA
        || ir.profile() != binding.profile.id()
        || ir.profile_digest() != binding.profile.digest()
        || !digest_matches_hex(ir.source_digest().sha256(), &binding.source_sha256)
    {
        return Err(RecordError::new(
            RecordErrorKind::BindingMismatch,
            0,
            "IR identity does not match the invocation binding",
        ));
    }
    if ir.members.len() > MAX_MEMBERS || ir.members.len() as u64 > binding.budget.max_files {
        return Err(RecordError::new(
            RecordErrorKind::LimitExceeded,
            0,
            "IR member count exceeds its bound",
        ));
    }
    let covering = require_zip_covering(ir)?;
    if !covering_is_exact(covering, binding.source_len)? {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "planning IR covering is not an exact structural partition",
        ));
    }
    if planning_metadata_bytes(ir)? > binding.budget.max_metadata_bytes {
        return Err(RecordError::new(
            RecordErrorKind::LimitExceeded,
            0,
            "IR metadata exceeds the invocation budget",
        ));
    }

    let mut paths = Vec::new();
    paths.try_reserve_exact(ir.members.len()).map_err(|_| {
        RecordError::new(
            RecordErrorKind::AllocationFailed,
            0,
            "bounded path-topology allocation failed",
        )
    })?;
    let mut declared_total = 0_u64;
    let mut local_intervals = Vec::new();
    local_intervals
        .try_reserve_exact(ir.members.len())
        .map_err(|_| {
            RecordError::new(
                RecordErrorKind::AllocationFailed,
                0,
                "bounded local-range allocation failed",
            )
        })?;
    let mut expected_central = covering.central_directory.offset;

    for member in &ir.members {
        let zip = require_zip_evidence(member)?;
        validate_pending_member(member, binding)?;
        let is_dir = matches!(member.kind, MemberKind::Directory);
        paths.push((member.canonical_path.as_str(), is_dir));

        if member.declared_uncomp_size > binding.budget.max_member_bytes {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "IR member exceeds the bound declared-size budget",
            ));
        }
        if binding.budget.max_ratio.is_some_and(|ratio| {
            ratio_exceeds(member.declared_uncomp_size, zip.declared_comp_size, ratio)
        }) {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "IR member exceeds the bound declared-ratio budget",
            ));
        }
        declared_total = declared_total
            .checked_add(member.declared_uncomp_size)
            .ok_or_else(|| {
                RecordError::new(
                    RecordErrorKind::IntegerOverflow,
                    0,
                    "IR declared-size aggregate overflowed",
                )
            })?;
        if declared_total > binding.budget.max_total_bytes {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "IR exceeds the bound aggregate declared-size budget",
            ));
        }

        let local_end = member_record_end(&zip.source_ranges)?;
        local_intervals.push((zip.source_ranges.local_header.offset, local_end));
        if zip.source_ranges.central_header.offset != expected_central {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "central headers do not preserve exact source order",
            ));
        }
        expected_central = checked_end(zip.source_ranges.central_header)?;
    }

    validate_path_topology(&mut paths, None)?;
    validate_path_topology(&mut paths, Some(binding.profile))?;

    if expected_central != checked_end(covering.central_directory)? {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "central headers do not exactly cover the central directory",
        ));
    }
    local_intervals.sort_unstable();
    let mut expected_local = covering.local_records.offset;
    for (start, end) in local_intervals {
        if start != expected_local || end < start {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "local records do not form an exact non-overlapping partition",
            ));
        }
        expected_local = end;
    }
    if expected_local != checked_end(covering.local_records)? {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "local records do not exactly cover the local-record region",
        ));
    }
    Ok(())
}

fn planning_metadata_bytes(ir: &ArchiveIR) -> Result<u64, RecordError> {
    let covering = require_zip_covering(ir)?;
    let mut metadata_bytes = covering
        .comment
        .len
        .checked_add(covering.central_directory.len)
        .ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::IntegerOverflow,
                0,
                "planning metadata aggregate overflowed u64",
            )
        })?;
    for member in &ir.members {
        let zip = require_zip_evidence(member)?;
        // The parser charges the complete variable-width local-header region:
        // the encoded name plus every local extra-field byte. Derive that value
        // from source geometry so a hostile record cannot understate the budget
        // by omitting semantic ExtraFieldRecord entries.
        let local_metadata_bytes = zip
            .source_ranges
            .local_header
            .len
            .checked_sub(30)
            .ok_or_else(|| {
                RecordError::new(
                    RecordErrorKind::InvalidSemanticState,
                    0,
                    "member local header is shorter than its ZIP32 fixed header",
                )
            })?;
        metadata_bytes = metadata_bytes
            .checked_add(local_metadata_bytes)
            .ok_or_else(|| {
                RecordError::new(
                    RecordErrorKind::IntegerOverflow,
                    0,
                    "planning metadata aggregate overflowed u64",
                )
            })?;
    }
    Ok(metadata_bytes)
}

fn validate_pending_member(
    member: &IrMember,
    binding: &InvocationBinding,
) -> Result<(), RecordError> {
    let zip = require_zip_evidence(member)?;
    if !matches!(member.verification, MemberVerification::Pending)
        || member.actual_uncomp_size.is_some()
        || member.actual_crc.is_some()
        || member.content_sha256.is_some()
    {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "planning IR contains measured or non-pending member state",
        ));
    }
    if member.raw_name_bytes.len() > MAX_NAME_BYTES
        || member.decoded_name.len() > MAX_NAME_BYTES
        || member.canonical_path.len() > MAX_NAME_BYTES
        || member.raw_name_bytes != member.decoded_name.as_bytes()
    {
        return Err(RecordError::new(
            RecordErrorKind::InvalidString,
            0,
            "member raw and decoded names are not the same bounded UTF-8 bytes",
        ));
    }
    let is_dir = matches!(member.kind, MemberKind::Directory);
    let jailed_input = if is_dir {
        member.decoded_name.strip_suffix('/').ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::InvalidString,
                0,
                "directory member name lacks its trailing slash",
            )
        })?
    } else {
        if member.decoded_name.ends_with('/') {
            return Err(RecordError::new(
                RecordErrorKind::InvalidString,
                0,
                "file member name has a directory trailing slash",
            ));
        }
        member.decoded_name.as_str()
    };
    let jailed = jail_name_fallible_for_profile(
        jailed_input,
        binding.budget.max_path_depth,
        binding.profile,
    )
    .map_err(|error| match error {
        JailNameError::Invalid { .. } => RecordError::new(
            RecordErrorKind::InvalidString,
            0,
            "member name does not satisfy the bound path grammar",
        ),
        JailNameError::AllocationFailed => RecordError::new(
            RecordErrorKind::AllocationFailed,
            0,
            "bounded path-validation allocation failed",
        ),
    })?;
    if jailed.components.len() > MAX_COMPONENTS
        || jailed.components != member.components
        || !components_equal_path(&jailed.components, &member.canonical_path)
    {
        return Err(RecordError::new(
            RecordErrorKind::InvalidString,
            0,
            "member components do not match canonical path derivation",
        ));
    }
    let action_offset = usize::from(is_dir);
    let actions_match = member.normalization_actions.len() == jailed.actions.len() + action_offset
        && (!is_dir
            || matches!(
                member.normalization_actions.first(),
                Some(NormalizationAction::StripDirectoryTrailingSlash)
            ))
        && member.normalization_actions[action_offset..] == jailed.actions;
    if !actions_match || member.normalization_actions.len() > MAX_NORMALIZATIONS_PER_MEMBER {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "member normalization actions do not match path derivation",
        ));
    }
    if zip.method != 0 && zip.method != 8 {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "admitted IR uses an unsupported compression method",
        ));
    }
    if (zip.flags & ((1 << 0) | (1 << 6) | (1 << 13))) != 0 {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "admitted IR carries encryption-related flags",
        ));
    }
    if binding.profile == ZipInterpretationProfile::StrictAsciiV2 && (zip.flags & !0x0008) != 0 {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "strict v2 IR carries a denied flag bit",
        ));
    }
    if binding.profile == ZipInterpretationProfile::WheelUtf8V1
        && ((zip.flags & !0x0800) != 0
            || (!member.raw_name_bytes.is_ascii() && (zip.flags & 0x0800) == 0)
            || member
                .normalization_actions
                .iter()
                .any(|action| matches!(action, NormalizationAction::DropDotComponent { .. })))
    {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "wheel UTF-8 IR violates its flag or normalization contract",
        ));
    }
    if binding.profile == ZipInterpretationProfile::PortableUtf8V1
        && ((zip.flags & !0x0808) != 0
            || (!member.raw_name_bytes.is_ascii() && (zip.flags & 0x0800) == 0)
            || portable_name_violation(&jailed).is_some())
    {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "portable UTF-8 IR violates its flag or canonical-name contract",
        ));
    }
    if is_dir
        && (zip.method != 0
            || zip.declared_comp_size != 0
            || member.declared_uncomp_size != 0
            || zip.declared_crc != 0)
    {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "directory member has nonempty content metadata",
        ));
    }
    validate_member_ranges(member, binding.source_len)?;
    validate_extra_fields(member, binding.profile)?;
    Ok(())
}

fn validate_member_ranges(member: &IrMember, source_len: u64) -> Result<(), RecordError> {
    let zip = require_zip_evidence(member)?;
    let ranges = &zip.source_ranges;
    for range in [
        ranges.local_header,
        ranges.compressed_payload,
        ranges.central_header,
    ] {
        if checked_end(range)? > source_len {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "member range exceeds the source length",
            ));
        }
    }
    let minimum_local_header_len = 30_u64
        .checked_add(u64::try_from(member.raw_name_bytes.len()).map_err(|_| {
            RecordError::new(
                RecordErrorKind::IntegerOverflow,
                0,
                "raw member-name length cannot be represented as u64",
            )
        })?)
        .ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::IntegerOverflow,
                0,
                "local-header minimum length overflowed",
            )
        })?;
    if ranges.local_header.len < minimum_local_header_len || ranges.central_header.len < 46 {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "member header range is shorter than its fixed fields and encoded name",
        ));
    }
    if checked_end(ranges.local_header)? != ranges.compressed_payload.offset
        || ranges.compressed_payload.len != zip.declared_comp_size
    {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "member payload does not exactly follow its local header",
        ));
    }
    let payload_end = checked_end(ranges.compressed_payload)?;
    match ranges.data_descriptor {
        None if (zip.flags & 0x0008) == 0 => {}
        Some(descriptor)
            if (zip.flags & 0x0008) != 0
                && descriptor.offset == payload_end
                && matches!(descriptor.len, 12 | 16)
                && checked_end(descriptor)? <= source_len => {}
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "data-descriptor range is incoherent with the member flags",
            ));
        }
    }
    Ok(())
}

fn validate_extra_fields(
    member: &IrMember,
    profile: ZipInterpretationProfile,
) -> Result<(), RecordError> {
    let zip = require_zip_evidence(member)?;
    if zip.extra_fields.len() > MAX_EXTRA_FIELDS_PER_MEMBER {
        return Err(RecordError::new(
            RecordErrorKind::LimitExceeded,
            0,
            "member extra-field count exceeds its bound",
        ));
    }
    if matches!(
        profile,
        ZipInterpretationProfile::StrictAsciiV2
            | ZipInterpretationProfile::PortableUtf8V1
            | ZipInterpretationProfile::WheelUtf8V1
    ) && !zip.extra_fields.is_empty()
    {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "strict v2 IR contains a denied extra field",
        ));
    }
    let mut ids = [0_u64; 1024];
    let mut site = ExtraSite::Central;
    let mut previous_end = None;
    let mut last_local_end = None;
    let mut central_extra_bytes = 0_u64;
    let mut local_extra_bytes = 0_u64;
    for extra in &zip.extra_fields {
        if site == ExtraSite::Local && extra.site == ExtraSite::Central {
            return Err(RecordError::new(
                RecordErrorKind::NonCanonicalOrder,
                0,
                "central extra field follows a local extra field",
            ));
        }
        if extra.site == ExtraSite::Local && site == ExtraSite::Central {
            site = ExtraSite::Local;
            previous_end = None;
            ids.fill(0);
        }
        let word = usize::from(extra.id) / u64::BITS as usize;
        let mask = 1_u64 << (u32::from(extra.id) % u64::BITS);
        if ids[word] & mask != 0 {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "member repeats an extra-field ID within one header",
            ));
        }
        ids[word] |= mask;
        if extra.header_range.len != 4
            || extra.data_range.len > u64::from(u16::MAX)
            || checked_end(extra.header_range)? != extra.data_range.offset
        {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "extra-field header and data ranges are incoherent",
            ));
        }
        if previous_end.is_some_and(|end| end != extra.header_range.offset) {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "extra fields do not form an exact on-wire sequence",
            ));
        }
        let owner = match extra.site {
            ExtraSite::Central => zip.source_ranges.central_header,
            ExtraSite::Local => zip.source_ranges.local_header,
        };
        let fixed_header_bytes = match extra.site {
            ExtraSite::Central => 46_u64,
            ExtraSite::Local => 30_u64,
        };
        let expected_first = owner
            .offset
            .checked_add(fixed_header_bytes)
            .and_then(|offset| offset.checked_add(member.raw_name_bytes.len() as u64))
            .ok_or_else(|| {
                RecordError::new(
                    RecordErrorKind::IntegerOverflow,
                    0,
                    "extra-field start calculation overflowed",
                )
            })?;
        if previous_end.is_none() && extra.header_range.offset != expected_first {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "first extra field does not follow the encoded member name",
            ));
        }
        if extra.header_range.offset < owner.offset
            || checked_end(extra.data_range)? > checked_end(owner)?
        {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "extra field escapes its owning ZIP header",
            ));
        }
        let encoded_len = 4_u64.checked_add(extra.data_range.len).ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::IntegerOverflow,
                0,
                "extra-field aggregate overflowed",
            )
        })?;
        let aggregate = match extra.site {
            ExtraSite::Central => &mut central_extra_bytes,
            ExtraSite::Local => &mut local_extra_bytes,
        };
        *aggregate = aggregate.checked_add(encoded_len).ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::IntegerOverflow,
                0,
                "extra-field aggregate overflowed",
            )
        })?;
        if *aggregate > u64::from(u16::MAX) {
            return Err(RecordError::new(
                RecordErrorKind::LimitExceeded,
                0,
                "extra-field aggregate exceeds the ZIP16 length limit",
            ));
        }
        if profile == ZipInterpretationProfile::StrictAsciiV1
            && (!matches!(extra.disposition, ExtraDisposition::Ignored)
                || matches!(extra.id, 0x0001 | 0x7075))
        {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "v1 admitted IR carries an invalid extra-field disposition",
            ));
        }
        previous_end = Some(checked_end(extra.data_range)?);
        if extra.site == ExtraSite::Local {
            last_local_end = previous_end;
        }
    }
    let local_extra_start = zip
        .source_ranges
        .local_header
        .offset
        .checked_add(30)
        .and_then(|offset| offset.checked_add(member.raw_name_bytes.len() as u64))
        .ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::IntegerOverflow,
                0,
                "local extra-field start calculation overflowed",
            )
        })?;
    if last_local_end.unwrap_or(local_extra_start) != checked_end(zip.source_ranges.local_header)? {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "local extra fields do not exactly cover the encoded local extra region",
        ));
    }
    Ok(())
}

fn covering_is_exact(covering: &ArchiveCovering, source_len: u64) -> Result<bool, RecordError> {
    for range in [
        covering.local_records,
        covering.central_directory,
        covering.eocd,
        covering.comment,
    ] {
        if checked_end(range)? > source_len {
            return Ok(false);
        }
    }
    Ok(covering.local_records.offset == 0
        && checked_end(covering.local_records)? == covering.central_directory.offset
        && checked_end(covering.central_directory)? == covering.eocd.offset
        && covering.eocd.len == 22
        && checked_end(covering.eocd)? == covering.comment.offset
        && checked_end(covering.comment)? == source_len)
}

fn checked_end(range: ByteRange) -> Result<u64, RecordError> {
    range.offset.checked_add(range.len).ok_or_else(|| {
        RecordError::new(
            RecordErrorKind::IntegerOverflow,
            0,
            "hostile range end overflowed u64",
        )
    })
}

fn member_record_end(ranges: &MemberSourceRanges) -> Result<u64, RecordError> {
    match ranges.data_descriptor {
        Some(range) => checked_end(range),
        None => checked_end(ranges.compressed_payload),
    }
}

fn validate_path_topology(
    paths: &mut [(&str, bool)],
    folded_profile: Option<ZipInterpretationProfile>,
) -> Result<(), RecordError> {
    paths.sort_unstable_by(|left, right| path_compare(left.0, right.0, folded_profile));
    for pair in paths.windows(2) {
        let path = pair[0].0;
        let candidate = pair[1].0;
        if path_equal(path, candidate, folded_profile) {
            let detail = if folded_profile.is_some() {
                "IR contains a case-fold collision"
            } else {
                "IR contains a duplicate canonical path"
            };
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                detail,
            ));
        }
    }
    for &(candidate, _) in paths.iter() {
        for (separator, _) in candidate.match_indices('/') {
            let ancestor = &candidate[..separator];
            let Ok(ancestor_index) =
                paths.binary_search_by(|entry| path_compare(entry.0, ancestor, folded_profile))
            else {
                continue;
            };
            if !paths[ancestor_index].1 {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidSemanticState,
                    0,
                    "IR contains a file-directory topology conflict",
                ));
            }
        }
    }
    Ok(())
}

fn path_compare(
    left: &str,
    right: &str,
    folded_profile: Option<ZipInterpretationProfile>,
) -> Ordering {
    folded_profile.map_or_else(
        || left.cmp(right),
        |profile| profile_case_fold(left, profile).cmp(&profile_case_fold(right, profile)),
    )
}

fn path_equal(left: &str, right: &str, folded_profile: Option<ZipInterpretationProfile>) -> bool {
    folded_profile.map_or_else(
        || left == right,
        |profile| profile_case_fold(left, profile) == profile_case_fold(right, profile),
    )
}

fn encode_planning(record: &PlanningRecord) -> Result<Vec<u8>, RecordError> {
    validate_planning(record)?;
    encode_planning_validated(record)
}

fn encode_planning_validated(record: &PlanningRecord) -> Result<Vec<u8>, RecordError> {
    let mut encoder = Encoder::new(KIND_PLANNING);
    encode_binding_validated(&mut encoder, &record.binding)?;
    encode_findings(&mut encoder, &record.findings)?;
    match &record.disposition {
        PlanningDisposition::ReadyForVerification => encoder.u8(0),
        PlanningDisposition::Terminal(axes) => {
            encoder.u8(1);
            encode_interpretation(&mut encoder, &axes.interpretation);
            encode_admission(&mut encoder, &axes.admission);
            encoder.u8(0); // Planning terminal verification is always StructureOnly.
            let (phase, _) = partial_parts(&axes.view_completeness)?;
            encode_stopping_phase(&mut encoder, phase);
            encoder.u32(
                u32::try_from(first_error_index(&record.findings)?).map_err(|_| {
                    RecordError::new(
                        RecordErrorKind::IntegerOverflow,
                        encoder.bytes.len(),
                        "planning cause index cannot be represented",
                    )
                })?,
            );
        }
    }
    match &record.ir {
        None => encoder.u8(0),
        Some(ir) => {
            encoder.u8(1);
            encode_ir(&mut encoder, ir)?;
        }
    }
    encoder.finish()
}

#[derive(Clone, Copy)]
enum PlanningExpectation<'a> {
    Exact(&'a InvocationBinding),
    Worker {
        operation_id: [u8; 16],
        requested_effect: RequestedEffect,
    },
}

fn decode_planning(
    input: &[u8],
    expected: &InvocationBinding,
    snapshot: &SourceSnapshot<'_>,
) -> Result<ValidatedPlanningRecord, RecordError> {
    decode_planning_for(input, PlanningExpectation::Exact(expected), snapshot)
}

fn decode_planning_for_worker(
    input: &[u8],
    operation_id: [u8; 16],
    requested_effect: RequestedEffect,
    snapshot: &SourceSnapshot<'_>,
) -> Result<ValidatedPlanningRecord, RecordError> {
    decode_planning_for(
        input,
        PlanningExpectation::Worker {
            operation_id,
            requested_effect,
        },
        snapshot,
    )
}

fn decode_planning_binding(input: &[u8]) -> Result<InvocationBinding, RecordError> {
    let mut cursor = Cursor::frame(input, KIND_PLANNING)?;
    decode_binding(&mut cursor)
}

fn decode_planning_for(
    input: &[u8],
    expectation: PlanningExpectation<'_>,
    snapshot: &SourceSnapshot<'_>,
) -> Result<ValidatedPlanningRecord, RecordError> {
    if let PlanningExpectation::Exact(expected) = expectation {
        validate_binding(expected)?;
    }
    let mut cursor = Cursor::frame(input, KIND_PLANNING)?;
    let binding = decode_binding(&mut cursor)?;
    match expectation {
        PlanningExpectation::Exact(expected) if &binding != expected => {
            return Err(RecordError::new(
                RecordErrorKind::BindingMismatch,
                HEADER_BYTES,
                "planning record does not match the expected invocation",
            ));
        }
        PlanningExpectation::Worker {
            operation_id,
            requested_effect,
        } if binding.operation_id != operation_id
            || binding.requested_effect != requested_effect =>
        {
            return Err(RecordError::new(
                RecordErrorKind::BindingMismatch,
                HEADER_BYTES,
                "planning record does not match the worker operation",
            ));
        }
        PlanningExpectation::Exact(_) | PlanningExpectation::Worker { .. } => {}
    }
    validate_snapshot_binding(snapshot, &binding)?;
    let findings = decode_findings(&mut cursor)?;
    let disposition = match cursor.u8()? {
        0 => PlanningDisposition::ReadyForVerification,
        1 => {
            let interpretation = decode_interpretation(&mut cursor)?;
            let admission = decode_admission(&mut cursor)?;
            if cursor.u8()? != 0 {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidEnum,
                    cursor.offset().saturating_sub(1),
                    "planning terminal verification tag is invalid",
                ));
            }
            let phase = decode_stopping_phase(&mut cursor)?;
            let cause_index = cursor.u32()? as usize;
            let first_error = first_error_index(&findings)?;
            if cause_index != first_error {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidSemanticState,
                    cursor.offset().saturating_sub(4),
                    "planning cause does not name the first error finding",
                ));
            }
            PlanningDisposition::Terminal(TerminalPlanningAxes {
                interpretation,
                admission,
                verification: VerificationStatus::StructureOnly,
                view_completeness: ViewCompleteness::Partial {
                    phase,
                    cause: try_record_string(
                        findings[cause_index].code.as_str(),
                        cursor.offset(),
                        "bounded planning cause allocation failed",
                    )?,
                },
            })
        }
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidEnum,
                cursor.offset().saturating_sub(1),
                "planning disposition tag is invalid",
            ));
        }
    };
    let ir = match cursor.u8()? {
        0 => None,
        1 => Some(decode_ir(&mut cursor, &binding)?),
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidEnum,
                cursor.offset().saturating_sub(1),
                "planning IR presence tag is invalid",
            ));
        }
    };
    cursor.finish()?;
    let record = PlanningRecord {
        binding,
        disposition,
        ir,
        findings,
    };
    validate_planning(&record)?;
    validate_planning_against_snapshot(&record, snapshot)?;
    let canonical = encode_planning_validated(&record)?;
    if canonical != input {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "decoded planning record did not re-encode identically",
        ));
    }
    Ok(ValidatedPlanningRecord {
        request_id: request_id(&record.binding)?,
        plan_id: plan_id(input),
        record,
    })
}

fn validate_snapshot_binding(
    snapshot: &SourceSnapshot<'_>,
    binding: &InvocationBinding,
) -> Result<(), RecordError> {
    if snapshot.len() != binding.source_len
        || !digest_matches_hex(snapshot.digest().sha256(), &binding.source_sha256)
    {
        return Err(RecordError::new(
            RecordErrorKind::BindingMismatch,
            0,
            "supervisor snapshot does not match the invocation binding",
        ));
    }
    Ok(())
}

fn validate_planning_against_snapshot(
    record: &PlanningRecord,
    snapshot: &SourceSnapshot<'_>,
) -> Result<(), RecordError> {
    match (&record.disposition, &record.ir) {
        (PlanningDisposition::ReadyForVerification, Some(ir)) => {
            audit_covering_fallible(snapshot, ir).map_err(|error| match error {
                CoveringAuditError::AllocationFailed => RecordError::new(
                    RecordErrorKind::AllocationFailed,
                    0,
                    "bounded covering-audit allocation failed",
                ),
                CoveringAuditError::Inconsistent { .. } => RecordError::new(
                    RecordErrorKind::InvalidSemanticState,
                    0,
                    "ready planning IR does not reproduce the supervisor snapshot covering",
                ),
            })?;
            validate_ready_ir_source_fields(snapshot, ir)?;
        }
        (PlanningDisposition::Terminal(_), Some(ir)) => {
            let reproduced = match audit_covering_fallible(snapshot, ir) {
                Ok(()) => {
                    return Err(RecordError::new(
                        RecordErrorKind::InvalidSemanticState,
                        0,
                        "covering terminal does not reproduce a supervisor-observed failure",
                    ));
                }
                Err(CoveringAuditError::AllocationFailed) => {
                    return Err(RecordError::new(
                        RecordErrorKind::AllocationFailed,
                        0,
                        "bounded covering-audit allocation failed",
                    ));
                }
                Err(CoveringAuditError::Inconsistent { detail, member }) => (detail, member),
            };
            let cause = &record.findings[first_error_index(&record.findings)?];
            if cause.code != FindingCode::CoveringInconsistent
                || cause.severity != Severity::Error
                || cause.detail != reproduced.0
                || cause.member.as_deref() != reproduced.1
            {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidSemanticState,
                    0,
                    "covering terminal cause does not match supervisor reproduction",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_ready_ir_source_fields(
    snapshot: &SourceSnapshot<'_>,
    ir: &ArchiveIR,
) -> Result<(), RecordError> {
    validate_ready_ir_global_source_fields(snapshot, ir)?;
    for member in &ir.members {
        let zip = require_zip_evidence(member)?;
        let mut local_fixed = [0_u8; 30];
        read_snapshot_exact(
            snapshot,
            zip.source_ranges.local_header.offset,
            &mut local_fixed,
            "cannot read the claimed local header from the supervisor snapshot",
        )?;
        let local_flags = source_u16(&local_fixed, 6);
        let local_method = source_u16(&local_fixed, 8);
        let local_crc = source_u32(&local_fixed, 14);
        let local_comp_size = u64::from(source_u32(&local_fixed, 18));
        let local_uncomp_size = u64::from(source_u32(&local_fixed, 22));
        let local_name_len = u64::from(u16::from_le_bytes([local_fixed[26], local_fixed[27]]));
        let local_extra_len = u64::from(u16::from_le_bytes([local_fixed[28], local_fixed[29]]));
        let expected_local_len = 30_u64
            .checked_add(local_name_len)
            .and_then(|value| value.checked_add(local_extra_len))
            .ok_or_else(|| {
                RecordError::new(
                    RecordErrorKind::IntegerOverflow,
                    0,
                    "source local-header length calculation overflowed",
                )
            })?;
        if zip.source_ranges.local_header.len != expected_local_len
            || local_name_len != member.raw_name_bytes.len() as u64
        {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "planning local-header geometry does not match the supervisor snapshot",
            ));
        }
        if local_flags != zip.flags || local_method != zip.method {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "planning local-header method or flags do not match the supervisor snapshot",
            ));
        }
        let uses_descriptor = (zip.flags & 0x0008) != 0;
        let local_values_match = if uses_descriptor {
            (local_crc == 0 || local_crc == zip.declared_crc)
                && (local_comp_size == 0 || local_comp_size == zip.declared_comp_size)
                && (local_uncomp_size == 0 || local_uncomp_size == member.declared_uncomp_size)
        } else {
            local_crc == zip.declared_crc
                && local_comp_size == zip.declared_comp_size
                && local_uncomp_size == member.declared_uncomp_size
        };
        if !local_values_match {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "planning local-header CRC or sizes do not match the supervisor snapshot",
            ));
        }
        let local_name_offset = zip
            .source_ranges
            .local_header
            .offset
            .checked_add(30)
            .ok_or_else(|| {
                RecordError::new(
                    RecordErrorKind::IntegerOverflow,
                    0,
                    "source local-name offset calculation overflowed",
                )
            })?;
        validate_source_name(snapshot, local_name_offset, &member.raw_name_bytes)?;
        let local_extra_offset =
            local_name_offset
                .checked_add(local_name_len)
                .ok_or_else(|| {
                    RecordError::new(
                        RecordErrorKind::IntegerOverflow,
                        0,
                        "source local-extra offset calculation overflowed",
                    )
                })?;
        validate_source_extra_fields(
            snapshot,
            member,
            ExtraSite::Local,
            local_extra_offset,
            local_extra_len,
        )?;

        let mut central_fixed = [0_u8; 46];
        read_snapshot_exact(
            snapshot,
            zip.source_ranges.central_header.offset,
            &mut central_fixed,
            "cannot read the claimed central header from the supervisor snapshot",
        )?;
        let central_version_made_by = source_u16(&central_fixed, 4);
        let central_flags = source_u16(&central_fixed, 8);
        let central_method = source_u16(&central_fixed, 10);
        let central_crc = source_u32(&central_fixed, 16);
        let central_comp_size = u64::from(source_u32(&central_fixed, 20));
        let central_uncomp_size = u64::from(source_u32(&central_fixed, 24));
        let central_name_len =
            u64::from(u16::from_le_bytes([central_fixed[28], central_fixed[29]]));
        let central_extra_len =
            u64::from(u16::from_le_bytes([central_fixed[30], central_fixed[31]]));
        let central_comment_len =
            u64::from(u16::from_le_bytes([central_fixed[32], central_fixed[33]]));
        let central_disk_start = source_u16(&central_fixed, 34);
        let central_external_attributes = source_u32(&central_fixed, 38);
        let central_local_offset = u64::from(source_u32(&central_fixed, 42));
        let expected_central_len = 46_u64
            .checked_add(central_name_len)
            .and_then(|value| value.checked_add(central_extra_len))
            .and_then(|value| value.checked_add(central_comment_len))
            .ok_or_else(|| {
                RecordError::new(
                    RecordErrorKind::IntegerOverflow,
                    0,
                    "source central-header length calculation overflowed",
                )
            })?;
        if zip.source_ranges.central_header.len != expected_central_len
            || central_name_len != member.raw_name_bytes.len() as u64
        {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "planning central-header geometry does not match the supervisor snapshot",
            ));
        }
        if central_comp_size == u64::from(u32::MAX)
            || central_uncomp_size == u64::from(u32::MAX)
            || central_local_offset == u64::from(u32::MAX)
            || central_disk_start == u16::MAX
        {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "planning central header uses a ZIP64 sentinel",
            ));
        }
        if central_flags != zip.flags
            || central_method != zip.method
            || central_crc != zip.declared_crc
            || central_comp_size != zip.declared_comp_size
            || central_uncomp_size != member.declared_uncomp_size
            || central_local_offset != zip.source_ranges.local_header.offset
            || central_disk_start != 0
        {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "planning central-header semantics do not match the supervisor snapshot",
            ));
        }
        if zip.creator_system != (central_version_made_by >> 8) as u8
            || zip.external_attributes != central_external_attributes
        {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "planning member container facts disagree with the central header",
            ));
        }
        validate_source_member_kind(member, central_version_made_by, central_external_attributes)?;
        let central_name_offset = zip
            .source_ranges
            .central_header
            .offset
            .checked_add(46)
            .ok_or_else(|| {
                RecordError::new(
                    RecordErrorKind::IntegerOverflow,
                    0,
                    "source central-name offset calculation overflowed",
                )
            })?;
        validate_source_name(snapshot, central_name_offset, &member.raw_name_bytes)?;
        let central_extra_offset = central_name_offset
            .checked_add(central_name_len)
            .ok_or_else(|| {
                RecordError::new(
                    RecordErrorKind::IntegerOverflow,
                    0,
                    "source central-extra offset calculation overflowed",
                )
            })?;
        validate_source_extra_fields(
            snapshot,
            member,
            ExtraSite::Central,
            central_extra_offset,
            central_extra_len,
        )?;
        let central_comment_offset = central_extra_offset
            .checked_add(central_extra_len)
            .ok_or_else(|| {
                RecordError::new(
                    RecordErrorKind::IntegerOverflow,
                    0,
                    "source central-comment offset calculation overflowed",
                )
            })?;
        validate_no_source_signatures(
            snapshot,
            ByteRange {
                offset: central_comment_offset,
                len: central_comment_len,
            },
            SourceSignatureClass::StructuralMetadata,
            "planning central comment contains an archive-record signature",
        )?;
        validate_source_data_descriptor(snapshot, member)?;
        if zip.method == 0 && uses_descriptor {
            validate_no_source_signatures(
                snapshot,
                zip.source_ranges.compressed_payload,
                SourceSignatureClass::Stream,
                "planning stored descriptor payload contains an alternate record signature",
            )?;
        }
    }
    Ok(())
}

fn validate_ready_ir_global_source_fields(
    snapshot: &SourceSnapshot<'_>,
    ir: &ArchiveIR,
) -> Result<(), RecordError> {
    let covering = require_zip_covering(ir)?;
    let mut eocd = [0_u8; 22];
    read_snapshot_exact(
        snapshot,
        covering.eocd.offset,
        &mut eocd,
        "cannot read the claimed EOCD from the supervisor snapshot",
    )?;
    let this_disk = source_u16(&eocd, 4);
    let central_disk = source_u16(&eocd, 6);
    let this_disk_entries = source_u16(&eocd, 8);
    let total_entries = source_u16(&eocd, 10);
    let central_len = source_u32(&eocd, 12);
    let central_offset = source_u32(&eocd, 16);
    let comment_len = source_u16(&eocd, 20);
    if total_entries == u16::MAX || central_len == u32::MAX || central_offset == u32::MAX {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "planning EOCD uses a ZIP64 sentinel",
        ));
    }
    if this_disk != 0
        || central_disk != 0
        || usize::from(this_disk_entries) != ir.members.len()
        || usize::from(total_entries) != ir.members.len()
        || u64::from(central_len) != covering.central_directory.len
        || u64::from(central_offset) != covering.central_directory.offset
        || u64::from(comment_len) != covering.comment.len
    {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "planning EOCD semantics do not match the claimed IR",
        ));
    }
    validate_no_source_signatures(
        snapshot,
        covering.comment,
        SourceSignatureClass::StructuralMetadata,
        "planning EOCD comment contains an archive-record signature",
    )
}

fn validate_source_member_kind(
    member: &IrMember,
    _version_made_by: u16,
    external_attributes: u32,
) -> Result<(), RecordError> {
    let member_is_directory = matches!(member.kind, MemberKind::Directory);
    let attribute_is_directory =
        (external_attributes & 0x10) != 0 || ((external_attributes >> 16) & 0xf000) == 0x4000;
    let unix_kind = (external_attributes >> 16) & 0xf000;
    let attribute_is_regular = unix_kind == 0x8000;
    let attribute_is_special = unix_kind != 0 && unix_kind != 0x4000 && unix_kind != 0x8000;
    if attribute_is_special
        || (attribute_is_directory && attribute_is_regular)
        || (attribute_is_directory != member_is_directory
            && (attribute_is_directory || attribute_is_regular))
    {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "planning member kind disagrees with central external attributes",
        ));
    }
    Ok(())
}

fn validate_source_data_descriptor(
    snapshot: &SourceSnapshot<'_>,
    member: &IrMember,
) -> Result<(), RecordError> {
    let zip = require_zip_evidence(member)?;
    let Some(range) = zip.source_ranges.data_descriptor else {
        return Ok(());
    };
    let mut bytes = [0_u8; 16];
    let len = usize::try_from(range.len).map_err(|_| {
        RecordError::new(
            RecordErrorKind::IntegerOverflow,
            0,
            "source data-descriptor length cannot be represented",
        )
    })?;
    read_snapshot_exact(
        snapshot,
        range.offset,
        &mut bytes[..len],
        "cannot read the claimed data descriptor from the supervisor snapshot",
    )?;
    let values_offset = match range.len {
        12 if source_u32(&bytes, 0) != 0x0807_4b50 => 0,
        16 if source_u32(&bytes, 0) == 0x0807_4b50 => 4,
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "planning data-descriptor signature or length is invalid",
            ));
        }
    };
    if source_u32(&bytes, values_offset) != zip.declared_crc
        || u64::from(source_u32(&bytes, values_offset + 4)) != zip.declared_comp_size
        || u64::from(source_u32(&bytes, values_offset + 8)) != member.declared_uncomp_size
    {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "planning data-descriptor values do not match the supervisor snapshot",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum SourceSignatureClass {
    Stream,
    StructuralMetadata,
}

fn validate_no_source_signatures(
    snapshot: &SourceSnapshot<'_>,
    range: ByteRange,
    class: SourceSignatureClass,
    detail: &'static str,
) -> Result<(), RecordError> {
    let signatures: &[u32] = match class {
        SourceSignatureClass::Stream => &[0x0403_4b50, 0x0201_4b50, 0x0807_4b50],
        SourceSignatureClass::StructuralMetadata => &[
            0x0403_4b50,
            0x0201_4b50,
            0x0807_4b50,
            0x0605_4b50,
            0x0606_4b50,
            0x0706_4b50,
        ],
    };
    let mut offset = range.offset;
    let mut remaining = range.len;
    let mut rolling = 0_u32;
    let mut seen = 0_u8;
    let mut buffer = [0_u8; 4_096];
    while remaining != 0 {
        let chunk_len = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| {
            RecordError::new(
                RecordErrorKind::IntegerOverflow,
                0,
                "source signature-scan length cannot be represented",
            )
        })?;
        read_snapshot_exact(
            snapshot,
            offset,
            &mut buffer[..chunk_len],
            "cannot scan source metadata from the supervisor snapshot",
        )?;
        for byte in &buffer[..chunk_len] {
            rolling = (rolling >> 8) | (u32::from(*byte) << 24);
            seen = seen.saturating_add(1);
            if seen >= 4 && signatures.contains(&rolling) {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidSemanticState,
                    0,
                    detail,
                ));
            }
        }
        offset = offset.checked_add(chunk_len as u64).ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::IntegerOverflow,
                0,
                "source signature-scan offset overflowed",
            )
        })?;
        remaining -= chunk_len as u64;
    }
    Ok(())
}

fn source_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn source_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn validate_source_name(
    snapshot: &SourceSnapshot<'_>,
    mut offset: u64,
    expected: &[u8],
) -> Result<(), RecordError> {
    let mut buffer = [0_u8; 1_024];
    for chunk in expected.chunks(buffer.len()) {
        read_snapshot_exact(
            snapshot,
            offset,
            &mut buffer[..chunk.len()],
            "cannot read a claimed member name from the supervisor snapshot",
        )?;
        if &buffer[..chunk.len()] != chunk {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "planning member name does not match the supervisor snapshot",
            ));
        }
        offset = offset.checked_add(chunk.len() as u64).ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::IntegerOverflow,
                0,
                "source member-name offset calculation overflowed",
            )
        })?;
    }
    Ok(())
}

fn validate_source_extra_fields(
    snapshot: &SourceSnapshot<'_>,
    member: &IrMember,
    site: ExtraSite,
    start: u64,
    len: u64,
) -> Result<(), RecordError> {
    let zip = require_zip_evidence(member)?;
    let expected_end = start.checked_add(len).ok_or_else(|| {
        RecordError::new(
            RecordErrorKind::IntegerOverflow,
            0,
            "source extra-field boundary calculation overflowed",
        )
    })?;
    let mut expected_offset = start;
    for extra in zip.extra_fields.iter().filter(|extra| extra.site == site) {
        if extra.header_range.offset != expected_offset {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "planning extra fields do not cover the supervisor snapshot sequence",
            ));
        }
        let mut header = [0_u8; 4];
        read_snapshot_exact(
            snapshot,
            expected_offset,
            &mut header,
            "cannot read a claimed extra-field header from the supervisor snapshot",
        )?;
        let source_id = u16::from_le_bytes([header[0], header[1]]);
        let source_len = u64::from(u16::from_le_bytes([header[2], header[3]]));
        if source_id != extra.id || source_len != extra.data_range.len {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "planning extra-field header does not match the supervisor snapshot",
            ));
        }
        expected_offset = checked_end(extra.data_range)?;
    }
    if expected_offset != expected_end {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "planning extra fields do not exactly cover the supervisor snapshot sequence",
        ));
    }
    Ok(())
}

fn read_snapshot_exact(
    snapshot: &SourceSnapshot<'_>,
    offset: u64,
    output: &mut [u8],
    detail: &'static str,
) -> Result<(), RecordError> {
    snapshot
        .read_exact_at(offset, output)
        .map_err(|_| RecordError::new(RecordErrorKind::InvalidSemanticState, 0, detail))
}

fn validate_planning(record: &PlanningRecord) -> Result<(), RecordError> {
    validate_binding(&record.binding)?;
    validate_findings(&record.findings)?;
    if record.findings.iter().any(|finding| {
        matches!(
            finding.code,
            FindingCode::PolicyUnsupported
                | FindingCode::MaterializeExists
                | FindingCode::MaterializeIo
                | FindingCode::MaterializeCommit
                | FindingCode::MaterializeUnsafeParent
                | FindingCode::MaterializeUnsafeComponent
                | FindingCode::MaterializeCleanup
                | FindingCode::MaterializeUnsupported
                | FindingCode::MaterializeUnsupportedFilesystem
                | FindingCode::MaterializeUnsafeStage
                | FindingCode::MaterializeAudit
        )
    }) {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "planning findings claim supervisor-owned policy or effect state",
        ));
    }
    match (&record.disposition, &record.ir) {
        (PlanningDisposition::ReadyForVerification, Some(ir)) => {
            if record
                .findings
                .iter()
                .any(|finding| finding.severity == Severity::Error)
            {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidSemanticState,
                    0,
                    "ready planning record contains an error finding",
                ));
            }
            validate_pending_ir(ir, &record.binding)?;
        }
        (PlanningDisposition::ReadyForVerification, None) => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "ready planning record lacks its complete pending IR",
            ));
        }
        (PlanningDisposition::Terminal(axes), ir) => {
            let cause_index = first_error_index(&record.findings)?;
            let cause = &record.findings[cause_index];
            validate_terminal_axes(axes, cause)?;
            let (phase, _) = partial_parts(&axes.view_completeness)?;
            let error_count = record
                .findings
                .iter()
                .filter(|finding| finding.severity == Severity::Error)
                .count();
            if matches!(phase, StoppingPhase::Structure) && error_count != 1 {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidSemanticState,
                    0,
                    "structure terminal must contain exactly one error finding",
                ));
            }
            if record
                .findings
                .iter()
                .any(|finding| !planning_finding_for_phase(finding.code, phase))
            {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidSemanticState,
                    0,
                    "planning finding cannot occur in the claimed phase",
                ));
            }
            match ir {
                None => {
                    if cause.code == FindingCode::CoveringInconsistent {
                        return Err(RecordError::new(
                            RecordErrorKind::InvalidSemanticState,
                            0,
                            "covering-inconsistent terminal lacks its retained IR",
                        ));
                    }
                }
                Some(ir) => {
                    if cause.code != FindingCode::CoveringInconsistent
                        || axes.interpretation != InterpretationStatus::Malformed
                        || axes.admission != AdmissionStatus::Denied
                        || !matches!(
                            axes.view_completeness,
                            ViewCompleteness::Partial {
                                phase: StoppingPhase::Structure,
                                ..
                            }
                        )
                    {
                        return Err(RecordError::new(
                            RecordErrorKind::InvalidSemanticState,
                            0,
                            "only reproduced covering inconsistency may retain terminal IR",
                        ));
                    }
                    validate_pending_ir(ir, &record.binding)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_terminal_axes(axes: &TerminalPlanningAxes, cause: &Finding) -> Result<(), RecordError> {
    if !matches!(axes.verification, VerificationStatus::StructureOnly) {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "planning terminal verification is not StructureOnly",
        ));
    }
    let (phase, encoded_cause) = partial_parts(&axes.view_completeness)?;
    if encoded_cause != cause.code.as_str() {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "planning terminal cause does not match the first error finding",
        ));
    }
    if !planning_finding_for_phase(cause.code, phase) {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "planning cause cannot occur in the claimed phase",
        ));
    }
    let expected = match phase {
        StoppingPhase::Admission => (InterpretationStatus::Interpreted, AdmissionStatus::Denied),
        StoppingPhase::Structure => match cause.code {
            FindingCode::SourceIo => (
                InterpretationStatus::Indeterminate,
                AdmissionStatus::NotEvaluated,
            ),
            FindingCode::FormatUnsupported => {
                if axes.admission == AdmissionStatus::Denied {
                    (InterpretationStatus::Unsupported, AdmissionStatus::Denied)
                } else {
                    (
                        InterpretationStatus::Unsupported,
                        AdmissionStatus::NotEvaluated,
                    )
                }
            }
            FindingCode::ZipDiffC5Zip64
            | FindingCode::ZipEncoding
            | FindingCode::ZipEncrypted
            | FindingCode::MethodUnsupported => (
                InterpretationStatus::Unsupported,
                AdmissionStatus::NotEvaluated,
            ),
            FindingCode::QuotaFiles | FindingCode::QuotaMetadata | FindingCode::QuotaOverflow => {
                (InterpretationStatus::Interpreted, AdmissionStatus::Denied)
            }
            FindingCode::CoveringInconsistent => {
                (InterpretationStatus::Malformed, AdmissionStatus::Denied)
            }
            _ => (
                InterpretationStatus::Malformed,
                AdmissionStatus::NotEvaluated,
            ),
        },
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "planning terminal phase is supervisor-owned or incoherent",
            ));
        }
    };
    if axes.interpretation != expected.0 || axes.admission != expected.1 {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "planning terminal axes are incoherent",
        ));
    }
    Ok(())
}

fn planning_finding_for_phase(code: FindingCode, phase: &StoppingPhase) -> bool {
    match phase {
        StoppingPhase::Structure => planning_structure_finding(code),
        StoppingPhase::Admission => planning_admission_finding(code),
        _ => false,
    }
}

fn planning_structure_finding(code: FindingCode) -> bool {
    matches!(
        code,
        FindingCode::SourceIo
            | FindingCode::QuotaMetadata
            | FindingCode::QuotaFiles
            | FindingCode::QuotaOverflow
            | FindingCode::ZipDiffA1Method
            | FindingCode::ZipDiffA2Size
            | FindingCode::ZipDiffA3Name
            | FindingCode::ZipDiffA4Dir
            | FindingCode::ZipDiffA5Crypt
            | FindingCode::ZipDiffC1Stream
            | FindingCode::ZipDiffC2Eocd
            | FindingCode::ZipDiffC3Count
            | FindingCode::ZipDiffC4Offset
            | FindingCode::ZipDiffC5Zip64
            | FindingCode::ZipOverlap
            | FindingCode::CoveringInconsistent
            | FindingCode::ZipEncoding
            | FindingCode::ZipExtra
            | FindingCode::ZipFlags
            | FindingCode::FormatUnsupported
    )
}

fn planning_admission_finding(code: FindingCode) -> bool {
    matches!(
        code,
        FindingCode::PathAbsolute
            | FindingCode::PathDotDot
            | FindingCode::PathEmpty
            | FindingCode::PathAds
            | FindingCode::PathReserved
            | FindingCode::PathTrailing
            | FindingCode::PathDepth
            | FindingCode::PathNul
            | FindingCode::PathInvalidChar
            | FindingCode::PathUnicode
            | FindingCode::PathCaseFold
            | FindingCode::PathConflict
            | FindingCode::QuotaMember
            | FindingCode::QuotaTotal
            | FindingCode::QuotaRatio
            | FindingCode::QuotaOverflow
            | FindingCode::ZipDiffB1Dup
            | FindingCode::ZipEncrypted
            | FindingCode::MethodUnsupported
    )
}

fn encode_completion(
    record: &CompletionRecord,
    planning: &ValidatedPlanningRecord,
) -> Result<Vec<u8>, RecordError> {
    validate_completion(record, planning)?;
    encode_completion_validated(record)
}

fn encode_completion_validated(record: &CompletionRecord) -> Result<Vec<u8>, RecordError> {
    let mut encoder = Encoder::new(KIND_COMPLETION);
    encoder.fixed(&record.operation_id);
    encoder.fixed(&record.request_id);
    encoder.fixed(&record.plan_id);
    encode_findings(&mut encoder, &record.findings)?;
    match record.disposition {
        CompletionDisposition::Complete => encoder.u8(0),
        CompletionDisposition::Stopped {
            verified_members,
            pending_members,
        } => {
            encoder.u8(1);
            encoder.u64(verified_members);
            encoder.u64(pending_members);
        }
    }
    encoder.u32(u32::try_from(record.members.len()).map_err(|_| {
        RecordError::new(
            RecordErrorKind::LimitExceeded,
            encoder.bytes.len(),
            "completion member-state count exceeds the record integer limit",
        )
    })?);
    for member in &record.members {
        match member {
            MemberCompletion::Pending => encoder.u8(0),
            MemberCompletion::Verified {
                actual_uncomp_size,
                actual_crc,
                content_sha256,
            } => {
                encoder.u8(1);
                encoder.u64(*actual_uncomp_size);
                encoder.u32(*actual_crc);
                encoder.fixed(content_sha256);
            }
            MemberCompletion::Failed { cause } => {
                encoder.u8(2);
                encoder.u16(finding_code_tag(*cause));
            }
        }
    }
    encoder.finish()
}

fn decode_completion(
    input: &[u8],
    planning: &ValidatedPlanningRecord,
) -> Result<BoundCompletionProposal, RecordError> {
    let mut cursor = Cursor::frame(input, KIND_COMPLETION)?;
    let operation_id = cursor.fixed()?;
    let request_id_value = cursor.fixed()?;
    let plan_id_value = cursor.fixed()?;
    if operation_id != planning.record.binding.operation_id
        || request_id_value != planning.request_id
        || plan_id_value != planning.plan_id
    {
        return Err(RecordError::new(
            RecordErrorKind::BindingMismatch,
            HEADER_BYTES,
            "completion correlation does not match the accepted plan",
        ));
    }
    let findings = decode_findings(&mut cursor)?;
    let disposition = match cursor.u8()? {
        0 => CompletionDisposition::Complete,
        1 => CompletionDisposition::Stopped {
            verified_members: cursor.u64()?,
            pending_members: cursor.u64()?,
        },
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidEnum,
                cursor.offset().saturating_sub(1),
                "completion disposition tag is invalid",
            ));
        }
    };
    let expected_members = planning
        .record
        .ir
        .as_ref()
        .map(|ir| ir.members.len())
        .ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::PhaseMismatch,
                0,
                "terminal planning record cannot accept completion",
            )
        })?;
    let count = cursor.count(
        expected_members,
        1,
        "completion member-state count exceeds plan or remaining bytes",
    )?;
    if count != expected_members {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            cursor.offset().saturating_sub(4),
            "completion member-state vector length differs from the plan",
        ));
    }
    let mut members = Vec::new();
    members.try_reserve_exact(count).map_err(|_| {
        RecordError::new(
            RecordErrorKind::AllocationFailed,
            cursor.offset(),
            "bounded completion member-state allocation failed",
        )
    })?;
    for _ in 0..count {
        members.push(match cursor.u8()? {
            0 => MemberCompletion::Pending,
            1 => MemberCompletion::Verified {
                actual_uncomp_size: cursor.u64()?,
                actual_crc: cursor.u32()?,
                content_sha256: cursor.fixed()?,
            },
            2 => MemberCompletion::Failed {
                cause: finding_code_from_tag(cursor.u16()?, cursor.offset().saturating_sub(2))?,
            },
            _ => {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidEnum,
                    cursor.offset().saturating_sub(1),
                    "completion member-state tag is invalid",
                ));
            }
        });
    }
    cursor.finish()?;
    let record = CompletionRecord {
        operation_id,
        request_id: request_id_value,
        plan_id: plan_id_value,
        disposition,
        members,
        findings,
    };
    let validation = validate_completion(&record, planning)?;
    let canonical = encode_completion_validated(&record)?;
    if canonical != input {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "decoded completion record did not re-encode identically",
        ));
    }
    drop(canonical);
    materialize_completion(record, validation)
}

fn validate_completion<'plan>(
    record: &CompletionRecord,
    planning: &'plan ValidatedPlanningRecord,
) -> Result<CompletionValidation<'plan>, RecordError> {
    if !matches!(
        planning.record.disposition,
        PlanningDisposition::ReadyForVerification
    ) {
        return Err(RecordError::new(
            RecordErrorKind::PhaseMismatch,
            0,
            "terminal planning record cannot accept completion",
        ));
    }
    if record.operation_id != planning.record.binding.operation_id
        || record.request_id != planning.request_id
        || record.plan_id != planning.plan_id
    {
        return Err(RecordError::new(
            RecordErrorKind::BindingMismatch,
            0,
            "completion correlation does not match the accepted plan",
        ));
    }
    validate_findings(&record.findings)?;
    for finding in &record.findings {
        if matches!(
            finding.code,
            FindingCode::PolicyUnsupported
                | FindingCode::MaterializeExists
                | FindingCode::MaterializeCommit
                | FindingCode::MaterializeUnsafeParent
                | FindingCode::MaterializeCleanup
                | FindingCode::MaterializeUnsupported
                | FindingCode::MaterializeUnsupportedFilesystem
                | FindingCode::MaterializeUnsafeStage
                | FindingCode::MaterializeAudit
        ) {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "completion findings claim supervisor-owned lifecycle state",
            ));
        }
        if matches!(
            finding.code,
            FindingCode::MaterializeIo | FindingCode::MaterializeUnsafeComponent
        ) && planning.record.binding.requested_effect != RequestedEffect::Materialize
        {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "materialization-only finding appears in inspect completion",
            ));
        }
    }
    let error_count = record
        .findings
        .iter()
        .filter(|finding| finding.severity == Severity::Error)
        .count();
    match record.disposition {
        CompletionDisposition::Complete if error_count != 0 => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "complete record contains an error finding",
            ));
        }
        CompletionDisposition::Stopped { .. } if error_count != 1 => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "stopped completion must contain exactly one error finding",
            ));
        }
        _ => {}
    }
    if record
        .findings
        .iter()
        .any(|finding| !completion_finding(finding.code, planning.record.binding.requested_effect))
    {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "completion finding cannot occur during member execution",
        ));
    }
    let ir = planning.record.ir.as_ref().ok_or_else(|| {
        RecordError::new(
            RecordErrorKind::PhaseMismatch,
            0,
            "ready planning record lacks an IR",
        )
    })?;
    if record.members.len() != ir.members.len() {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "completion member-state vector length differs from the plan",
        ));
    }
    let mut verified_prefix = 0_usize;
    let mut failed_index = None;
    let mut pending_started = false;
    let mut actual_total = 0_u64;
    for (index, state) in record.members.iter().enumerate() {
        match state {
            MemberCompletion::Verified {
                actual_uncomp_size,
                actual_crc,
                content_sha256,
            } => {
                if failed_index.is_some() || pending_started {
                    return Err(RecordError::new(
                        RecordErrorKind::InvalidSemanticState,
                        0,
                        "verified member follows the failure frontier",
                    ));
                }
                let planned = &ir.members[index];
                let planned_zip = require_zip_evidence(planned)?;
                if *actual_uncomp_size != planned.declared_uncomp_size
                    || *actual_crc != planned_zip.declared_crc
                {
                    return Err(RecordError::new(
                        RecordErrorKind::InvalidSemanticState,
                        0,
                        "verified measurements disagree with declared member metadata",
                    ));
                }
                let empty_sha256: [u8; 32] = Sha256::digest([]).into();
                if matches!(planned.kind, MemberKind::Directory)
                    && (*actual_uncomp_size != 0
                        || *actual_crc != 0
                        || *content_sha256 != empty_sha256)
                {
                    return Err(RecordError::new(
                        RecordErrorKind::InvalidSemanticState,
                        0,
                        "verified directory does not have canonical empty content",
                    ));
                }
                actual_total = actual_total
                    .checked_add(*actual_uncomp_size)
                    .ok_or_else(|| {
                        RecordError::new(
                            RecordErrorKind::IntegerOverflow,
                            0,
                            "completion actual-size aggregate overflowed",
                        )
                    })?;
                if actual_total > planning.record.binding.budget.max_total_bytes {
                    return Err(RecordError::new(
                        RecordErrorKind::InvalidSemanticState,
                        0,
                        "completion exceeds the aggregate actual-size budget",
                    ));
                }
                verified_prefix += 1;
            }
            MemberCompletion::Failed { cause } => {
                if failed_index.is_some() || pending_started {
                    return Err(RecordError::new(
                        RecordErrorKind::InvalidSemanticState,
                        0,
                        "completion has more than one failure frontier",
                    ));
                }
                failed_index = Some((index, *cause));
            }
            MemberCompletion::Pending => pending_started = true,
        }
    }

    let (interpretation, admission, verification, view_cause) = match record.disposition {
        CompletionDisposition::Complete => {
            if verified_prefix != ir.members.len()
                || failed_index.is_some()
                || record
                    .findings
                    .iter()
                    .any(|finding| finding.severity == Severity::Error)
            {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidSemanticState,
                    0,
                    "complete record is not completely verified and error-free",
                ));
            }
            (
                InterpretationStatus::Interpreted,
                AdmissionStatus::Admitted,
                VerificationStatus::Complete,
                None,
            )
        }
        CompletionDisposition::Stopped {
            verified_members,
            pending_members,
        } => {
            let (failed_member_index, failed_cause) = failed_index.ok_or_else(|| {
                RecordError::new(
                    RecordErrorKind::InvalidSemanticState,
                    0,
                    "stopped completion lacks exactly one failed frontier member",
                )
            })?;
            let first_error = &record.findings[first_error_index(&record.findings)?];
            if first_error.code != failed_cause {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidSemanticState,
                    0,
                    "failed member cause differs from the first error finding",
                ));
            }
            if !completion_cause_reachable(
                planning.record.binding.requested_effect,
                &ir.members[failed_member_index],
                first_error.code,
            ) {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidSemanticState,
                    0,
                    "completion failure cause is unreachable for the planned member",
                ));
            }
            let expected_verified = verified_prefix as u64;
            let expected_pending = (ir.members.len() - verified_prefix) as u64;
            if verified_members != expected_verified || pending_members != expected_pending {
                return Err(RecordError::new(
                    RecordErrorKind::InvalidSemanticState,
                    0,
                    "partial verification counts disagree with the frontier",
                ));
            }
            let (interpretation, admission) = completion_stop_axes(first_error.code);
            (
                interpretation,
                admission,
                VerificationStatus::Partial {
                    verified_members,
                    pending_members,
                },
                Some(first_error.code),
            )
        }
    };
    Ok(CompletionValidation {
        interpretation,
        admission,
        verification,
        view_cause,
        ir,
    })
}

fn completion_stop_axes(cause: FindingCode) -> (InterpretationStatus, AdmissionStatus) {
    match cause {
        FindingCode::SourceIo => (
            InterpretationStatus::Indeterminate,
            AdmissionStatus::Admitted,
        ),
        FindingCode::CodecDeflateInvalidStream
        | FindingCode::CodecDeflateTrailingInput
        | FindingCode::ZipDiffC4Offset => (
            InterpretationStatus::Malformed,
            AdmissionStatus::NotEvaluated,
        ),
        FindingCode::MaterializeIo
        | FindingCode::MaterializeUnsafeComponent
        | FindingCode::MaterializeCommit
        | FindingCode::MaterializeExists => {
            (InterpretationStatus::Interpreted, AdmissionStatus::Admitted)
        }
        _ => (InterpretationStatus::Interpreted, AdmissionStatus::Denied),
    }
}

fn materialize_completion(
    record: CompletionRecord,
    validation: CompletionValidation<'_>,
) -> Result<BoundCompletionProposal, RecordError> {
    #[cfg(test)]
    COMPLETION_IR_MATERIALIZATIONS.with(|count| count.set(count.get() + 1));

    let mut ir = try_clone_archive_ir(validation.ir)?;
    for (member, state) in ir.members.iter_mut().zip(&record.members) {
        match state {
            MemberCompletion::Pending => {}
            MemberCompletion::Verified {
                actual_uncomp_size,
                actual_crc,
                content_sha256,
            } => {
                if matches!(member.kind, MemberKind::Directory) {
                    member.mark_directory_verified();
                } else {
                    member.mark_file_verified(
                        *actual_uncomp_size,
                        *actual_crc,
                        try_hex_32(content_sha256)?,
                    );
                }
            }
            MemberCompletion::Failed { cause } => {
                member.verification = MemberVerification::Failed {
                    cause: try_clone_string(
                        cause.as_str(),
                        "bounded completion failure-cause allocation failed",
                    )?,
                };
            }
        }
    }
    let view_completeness = match validation.view_cause {
        None => ViewCompleteness::Complete,
        Some(cause) => ViewCompleteness::Partial {
            phase: StoppingPhase::Verification,
            cause: try_clone_string(
                cause.as_str(),
                "bounded completion view-cause allocation failed",
            )?,
        },
    };
    Ok(BoundCompletionProposal {
        interpretation: validation.interpretation,
        admission: validation.admission,
        verification: validation.verification,
        view_completeness,
        ir,
        findings: record.findings,
    })
}

fn try_clone_archive_ir(ir: &ArchiveIR) -> Result<ArchiveIR, RecordError> {
    let covering = require_zip_covering(ir)?.clone();
    let profile_digest = try_clone_string(
        &ir.profile_digest,
        "bounded completion profile-digest allocation failed",
    )?;
    let source_digest = match &ir.source_digest {
        SourceDigest::Available { sha256 } => SourceDigest::Available {
            sha256: try_clone_string(sha256, "bounded completion source-digest allocation failed")?,
        },
        SourceDigest::Unavailable => SourceDigest::Unavailable,
    };
    let mut members = Vec::new();
    completion_allocation_gate(
        "bounded completion member reconstruction allocation failed",
        allocation_bytes::<IrMember>(ir.members.len())?,
    )?;
    members.try_reserve_exact(ir.members.len()).map_err(|_| {
        RecordError::new(
            RecordErrorKind::AllocationFailed,
            0,
            "bounded completion member reconstruction allocation failed",
        )
    })?;
    for member in &ir.members {
        members.push(try_clone_pending_member(member)?);
    }
    Ok(ArchiveIR {
        schema: ir.schema,
        profile: ir.profile,
        profile_digest,
        source_digest,
        evidence: ArchiveEvidence::Zip(covering),
        members,
    })
}

fn try_clone_pending_member(member: &IrMember) -> Result<IrMember, RecordError> {
    let zip = require_zip_evidence(member)?;
    let mut raw_name_bytes = Vec::new();
    completion_allocation_gate(
        "bounded completion raw-name allocation failed",
        member.raw_name_bytes.len(),
    )?;
    raw_name_bytes
        .try_reserve_exact(member.raw_name_bytes.len())
        .map_err(|_| {
            RecordError::new(
                RecordErrorKind::AllocationFailed,
                0,
                "bounded completion raw-name allocation failed",
            )
        })?;
    raw_name_bytes.extend_from_slice(&member.raw_name_bytes);

    let mut components = Vec::new();
    completion_allocation_gate(
        "bounded completion path-component allocation failed",
        allocation_bytes::<String>(member.components.len())?,
    )?;
    components
        .try_reserve_exact(member.components.len())
        .map_err(|_| {
            RecordError::new(
                RecordErrorKind::AllocationFailed,
                0,
                "bounded completion path-component allocation failed",
            )
        })?;
    for component in &member.components {
        components.push(try_clone_string(
            component,
            "bounded completion path-component string allocation failed",
        )?);
    }

    let mut extra_fields = Vec::new();
    completion_allocation_gate(
        "bounded completion extra-field allocation failed",
        allocation_bytes::<ExtraFieldRecord>(zip.extra_fields.len())?,
    )?;
    extra_fields
        .try_reserve_exact(zip.extra_fields.len())
        .map_err(|_| {
            RecordError::new(
                RecordErrorKind::AllocationFailed,
                0,
                "bounded completion extra-field allocation failed",
            )
        })?;
    extra_fields.extend_from_slice(&zip.extra_fields);

    let mut normalization_actions = Vec::new();
    completion_allocation_gate(
        "bounded completion normalization allocation failed",
        allocation_bytes::<NormalizationAction>(member.normalization_actions.len())?,
    )?;
    normalization_actions
        .try_reserve_exact(member.normalization_actions.len())
        .map_err(|_| {
            RecordError::new(
                RecordErrorKind::AllocationFailed,
                0,
                "bounded completion normalization allocation failed",
            )
        })?;
    normalization_actions.extend_from_slice(&member.normalization_actions);

    Ok(IrMember {
        raw_name_bytes,
        decoded_name: try_clone_string(
            &member.decoded_name,
            "bounded completion decoded-name allocation failed",
        )?,
        canonical_path: try_clone_string(
            &member.canonical_path,
            "bounded completion canonical-path allocation failed",
        )?,
        components,
        kind: member.kind,
        declared_uncomp_size: member.declared_uncomp_size,
        evidence: MemberEvidence::Zip(ZipMemberEvidence {
            method: zip.method,
            flags: zip.flags,
            creator_system: zip.creator_system,
            external_attributes: zip.external_attributes,
            declared_crc: zip.declared_crc,
            declared_comp_size: zip.declared_comp_size,
            source_ranges: zip.source_ranges.clone(),
            extra_fields,
        }),
        actual_uncomp_size: None,
        actual_crc: None,
        content_sha256: None,
        verification: MemberVerification::Pending,
        normalization_actions,
    })
}

fn try_clone_string(value: &str, detail: &'static str) -> Result<String, RecordError> {
    completion_allocation_gate(detail, value.len())?;
    try_record_string(value, 0, detail)
}

fn try_record_string(
    value: &str,
    offset: usize,
    detail: &'static str,
) -> Result<String, RecordError> {
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| RecordError::new(RecordErrorKind::AllocationFailed, offset, detail))?;
    result.push_str(value);
    Ok(result)
}

fn try_hex_32(value: &[u8; 32]) -> Result<String, RecordError> {
    completion_allocation_gate("bounded completion digest allocation failed", 64)?;
    try_record_hex_32(value, 0, "bounded completion digest allocation failed")
}

fn try_record_hex_32(
    value: &[u8; 32],
    offset: usize,
    detail: &'static str,
) -> Result<String, RecordError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::new();
    result
        .try_reserve_exact(64)
        .map_err(|_| RecordError::new(RecordErrorKind::AllocationFailed, offset, detail))?;
    for byte in value {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(result)
}

fn allocation_bytes<T>(count: usize) -> Result<usize, RecordError> {
    count.checked_mul(std::mem::size_of::<T>()).ok_or_else(|| {
        RecordError::new(
            RecordErrorKind::IntegerOverflow,
            0,
            "completion reconstruction size calculation overflowed",
        )
    })
}

fn completion_allocation_gate(
    detail: &'static str,
    requested_bytes: usize,
) -> Result<(), RecordError> {
    #[cfg(test)]
    {
        let should_fail =
            COMPLETION_ALLOCATION_FAIL_AFTER.with(|remaining| match remaining.get() {
                None => false,
                Some(0) => true,
                Some(value) => {
                    remaining.set(Some(value - 1));
                    false
                }
            });
        if should_fail {
            return Err(RecordError::new(
                RecordErrorKind::AllocationFailed,
                0,
                detail,
            ));
        }
        let within_budget = COMPLETION_ALLOCATION_BUDGET.with(|budget| match budget.get() {
            None => true,
            Some(remaining) if requested_bytes <= remaining => {
                budget.set(Some(remaining - requested_bytes));
                true
            }
            Some(_) => false,
        });
        if !within_budget {
            return Err(RecordError::new(
                RecordErrorKind::AllocationFailed,
                0,
                detail,
            ));
        }
    }
    let _ = (detail, requested_bytes);
    Ok(())
}

fn completion_finding(code: FindingCode, requested_effect: RequestedEffect) -> bool {
    matches!(
        code,
        FindingCode::SourceIo
            | FindingCode::QuotaDeclaredLie
            | FindingCode::CodecDeflateInvalidStream
            | FindingCode::CodecDeflateTrailingInput
            | FindingCode::CrcMismatch
    ) || (requested_effect == RequestedEffect::Materialize
        && matches!(
            code,
            FindingCode::MaterializeIo | FindingCode::MaterializeUnsafeComponent
        ))
}

fn completion_cause_reachable(
    requested_effect: RequestedEffect,
    member: &IrMember,
    code: FindingCode,
) -> bool {
    executor::inspect_failure_reachable(member, code)
        || (requested_effect == RequestedEffect::Materialize
            && matches!(
                code,
                FindingCode::MaterializeIo | FindingCode::MaterializeUnsafeComponent
            ))
}

fn encode_findings(encoder: &mut Encoder, findings: &[Finding]) -> Result<(), RecordError> {
    validate_findings(findings)?;
    encoder.u32(u32::try_from(findings.len()).map_err(|_| {
        RecordError::new(
            RecordErrorKind::LimitExceeded,
            encoder.bytes.len(),
            "finding count exceeds the record integer limit",
        )
    })?);
    for finding in findings {
        encode_finding(encoder, finding)?;
    }
    Ok(())
}

fn decode_findings(cursor: &mut Cursor<'_>) -> Result<Vec<Finding>, RecordError> {
    let count = cursor.count(
        MAX_FINDINGS,
        MIN_FINDING_BYTES,
        "finding count exceeds its bound or remaining bytes",
    )?;
    let mut findings = Vec::new();
    findings.try_reserve_exact(count).map_err(|_| {
        RecordError::new(
            RecordErrorKind::AllocationFailed,
            cursor.offset(),
            "bounded finding allocation failed",
        )
    })?;
    for _ in 0..count {
        findings.push(decode_finding(cursor)?);
    }
    Ok(findings)
}

fn validate_findings(findings: &[Finding]) -> Result<(), RecordError> {
    if findings.len() > MAX_FINDINGS {
        return Err(RecordError::new(
            RecordErrorKind::LimitExceeded,
            0,
            "finding count exceeds its bound",
        ));
    }
    for finding in findings {
        validate_finding(finding)?;
    }
    Ok(())
}

fn first_error_index(findings: &[Finding]) -> Result<usize, RecordError> {
    findings
        .iter()
        .position(|finding| finding.severity == Severity::Error)
        .ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "terminal record lacks an error finding",
            )
        })
}

fn partial_parts(completeness: &ViewCompleteness) -> Result<(&StoppingPhase, &str), RecordError> {
    match completeness {
        ViewCompleteness::Partial { phase, cause } => Ok((phase, cause)),
        ViewCompleteness::Complete => Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "terminal planning record claims a complete view",
        )),
    }
}

fn encode_interpretation(encoder: &mut Encoder, value: &InterpretationStatus) {
    encoder.u8(match value {
        InterpretationStatus::Interpreted => 0,
        InterpretationStatus::Malformed => 1,
        InterpretationStatus::Unsupported => 2,
        InterpretationStatus::Indeterminate => 3,
    });
}

fn decode_interpretation(cursor: &mut Cursor<'_>) -> Result<InterpretationStatus, RecordError> {
    match cursor.u8()? {
        0 => Ok(InterpretationStatus::Interpreted),
        1 => Ok(InterpretationStatus::Malformed),
        2 => Ok(InterpretationStatus::Unsupported),
        3 => Ok(InterpretationStatus::Indeterminate),
        _ => Err(RecordError::new(
            RecordErrorKind::InvalidEnum,
            cursor.offset().saturating_sub(1),
            "interpretation status tag is invalid",
        )),
    }
}

fn encode_admission(encoder: &mut Encoder, value: &AdmissionStatus) {
    encoder.u8(match value {
        AdmissionStatus::Admitted => 0,
        AdmissionStatus::Denied => 1,
        AdmissionStatus::NotEvaluated => 2,
    });
}

fn decode_admission(cursor: &mut Cursor<'_>) -> Result<AdmissionStatus, RecordError> {
    match cursor.u8()? {
        0 => Ok(AdmissionStatus::Admitted),
        1 => Ok(AdmissionStatus::Denied),
        2 => Ok(AdmissionStatus::NotEvaluated),
        _ => Err(RecordError::new(
            RecordErrorKind::InvalidEnum,
            cursor.offset().saturating_sub(1),
            "admission status tag is invalid",
        )),
    }
}

fn encode_stopping_phase(encoder: &mut Encoder, value: &StoppingPhase) {
    encoder.u8(match value {
        StoppingPhase::Source => 0,
        StoppingPhase::Structure => 1,
        StoppingPhase::Admission => 2,
        StoppingPhase::Verification => 3,
        StoppingPhase::Effect => 4,
    });
}

fn decode_stopping_phase(cursor: &mut Cursor<'_>) -> Result<StoppingPhase, RecordError> {
    match cursor.u8()? {
        0 => Ok(StoppingPhase::Source),
        1 => Ok(StoppingPhase::Structure),
        2 => Ok(StoppingPhase::Admission),
        3 => Ok(StoppingPhase::Verification),
        4 => Ok(StoppingPhase::Effect),
        _ => Err(RecordError::new(
            RecordErrorKind::InvalidEnum,
            cursor.offset().saturating_sub(1),
            "stopping phase tag is invalid",
        )),
    }
}

#[cfg(feature = "__internal-fuzzing")]
pub(crate) fn exercise_fuzz_input(input: &[u8]) {
    fuzzing::exercise(input);
}

#[cfg(feature = "__internal-fuzzing")]
mod fuzzing {
    use std::sync::OnceLock;

    use super::*;
    use crate::apply::{
        apply_with_options, plan_source, ApplyOptions, PlanDecision, PlanningContext, Request,
        Source,
    };
    use crate::policy::Policy;

    struct FuzzContext {
        source: Vec<u8>,
        binding: InvocationBinding,
        planning: ValidatedPlanningRecord,
        pending_ir_json: Vec<u8>,
        planning_bytes: Vec<u8>,
        terminal_bytes: Vec<u8>,
        completion_bytes: Vec<u8>,
        stopped_bytes: Vec<u8>,
    }

    pub(super) fn exercise(input: &[u8]) {
        static CONTEXTS: OnceLock<[FuzzContext; 2]> = OnceLock::new();
        let contexts = CONTEXTS.get_or_init(|| {
            [
                context(ZipInterpretationProfile::StrictAsciiV1, false),
                context(ZipInterpretationProfile::StrictAsciiV2, true),
            ]
        });
        let selector = input.first().copied().unwrap_or_default() as usize % contexts.len();
        let context = &contexts[selector];
        let alternate = &contexts[(selector + 1) % contexts.len()];
        let mutations = input.get(1..).unwrap_or_default();

        exercise_planning(input, context);
        exercise_completion(input, context);
        if decode_completion(input, &context.planning).is_ok() {
            assert!(decode_completion(input, &alternate.planning).is_err());
        }
        exercise_planning(&context.planning_bytes, context);
        exercise_planning(&context.terminal_bytes, context);
        exercise_completion(&context.completion_bytes, context);
        exercise_completion(&context.stopped_bytes, context);

        let mut planning = context.planning_bytes.clone();
        mutate(&mut planning, mutations);
        exercise_planning(&planning, context);

        let mut terminal = context.terminal_bytes.clone();
        mutate(&mut terminal, mutations);
        exercise_planning(&terminal, context);

        let mut completion = context.completion_bytes.clone();
        mutate(&mut completion, mutations);
        exercise_completion(&completion, context);

        let mut stopped = context.stopped_bytes.clone();
        mutate(&mut stopped, mutations);
        exercise_completion(&stopped, context);
    }

    fn exercise_planning(input: &[u8], context: &FuzzContext) {
        let snapshot = SourceSnapshot::borrowed(None, &context.source);
        let first = decode_planning(input, &context.binding, &snapshot);
        let second = decode_planning(input, &context.binding, &snapshot);
        match (first, second) {
            (Ok(decoded), Ok(repeated)) => {
                assert_eq!(decoded.request_id, request_id(&context.binding).unwrap());
                assert_eq!(decoded.request_id, repeated.request_id);
                assert_eq!(decoded.plan_id, plan_id(input));
                assert_eq!(decoded.plan_id, repeated.plan_id);
                assert_eq!(encode_planning(&decoded.record).unwrap(), input);
                if matches!(
                    decoded.record.disposition,
                    PlanningDisposition::ReadyForVerification
                ) {
                    assert_eq!(
                        serde_json::to_vec(decoded.record.ir.as_ref().unwrap()).unwrap(),
                        context.pending_ir_json
                    );
                }
            }
            (Err(first), Err(second)) => {
                assert_eq!(first.kind, second.kind);
                assert_eq!(first.offset, second.offset);
                assert!(first.offset <= input.len());
            }
            _ => panic!("semantic planning decode is nondeterministic"),
        }
    }

    fn exercise_completion(input: &[u8], context: &FuzzContext) {
        let first = decode_completion(input, &context.planning);
        let second = decode_completion(input, &context.planning);
        match (first, second) {
            (Ok(decoded), Ok(repeated)) => {
                assert_eq!(decoded.interpretation, repeated.interpretation);
                assert_eq!(decoded.admission, repeated.admission);
                assert_eq!(decoded.verification, repeated.verification);
                assert_eq!(decoded.view_completeness, repeated.view_completeness);
                assert_eq!(decoded.findings, repeated.findings);
                assert_eq!(decoded.ir.members.len(), repeated.ir.members.len());
            }
            (Err(first), Err(second)) => {
                assert_eq!(first.kind, second.kind);
                assert_eq!(first.offset, second.offset);
                assert!(first.offset <= input.len());
            }
            _ => panic!("semantic completion decode is nondeterministic"),
        }
    }

    fn mutate(seed: &mut [u8], input: &[u8]) {
        for mutation in input.as_chunks::<3>().0.iter().take(128) {
            let index = usize::from(u16::from_le_bytes([mutation[0], mutation[1]])) % seed.len();
            seed[index] = mutation[2];
        }
    }

    fn context(profile: ZipInterpretationProfile, materialize: bool) -> FuzzContext {
        let source = sample_zip(!materialize);
        let policy = Policy::default_v1();
        let controls = policy.compile().expect("default policy compiles");
        let options = ApplyOptions::new().with_interpretation_profile(profile);
        let operation_source = Source::Bytes {
            path: Some("semantic-record-fuzz.zip"),
            data: &source,
        };
        let planning_context =
            PlanningContext::compile(&policy, profile).expect("fuzz fixture policy compiles");
        let ready = match plan_source(&operation_source, planning_context)
            .expect("fuzz fixture source snapshots")
        {
            PlanDecision::Ready(ready) => ready,
            PlanDecision::Terminal(terminal) => {
                panic!("valid fuzz fixture reached terminal planning: {terminal:?}")
            }
        };
        let (planning_snapshot, pending, _payloads, planning_findings, planning_context) =
            ready.into_parts();
        assert!(planning_findings.is_empty());
        assert_eq!(planning_context.controls(), controls);
        assert_eq!(planning_context.profile(), profile);
        let outcome = apply_with_options(
            Request {
                source: operation_source,
                policy: &policy,
                dest: None,
            },
            &options,
        );
        assert_eq!(outcome.admission, AdmissionStatus::Admitted);
        assert_eq!(outcome.verification, VerificationStatus::Complete);
        let completed = outcome
            .archive_ir()
            .expect("valid fuzz fixture has IR")
            .clone();
        let requested_effect = if materialize {
            RequestedEffect::Materialize
        } else {
            RequestedEffect::Inspect
        };
        let binding = InvocationBinding {
            operation_id: if materialize { [0x52; 16] } else { [0x41; 16] },
            source_len: planning_snapshot.len(),
            source_sha256: parse_hex_32(
                planning_snapshot
                    .digest()
                    .sha256()
                    .expect("planned snapshot has a digest"),
            )
            .expect("source digest is valid"),
            profile: planning_context.profile(),
            profile_sha256: parse_hex_32(&planning_context.profile().digest())
                .expect("profile digest is valid"),
            policy_id: planning_context.policy_id().to_owned(),
            policy_sha256: parse_hex_32(planning_context.policy_sha256())
                .expect("policy digest is valid"),
            budget: planning_context.controls().budget,
            target: planning_context.controls().target,
            consumer: planning_context.controls().consumer,
            requested_effect,
            target_sha256: materialize.then_some([0x54; 32]),
            member_sync: planning_context.controls().effect.member_sync,
            retention: if materialize {
                RetentionBinding::Plan {
                    paths: vec!["a.txt".into(), "nested/b.txt".into()],
                    max_member_bytes: 64,
                    max_total_bytes: 128,
                }
            } else {
                RetentionBinding::None
            },
        };
        let record = PlanningRecord {
            binding: binding.clone(),
            disposition: PlanningDisposition::ReadyForVerification,
            ir: Some(pending),
            findings: planning_findings,
        };
        let planning_bytes = encode_planning(&record).expect("reference plan encodes");
        let pending_ir_json = serde_json::to_vec(record.ir.as_ref().unwrap()).unwrap();
        let terminal = PlanningRecord {
            binding: binding.clone(),
            disposition: PlanningDisposition::Terminal(TerminalPlanningAxes {
                interpretation: InterpretationStatus::Interpreted,
                admission: AdmissionStatus::Denied,
                verification: VerificationStatus::StructureOnly,
                view_completeness: ViewCompleteness::Partial {
                    phase: StoppingPhase::Admission,
                    cause: FindingCode::PathDotDot.as_str().into(),
                },
            }),
            ir: None,
            findings: vec![
                Finding::error(FindingCode::PathDotDot, "parent path").on("../outside.txt")
            ],
        };
        let terminal_bytes = encode_planning(&terminal).expect("reference terminal encodes");
        let planning = decode_planning(&planning_bytes, &binding, &planning_snapshot)
            .expect("reference plan decodes");
        let completion = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: planning.request_id,
            plan_id: planning.plan_id,
            disposition: CompletionDisposition::Complete,
            members: completed
                .members
                .iter()
                .map(|member| MemberCompletion::Verified {
                    actual_uncomp_size: member
                        .actual_uncomp_size
                        .expect("completed member has actual size"),
                    actual_crc: member.actual_crc.expect("completed member has CRC"),
                    content_sha256: parse_hex_32(
                        member
                            .content_sha256
                            .as_deref()
                            .expect("completed member has content digest"),
                    )
                    .expect("content digest is valid"),
                })
                .collect(),
            findings: Vec::new(),
        };
        let synthesized_completion_bytes =
            encode_completion(&completion, &planning).expect("reference completion encodes");
        let completion_bytes = if materialize {
            synthesized_completion_bytes
        } else {
            let execution_snapshot = SourceSnapshot::borrowed(None, &source);
            let execution_plan = decode_planning(&planning_bytes, &binding, &execution_snapshot)
                .expect("inspect execution plan decodes");
            let executed = execution_plan
                .bind_inspect_execution(execution_snapshot)
                .expect("inspect execution plan binds")
                .execute()
                .expect("inspect execution completes");
            assert_eq!(executed.completion(), synthesized_completion_bytes);
            executed.completion().to_vec()
        };
        let first = completed.members.first().expect("fixture has members");
        let stopped = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: planning.request_id,
            plan_id: planning.plan_id,
            disposition: CompletionDisposition::Stopped {
                verified_members: 1,
                pending_members: (completed.members.len() - 1) as u64,
            },
            members: std::iter::once(MemberCompletion::Verified {
                actual_uncomp_size: first.actual_uncomp_size.unwrap(),
                actual_crc: first.actual_crc.unwrap(),
                content_sha256: parse_hex_32(first.content_sha256.as_deref().unwrap()).unwrap(),
            })
            .chain(std::iter::once(MemberCompletion::Failed {
                cause: FindingCode::CrcMismatch,
            }))
            .chain(std::iter::repeat_n(
                MemberCompletion::Pending,
                completed.members.len().saturating_sub(2),
            ))
            .collect(),
            findings: vec![Finding::error(FindingCode::CrcMismatch, "mismatch")
                .on(&completed.members[1].decoded_name)],
        };
        let stopped_bytes =
            encode_completion(&stopped, &planning).expect("reference stopped completion encodes");
        FuzzContext {
            source,
            binding,
            planning,
            pending_ir_json,
            planning_bytes,
            terminal_bytes,
            completion_bytes,
            stopped_bytes,
        }
    }

    fn sample_zip(with_descriptor: bool) -> Vec<u8> {
        let entries: [(&str, &[u8]); 2] = [("a.txt", b"a"), ("nested/b.txt", b"payload")];
        let mut archive = Vec::new();
        let mut central = Vec::new();

        for (name, data) in entries {
            let local_offset = u32::try_from(archive.len()).expect("fixture offset fits u32");
            let name_len = u16::try_from(name.len()).expect("fixture name fits u16");
            let data_len = u32::try_from(data.len()).expect("fixture data fits u32");
            let crc = crc32fast::hash(data);
            let flags = if with_descriptor { 0x0008 } else { 0 };

            push_u32(&mut archive, 0x0403_4b50);
            push_u16(&mut archive, 20);
            push_u16(&mut archive, flags);
            push_u16(&mut archive, 0);
            push_u16(&mut archive, 0);
            push_u16(&mut archive, 0);
            push_u32(&mut archive, if with_descriptor { 0 } else { crc });
            push_u32(&mut archive, if with_descriptor { 0 } else { data_len });
            push_u32(&mut archive, if with_descriptor { 0 } else { data_len });
            push_u16(&mut archive, name_len);
            push_u16(&mut archive, 0);
            archive.extend_from_slice(name.as_bytes());
            archive.extend_from_slice(data);
            if with_descriptor {
                push_u32(&mut archive, 0x0807_4b50);
                push_u32(&mut archive, crc);
                push_u32(&mut archive, data_len);
                push_u32(&mut archive, data_len);
            }

            push_u32(&mut central, 0x0201_4b50);
            push_u16(&mut central, 20);
            push_u16(&mut central, 20);
            push_u16(&mut central, flags);
            push_u16(&mut central, 0);
            push_u16(&mut central, 0);
            push_u16(&mut central, 0);
            push_u32(&mut central, crc);
            push_u32(&mut central, data_len);
            push_u32(&mut central, data_len);
            push_u16(&mut central, name_len);
            push_u16(&mut central, 0);
            push_u16(&mut central, 0);
            push_u16(&mut central, 0);
            push_u16(&mut central, 0);
            push_u32(&mut central, 0);
            push_u32(&mut central, local_offset);
            central.extend_from_slice(name.as_bytes());
        }

        let central_offset = u32::try_from(archive.len()).expect("fixture offset fits u32");
        let central_len = u32::try_from(central.len()).expect("fixture length fits u32");
        archive.extend_from_slice(&central);
        push_u32(&mut archive, 0x0605_4b50);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, entries.len() as u16);
        push_u16(&mut archive, entries.len() as u16);
        push_u32(&mut archive, central_len);
        push_u32(&mut archive, central_offset);
        push_u16(&mut archive, 0);
        archive
    }

    fn push_u16(output: &mut Vec<u8>, value: u16) {
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(&value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Cursor as IoCursor, Write};
    use std::path::PathBuf;

    use ::zip::write::SimpleFileOptions;
    use ::zip::{CompressionMethod, DateTime, System, ZipWriter};

    use super::*;
    use crate::apply::{
        apply_with_options, plan_source, ApplyOptions, Outcome, PlanDecision, PlanningContext,
        Request, Source,
    };
    use crate::outcome::EffectStatus;
    use crate::policy::{hex_sha256, Policy};
    use crate::snapshot::{
        inject_read_failure, reset_test_read_ranges, test_read_failure_is_armed, test_read_ranges,
    };
    use crate::verification::{reset_verify_payload_calls, verify_payload_calls};

    #[test]
    fn gzip_extra_finding_code_has_a_stable_wire_tag() {
        assert_eq!(finding_code_tag(FindingCode::GzipExtra), 65);
        assert_eq!(
            finding_code_from_tag(65, 0).unwrap(),
            FindingCode::GzipExtra
        );
    }

    #[test]
    fn derived_quota_finding_code_has_a_stable_wire_tag() {
        assert_eq!(finding_code_tag(FindingCode::QuotaDerived), 66);
        assert_eq!(
            finding_code_from_tag(66, 0).unwrap(),
            FindingCode::QuotaDerived
        );
    }

    #[test]
    fn gnu_tar_finding_codes_append_stable_wire_tags() {
        assert_eq!(finding_code_tag(FindingCode::TarGnuLongName), 69);
        assert_eq!(finding_code_tag(FindingCode::TarGnuState), 70);
        assert_eq!(
            finding_code_from_tag(69, 0).unwrap(),
            FindingCode::TarGnuLongName
        );
        assert_eq!(
            finding_code_from_tag(70, 0).unwrap(),
            FindingCode::TarGnuState
        );
    }

    #[test]
    fn xz_finding_codes_append_stable_wire_tags() {
        assert_eq!(finding_code_tag(FindingCode::CodecXzInvalidStream), 73);
        assert_eq!(finding_code_tag(FindingCode::CodecXzTrailingInput), 74);
        assert_eq!(
            finding_code_from_tag(73, 0).unwrap(),
            FindingCode::CodecXzInvalidStream
        );
        assert_eq!(
            finding_code_from_tag(74, 0).unwrap(),
            FindingCode::CodecXzTrailingInput
        );
    }

    #[test]
    fn bzip2_finding_codes_append_stable_wire_tags() {
        assert_eq!(finding_code_tag(FindingCode::CodecBzip2InvalidStream), 75);
        assert_eq!(finding_code_tag(FindingCode::CodecBzip2TrailingInput), 76);
        assert_eq!(
            finding_code_from_tag(75, 0).unwrap(),
            FindingCode::CodecBzip2InvalidStream
        );
        assert_eq!(
            finding_code_from_tag(76, 0).unwrap(),
            FindingCode::CodecBzip2TrailingInput
        );
    }

    #[test]
    fn sevenz_finding_codes_append_stable_wire_tags() {
        assert_eq!(finding_code_tag(FindingCode::SevenZInvalidStructure), 77);
        assert_eq!(
            finding_code_from_tag(77, 0).unwrap(),
            FindingCode::SevenZInvalidStructure
        );
    }

    #[test]
    fn zstd_finding_codes_append_stable_wire_tags() {
        assert_eq!(finding_code_tag(FindingCode::CodecZstdInvalidFrame), 71);
        assert_eq!(finding_code_tag(FindingCode::CodecZstdTrailingInput), 72);
        assert_eq!(
            finding_code_from_tag(71, 0).unwrap(),
            FindingCode::CodecZstdInvalidFrame
        );
        assert_eq!(
            finding_code_from_tag(72, 0).unwrap(),
            FindingCode::CodecZstdTrailingInput
        );
    }

    fn test_zip_evidence(member: &IrMember) -> &ZipMemberEvidence {
        member
            .zip_evidence()
            .expect("semantic-record test member must carry ZIP evidence")
    }

    fn test_zip_evidence_mut(member: &mut IrMember) -> &mut ZipMemberEvidence {
        member
            .zip_evidence_mut()
            .expect("semantic-record test member must carry ZIP evidence")
    }

    fn test_zip_covering(ir: &ArchiveIR) -> &ArchiveCovering {
        ir.zip_covering()
            .expect("semantic-record test archive must carry ZIP evidence")
    }

    fn test_zip_covering_mut(ir: &mut ArchiveIR) -> &mut ArchiveCovering {
        match &mut ir.evidence {
            ArchiveEvidence::Zip(covering) => covering,
            ArchiveEvidence::Zip64(_)
            | ArchiveEvidence::Tar(_)
            | ArchiveEvidence::TarGzip(_)
            | ArchiveEvidence::TarPax(_)
            | ArchiveEvidence::TarGnuLongName(_)
            | ArchiveEvidence::TarGzipPax(_)
            | ArchiveEvidence::TarGzipGnuLongName(_)
            | ArchiveEvidence::TarZstd(_)
            | ArchiveEvidence::TarXz(_)
            | ArchiveEvidence::TarBzip2(_)
            | ArchiveEvidence::SevenZ(_) => {
                panic!("semantic-record test archive must carry ZIP evidence")
            }
        }
    }

    fn reset_completion_materializations() {
        COMPLETION_IR_MATERIALIZATIONS.with(|count| count.set(0));
    }

    fn completion_materializations() -> usize {
        COMPLETION_IR_MATERIALIZATIONS.with(std::cell::Cell::get)
    }

    fn fail_completion_allocation_after(successes: Option<usize>) {
        COMPLETION_ALLOCATION_FAIL_AFTER.with(|remaining| remaining.set(successes));
    }

    fn set_completion_allocation_budget(bytes: Option<usize>) {
        COMPLETION_ALLOCATION_BUDGET.with(|budget| budget.set(bytes));
    }

    fn completion_allocation_budget() -> Option<usize> {
        COMPLETION_ALLOCATION_BUDGET.with(std::cell::Cell::get)
    }

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        make_zip_with_method(entries, CompressionMethod::Stored)
    }

    fn make_zip_with_method(entries: &[(&str, &[u8])], method: CompressionMethod) -> Vec<u8> {
        let entries: Vec<_> = entries
            .iter()
            .map(|(name, bytes)| (*name, *bytes, method))
            .collect();
        make_zip_with_methods(&entries)
    }

    fn make_zip_with_methods(entries: &[(&str, &[u8], CompressionMethod)]) -> Vec<u8> {
        let mut writer = ZipWriter::new(IoCursor::new(Vec::new()));
        for (name, bytes, method) in entries {
            let options = SimpleFileOptions::default()
                .compression_method(*method)
                .last_modified_time(DateTime::default())
                .system(System::Dos);
            if name.ends_with('/') {
                writer.add_directory(*name, options).unwrap();
            } else {
                writer.start_file(*name, options).unwrap();
                writer.write_all(bytes).unwrap();
            }
        }
        writer.finish().unwrap().into_inner()
    }

    fn signature_offset(bytes: &[u8], signature: [u8; 4]) -> usize {
        let offsets: Vec<_> = bytes
            .windows(signature.len())
            .enumerate()
            .filter_map(|(index, window)| (window == signature).then_some(index))
            .collect();
        assert_eq!(offsets.len(), 1);
        offsets[0]
    }

    fn signature_offsets(bytes: &[u8], signature: [u8; 4]) -> Vec<usize> {
        bytes
            .windows(signature.len())
            .enumerate()
            .filter_map(|(index, window)| (window == signature).then_some(index))
            .collect()
    }

    fn u16_at(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn add_matching_extra_fields(bytes: &mut Vec<u8>, extra: &[u8]) {
        let local = signature_offset(bytes, [0x50, 0x4b, 0x03, 0x04]);
        let central = signature_offset(bytes, [0x50, 0x4b, 0x01, 0x02]);
        let eocd = signature_offset(bytes, [0x50, 0x4b, 0x05, 0x06]);
        let central_directory_size = u32_at(bytes, eocd + 12);

        let local_name_len = usize::from(u16_at(bytes, local + 26));
        let local_extra_len = usize::from(u16_at(bytes, local + 28));
        let local_insert = local + 30 + local_name_len + local_extra_len;
        bytes.splice(local_insert..local_insert, extra.iter().copied());
        put_u16(
            bytes,
            local + 28,
            u16::try_from(local_extra_len + extra.len()).unwrap(),
        );

        let central = central + extra.len();
        let central_name_len = usize::from(u16_at(bytes, central + 28));
        let central_extra_len = usize::from(u16_at(bytes, central + 30));
        let central_insert = central + 46 + central_name_len + central_extra_len;
        bytes.splice(central_insert..central_insert, extra.iter().copied());
        put_u16(
            bytes,
            central + 30,
            u16::try_from(central_extra_len + extra.len()).unwrap(),
        );

        let eocd = eocd + extra.len() * 2;
        put_u32(
            bytes,
            eocd + 12,
            central_directory_size + u32::try_from(extra.len()).unwrap(),
        );
        put_u32(bytes, eocd + 16, u32::try_from(central).unwrap());
    }

    fn add_central_comment(bytes: &mut Vec<u8>, comment: &[u8]) {
        let central = signature_offset(bytes, [0x50, 0x4b, 0x01, 0x02]);
        let eocd = signature_offset(bytes, [0x50, 0x4b, 0x05, 0x06]);
        let central_directory_size = u32_at(bytes, eocd + 12);
        let name_len = usize::from(u16_at(bytes, central + 28));
        let extra_len = usize::from(u16_at(bytes, central + 30));
        let old_comment_len = usize::from(u16_at(bytes, central + 32));
        let insert = central + 46 + name_len + extra_len + old_comment_len;
        bytes.splice(insert..insert, comment.iter().copied());
        put_u16(
            bytes,
            central + 32,
            u16::try_from(old_comment_len + comment.len()).unwrap(),
        );
        let shifted_eocd = eocd + comment.len();
        put_u32(
            bytes,
            shifted_eocd + 12,
            central_directory_size + u32::try_from(comment.len()).unwrap(),
        );
    }

    fn add_matching_data_descriptor(bytes: &mut Vec<u8>) {
        add_matching_final_data_descriptor_at(bytes, 0);
    }

    fn add_matching_final_data_descriptor_at(bytes: &mut Vec<u8>, index: usize) {
        let locals = signature_offsets(bytes, [0x50, 0x4b, 0x03, 0x04]);
        let centrals = signature_offsets(bytes, [0x50, 0x4b, 0x01, 0x02]);
        assert_eq!(locals.len(), centrals.len());
        assert_eq!(index + 1, locals.len());
        let local = locals[index];
        let central = centrals[index];
        let central_start = centrals[0];
        let crc = u32_at(bytes, central + 16);
        let comp = u32_at(bytes, central + 20);
        let uncomp = u32_at(bytes, central + 24);
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&0x0807_4b50_u32.to_le_bytes());
        descriptor.extend_from_slice(&crc.to_le_bytes());
        descriptor.extend_from_slice(&comp.to_le_bytes());
        descriptor.extend_from_slice(&uncomp.to_le_bytes());
        bytes.splice(central_start..central_start, descriptor);

        let shifted_central = central + 16;
        let eocd = signature_offset(bytes, [0x50, 0x4b, 0x05, 0x06]);
        let local_flags = u16_at(bytes, local + 6) | 0x0008;
        let central_flags = u16_at(bytes, shifted_central + 8) | 0x0008;
        put_u16(bytes, local + 6, local_flags);
        put_u16(bytes, shifted_central + 8, central_flags);
        put_u32(bytes, eocd + 16, u32::try_from(central_start + 16).unwrap());
    }

    fn replace_declared_deflate_payload(bytes: &mut Vec<u8>, replacement: &[u8]) {
        let local = signature_offset(bytes, [0x50, 0x4b, 0x03, 0x04]);
        let central = signature_offset(bytes, [0x50, 0x4b, 0x01, 0x02]);
        let old_size = usize::try_from(u32_at(bytes, local + 18)).unwrap();
        assert_eq!(u32_at(bytes, central + 20) as usize, old_size);
        let name_len = usize::from(u16_at(bytes, local + 26));
        let extra_len = usize::from(u16_at(bytes, local + 28));
        let payload = local + 30 + name_len + extra_len;
        assert_eq!(payload + old_size, central);
        bytes.splice(payload..central, replacement.iter().copied());
        let new_size = u32::try_from(replacement.len()).unwrap();
        put_u32(bytes, local + 18, new_size);
        let shifted_central = payload + replacement.len();
        put_u32(bytes, shifted_central + 20, new_size);
        let eocd = signature_offset(bytes, [0x50, 0x4b, 0x05, 0x06]);
        put_u32(bytes, eocd + 16, u32::try_from(shifted_central).unwrap());
    }

    fn extend_declared_deflate_payload(bytes: &mut Vec<u8>, suffix: &[u8]) {
        let local = signature_offset(bytes, [0x50, 0x4b, 0x03, 0x04]);
        let central = signature_offset(bytes, [0x50, 0x4b, 0x01, 0x02]);
        let old_size = usize::try_from(u32_at(bytes, local + 18)).unwrap();
        let name_len = usize::from(u16_at(bytes, local + 26));
        let extra_len = usize::from(u16_at(bytes, local + 28));
        let payload = local + 30 + name_len + extra_len;
        assert_eq!(payload + old_size, central);
        let mut replacement = bytes[payload..central].to_vec();
        replacement.extend_from_slice(suffix);
        replace_declared_deflate_payload(bytes, &replacement);
    }

    fn set_declared_uncompressed_size(bytes: &mut [u8], size: u32) {
        let local = signature_offset(bytes, [0x50, 0x4b, 0x03, 0x04]);
        let central = signature_offset(bytes, [0x50, 0x4b, 0x01, 0x02]);
        put_u32(bytes, local + 22, size);
        put_u32(bytes, central + 24, size);
    }

    fn member_payload_range(bytes: &[u8]) -> (u64, u64) {
        let local = signature_offset(bytes, [0x50, 0x4b, 0x03, 0x04]);
        let name_len = usize::from(u16_at(bytes, local + 26));
        let extra_len = usize::from(u16_at(bytes, local + 28));
        let payload = local + 30 + name_len + extra_len;
        (payload as u64, u64::from(u32_at(bytes, local + 18)))
    }

    fn corrupt_member_crc(bytes: &mut [u8], index: usize) {
        let locals = signature_offsets(bytes, [0x50, 0x4b, 0x03, 0x04]);
        let centrals = signature_offsets(bytes, [0x50, 0x4b, 0x01, 0x02]);
        assert_eq!(locals.len(), centrals.len());
        assert!(index < locals.len());
        let wrong_crc = u32_at(bytes, centrals[index] + 16) ^ 1;
        put_u32(bytes, locals[index] + 14, wrong_crc);
        put_u32(bytes, centrals[index] + 16, wrong_crc);
    }

    fn rebind_source(binding: &mut InvocationBinding, ir: &mut ArchiveIR, source: &[u8]) {
        let digest: [u8; 32] = Sha256::digest(source).into();
        binding.source_len = source.len() as u64;
        binding.source_sha256 = digest;
        ir.source_digest = SourceDigest::available(hex_32(&digest));
    }

    fn encode_ready_planning_unchecked(record: &PlanningRecord) -> Vec<u8> {
        assert!(matches!(
            record.disposition,
            PlanningDisposition::ReadyForVerification
        ));
        let mut encoder = Encoder::new(KIND_PLANNING);
        encode_binding(&mut encoder, &record.binding).unwrap();
        encode_findings(&mut encoder, &record.findings).unwrap();
        encoder.u8(0);
        encoder.u8(1);
        encode_ir(&mut encoder, record.ir.as_ref().unwrap()).unwrap();
        encoder.finish().unwrap()
    }

    fn reference(
        bytes: &[u8],
        profile: ZipInterpretationProfile,
    ) -> (InvocationBinding, ArchiveIR, ArchiveIR) {
        let policy = Policy::default_v1();
        reference_with_policy(bytes, profile, &policy)
    }

    fn reference_with_policy(
        bytes: &[u8],
        profile: ZipInterpretationProfile,
        policy: &Policy,
    ) -> (InvocationBinding, ArchiveIR, ArchiveIR) {
        let controls = policy.compile().unwrap();
        let options = ApplyOptions::new().with_interpretation_profile(profile);
        let source = Source::Bytes {
            path: Some("semantic-record.zip"),
            data: bytes,
        };
        let verify_calls_before = verify_payload_calls();
        let planning_context = PlanningContext::compile(policy, profile).unwrap();
        let ready = match plan_source(&source, planning_context).unwrap() {
            PlanDecision::Ready(ready) => ready,
            PlanDecision::Terminal(terminal) => {
                panic!("reference source reached terminal planning: {terminal:?}")
            }
        };
        assert_eq!(verify_payload_calls(), verify_calls_before);
        let (snapshot, pending, _payloads, planning_findings, planning_context) =
            ready.into_parts();
        assert!(planning_findings.is_empty());
        assert_eq!(planning_context.controls(), controls);
        assert_eq!(planning_context.profile(), profile);
        assert_eq!(planning_context.policy_id(), policy.id);
        assert_eq!(planning_context.policy_sha256(), policy.digest_hex());
        let binding = binding_for_planned(&snapshot, &planning_context, RequestedEffect::Inspect);
        let outcome = apply_with_options(
            Request {
                source,
                policy,
                dest: None,
            },
            &options,
        );
        assert_eq!(outcome.admission, AdmissionStatus::Admitted);
        assert_eq!(outcome.verification, VerificationStatus::Complete);
        let completed = outcome.archive_ir().unwrap().clone();
        (binding, pending, completed)
    }

    fn ready_plan(binding: InvocationBinding, ir: ArchiveIR) -> PlanningRecord {
        ready_plan_with_findings(binding, ir, Vec::new())
    }

    fn ready_plan_with_findings(
        binding: InvocationBinding,
        ir: ArchiveIR,
        findings: Vec<Finding>,
    ) -> PlanningRecord {
        PlanningRecord {
            binding,
            disposition: PlanningDisposition::ReadyForVerification,
            ir: Some(ir),
            findings,
        }
    }

    fn decode_plan(
        input: &[u8],
        expected: &InvocationBinding,
        source: &[u8],
    ) -> Result<ValidatedPlanningRecord, RecordError> {
        let snapshot = SourceSnapshot::borrowed(None, source);
        decode_planning(input, expected, &snapshot)
    }

    fn encoded_max_metadata_offset(binding: &InvocationBinding) -> usize {
        HEADER_BYTES
            + 16
            + 8
            + 32
            + 1
            + 32
            + 4
            + binding.policy_id.len()
            + 32
            + 1
            + 8 * 4
            + 1
            + 8
            + 4
    }

    fn complete_states(ir: &ArchiveIR) -> Vec<MemberCompletion> {
        ir.members
            .iter()
            .map(|member| MemberCompletion::Verified {
                actual_uncomp_size: member.actual_uncomp_size.unwrap(),
                actual_crc: member.actual_crc.unwrap(),
                content_sha256: parse_hex_32(member.content_sha256.as_deref().unwrap()).unwrap(),
            })
            .collect()
    }

    fn assert_ir_eq(left: &ArchiveIR, right: &ArchiveIR) {
        assert_eq!(
            serde_json::to_vec(left).unwrap(),
            serde_json::to_vec(right).unwrap()
        );
    }

    fn binding_for(
        bytes: &[u8],
        profile: ZipInterpretationProfile,
        policy: &Policy,
        requested_effect: RequestedEffect,
    ) -> InvocationBinding {
        let controls = policy.compile().unwrap();
        InvocationBinding {
            operation_id: match requested_effect {
                RequestedEffect::Inspect => [0x41; 16],
                RequestedEffect::Materialize => [0x52; 16],
            },
            source_len: bytes.len() as u64,
            source_sha256: Sha256::digest(bytes).into(),
            profile,
            profile_sha256: parse_hex_32(&profile.digest()).unwrap(),
            policy_id: policy.id.clone(),
            policy_sha256: parse_hex_32(&policy.digest_hex()).unwrap(),
            budget: controls.budget,
            target: controls.target,
            consumer: controls.consumer,
            requested_effect,
            target_sha256: (requested_effect == RequestedEffect::Materialize).then_some([0x54; 32]),
            member_sync: controls.effect.member_sync,
            retention: RetentionBinding::None,
        }
    }

    fn binding_for_planned(
        snapshot: &SourceSnapshot<'_>,
        context: &PlanningContext,
        requested_effect: RequestedEffect,
    ) -> InvocationBinding {
        let controls = context.controls();
        InvocationBinding {
            operation_id: match requested_effect {
                RequestedEffect::Inspect => [0x41; 16],
                RequestedEffect::Materialize => [0x52; 16],
            },
            source_len: snapshot.len(),
            source_sha256: parse_hex_32(
                snapshot
                    .digest()
                    .sha256()
                    .expect("planned snapshots always have a digest"),
            )
            .unwrap(),
            profile: context.profile(),
            profile_sha256: parse_hex_32(&context.profile().digest()).unwrap(),
            policy_id: context.policy_id().to_owned(),
            policy_sha256: parse_hex_32(context.policy_sha256()).unwrap(),
            budget: controls.budget,
            target: controls.target,
            consumer: controls.consumer,
            requested_effect,
            target_sha256: (requested_effect == RequestedEffect::Materialize).then_some([0x54; 32]),
            member_sync: controls.effect.member_sync,
            retention: RetentionBinding::None,
        }
    }

    fn enum_name(value: &impl serde::Serialize) -> String {
        let value = serde_json::to_value(value).unwrap();
        value
            .as_str()
            .or_else(|| value.get("status").and_then(serde_json::Value::as_str))
            .unwrap()
            .to_owned()
    }

    fn verification_name(value: &VerificationStatus) -> String {
        match value {
            VerificationStatus::StructureOnly => "structure-only",
            VerificationStatus::Partial { .. } => "partial",
            VerificationStatus::Complete => "complete",
        }
        .to_owned()
    }

    fn ir_digest(ir: &ArchiveIR) -> String {
        hex_32(&Sha256::digest(serde_json::to_vec(ir).unwrap()).into())
    }

    fn bytes_digest(bytes: &[u8]) -> String {
        hex_32(&Sha256::digest(bytes).into())
    }

    fn hex_bytes(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn frontier(ir: &ArchiveIR) -> Vec<String> {
        ir.members
            .iter()
            .map(|member| match &member.verification {
                MemberVerification::Pending => "pending".to_owned(),
                MemberVerification::Verified => "verified".to_owned(),
                MemberVerification::Failed { cause } => format!("failed:{cause}"),
            })
            .collect()
    }

    fn phase_and_cause(completeness: &ViewCompleteness) -> (Option<String>, Option<String>) {
        match completeness {
            ViewCompleteness::Complete => (None, None),
            ViewCompleteness::Partial { phase, cause } => {
                (Some(enum_name(phase)), Some(cause.clone()))
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct FindingSignature {
        severity: String,
        code: String,
        member: Option<String>,
    }

    #[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct ShadowEvidence {
        name: String,
        profile_id: String,
        policy_id: String,
        policy_sha256: String,
        requested_effect: String,
        retention: String,
        finding_code: Option<String>,
        interpretation: String,
        admission: String,
        verification: String,
        effect: String,
        phase: Option<String>,
        cause: Option<String>,
        verified_members: Option<u64>,
        pending_members: Option<u64>,
        source_sha256: String,
        request_id: String,
        plan_id: String,
        pending_ir_sha256: Option<String>,
        final_ir_sha256: Option<String>,
        frontier: Vec<String>,
        findings: Vec<FindingSignature>,
        findings_sha256: Option<String>,
        planning_frame_sha256: String,
        completion_frame_sha256: Option<String>,
    }

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct ShadowManifest {
        schema: String,
        operation_ids: Vec<String>,
        cases: Vec<ShadowEvidence>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "kebab-case")]
    enum ShadowOracle {
        ApplyOutcomeParity,
        BackendSemanticParity,
        SupervisorReproducedTerminal,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "kebab-case")]
    enum ShadowBackend {
        MemoryBorrowed,
        PrivateFile,
    }

    #[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct ShadowPredecessor {
        schema: String,
        path: String,
        bytes: u64,
        sha256: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct ShadowCaseV2 {
        oracles: Vec<ShadowOracle>,
        backend: ShadowBackend,
        parity_group: Option<String>,
        evidence: ShadowEvidence,
    }

    #[derive(Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct ShadowManifestV2 {
        schema: String,
        predecessor: ShadowPredecessor,
        operation_ids: Vec<String>,
        cases: Vec<ShadowCaseV2>,
    }

    struct CompletionArtifact {
        plan: ValidatedPlanningRecord,
        bytes: Vec<u8>,
    }

    fn assert_historical_shadow_semantics(historical: &ShadowEvidence, current: &ShadowEvidence) {
        let mut normalized = current.clone();
        normalized.plan_id.clone_from(&historical.plan_id);
        normalized
            .planning_frame_sha256
            .clone_from(&historical.planning_frame_sha256);
        normalized
            .completion_frame_sha256
            .clone_from(&historical.completion_frame_sha256);
        assert_eq!(historical, &normalized);
    }

    #[allow(clippy::too_many_arguments)]
    fn evidence(
        name: &str,
        bytes: &[u8],
        outcome: &Outcome,
        finding_code: Option<FindingCode>,
        plan: &ValidatedPlanningRecord,
        pending: Option<&ArchiveIR>,
        planning_frame: &[u8],
        completion_frame: Option<&[u8]>,
        hash_findings: bool,
    ) -> ShadowEvidence {
        let (phase, cause) = phase_and_cause(&outcome.view_completeness);
        let (verified_members, pending_members) = match &outcome.verification {
            VerificationStatus::Partial {
                verified_members,
                pending_members,
            } => (Some(*verified_members), Some(*pending_members)),
            _ => (None, None),
        };
        ShadowEvidence {
            name: name.to_owned(),
            profile_id: plan.record.binding.profile.id().to_owned(),
            policy_id: plan.record.binding.policy_id.clone(),
            policy_sha256: hex_32(&plan.record.binding.policy_sha256),
            requested_effect: match plan.record.binding.requested_effect {
                RequestedEffect::Inspect => "inspect",
                RequestedEffect::Materialize => "materialize",
            }
            .to_owned(),
            retention: match &plan.record.binding.retention {
                RetentionBinding::None => "none",
                RetentionBinding::Plan { .. } => "plan",
            }
            .to_owned(),
            finding_code: finding_code.map(|code| code.as_str().to_owned()),
            interpretation: enum_name(&outcome.interpretation),
            admission: enum_name(&outcome.admission),
            verification: verification_name(&outcome.verification),
            effect: enum_name(&outcome.effect),
            phase,
            cause,
            verified_members,
            pending_members,
            source_sha256: hex_32(&Sha256::digest(bytes).into()),
            request_id: hex_32(&plan.request_id),
            plan_id: hex_32(&plan.plan_id),
            pending_ir_sha256: pending.map(ir_digest),
            final_ir_sha256: outcome.archive_ir().map(ir_digest),
            frontier: outcome.archive_ir().map(frontier).unwrap_or_default(),
            findings: outcome
                .view
                .findings
                .iter()
                .map(|finding| FindingSignature {
                    severity: enum_name(&finding.severity),
                    code: finding.code.as_str().to_owned(),
                    member: finding.member.clone(),
                })
                .collect(),
            findings_sha256: hash_findings
                .then(|| bytes_digest(&serde_json::to_vec(&outcome.view.findings).unwrap())),
            planning_frame_sha256: bytes_digest(planning_frame),
            completion_frame_sha256: completion_frame.map(bytes_digest),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assert_outcome(
        name: &str,
        outcome: &Outcome,
        interpretation: InterpretationStatus,
        admission: AdmissionStatus,
        verification: VerificationStatus,
        effect: EffectStatus,
        completeness: ViewCompleteness,
        finding_code: Option<FindingCode>,
    ) {
        assert_eq!(outcome.interpretation, interpretation, "{name}");
        assert_eq!(outcome.admission, admission, "{name}");
        assert_eq!(outcome.verification, verification, "{name}");
        assert_eq!(outcome.effect, effect, "{name}");
        assert_eq!(outcome.view_completeness, completeness, "{name}");
        assert_eq!(outcome.view.findings, outcome.receipt.findings, "{name}");
        let errors: Vec<_> = outcome
            .view
            .findings
            .iter()
            .filter(|finding| finding.severity == Severity::Error)
            .collect();
        match finding_code {
            None => assert!(errors.is_empty(), "{name}: {errors:?}"),
            Some(code) => {
                assert_eq!(errors.len(), 1, "{name}: {errors:?}");
                assert_eq!(errors[0].code, code, "{name}");
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_completion_shadow(
        name: &str,
        bytes: &[u8],
        policy: &Policy,
        expected_interpretation: InterpretationStatus,
        expected_admission: AdmissionStatus,
        expected_verification: VerificationStatus,
        expected_effect: EffectStatus,
        expected_completeness: ViewCompleteness,
        finding_code: Option<FindingCode>,
    ) -> (ShadowEvidence, CompletionArtifact) {
        run_completion_shadow_for_backend(
            name,
            bytes,
            ZipInterpretationProfile::StrictAsciiV1,
            policy,
            ShadowBackend::MemoryBorrowed,
            expected_interpretation,
            expected_admission,
            expected_verification,
            expected_effect,
            expected_completeness,
            finding_code,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn run_terminal_shadow(
        name: &str,
        bytes: &[u8],
        policy: &Policy,
        interpretation: InterpretationStatus,
        admission: AdmissionStatus,
        phase: StoppingPhase,
        finding_code: FindingCode,
    ) -> ShadowEvidence {
        run_terminal_shadow_for_profile(
            name,
            bytes,
            ZipInterpretationProfile::StrictAsciiV1,
            policy,
            interpretation,
            admission,
            phase,
            finding_code,
        )
        .0
    }

    #[allow(clippy::too_many_arguments)]
    fn run_completion_shadow_for_backend(
        name: &str,
        bytes: &[u8],
        profile: ZipInterpretationProfile,
        policy: &Policy,
        backend: ShadowBackend,
        expected_interpretation: InterpretationStatus,
        expected_admission: AdmissionStatus,
        expected_verification: VerificationStatus,
        expected_effect: EffectStatus,
        expected_completeness: ViewCompleteness,
        finding_code: Option<FindingCode>,
    ) -> (ShadowEvidence, CompletionArtifact) {
        let controls = policy.compile().unwrap();
        let mut source_file = (backend == ShadowBackend::PrivateFile)
            .then(|| TempShadowFile::new(&format!("{name}-source.zip"), bytes));
        let planning_path = source_file.as_ref().map(|file| file.path().to_owned());
        let planning_source = match backend {
            ShadowBackend::MemoryBorrowed => Source::Bytes {
                path: Some("semantic-shadow-v2.zip"),
                data: bytes,
            },
            ShadowBackend::PrivateFile => Source::Path(planning_path.as_deref().unwrap()),
        };
        let verify_calls_before = verify_payload_calls();
        let planning_context = PlanningContext::compile(policy, profile).unwrap();
        let ready = match plan_source(&planning_source, planning_context).unwrap() {
            PlanDecision::Ready(ready) => ready,
            PlanDecision::Terminal(terminal) => {
                panic!("{name} reached terminal planning: {terminal:?}")
            }
        };
        assert_eq!(verify_payload_calls(), verify_calls_before, "{name}");

        let outcome = match backend {
            ShadowBackend::MemoryBorrowed => apply_with_options(
                Request {
                    source: Source::Bytes {
                        path: Some("semantic-shadow-v2.zip"),
                        data: bytes,
                    },
                    policy,
                    dest: None,
                },
                &ApplyOptions::new().with_interpretation_profile(profile),
            ),
            ShadowBackend::PrivateFile => apply_with_options(
                Request {
                    source: Source::Path(source_file.as_ref().unwrap().path()),
                    policy,
                    dest: None,
                },
                &ApplyOptions::new().with_interpretation_profile(profile),
            ),
        };
        assert_eq!(
            outcome.receipt.source_snapshot,
            match backend {
                ShadowBackend::MemoryBorrowed => crate::snapshot::SnapshotKind::MemoryBorrowed,
                ShadowBackend::PrivateFile => crate::snapshot::SnapshotKind::PrivateFile,
            },
            "{name}"
        );
        assert_outcome(
            name,
            &outcome,
            expected_interpretation,
            expected_admission,
            expected_verification,
            expected_effect,
            expected_completeness,
            finding_code,
        );

        if let Some(file) = &mut source_file {
            file.remove();
        }
        let (execution_snapshot, pending, _payloads, planning_findings, planning_context) =
            ready.into_parts();
        assert_eq!(planning_context.controls(), controls, "{name}");
        let binding = binding_for_planned(
            &execution_snapshot,
            &planning_context,
            RequestedEffect::Inspect,
        );
        let expected_planning_findings = planning_findings.clone();
        let plan_bytes = encode_planning(&ready_plan_with_findings(
            binding.clone(),
            pending.clone(),
            planning_findings,
        ))
        .unwrap();
        let plan = decode_planning(&plan_bytes, &binding, &execution_snapshot).unwrap();
        let correlation_plan = decode_plan(&plan_bytes, &binding, bytes).unwrap();
        assert_eq!(encode_planning(&plan.record).unwrap(), plan_bytes, "{name}");
        assert_eq!(plan.record.binding, binding, "{name}");
        assert_eq!(plan.record.findings, expected_planning_findings, "{name}");
        assert_ir_eq(plan.record.ir.as_ref().unwrap(), &pending);
        assert_eq!(plan.request_id, request_id(&binding).unwrap(), "{name}");
        assert_eq!(plan.plan_id, plan_id(&plan_bytes), "{name}");

        let final_ir = outcome.archive_ir().expect("completion outcome retains IR");
        crate::zip::reset_parse_calls();
        let executed = plan
            .bind_inspect_execution(execution_snapshot)
            .unwrap()
            .execute()
            .unwrap();
        assert_eq!(crate::zip::parse_calls(), 0, "{name}");
        let decoded = decode_completion(executed.completion(), executed.planning()).unwrap();
        assert_eq!(decoded.interpretation, outcome.interpretation, "{name}");
        assert_eq!(decoded.admission, outcome.admission, "{name}");
        assert_eq!(decoded.verification, outcome.verification, "{name}");
        assert_eq!(
            decoded.view_completeness, outcome.view_completeness,
            "{name}"
        );
        assert_eq!(decoded.findings, outcome.view.findings, "{name}");
        assert_ir_eq(&decoded.ir, final_ir);
        assert_eq!(frontier(&decoded.ir), frontier(final_ir), "{name}");
        let shadow = evidence(
            name,
            bytes,
            &outcome,
            finding_code,
            executed.planning(),
            Some(&pending),
            &plan_bytes,
            Some(executed.completion()),
            true,
        );
        let completion_bytes = executed.completion().to_vec();
        (
            shadow,
            CompletionArtifact {
                plan: correlation_plan,
                bytes: completion_bytes,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn run_terminal_shadow_for_profile(
        name: &str,
        bytes: &[u8],
        profile: ZipInterpretationProfile,
        policy: &Policy,
        interpretation: InterpretationStatus,
        admission: AdmissionStatus,
        phase: StoppingPhase,
        finding_code: FindingCode,
    ) -> (ShadowEvidence, ValidatedPlanningRecord) {
        let source = Source::Bytes {
            path: Some("semantic-shadow-v2-terminal.bin"),
            data: bytes,
        };
        let verify_calls_before = verify_payload_calls();
        let planning_context = PlanningContext::compile(policy, profile).unwrap();
        let terminal = match plan_source(&source, planning_context).unwrap() {
            PlanDecision::Terminal(terminal) => terminal,
            PlanDecision::Ready(ready) => panic!("{name} unexpectedly reached Ready: {ready:?}"),
        };
        assert_eq!(verify_payload_calls(), verify_calls_before, "{name}");
        let outcome = apply_with_options(
            Request {
                source,
                policy,
                dest: None,
            },
            &ApplyOptions::new().with_interpretation_profile(profile),
        );
        let (snapshot, magic, planning_ir, planning_findings, planning_axes, planning_context) =
            terminal.into_parts();
        let binding = binding_for_planned(&snapshot, &planning_context, RequestedEffect::Inspect);
        let completeness = ViewCompleteness::Partial {
            phase,
            cause: finding_code.as_str().to_owned(),
        };
        assert_outcome(
            name,
            &outcome,
            interpretation.clone(),
            admission.clone(),
            VerificationStatus::StructureOnly,
            EffectStatus::NotRequested,
            completeness.clone(),
            Some(finding_code),
        );
        assert_eq!(magic, outcome.view.source.magic, "{name}");
        assert_eq!(
            planning_axes.interpretation, outcome.interpretation,
            "{name}"
        );
        assert_eq!(planning_axes.admission, outcome.admission, "{name}");
        assert_eq!(planning_axes.verification, outcome.verification, "{name}");
        assert_eq!(planning_axes.effect, outcome.effect, "{name}");
        assert_eq!(
            planning_axes.view_completeness, outcome.view_completeness,
            "{name}"
        );
        assert_eq!(planning_findings, outcome.view.findings, "{name}");
        assert!(planning_ir.is_none(), "{name}");
        assert!(outcome.archive_ir().is_none(), "{name}");
        let record = PlanningRecord {
            binding: binding.clone(),
            disposition: PlanningDisposition::Terminal(TerminalPlanningAxes {
                interpretation: planning_axes.interpretation,
                admission: planning_axes.admission,
                verification: VerificationStatus::StructureOnly,
                view_completeness: planning_axes.view_completeness,
            }),
            ir: None,
            findings: planning_findings,
        };
        let record_bytes = encode_planning(&record).unwrap();
        let plan = decode_planning(&record_bytes, &binding, &snapshot).unwrap();
        assert_eq!(
            encode_planning(&plan.record).unwrap(),
            record_bytes,
            "{name}"
        );
        assert_eq!(plan.record.disposition, record.disposition, "{name}");
        assert_eq!(plan.record.findings, outcome.view.findings, "{name}");
        assert!(plan.record.ir.is_none(), "{name}");
        (
            evidence(
                name,
                bytes,
                &outcome,
                Some(finding_code),
                &plan,
                None,
                &record_bytes,
                None,
                true,
            ),
            plan,
        )
    }

    fn run_covering_terminal_shadow_v2(name: &str, policy: &Policy) -> ShadowEvidence {
        let profile = ZipInterpretationProfile::StrictAsciiV2;
        let valid_bytes = make_zip(&[("covering.txt", b"covering")]);
        let (_, mut retained_ir, _) = reference_with_policy(&valid_bytes, profile, policy);
        let mut bytes = valid_bytes;
        let eocd_offset = usize::try_from(test_zip_covering(&retained_ir).eocd.offset).unwrap();
        bytes[eocd_offset] ^= 0xff;

        let binding = binding_for(&bytes, profile, policy, RequestedEffect::Inspect);
        retained_ir.source_digest = SourceDigest::available(hex_32(&binding.source_sha256));
        let ready_bytes =
            encode_planning(&ready_plan(binding.clone(), retained_ir.clone())).unwrap();
        assert_eq!(
            decode_plan(&ready_bytes, &binding, &bytes)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState,
            "{name}"
        );

        let snapshot = SourceSnapshot::borrowed(None, &bytes);
        let finding = audit_covering(&snapshot, &retained_ir).unwrap_err();
        assert_eq!(finding.code, FindingCode::CoveringInconsistent, "{name}");
        let record = PlanningRecord {
            binding: binding.clone(),
            disposition: PlanningDisposition::Terminal(TerminalPlanningAxes {
                interpretation: InterpretationStatus::Malformed,
                admission: AdmissionStatus::Denied,
                verification: VerificationStatus::StructureOnly,
                view_completeness: ViewCompleteness::Partial {
                    phase: StoppingPhase::Structure,
                    cause: FindingCode::CoveringInconsistent.as_str().to_owned(),
                },
            }),
            ir: Some(retained_ir.clone()),
            findings: vec![finding],
        };
        let record_bytes = encode_planning(&record).unwrap();
        let plan = decode_planning(&record_bytes, &binding, &snapshot).unwrap();
        assert_eq!(
            encode_planning(&plan.record).unwrap(),
            record_bytes,
            "{name}"
        );
        assert_eq!(plan.record.disposition, record.disposition, "{name}");
        assert_eq!(plan.record.findings, record.findings, "{name}");
        assert_ir_eq(plan.record.ir.as_ref().unwrap(), &retained_ir);

        ShadowEvidence {
            name: name.to_owned(),
            profile_id: binding.profile.id().to_owned(),
            policy_id: binding.policy_id.clone(),
            policy_sha256: hex_32(&binding.policy_sha256),
            requested_effect: "inspect".to_owned(),
            retention: "none".to_owned(),
            finding_code: Some(FindingCode::CoveringInconsistent.as_str().to_owned()),
            interpretation: "malformed".to_owned(),
            admission: "denied".to_owned(),
            verification: "structure-only".to_owned(),
            effect: "not-requested".to_owned(),
            phase: Some("structure".to_owned()),
            cause: Some(FindingCode::CoveringInconsistent.as_str().to_owned()),
            verified_members: None,
            pending_members: None,
            source_sha256: hex_32(&binding.source_sha256),
            request_id: hex_32(&plan.request_id),
            plan_id: hex_32(&plan.plan_id),
            pending_ir_sha256: Some(ir_digest(&retained_ir)),
            final_ir_sha256: None,
            frontier: frontier(&retained_ir),
            findings: plan
                .record
                .findings
                .iter()
                .map(|finding| FindingSignature {
                    severity: enum_name(&finding.severity),
                    code: finding.code.as_str().to_owned(),
                    member: finding.member.clone(),
                })
                .collect(),
            findings_sha256: Some(bytes_digest(
                &serde_json::to_vec(&plan.record.findings).unwrap(),
            )),
            planning_frame_sha256: bytes_digest(&record_bytes),
            completion_frame_sha256: None,
        }
    }

    struct TempShadowFile {
        path: PathBuf,
        present: bool,
    }

    impl TempShadowFile {
        fn new(label: &str, bytes: &[u8]) -> Self {
            let path = temp_shadow_dest(label);
            fs::write(&path, bytes).unwrap();
            Self {
                path,
                present: true,
            }
        }

        fn path(&self) -> &std::path::Path {
            &self.path
        }

        fn remove(&mut self) {
            if self.present {
                fs::remove_file(&self.path).unwrap();
                self.present = false;
            }
        }
    }

    impl Drop for TempShadowFile {
        fn drop(&mut self) {
            if self.present {
                let _ = fs::remove_file(&self.path);
            }
        }
    }

    fn temp_shadow_dest(label: &str) -> PathBuf {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        std::env::temp_dir().join(format!("sealr-semantic-shadow-{label}-{suffix}"))
    }

    #[test]
    fn shared_planner_is_plan_only_and_owns_the_exact_snapshot() {
        let bytes = make_zip_with_method(
            &[("planned.txt", b"planned".as_slice())],
            CompressionMethod::Deflated,
        );
        let policy = Policy::default_v1();
        let controls = policy.compile().unwrap();
        let profile = ZipInterpretationProfile::StrictAsciiV2;
        let mut caller_file = TempShadowFile::new("shared-plan-source.zip", &bytes);
        let caller_path = caller_file.path().to_owned();
        let source = Source::Path(&caller_path);

        crate::zip::reset_parse_calls();
        reset_verify_payload_calls();
        let planning_context = PlanningContext::compile(&policy, profile).unwrap();
        let ready = match plan_source(&source, planning_context).unwrap() {
            PlanDecision::Ready(ready) => ready,
            PlanDecision::Terminal(terminal) => {
                panic!("valid shared-plan fixture reached terminal planning: {terminal:?}")
            }
        };
        assert_eq!(crate::zip::parse_calls(), 1);
        assert_eq!(verify_payload_calls(), 0);

        caller_file.remove();
        assert!(!caller_path.exists());
        let (snapshot, pending, _payloads, planning_findings, context) = ready.into_parts();
        assert_eq!(snapshot.kind(), crate::snapshot::SnapshotKind::PrivateFile);
        assert_eq!(snapshot.len(), bytes.len() as u64);
        assert_eq!(
            snapshot.digest().sha256(),
            Some(hex_sha256(&bytes).as_str())
        );
        assert!(planning_findings.is_empty());
        assert_eq!(context.controls(), controls);
        assert_eq!(context.profile(), profile);
        assert!(pending
            .members
            .iter()
            .all(|member| matches!(member.verification, MemberVerification::Pending)));

        let binding = binding_for_planned(&snapshot, &context, RequestedEffect::Inspect);
        let planning_bytes = encode_planning(&ready_plan_with_findings(
            binding.clone(),
            pending,
            planning_findings,
        ))
        .unwrap();
        let validated = decode_planning(&planning_bytes, &binding, &snapshot).unwrap();
        crate::zip::reset_parse_calls();
        reset_verify_payload_calls();
        let executed = validated
            .bind_inspect_execution(snapshot)
            .unwrap()
            .execute()
            .unwrap();
        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(verify_payload_calls(), 1);
        assert_eq!(
            decode_completion(executed.completion(), executed.planning())
                .unwrap()
                .verification,
            VerificationStatus::Complete
        );

        let mut one_under = policy.clone();
        one_under.max_archive_bytes = bytes.len() as u64 - 1;
        crate::zip::reset_parse_calls();
        reset_verify_payload_calls();
        assert!(plan_source(
            &Source::Bytes {
                path: Some("one-over-cap.zip"),
                data: &bytes,
            },
            PlanningContext::compile(&one_under, profile).unwrap(),
        )
        .is_err());
        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(verify_payload_calls(), 0);
    }

    fn run_setup_failure_shadow(bytes: &[u8], policy: &Policy) -> ShadowEvidence {
        let name = "setup-failure";
        let profile = ZipInterpretationProfile::StrictAsciiV1;
        let source = Source::Bytes {
            path: Some("semantic-shadow-setup.zip"),
            data: bytes,
        };
        let verify_calls_before = verify_payload_calls();
        let planning_context = PlanningContext::compile(policy, profile).unwrap();
        let ready = match plan_source(&source, planning_context).unwrap() {
            PlanDecision::Ready(ready) => ready,
            PlanDecision::Terminal(terminal) => {
                panic!("setup fixture reached terminal planning: {terminal:?}")
            }
        };
        assert_eq!(verify_payload_calls(), verify_calls_before);
        let (snapshot, pending, _payloads, planning_findings, planning_context) =
            ready.into_parts();
        let binding =
            binding_for_planned(&snapshot, &planning_context, RequestedEffect::Materialize);
        let destination = temp_shadow_dest("existing");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("sentinel.txt"), b"unchanged").unwrap();
        let outcome = apply_with_options(
            Request {
                source,
                policy,
                dest: Some(&destination),
            },
            &ApplyOptions::new().with_interpretation_profile(profile),
        );
        let completeness = ViewCompleteness::Partial {
            phase: StoppingPhase::Effect,
            cause: FindingCode::MaterializeExists.as_str().to_owned(),
        };
        assert_outcome(
            name,
            &outcome,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Admitted,
            VerificationStatus::StructureOnly,
            EffectStatus::Failed,
            completeness,
            Some(FindingCode::MaterializeExists),
        );
        assert_ir_eq(outcome.archive_ir().unwrap(), &pending);
        assert_eq!(
            fs::read(destination.join("sentinel.txt")).unwrap(),
            b"unchanged"
        );
        let plan_bytes = encode_planning(&ready_plan_with_findings(
            binding.clone(),
            pending.clone(),
            planning_findings,
        ))
        .unwrap();
        let plan = decode_plan(&plan_bytes, &binding, bytes).unwrap();
        assert_eq!(encode_planning(&plan.record).unwrap(), plan_bytes);
        let finding = outcome
            .view
            .findings
            .iter()
            .find(|finding| finding.severity == Severity::Error)
            .unwrap();
        let axes = plan.setup_failure_axes(finding).unwrap();
        assert_eq!(axes.interpretation, outcome.interpretation);
        assert_eq!(axes.admission, outcome.admission);
        assert_eq!(axes.verification, outcome.verification);
        assert_eq!(axes.effect, outcome.effect);
        assert_eq!(axes.view_completeness, outcome.view_completeness);
        let result = evidence(
            name,
            bytes,
            &outcome,
            Some(FindingCode::MaterializeExists),
            &plan,
            Some(&pending),
            &plan_bytes,
            None,
            false,
        );
        fs::remove_dir_all(destination).unwrap();
        result
    }

    fn assert_cross_case_id_swaps_reject(left: &CompletionArtifact, right: &CompletionArtifact) {
        assert_ne!(left.plan.request_id, right.plan.request_id);
        assert_ne!(left.plan.plan_id, right.plan.plan_id);
        let request_offset = HEADER_BYTES + 16;
        let plan_offset = request_offset + 32;

        let mut swapped_request = left.bytes.clone();
        swapped_request[request_offset..request_offset + 32]
            .copy_from_slice(&right.plan.request_id);
        assert_eq!(
            decode_completion(&swapped_request, &left.plan)
                .unwrap_err()
                .kind,
            RecordErrorKind::BindingMismatch
        );

        let mut swapped_plan = left.bytes.clone();
        swapped_plan[plan_offset..plan_offset + 32].copy_from_slice(&right.plan.plan_id);
        assert_eq!(
            decode_completion(&swapped_plan, &left.plan)
                .unwrap_err()
                .kind,
            RecordErrorKind::BindingMismatch
        );
    }

    #[test]
    fn semantic_shadow_v1_matches_reachable_apply_outcomes() {
        let policy = Policy::default_v1();
        let mut cases = Vec::new();

        let store = make_zip(&[("stored/a.txt", b"stored"), ("stored/b.txt", b"bytes")]);
        let (store_evidence, store_artifact) = run_completion_shadow(
            "store-complete",
            &store,
            &policy,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Admitted,
            VerificationStatus::Complete,
            EffectStatus::NotRequested,
            ViewCompleteness::Complete,
            None,
        );
        cases.push(store_evidence);

        let deflate = make_zip_with_method(
            &[("deflated.txt", b"deflated payload")],
            CompressionMethod::Deflated,
        );
        let (deflate_evidence, deflate_artifact) = run_completion_shadow(
            "deflate-complete",
            &deflate,
            &policy,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Admitted,
            VerificationStatus::Complete,
            EffectStatus::NotRequested,
            ViewCompleteness::Complete,
            None,
        );
        cases.push(deflate_evidence);

        let mut descriptor = make_zip(&[("descriptor.txt", b"descriptor payload")]);
        add_matching_data_descriptor(&mut descriptor);
        let (descriptor_evidence, _) = run_completion_shadow(
            "descriptor-complete",
            &descriptor,
            &policy,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Admitted,
            VerificationStatus::Complete,
            EffectStatus::NotRequested,
            ViewCompleteness::Complete,
            None,
        );
        cases.push(descriptor_evidence);

        let unknown_magic = b"not an archive".to_vec();
        cases.push(run_terminal_shadow(
            "unknown-magic-terminal",
            &unknown_magic,
            &policy,
            InterpretationStatus::Unsupported,
            AdmissionStatus::NotEvaluated,
            StoppingPhase::Structure,
            FindingCode::FormatUnsupported,
        ));

        let mut malformed = make_zip(&[("mismatch.txt", b"malformed")]);
        let local = signature_offset(&malformed, [0x50, 0x4b, 0x03, 0x04]);
        malformed[local + 30] ^= 1;
        cases.push(run_terminal_shadow(
            "name-mismatch-terminal",
            &malformed,
            &policy,
            InterpretationStatus::Malformed,
            AdmissionStatus::NotEvaluated,
            StoppingPhase::Structure,
            FindingCode::ZipDiffA3Name,
        ));

        let mut admission_quota_policy = policy.clone();
        admission_quota_policy.max_member_bytes = 0;
        let admission_quota = make_zip(&[("quota.txt", b"q")]);
        cases.push(run_terminal_shadow(
            "member-quota-terminal",
            &admission_quota,
            &admission_quota_policy,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Denied,
            StoppingPhase::Admission,
            FindingCode::QuotaMember,
        ));

        let mut crc_mismatch = make_zip(&[("first.txt", b"first"), ("second.txt", b"second")]);
        corrupt_member_crc(&mut crc_mismatch, 1);
        let (crc_evidence, _) = run_completion_shadow(
            "crc-mismatch-stopped",
            &crc_mismatch,
            &policy,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Denied,
            VerificationStatus::Partial {
                verified_members: 1,
                pending_members: 1,
            },
            EffectStatus::NotRequested,
            ViewCompleteness::Partial {
                phase: StoppingPhase::Verification,
                cause: FindingCode::CrcMismatch.as_str().to_owned(),
            },
            Some(FindingCode::CrcMismatch),
        );
        cases.push(crc_evidence);

        let mut declared_lie = make_zip_with_method(
            &[("declared-lie.txt", b"more than one byte")],
            CompressionMethod::Deflated,
        );
        set_declared_uncompressed_size(&mut declared_lie, 1);
        let (declared_lie_evidence, _) = run_completion_shadow(
            "declared-lie-stopped",
            &declared_lie,
            &policy,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Denied,
            VerificationStatus::Partial {
                verified_members: 0,
                pending_members: 1,
            },
            EffectStatus::NotRequested,
            ViewCompleteness::Partial {
                phase: StoppingPhase::Verification,
                cause: FindingCode::QuotaDeclaredLie.as_str().to_owned(),
            },
            Some(FindingCode::QuotaDeclaredLie),
        );
        cases.push(declared_lie_evidence);

        let mut invalid_stream = make_zip_with_method(
            &[("invalid-deflate.txt", b"deflate payload")],
            CompressionMethod::Deflated,
        );
        replace_declared_deflate_payload(&mut invalid_stream, &[0xff]);
        let (invalid_stream_evidence, _) = run_completion_shadow(
            "invalid-deflate-stopped",
            &invalid_stream,
            &policy,
            InterpretationStatus::Malformed,
            AdmissionStatus::NotEvaluated,
            VerificationStatus::Partial {
                verified_members: 0,
                pending_members: 1,
            },
            EffectStatus::NotRequested,
            ViewCompleteness::Partial {
                phase: StoppingPhase::Verification,
                cause: FindingCode::CodecDeflateInvalidStream.as_str().to_owned(),
            },
            Some(FindingCode::CodecDeflateInvalidStream),
        );
        cases.push(invalid_stream_evidence);

        let mut trailing_input = make_zip_with_method(
            &[("trailing-deflate.txt", b"deflate payload")],
            CompressionMethod::Deflated,
        );
        extend_declared_deflate_payload(&mut trailing_input, &[0xde, 0xad, 0xbe, 0xef]);
        let (trailing_input_evidence, _) = run_completion_shadow(
            "trailing-deflate-stopped",
            &trailing_input,
            &policy,
            InterpretationStatus::Malformed,
            AdmissionStatus::NotEvaluated,
            VerificationStatus::Partial {
                verified_members: 0,
                pending_members: 1,
            },
            EffectStatus::NotRequested,
            ViewCompleteness::Partial {
                phase: StoppingPhase::Verification,
                cause: FindingCode::CodecDeflateTrailingInput.as_str().to_owned(),
            },
            Some(FindingCode::CodecDeflateTrailingInput),
        );
        cases.push(trailing_input_evidence);

        let source_io = make_zip(&[("source-io.txt", b"source bytes")]);
        let (payload_offset, payload_len) = member_payload_range(&source_io);
        let source_io_guard = inject_read_failure(payload_offset, payload_len);
        let (source_io_evidence, _) = run_completion_shadow(
            "source-io-stopped",
            &source_io,
            &policy,
            InterpretationStatus::Indeterminate,
            AdmissionStatus::Admitted,
            VerificationStatus::Partial {
                verified_members: 0,
                pending_members: 1,
            },
            EffectStatus::NotRequested,
            ViewCompleteness::Partial {
                phase: StoppingPhase::Verification,
                cause: FindingCode::SourceIo.as_str().to_owned(),
            },
            Some(FindingCode::SourceIo),
        );
        drop(source_io_guard);
        cases.push(source_io_evidence);

        let setup = make_zip(&[("setup.txt", b"setup")]);
        cases.push(run_setup_failure_shadow(&setup, &policy));

        assert_cross_case_id_swaps_reject(&store_artifact, &deflate_artifact);

        let expected_cases = [
            "store-complete",
            "deflate-complete",
            "descriptor-complete",
            "unknown-magic-terminal",
            "name-mismatch-terminal",
            "member-quota-terminal",
            "crc-mismatch-stopped",
            "declared-lie-stopped",
            "invalid-deflate-stopped",
            "trailing-deflate-stopped",
            "source-io-stopped",
            "setup-failure",
        ];
        assert_eq!(cases.len(), expected_cases.len());
        assert_eq!(
            cases
                .iter()
                .map(|case| case.name.as_str())
                .collect::<Vec<_>>(),
            expected_cases
        );

        let manifest_json = include_str!("../tests/conformance/semantic-shadow-v1.json");
        assert_eq!(manifest_json.len(), 17_119);
        assert_eq!(
            bytes_digest(manifest_json.as_bytes()),
            "b064c6945ca31603914d45a3d18775750bf30ddb667c356eb6d331673a9feb59"
        );
        let manifest: ShadowManifest = serde_json::from_str(manifest_json).unwrap();
        let unknown_field =
            manifest_json.replacen("\"schema\":", "\"unexpected\": true,\n  \"schema\":", 1);
        assert!(serde_json::from_str::<ShadowManifest>(&unknown_field).is_err());
        assert_eq!(manifest.schema, "sealr.semantic-shadow.v1");
        assert_eq!(
            manifest.operation_ids,
            vec![hex_bytes(&[0x41; 16]), hex_bytes(&[0x52; 16])]
        );
        assert_eq!(manifest.cases.len(), cases.len());
        for (historical, current) in manifest.cases.iter().zip(&cases) {
            assert_historical_shadow_semantics(historical, current);
        }
    }

    #[test]
    fn semantic_shadow_v2_additions_match_owned_oracles() {
        let default_policy = Policy::default_v1();
        let mut cases = Vec::new();
        let case = |evidence: ShadowEvidence,
                    oracles: Vec<ShadowOracle>,
                    backend: ShadowBackend,
                    parity_group: Option<&str>| ShadowCaseV2 {
            oracles,
            backend,
            parity_group: parity_group.map(str::to_owned),
            evidence,
        };

        let mut mixed = make_zip_with_methods(&[
            ("mixed/", b"", CompressionMethod::Stored),
            ("mixed/stored.txt", b"stored", CompressionMethod::Stored),
            (
                "mixed/deflated.txt",
                b"deflated payload",
                CompressionMethod::Deflated,
            ),
        ]);
        add_matching_final_data_descriptor_at(&mut mixed, 2);
        let (mixed_memory, mixed_memory_artifact) = run_completion_shadow_for_backend(
            "strict-v2-mixed-memory-complete",
            &mixed,
            ZipInterpretationProfile::StrictAsciiV2,
            &default_policy,
            ShadowBackend::MemoryBorrowed,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Admitted,
            VerificationStatus::Complete,
            EffectStatus::NotRequested,
            ViewCompleteness::Complete,
            None,
        );
        let (mixed_private, mixed_private_artifact) = run_completion_shadow_for_backend(
            "strict-v2-mixed-private-file-complete",
            &mixed,
            ZipInterpretationProfile::StrictAsciiV2,
            &default_policy,
            ShadowBackend::PrivateFile,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Admitted,
            VerificationStatus::Complete,
            EffectStatus::NotRequested,
            ViewCompleteness::Complete,
            None,
        );
        let pending = mixed_memory_artifact.plan.record.ir.as_ref().unwrap();
        assert_eq!(
            pending
                .members
                .iter()
                .map(|member| member.kind)
                .collect::<Vec<_>>(),
            vec![MemberKind::Directory, MemberKind::File, MemberKind::File]
        );
        assert_eq!(
            pending
                .members
                .iter()
                .map(|member| test_zip_evidence(member).method)
                .collect::<Vec<_>>(),
            vec![0, 0, 8]
        );
        assert_eq!(
            pending
                .members
                .iter()
                .map(|member| test_zip_evidence(member).flags)
                .collect::<Vec<_>>(),
            vec![0, 0, 0x0008]
        );
        let mut normalized_private = mixed_private.clone();
        normalized_private.name = mixed_memory.name.clone();
        assert_eq!(mixed_memory, normalized_private);
        assert_eq!(
            encode_planning(&mixed_memory_artifact.plan.record).unwrap(),
            encode_planning(&mixed_private_artifact.plan.record).unwrap()
        );
        assert_eq!(mixed_memory_artifact.bytes, mixed_private_artifact.bytes);
        cases.push(case(
            mixed_memory,
            vec![
                ShadowOracle::ApplyOutcomeParity,
                ShadowOracle::BackendSemanticParity,
            ],
            ShadowBackend::MemoryBorrowed,
            Some("strict-v2-mixed-backends"),
        ));
        cases.push(case(
            mixed_private,
            vec![
                ShadowOracle::ApplyOutcomeParity,
                ShadowOracle::BackendSemanticParity,
            ],
            ShadowBackend::PrivateFile,
            Some("strict-v2-mixed-backends"),
        ));

        let mut extra = make_zip(&[("extra.txt", b"content")]);
        add_matching_extra_fields(&mut extra, &[0x55, 0x78, 0x00, 0x00]);
        let (extra_v1, extra_v1_artifact) = run_completion_shadow_for_backend(
            "same-extra-strict-v1-complete",
            &extra,
            ZipInterpretationProfile::StrictAsciiV1,
            &default_policy,
            ShadowBackend::MemoryBorrowed,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Admitted,
            VerificationStatus::Complete,
            EffectStatus::NotRequested,
            ViewCompleteness::Complete,
            None,
        );
        let extra_ir = extra_v1_artifact.plan.record.ir.as_ref().unwrap();
        assert_eq!(
            test_zip_evidence(&extra_ir.members[0]).extra_fields.len(),
            2
        );
        assert!(test_zip_evidence(&extra_ir.members[0])
            .extra_fields
            .iter()
            .all(|extra| extra.disposition == ExtraDisposition::Ignored));
        assert!(test_zip_evidence(&extra_ir.members[0])
            .extra_fields
            .iter()
            .any(|extra| extra.site == ExtraSite::Local));
        assert!(test_zip_evidence(&extra_ir.members[0])
            .extra_fields
            .iter()
            .any(|extra| extra.site == ExtraSite::Central));
        let (extra_v2, extra_v2_plan) = run_terminal_shadow_for_profile(
            "same-extra-strict-v2-terminal",
            &extra,
            ZipInterpretationProfile::StrictAsciiV2,
            &default_policy,
            InterpretationStatus::Malformed,
            AdmissionStatus::NotEvaluated,
            StoppingPhase::Structure,
            FindingCode::ZipExtra,
        );
        assert_eq!(extra_v1.source_sha256, extra_v2.source_sha256);
        assert_ne!(extra_v1.profile_id, extra_v2.profile_id);
        assert_ne!(extra_v1.request_id, extra_v2.request_id);
        assert_ne!(extra_v1.plan_id, extra_v2.plan_id);
        let v1_plan_bytes = encode_planning(&extra_v1_artifact.plan.record).unwrap();
        let v2_binding = binding_for(
            &extra,
            ZipInterpretationProfile::StrictAsciiV2,
            &default_policy,
            RequestedEffect::Inspect,
        );
        assert_eq!(
            decode_plan(&v1_plan_bytes, &v2_binding, &extra)
                .unwrap_err()
                .kind,
            RecordErrorKind::BindingMismatch
        );
        assert_eq!(
            decode_completion(&extra_v1_artifact.bytes, &extra_v2_plan)
                .unwrap_err()
                .kind,
            RecordErrorKind::BindingMismatch
        );
        cases.push(case(
            extra_v1,
            vec![ShadowOracle::ApplyOutcomeParity],
            ShadowBackend::MemoryBorrowed,
            Some("same-extra-profile-differential"),
        ));
        cases.push(case(
            extra_v2,
            vec![ShadowOracle::ApplyOutcomeParity],
            ShadowBackend::MemoryBorrowed,
            Some("same-extra-profile-differential"),
        ));

        let (dotdot, _) = run_terminal_shadow_for_profile(
            "dotdot-terminal",
            &make_zip(&[("../outside.txt", b"nope")]),
            ZipInterpretationProfile::StrictAsciiV2,
            &default_policy,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Denied,
            StoppingPhase::Admission,
            FindingCode::PathDotDot,
        );
        cases.push(case(
            dotdot,
            vec![ShadowOracle::ApplyOutcomeParity],
            ShadowBackend::MemoryBorrowed,
            None,
        ));

        let (exact_topology, _) = run_terminal_shadow_for_profile(
            "interleaved-exact-topology-terminal",
            &make_zip(&[("a", b"file"), ("a-foo", b"sibling"), ("a/child", b"child")]),
            ZipInterpretationProfile::StrictAsciiV2,
            &default_policy,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Denied,
            StoppingPhase::Admission,
            FindingCode::PathConflict,
        );
        cases.push(case(
            exact_topology,
            vec![ShadowOracle::ApplyOutcomeParity],
            ShadowBackend::MemoryBorrowed,
            None,
        ));

        let (folded_topology, _) = run_terminal_shadow_for_profile(
            "interleaved-folded-topology-terminal",
            &make_zip(&[("A", b"file"), ("a-foo", b"sibling"), ("a/child", b"child")]),
            ZipInterpretationProfile::StrictAsciiV2,
            &default_policy,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Denied,
            StoppingPhase::Admission,
            FindingCode::PathCaseFold,
        );
        cases.push(case(
            folded_topology,
            vec![ShadowOracle::ApplyOutcomeParity],
            ShadowBackend::MemoryBorrowed,
            None,
        ));

        let total_bytes = make_zip(&[("five.bin", b"12345"), ("six.bin", b"123456")]);
        let mut total_exact_policy = default_policy.clone();
        total_exact_policy.max_total_bytes = 11;
        total_exact_policy.max_ratio = None;
        let (total_exact, _) = run_completion_shadow_for_backend(
            "total-quota-exact-complete",
            &total_bytes,
            ZipInterpretationProfile::StrictAsciiV2,
            &total_exact_policy,
            ShadowBackend::MemoryBorrowed,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Admitted,
            VerificationStatus::Complete,
            EffectStatus::NotRequested,
            ViewCompleteness::Complete,
            None,
        );
        let mut total_under_policy = total_exact_policy.clone();
        total_under_policy.max_total_bytes = 10;
        let (total_under, _) = run_terminal_shadow_for_profile(
            "total-quota-one-under-terminal",
            &total_bytes,
            ZipInterpretationProfile::StrictAsciiV2,
            &total_under_policy,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Denied,
            StoppingPhase::Admission,
            FindingCode::QuotaTotal,
        );
        cases.push(case(
            total_exact,
            vec![ShadowOracle::ApplyOutcomeParity],
            ShadowBackend::MemoryBorrowed,
            Some("total-quota-boundary"),
        ));
        cases.push(case(
            total_under,
            vec![ShadowOracle::ApplyOutcomeParity],
            ShadowBackend::MemoryBorrowed,
            Some("total-quota-boundary"),
        ));

        let ratio_payload = vec![b'x'; 4096];
        let ratio_bytes = make_zip_with_method(
            &[("ratio.bin", ratio_payload.as_slice())],
            CompressionMethod::Deflated,
        );
        let central = signature_offset(&ratio_bytes, [0x50, 0x4b, 0x01, 0x02]);
        let declared_compressed = u64::from(u32_at(&ratio_bytes, central + 20));
        let declared_uncompressed = u64::from(u32_at(&ratio_bytes, central + 24));
        let exact_ratio = declared_uncompressed.div_ceil(declared_compressed);
        assert!(exact_ratio > 0);
        let mut ratio_exact_policy = default_policy.clone();
        ratio_exact_policy.max_ratio = Some(exact_ratio);
        let (ratio_exact, _) = run_completion_shadow_for_backend(
            "ratio-quota-exact-complete",
            &ratio_bytes,
            ZipInterpretationProfile::StrictAsciiV2,
            &ratio_exact_policy,
            ShadowBackend::MemoryBorrowed,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Admitted,
            VerificationStatus::Complete,
            EffectStatus::NotRequested,
            ViewCompleteness::Complete,
            None,
        );
        let mut ratio_under_policy = ratio_exact_policy.clone();
        ratio_under_policy.max_ratio = Some(exact_ratio - 1);
        let (ratio_under, _) = run_terminal_shadow_for_profile(
            "ratio-quota-one-under-terminal",
            &ratio_bytes,
            ZipInterpretationProfile::StrictAsciiV2,
            &ratio_under_policy,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Denied,
            StoppingPhase::Admission,
            FindingCode::QuotaRatio,
        );
        cases.push(case(
            ratio_exact,
            vec![ShadowOracle::ApplyOutcomeParity],
            ShadowBackend::MemoryBorrowed,
            Some("ratio-quota-boundary"),
        ));
        cases.push(case(
            ratio_under,
            vec![ShadowOracle::ApplyOutcomeParity],
            ShadowBackend::MemoryBorrowed,
            Some("ratio-quota-boundary"),
        ));

        cases.push(case(
            run_covering_terminal_shadow_v2("covering-inconsistent-terminal", &default_policy),
            vec![ShadowOracle::SupervisorReproducedTerminal],
            ShadowBackend::MemoryBorrowed,
            None,
        ));

        let expected_names = [
            "strict-v2-mixed-memory-complete",
            "strict-v2-mixed-private-file-complete",
            "same-extra-strict-v1-complete",
            "same-extra-strict-v2-terminal",
            "dotdot-terminal",
            "interleaved-exact-topology-terminal",
            "interleaved-folded-topology-terminal",
            "total-quota-exact-complete",
            "total-quota-one-under-terminal",
            "ratio-quota-exact-complete",
            "ratio-quota-one-under-terminal",
            "covering-inconsistent-terminal",
        ];
        assert_eq!(cases.len(), expected_names.len());
        assert_eq!(
            cases
                .iter()
                .map(|case| case.evidence.name.as_str())
                .collect::<Vec<_>>(),
            expected_names
        );
        let mut unique_names = std::collections::HashSet::new();
        assert!(cases
            .iter()
            .all(|case| unique_names.insert(case.evidence.name.as_str())));
        let backend_twins: Vec<_> = cases
            .iter()
            .filter(|case| case.parity_group.as_deref() == Some("strict-v2-mixed-backends"))
            .collect();
        assert_eq!(backend_twins.len(), 2);
        assert_ne!(backend_twins[0].backend, backend_twins[1].backend);

        let v1_bytes = include_bytes!("../tests/conformance/semantic-shadow-v1.json");
        let expected = ShadowManifestV2 {
            schema: "sealr.semantic-shadow.v2".to_owned(),
            predecessor: ShadowPredecessor {
                schema: "sealr.semantic-shadow.v1".to_owned(),
                path: "crates/sealr/tests/conformance/semantic-shadow-v1.json".to_owned(),
                bytes: u64::try_from(v1_bytes.len()).unwrap(),
                sha256: bytes_digest(v1_bytes),
            },
            operation_ids: vec![hex_bytes(&[0x41; 16])],
            cases,
        };
        let manifest_json = include_str!("../tests/conformance/semantic-shadow-v2.json");
        assert_eq!(manifest_json.len(), 19_769);
        assert_eq!(
            bytes_digest(manifest_json.as_bytes()),
            "9243570b35667aaf9142483d823cb676391e8ba4a90b3594928533a0139b1967"
        );
        let manifest: ShadowManifestV2 = serde_json::from_str(manifest_json).unwrap();
        assert_eq!(manifest.schema, expected.schema);
        assert_eq!(manifest.predecessor, expected.predecessor);
        assert_eq!(manifest.operation_ids, expected.operation_ids);
        assert_eq!(manifest.cases.len(), expected.cases.len());
        for (historical, current) in manifest.cases.iter().zip(&expected.cases) {
            assert_eq!(historical.oracles, current.oracles);
            assert_eq!(historical.backend, current.backend);
            assert_eq!(historical.parity_group, current.parity_group);
            assert_historical_shadow_semantics(&historical.evidence, &current.evidence);
        }
        assert_eq!(
            manifest_json,
            format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap())
        );
        assert!(!manifest_json.starts_with('\u{feff}'));
        assert!(!manifest_json.contains('\r'));
        assert!(!manifest_json.ends_with("\n\n"));

        for unknown in [
            manifest_json.replacen("\"schema\":", "\"unexpected\": true,\n  \"schema\":", 1),
            manifest_json.replacen(
                "\"predecessor\": {",
                "\"predecessor\": {\n    \"unexpected\": true,",
                1,
            ),
            manifest_json.replacen(
                "\"oracles\": [",
                "\"unexpected\": true,\n      \"oracles\": [",
                1,
            ),
            manifest_json.replacen(
                "\"evidence\": {",
                "\"evidence\": {\n        \"unexpected\": true,",
                1,
            ),
        ] {
            assert!(serde_json::from_str::<ShadowManifestV2>(&unknown).is_err());
        }
    }

    #[test]
    fn semantic_wire_v2_round_trips_source_bound_container_facts() {
        let mut bytes = make_zip(&[("executable.py", b"print('verified')\n")]);
        let central = signature_offset(&bytes, [0x50, 0x4b, 0x01, 0x02]);
        put_u16(&mut bytes, central + 4, (3_u16 << 8) | 20);
        put_u32(&mut bytes, central + 38, 0o100755_u32 << 16);

        let policy = Policy::default_v1();
        let context =
            PlanningContext::compile(&policy, ZipInterpretationProfile::WheelUtf8V1).unwrap();
        let ready = match plan_source(
            &Source::Bytes {
                path: Some("semantic-wire-v2.zip"),
                data: &bytes,
            },
            context,
        )
        .unwrap()
        {
            PlanDecision::Ready(ready) => ready,
            PlanDecision::Terminal(terminal) => {
                panic!("wire-v2 fixture reached terminal planning: {terminal:?}")
            }
        };
        let (snapshot, pending, _payloads, findings, context) = ready.into_parts();
        assert!(findings.is_empty());
        assert_eq!(test_zip_evidence(&pending.members[0]).creator_system, 3);
        assert_eq!(
            test_zip_evidence(&pending.members[0]).external_attributes,
            0o100755_u32 << 16
        );

        let binding = binding_for_planned(&snapshot, &context, RequestedEffect::Inspect);
        let frame = encode_planning(&ready_plan_with_findings(
            binding.clone(),
            pending,
            findings,
        ))
        .unwrap();
        assert_eq!(u16::from_le_bytes([frame[8], frame[9]]), VERSION);
        assert_eq!(frame.len(), 436);
        assert_eq!(
            bytes_digest(&frame),
            "b7f7f8bd068b3392799b8abff78a689d61118e8c9377bac0f3a7d17b8c471ea3"
        );

        let plan = decode_planning(&frame, &binding, &snapshot).unwrap();
        let facts = plan.record.ir.as_ref().unwrap().members[0]
            .container_facts()
            .expect("semantic-record test member must expose ZIP container facts");
        assert_eq!(facts.creator_system, 3);
        assert_eq!(facts.external_attributes, 0o100755_u32 << 16);
        assert_eq!(facts.unix_mode(), Some(0o100755));
        assert!(facts.pypa_installer_0_7_executable());

        let mut forged = plan.record.clone();
        test_zip_evidence_mut(&mut forged.ir.as_mut().unwrap().members[0]).creator_system = 0;
        let forged_frame = encode_planning(&forged).unwrap();
        assert_eq!(
            decode_planning(&forged_frame, &binding, &snapshot)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );
    }

    #[test]
    fn inspect_executor_owns_snapshot_and_reads_only_planned_payload_ranges() {
        let mut ignored_extra = make_zip(&[("extra.txt", b"content")]);
        add_matching_extra_fields(&mut ignored_extra, &[0x55, 0x78, 0x00, 0x00]);
        let cases = [
            (ZipInterpretationProfile::StrictAsciiV1, make_zip(&[]), 0),
            (ZipInterpretationProfile::StrictAsciiV1, ignored_extra, 1),
            (
                ZipInterpretationProfile::StrictAsciiV2,
                make_zip(&[("dir/", b""), ("dir/file.txt", b"payload")]),
                1,
            ),
        ];

        for (profile, bytes, expected_payloads) in cases {
            crate::zip::reset_parse_calls();
            let (binding, pending, completed) = reference(&bytes, profile);
            let parse_calls_before_execution = crate::zip::parse_calls();
            assert_eq!(parse_calls_before_execution, 2);
            let plan_bytes =
                encode_planning(&ready_plan(binding.clone(), pending.clone())).unwrap();
            let plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
            let structural = test_zip_covering(&pending).eocd;
            let structural_failure = inject_read_failure(structural.offset, structural.len);
            reset_verify_payload_calls();
            let bound = plan
                .bind_inspect_execution(SourceSnapshot::borrowed(None, &bytes))
                .unwrap();
            reset_test_read_ranges();

            let executed = bound.execute().unwrap();

            assert_eq!(crate::zip::parse_calls(), parse_calls_before_execution);
            assert_eq!(verify_payload_calls(), expected_payloads);
            let payload_ranges: Vec<_> = pending
                .members
                .iter()
                .filter(|member| !matches!(member.kind, MemberKind::Directory))
                .map(|member| test_zip_evidence(member).source_ranges.compressed_payload)
                .collect();
            for (offset, len) in test_read_ranges() {
                let end = offset.checked_add(len).unwrap();
                assert!(payload_ranges.iter().any(|range| {
                    let range_end = range.offset.checked_add(range.len).unwrap();
                    offset >= range.offset && end <= range_end
                }));
            }
            assert_eq!(
                test_read_ranges().is_empty(),
                payload_ranges.iter().all(|range| range.len == 0)
            );
            assert!(test_read_failure_is_armed());
            let decoded = decode_completion(executed.completion(), executed.planning()).unwrap();
            assert_ir_eq(&decoded.ir, &completed);
            assert_eq!(decoded.verification, VerificationStatus::Complete);
            drop(structural_failure);
        }
    }

    #[test]
    fn inspect_executor_private_snapshot_matches_memory_after_source_removal() {
        let bytes = make_zip_with_method(
            &[("first.txt", b"first"), ("second.txt", b"second")],
            CompressionMethod::Deflated,
        );
        let (binding, pending, _) = reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);
        let plan_bytes = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
        let memory_plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
        let private_plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();

        let source_path = temp_shadow_dest("executor-private-source.zip");
        fs::write(&source_path, &bytes).unwrap();
        let private_snapshot = SourceSnapshot::private_file_from_path(
            &source_path,
            None,
            binding.budget.max_archive_bytes,
        )
        .unwrap();
        fs::remove_file(&source_path).unwrap();

        crate::zip::reset_parse_calls();
        let memory = memory_plan
            .bind_inspect_execution(SourceSnapshot::borrowed(None, &bytes))
            .unwrap()
            .execute()
            .unwrap();
        let private = private_plan
            .bind_inspect_execution(private_snapshot)
            .unwrap()
            .execute()
            .unwrap();

        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(memory.completion(), private.completion());
        let decoded = decode_completion(private.completion(), private.planning()).unwrap();
        assert_eq!(decoded.verification, VerificationStatus::Complete);
    }

    #[test]
    fn inspect_executor_rejects_ineligible_or_unbound_work_without_payload_reads() {
        let bytes = make_zip(&[("file.txt", b"payload")]);
        let (binding, pending, _) = reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);

        let plan_bytes = encode_planning(&ready_plan(binding.clone(), pending.clone())).unwrap();
        let wrong_snapshot_plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
        let wrong_snapshot = SourceSnapshot::borrowed(None, b"different snapshot");
        assert_eq!(
            wrong_snapshot_plan
                .bind_inspect_execution(wrong_snapshot)
                .unwrap_err()
                .kind,
            RecordErrorKind::BindingMismatch
        );

        let digest_mismatch_plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
        let mut same_length_snapshot = bytes.clone();
        let last = same_length_snapshot.last_mut().unwrap();
        *last ^= 1;
        assert_eq!(
            digest_mismatch_plan
                .bind_inspect_execution(SourceSnapshot::borrowed(None, &same_length_snapshot))
                .unwrap_err()
                .kind,
            RecordErrorKind::BindingMismatch
        );

        let mut materialize_binding = binding_for(
            &bytes,
            ZipInterpretationProfile::StrictAsciiV1,
            &Policy::default_v1(),
            RequestedEffect::Materialize,
        );
        materialize_binding.operation_id = [0x52; 16];
        let materialize_bytes =
            encode_planning(&ready_plan(materialize_binding.clone(), pending.clone())).unwrap();
        let materialize_plan =
            decode_plan(&materialize_bytes, &materialize_binding, &bytes).unwrap();
        assert_eq!(
            materialize_plan
                .bind_inspect_execution(SourceSnapshot::borrowed(None, &bytes))
                .unwrap_err()
                .kind,
            RecordErrorKind::PhaseMismatch
        );

        let mut retention_binding = binding.clone();
        retention_binding.retention = RetentionBinding::Plan {
            paths: Vec::new(),
            max_member_bytes: 0,
            max_total_bytes: 0,
        };
        let retention_bytes =
            encode_planning(&ready_plan(retention_binding.clone(), pending.clone())).unwrap();
        let retention_plan = decode_plan(&retention_bytes, &retention_binding, &bytes).unwrap();
        let retention_execution = retention_plan
            .bind_inspect_execution(SourceSnapshot::borrowed(None, &bytes))
            .unwrap()
            .execute()
            .unwrap();
        assert_eq!(
            retained_content::validate(
                retention_execution.planning(),
                retention_execution.completion(),
                retention_execution.retained_content(),
            )
            .unwrap(),
            retained_content::RetainedContentEvidence {
                requested_paths: 0,
                retained_members: 0,
                retained_bytes: 0,
            }
        );

        let terminal_record = PlanningRecord {
            binding: binding.clone(),
            disposition: PlanningDisposition::Terminal(TerminalPlanningAxes {
                interpretation: InterpretationStatus::Interpreted,
                admission: AdmissionStatus::Denied,
                verification: VerificationStatus::StructureOnly,
                view_completeness: ViewCompleteness::Partial {
                    phase: StoppingPhase::Admission,
                    cause: FindingCode::QuotaMember.as_str().into(),
                },
            }),
            ir: None,
            findings: vec![Finding::error(
                FindingCode::QuotaMember,
                "declared member size exceeded the member cap",
            )],
        };
        let terminal_bytes = encode_planning(&terminal_record).unwrap();
        let terminal_plan = decode_plan(&terminal_bytes, &binding, &bytes).unwrap();
        crate::zip::reset_parse_calls();
        reset_verify_payload_calls();
        assert_eq!(
            terminal_plan
                .bind_inspect_execution(SourceSnapshot::borrowed(None, &bytes))
                .unwrap_err()
                .kind,
            RecordErrorKind::PhaseMismatch
        );
        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(verify_payload_calls(), 0);

        let allocation_plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
        let allocation_failure = executor::fail_state_reservation();
        crate::zip::reset_parse_calls();
        reset_verify_payload_calls();
        assert_eq!(
            allocation_plan
                .bind_inspect_execution(SourceSnapshot::borrowed(None, &bytes))
                .unwrap()
                .execute()
                .unwrap_err()
                .kind,
            RecordErrorKind::AllocationFailed
        );
        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(verify_payload_calls(), 0);
        drop(allocation_failure);

        let encoder_plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
        let bound = encoder_plan
            .bind_inspect_execution(SourceSnapshot::borrowed(None, &bytes))
            .unwrap();
        let encoder_failure = fail_encoder_reservation();
        crate::zip::reset_parse_calls();
        reset_verify_payload_calls();
        assert_eq!(
            bound.execute().unwrap_err().kind,
            RecordErrorKind::AllocationFailed
        );
        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(verify_payload_calls(), 1);
        drop(encoder_failure);
    }

    #[test]
    fn inspect_executor_matches_end_of_stream_lie_and_source_io_after_prefix() {
        let policy = Policy::default_v1();

        let mut overstated = make_zip_with_method(
            &[("overstated.txt", b"short payload")],
            CompressionMethod::Deflated,
        );
        set_declared_uncompressed_size(&mut overstated, 64);
        run_completion_shadow(
            "declared-size-overstated",
            &overstated,
            &policy,
            InterpretationStatus::Interpreted,
            AdmissionStatus::Denied,
            VerificationStatus::Partial {
                verified_members: 0,
                pending_members: 1,
            },
            EffectStatus::NotRequested,
            ViewCompleteness::Partial {
                phase: StoppingPhase::Verification,
                cause: FindingCode::QuotaDeclaredLie.as_str().to_owned(),
            },
            Some(FindingCode::QuotaDeclaredLie),
        );

        let source_io = make_zip(&[("first.txt", b"first"), ("second.txt", b"second")]);
        let (_, pending, _) = reference(&source_io, ZipInterpretationProfile::StrictAsciiV1);
        let second_payload = test_zip_evidence(&pending.members[1])
            .source_ranges
            .compressed_payload;
        let source_io_failure = inject_read_failure(second_payload.offset, second_payload.len);
        run_completion_shadow(
            "source-io-after-prefix",
            &source_io,
            &policy,
            InterpretationStatus::Indeterminate,
            AdmissionStatus::Admitted,
            VerificationStatus::Partial {
                verified_members: 1,
                pending_members: 1,
            },
            EffectStatus::NotRequested,
            ViewCompleteness::Partial {
                phase: StoppingPhase::Verification,
                cause: FindingCode::SourceIo.as_str().to_owned(),
            },
            Some(FindingCode::SourceIo),
        );
        drop(source_io_failure);
    }

    #[test]
    fn inspect_executor_stops_at_middle_failure_and_leaves_later_payload_unread() {
        let mut bytes = make_zip(&[
            ("first.txt", b"first"),
            ("second.txt", b"second"),
            ("third.txt", b"third"),
        ]);
        let (_, pending, _) = reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);
        let third_payload = test_zip_evidence(&pending.members[2])
            .source_ranges
            .compressed_payload;
        corrupt_member_crc(&mut bytes, 1);
        let later_payload_failure = inject_read_failure(third_payload.offset, third_payload.len);
        reset_verify_payload_calls();

        let (_, artifact) = run_completion_shadow(
            "crc-middle-frontier",
            &bytes,
            &Policy::default_v1(),
            InterpretationStatus::Interpreted,
            AdmissionStatus::Denied,
            VerificationStatus::Partial {
                verified_members: 1,
                pending_members: 2,
            },
            EffectStatus::NotRequested,
            ViewCompleteness::Partial {
                phase: StoppingPhase::Verification,
                cause: FindingCode::CrcMismatch.as_str().to_owned(),
            },
            Some(FindingCode::CrcMismatch),
        );

        assert_eq!(verify_payload_calls(), 4);
        assert!(test_read_failure_is_armed());
        let decoded = decode_completion(&artifact.bytes, &artifact.plan).unwrap();
        assert!(matches!(
            &decoded.ir.members[0].verification,
            MemberVerification::Verified
        ));
        assert!(matches!(
            &decoded.ir.members[1].verification,
            MemberVerification::Failed { .. }
        ));
        assert!(matches!(
            &decoded.ir.members[2].verification,
            MemberVerification::Pending
        ));
        drop(later_payload_failure);
    }

    #[test]
    fn inspect_executor_runs_at_exact_resource_boundaries_and_denies_one_under() {
        let execute_exact = |bytes: &[u8], policy: &Policy, expected_payloads: u64| {
            let (binding, pending, completed) =
                reference_with_policy(bytes, ZipInterpretationProfile::StrictAsciiV1, policy);
            let plan_bytes = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
            let plan = decode_plan(&plan_bytes, &binding, bytes).unwrap();
            reset_verify_payload_calls();
            let executed = plan
                .bind_inspect_execution(SourceSnapshot::borrowed(None, bytes))
                .unwrap()
                .execute()
                .unwrap();
            assert_eq!(verify_payload_calls(), expected_payloads);
            let decoded = decode_completion(executed.completion(), executed.planning()).unwrap();
            assert_eq!(decoded.verification, VerificationStatus::Complete);
            assert_ir_eq(&decoded.ir, &completed);
        };
        let deny_one_under = |bytes: &[u8], policy: &Policy, expected: FindingCode| {
            reset_verify_payload_calls();
            let source = Source::Bytes {
                path: Some("semantic-budget-boundary.zip"),
                data: bytes,
            };
            let planning_context =
                PlanningContext::compile(policy, ZipInterpretationProfile::StrictAsciiV1).unwrap();
            let terminal = match plan_source(&source, planning_context).unwrap() {
                PlanDecision::Terminal(terminal) => terminal,
                PlanDecision::Ready(ready) => {
                    panic!("one-under fixture unexpectedly reached Ready: {ready:?}")
                }
            };
            let (_snapshot, _magic, ir, findings, axes, _context) = terminal.into_parts();
            assert!(ir.is_none());
            assert_eq!(axes.admission, AdmissionStatus::Denied);
            assert_eq!(axes.verification, VerificationStatus::StructureOnly);
            assert_eq!(
                findings
                    .iter()
                    .find(|finding| finding.severity == Severity::Error)
                    .unwrap()
                    .code,
                expected
            );
            assert_eq!(verify_payload_calls(), 0);
            let outcome = apply_with_options(
                Request {
                    source,
                    policy,
                    dest: None,
                },
                &ApplyOptions::new()
                    .with_interpretation_profile(ZipInterpretationProfile::StrictAsciiV1),
            );
            assert_eq!(outcome.admission, AdmissionStatus::Denied);
            assert_eq!(outcome.verification, VerificationStatus::StructureOnly);
            assert_eq!(
                outcome
                    .view
                    .findings
                    .iter()
                    .find(|finding| finding.severity == Severity::Error)
                    .unwrap()
                    .code,
                expected
            );
            assert_eq!(verify_payload_calls(), 0);
        };

        let aggregate = make_zip(&[("five.bin", b"12345"), ("six.bin", b"123456")]);
        let mut member_exact = Policy::default_v1();
        member_exact.max_member_bytes = 6;
        member_exact.max_ratio = None;
        execute_exact(&aggregate, &member_exact, 2);
        let mut member_under = member_exact.clone();
        member_under.max_member_bytes = 5;
        deny_one_under(&aggregate, &member_under, FindingCode::QuotaMember);

        let mut total_exact = Policy::default_v1();
        total_exact.max_total_bytes = 11;
        total_exact.max_ratio = None;
        execute_exact(&aggregate, &total_exact, 2);
        let mut total_under = total_exact.clone();
        total_under.max_total_bytes = 10;
        deny_one_under(&aggregate, &total_under, FindingCode::QuotaTotal);

        let ratio_payload = vec![b'x'; 4096];
        let ratio = make_zip_with_method(
            &[("ratio.bin", ratio_payload.as_slice())],
            CompressionMethod::Deflated,
        );
        let mut ratio_unlimited = Policy::default_v1();
        ratio_unlimited.max_ratio = None;
        let (_, ratio_pending, _) = reference_with_policy(
            &ratio,
            ZipInterpretationProfile::StrictAsciiV1,
            &ratio_unlimited,
        );
        let ratio_member = &ratio_pending.members[0];
        let exact_ratio = ratio_member
            .declared_uncomp_size
            .div_ceil(test_zip_evidence(ratio_member).declared_comp_size);
        assert!(exact_ratio > 0);
        let mut ratio_exact = Policy::default_v1();
        ratio_exact.max_ratio = Some(exact_ratio);
        execute_exact(&ratio, &ratio_exact, 1);
        let mut ratio_under = ratio_exact.clone();
        ratio_under.max_ratio = Some(exact_ratio - 1);
        deny_one_under(&ratio, &ratio_under, FindingCode::QuotaRatio);
    }

    #[test]
    fn completion_rejects_unreachable_quota_and_member_specific_failures() {
        let store = make_zip(&[("stored.txt", b"stored")]);
        let (binding, pending, _) = reference(&store, ZipInterpretationProfile::StrictAsciiV1);
        let plan_bytes = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
        let plan = decode_plan(&plan_bytes, &binding, &store).unwrap();

        for code in [
            FindingCode::QuotaMember,
            FindingCode::QuotaTotal,
            FindingCode::QuotaRatio,
            FindingCode::QuotaOverflow,
            FindingCode::CodecDeflateInvalidStream,
            FindingCode::CodecDeflateTrailingInput,
        ] {
            let forged = CompletionRecord {
                operation_id: plan.record.binding.operation_id,
                request_id: plan.request_id,
                plan_id: plan.plan_id,
                disposition: CompletionDisposition::Stopped {
                    verified_members: 0,
                    pending_members: 1,
                },
                members: vec![MemberCompletion::Failed { cause: code }],
                findings: vec![Finding::error(code, "unreachable executor cause").on("stored.txt")],
            };
            assert_eq!(
                encode_completion(&forged, &plan).unwrap_err().kind,
                RecordErrorKind::InvalidSemanticState,
                "{code:?}"
            );
            let hostile = encode_completion_validated(&forged).unwrap();
            assert_eq!(
                decode_completion(&hostile, &plan).unwrap_err().kind,
                RecordErrorKind::InvalidSemanticState,
                "{code:?}"
            );
        }

        let directory = make_zip(&[("directory/", b"")]);
        let (directory_binding, directory_pending, _) =
            reference(&directory, ZipInterpretationProfile::StrictAsciiV1);
        let directory_plan_bytes =
            encode_planning(&ready_plan(directory_binding.clone(), directory_pending)).unwrap();
        let directory_plan =
            decode_plan(&directory_plan_bytes, &directory_binding, &directory).unwrap();
        let forged_directory = CompletionRecord {
            operation_id: directory_plan.record.binding.operation_id,
            request_id: directory_plan.request_id,
            plan_id: directory_plan.plan_id,
            disposition: CompletionDisposition::Stopped {
                verified_members: 0,
                pending_members: 1,
            },
            members: vec![MemberCompletion::Failed {
                cause: FindingCode::CrcMismatch,
            }],
            findings: vec![
                Finding::error(FindingCode::CrcMismatch, "directory CRC").on("directory/")
            ],
        };
        assert_eq!(
            encode_completion(&forged_directory, &directory_plan)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );
    }

    #[test]
    fn path_topology_rejects_interleaved_file_ancestors() {
        let mut exact = [("a", false), ("a-foo", false), ("a/child", false)];
        assert_eq!(
            validate_path_topology(&mut exact, None).unwrap_err().kind,
            RecordErrorKind::InvalidSemanticState
        );

        let mut folded = [("A", false), ("a-foo", false), ("a/child", false)];
        assert_eq!(
            validate_path_topology(&mut folded, Some(ZipInterpretationProfile::StrictAsciiV1))
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );

        let mut directory = [("a", true), ("a-foo", false), ("a/child", false)];
        validate_path_topology(&mut directory, None)
            .expect("a directory may precede descendants despite an interleaving sibling");

        let mut portable_sigma = [("\u{3c3}", false), ("\u{3c2}", false)];
        assert_eq!(
            validate_path_topology(
                &mut portable_sigma,
                Some(ZipInterpretationProfile::PortableUtf8V1)
            )
            .unwrap_err()
            .kind,
            RecordErrorKind::InvalidSemanticState
        );
        validate_path_topology(
            &mut portable_sigma,
            Some(ZipInterpretationProfile::WheelUtf8V1),
        )
        .expect("the immutable research profile retains its lowercase-only model");
    }

    #[test]
    fn ready_plan_round_trips_complete_pending_ir_in_source_order() {
        let bytes = make_zip(&[("z.txt", b"z"), ("a.txt", b"a")]);
        let (binding, pending, _) = reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);
        assert_eq!(pending.members[0].canonical_path, "z.txt");
        assert_eq!(pending.members[1].canonical_path, "a.txt");
        let encoded = encode_planning(&ready_plan(binding.clone(), pending.clone())).unwrap();
        let decoded = decode_plan(&encoded, &binding, &bytes).unwrap();
        assert_eq!(decoded.request_id, request_id(&binding).unwrap());
        assert_eq!(decoded.plan_id, plan_id(&encoded));
        assert_ir_eq(decoded.record.ir.as_ref().unwrap(), &pending);
        assert_eq!(
            decoded.record.ir.as_ref().unwrap().members[0].canonical_path,
            "z.txt"
        );
    }

    #[test]
    fn record_vector_digests_are_stable() {
        let bytes = make_zip(&[]);
        let (binding, pending, completed) =
            reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);
        let plan_bytes = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
        let plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
        let completion = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: plan.request_id,
            plan_id: plan.plan_id,
            disposition: CompletionDisposition::Complete,
            members: complete_states(&completed),
            findings: Vec::new(),
        };
        let completion_bytes = encode_completion(&completion, &plan).unwrap();
        let completion_digest: [u8; 32] = Sha256::digest(completion_bytes).into();
        assert_eq!(
            hex_32(&plan.plan_id),
            "29479161b3f063c5127184c4a207ae9eaa117a213ac57649106be0c84a280737"
        );
        assert_eq!(
            hex_32(&completion_digest),
            "7d757e89451355b90243ecd3d4b447dec705d13c86c0baec6b31e4c9ac42c10b"
        );
    }

    #[test]
    fn complete_record_reconstructs_exact_verified_ir_without_effect_authority() {
        let bytes = make_zip(&[("dir/", b""), ("dir/z.txt", b"z"), ("a.txt", b"a")]);
        let (binding, pending, completed) =
            reference(&bytes, ZipInterpretationProfile::StrictAsciiV2);
        let plan_bytes = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
        let plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
        let completion = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: plan.request_id,
            plan_id: plan.plan_id,
            disposition: CompletionDisposition::Complete,
            members: complete_states(&completed),
            findings: Vec::new(),
        };
        reset_completion_materializations();
        let encoded = encode_completion(&completion, &plan).unwrap();
        assert_eq!(completion_materializations(), 0);
        let decoded = decode_completion(&encoded, &plan).unwrap();
        assert_eq!(completion_materializations(), 1);
        assert_eq!(decoded.interpretation, InterpretationStatus::Interpreted);
        assert_eq!(decoded.admission, AdmissionStatus::Admitted);
        assert_eq!(decoded.verification, VerificationStatus::Complete);
        assert_eq!(decoded.view_completeness, ViewCompleteness::Complete);
        assert_ir_eq(&decoded.ir, &completed);
    }

    #[test]
    fn bound_completion_proposal_does_not_prove_file_content_digest() {
        let bytes = make_zip(&[("payload.bin", b"actual payload")]);
        let (binding, pending, completed) =
            reference(&bytes, ZipInterpretationProfile::StrictAsciiV2);
        let plan_bytes = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
        let plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
        let forged_digest = [0xa5; 32];
        let mut members = complete_states(&completed);
        let MemberCompletion::Verified { content_sha256, .. } = &mut members[0] else {
            panic!("file reference state must be verified");
        };
        *content_sha256 = forged_digest;
        let completion = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: plan.request_id,
            plan_id: plan.plan_id,
            disposition: CompletionDisposition::Complete,
            members,
            findings: Vec::new(),
        };

        let encoded = encode_completion(&completion, &plan).unwrap();
        let proposal = decode_completion(&encoded, &plan).unwrap();
        let forged_hex = hex_32(&forged_digest);
        assert_eq!(
            proposal.ir.members[0].content_sha256.as_deref(),
            Some(forged_hex.as_str())
        );
        assert_ne!(
            proposal.ir.members[0].content_sha256,
            completed.members[0].content_sha256
        );
    }

    #[test]
    fn every_completion_reconstruction_allocation_fails_typed_and_without_plan_mutation() {
        let bytes = make_zip(&[
            ("dir/", b""),
            ("dir/one.txt", b"one"),
            ("dir/deep/two.txt", b"two"),
        ]);
        let (binding, pending, completed) =
            reference(&bytes, ZipInterpretationProfile::StrictAsciiV2);
        let plan_bytes = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
        let plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
        let completion = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: plan.request_id,
            plan_id: plan.plan_id,
            disposition: CompletionDisposition::Complete,
            members: complete_states(&completed),
            findings: Vec::new(),
        };
        let encoded = encode_completion(&completion, &plan).unwrap();

        let mut successful_allocations = 0;
        loop {
            assert!(successful_allocations < 128);
            fail_completion_allocation_after(Some(successful_allocations));
            reset_completion_materializations();
            match decode_completion(&encoded, &plan) {
                Err(error) => {
                    assert_eq!(error.kind, RecordErrorKind::AllocationFailed);
                    assert_eq!(completion_materializations(), 1);
                    assert!(plan
                        .record
                        .ir
                        .as_ref()
                        .unwrap()
                        .members
                        .iter()
                        .all(|member| matches!(member.verification, MemberVerification::Pending)));
                    successful_allocations += 1;
                }
                Ok(decoded) => {
                    assert!(successful_allocations >= 20);
                    assert_eq!(completion_materializations(), 1);
                    assert_ir_eq(&decoded.ir, &completed);
                    break;
                }
            }
        }
        fail_completion_allocation_after(None);
    }

    #[test]
    fn scaled_record_keeps_completion_reconstruction_to_one_ir_materialization() {
        let names: Vec<String> = (0..512)
            .map(|index| format!("deep/tree/member-{index:04}.txt"))
            .collect();
        let entries: Vec<(&str, &[u8])> = names
            .iter()
            .map(|name| (name.as_str(), b"x".as_slice()))
            .collect();
        let bytes = make_zip(&entries);
        let (binding, pending, completed) =
            reference(&bytes, ZipInterpretationProfile::StrictAsciiV2);
        let plan_bytes = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
        assert!(plan_bytes.len() > 64 * 1024);
        let plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
        let completion = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: plan.request_id,
            plan_id: plan.plan_id,
            disposition: CompletionDisposition::Complete,
            members: complete_states(&completed),
            findings: Vec::new(),
        };

        reset_completion_materializations();
        let encoded = encode_completion(&completion, &plan).unwrap();
        assert_eq!(completion_materializations(), 0);

        set_completion_allocation_budget(Some(usize::MAX));
        let decoded = decode_completion(&encoded, &plan).unwrap();
        assert_eq!(completion_materializations(), 1);
        assert_ir_eq(&decoded.ir, &completed);
        let required = usize::MAX - completion_allocation_budget().unwrap();
        assert!(required > plan_bytes.len());

        set_completion_allocation_budget(Some(required - 1));
        reset_completion_materializations();
        assert_eq!(
            decode_completion(&encoded, &plan).unwrap_err().kind,
            RecordErrorKind::AllocationFailed
        );
        assert_eq!(completion_materializations(), 1);

        set_completion_allocation_budget(Some(required));
        reset_completion_materializations();
        let decoded = decode_completion(&encoded, &plan).unwrap();
        assert_eq!(completion_allocation_budget(), Some(0));
        assert_eq!(completion_materializations(), 1);
        assert_ir_eq(&decoded.ir, &completed);
        set_completion_allocation_budget(None);
    }

    #[test]
    fn stopped_record_preserves_verified_prefix_and_hostile_finding_label() {
        let bytes = make_zip(&[("z.txt", b"z"), ("a.txt", b"a"), ("m.txt", b"m")]);
        let (binding, pending, completed) =
            reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);
        let plan_bytes = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
        let plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
        let first = &completed.members[0];
        let completion = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: plan.request_id,
            plan_id: plan.plan_id,
            disposition: CompletionDisposition::Stopped {
                verified_members: 1,
                pending_members: 2,
            },
            members: vec![
                MemberCompletion::Verified {
                    actual_uncomp_size: first.actual_uncomp_size.unwrap(),
                    actual_crc: first.actual_crc.unwrap(),
                    content_sha256: parse_hex_32(first.content_sha256.as_deref().unwrap()).unwrap(),
                },
                MemberCompletion::Failed {
                    cause: FindingCode::CrcMismatch,
                },
                MemberCompletion::Pending,
            ],
            findings: vec![
                Finding {
                    code: FindingCode::CrcMismatch,
                    severity: Severity::Warn,
                    member: Some("../outside.txt".into()),
                    detail: "diagnostic only".into(),
                },
                Finding::error(FindingCode::CrcMismatch, "mismatch").on("safe.txt:hidden"),
            ],
        };
        reset_completion_materializations();
        let encoded = encode_completion(&completion, &plan).unwrap();
        assert_eq!(completion_materializations(), 0);
        let decoded = decode_completion(&encoded, &plan).unwrap();
        assert_eq!(completion_materializations(), 1);
        assert_eq!(
            decoded.verification,
            VerificationStatus::Partial {
                verified_members: 1,
                pending_members: 2,
            }
        );
        assert_eq!(
            decoded.findings[0].member.as_deref(),
            Some("../outside.txt")
        );
        assert_eq!(
            decoded.findings[1].member.as_deref(),
            Some("safe.txt:hidden")
        );
        assert!(matches!(
            decoded.ir.members[0].verification,
            MemberVerification::Verified
        ));
        assert!(matches!(
            decoded.ir.members[1].verification,
            MemberVerification::Failed { .. }
        ));
        assert!(matches!(
            decoded.ir.members[2].verification,
            MemberVerification::Pending
        ));
    }

    #[test]
    fn stopped_source_io_is_indeterminate_but_admitted() {
        let bytes = make_zip(&[("a.txt", b"a")]);
        let (binding, pending, _) = reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);
        let plan_bytes = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
        let plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
        let completion = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: plan.request_id,
            plan_id: plan.plan_id,
            disposition: CompletionDisposition::Stopped {
                verified_members: 0,
                pending_members: 1,
            },
            members: vec![MemberCompletion::Failed {
                cause: FindingCode::SourceIo,
            }],
            findings: vec![
                Finding::error(FindingCode::SourceIo, "snapshot read failed").on("a.txt"),
            ],
        };
        let encoded = encode_completion(&completion, &plan).unwrap();
        let decoded = decode_completion(&encoded, &plan).unwrap();
        assert_eq!(decoded.interpretation, InterpretationStatus::Indeterminate);
        assert_eq!(decoded.admission, AdmissionStatus::Admitted);
        assert_eq!(
            decoded.verification,
            VerificationStatus::Partial {
                verified_members: 0,
                pending_members: 1,
            }
        );
        assert_eq!(
            decoded.view_completeness,
            ViewCompleteness::Partial {
                phase: StoppingPhase::Verification,
                cause: FindingCode::SourceIo.as_str().into(),
            }
        );
        assert!(matches!(
            decoded.ir.members[0].verification,
            MemberVerification::Failed { .. }
        ));
    }

    #[test]
    fn supervisor_setup_failure_merge_matches_current_axes() {
        let bytes = make_zip(&[("a.txt", b"a")]);
        let (inspect_binding, pending, _) =
            reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);
        let encoded =
            encode_planning(&ready_plan(inspect_binding.clone(), pending.clone())).unwrap();
        let inspect_plan = decode_plan(&encoded, &inspect_binding, &bytes).unwrap();
        let finding = Finding::error(FindingCode::MaterializeUnsafeParent, "setup failed");
        assert_eq!(
            inspect_plan.setup_failure_axes(&finding).unwrap_err().kind,
            RecordErrorKind::PhaseMismatch
        );

        let mut binding = inspect_binding;
        binding.requested_effect = RequestedEffect::Materialize;
        binding.target_sha256 = Some([0x54; 32]);
        let encoded = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
        let plan = decode_plan(&encoded, &binding, &bytes).unwrap();
        assert_eq!(
            plan.setup_failure_axes(&finding).unwrap(),
            SemanticAxes::admitted_setup_failed(&finding)
        );
        let unsafe_component = Finding::error(
            FindingCode::MaterializeUnsafeComponent,
            "stage reparse point",
        );
        assert_eq!(
            plan.setup_failure_axes(&unsafe_component).unwrap(),
            SemanticAxes::admitted_setup_failed(&unsafe_component)
        );
        let unrelated = Finding::error(FindingCode::CrcMismatch, "not setup");
        assert_eq!(
            plan.setup_failure_axes(&unrelated).unwrap_err().kind,
            RecordErrorKind::InvalidSemanticState
        );
    }

    #[test]
    fn terminal_records_preserve_no_ir_and_covering_ir_states() {
        let bytes = make_zip(&[("a.txt", b"a")]);
        let (binding, mut pending, _) = reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);
        let admission_finding =
            Finding::error(FindingCode::PathDotDot, "parent path").on("../outside.txt");
        let terminal = PlanningRecord {
            binding: binding.clone(),
            disposition: PlanningDisposition::Terminal(TerminalPlanningAxes {
                interpretation: InterpretationStatus::Interpreted,
                admission: AdmissionStatus::Denied,
                verification: VerificationStatus::StructureOnly,
                view_completeness: ViewCompleteness::Partial {
                    phase: StoppingPhase::Admission,
                    cause: FindingCode::PathDotDot.as_str().into(),
                },
            }),
            ir: None,
            findings: vec![admission_finding],
        };
        let encoded = encode_planning(&terminal).unwrap();
        let decoded = decode_plan(&encoded, &binding, &bytes).unwrap();
        assert!(decoded.record.ir.is_none());
        assert_eq!(
            decoded.record.findings[0].member.as_deref(),
            Some("../outside.txt")
        );

        let mut inconsistent_bytes = bytes.clone();
        let eocd_offset = usize::try_from(test_zip_covering(&pending).eocd.offset).unwrap();
        inconsistent_bytes[eocd_offset] ^= 0xff;
        let source_sha256: [u8; 32] = Sha256::digest(&inconsistent_bytes).into();
        let mut covering_binding = binding.clone();
        covering_binding.source_sha256 = source_sha256;
        pending.source_digest = SourceDigest::available(hex_32(&source_sha256));
        let ready_bytes =
            encode_planning(&ready_plan(covering_binding.clone(), pending.clone())).unwrap();
        assert_eq!(
            decode_plan(&ready_bytes, &covering_binding, &inconsistent_bytes)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );
        let snapshot = SourceSnapshot::borrowed(None, &inconsistent_bytes);
        let covering_finding = audit_covering(&snapshot, &pending).unwrap_err();
        let covering_terminal = PlanningRecord {
            binding: covering_binding.clone(),
            disposition: PlanningDisposition::Terminal(TerminalPlanningAxes {
                interpretation: InterpretationStatus::Malformed,
                admission: AdmissionStatus::Denied,
                verification: VerificationStatus::StructureOnly,
                view_completeness: ViewCompleteness::Partial {
                    phase: StoppingPhase::Structure,
                    cause: FindingCode::CoveringInconsistent.as_str().into(),
                },
            }),
            ir: Some(pending),
            findings: vec![covering_finding],
        };
        let encoded = encode_planning(&covering_terminal).unwrap();
        let decoded = decode_plan(&encoded, &covering_binding, &inconsistent_bytes).unwrap();
        assert!(decoded.record.ir.is_some());
    }

    #[test]
    fn every_truncation_trailing_byte_and_cross_phase_decode_fails() {
        let bytes = make_zip(&[("a.txt", b"a")]);
        let (binding, pending, completed) =
            reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);
        let plan_bytes = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
        for cutoff in 0..plan_bytes.len() {
            assert!(decode_plan(&plan_bytes[..cutoff], &binding, &bytes).is_err());
        }
        let mut trailing_plan = plan_bytes.clone();
        trailing_plan.push(0);
        assert_eq!(
            decode_plan(&trailing_plan, &binding, &bytes)
                .unwrap_err()
                .kind,
            RecordErrorKind::TrailingBytes
        );
        let plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
        let completion = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: plan.request_id,
            plan_id: plan.plan_id,
            disposition: CompletionDisposition::Complete,
            members: complete_states(&completed),
            findings: Vec::new(),
        };
        let completion_bytes = encode_completion(&completion, &plan).unwrap();
        for cutoff in 0..completion_bytes.len() {
            assert!(decode_completion(&completion_bytes[..cutoff], &plan).is_err());
        }
        let mut trailing_completion = completion_bytes.clone();
        trailing_completion.push(0);
        assert_eq!(
            decode_completion(&trailing_completion, &plan)
                .unwrap_err()
                .kind,
            RecordErrorKind::TrailingBytes
        );
        assert_eq!(
            decode_plan(&completion_bytes, &binding, &bytes)
                .unwrap_err()
                .kind,
            RecordErrorKind::UnexpectedKind
        );
        assert_eq!(
            decode_completion(&plan_bytes, &plan).unwrap_err().kind,
            RecordErrorKind::UnexpectedKind
        );
    }

    #[test]
    fn header_and_structured_binding_mutations_fail_closed() {
        let bytes = make_zip(&[("a.txt", b"a")]);
        let (binding, pending, _) = reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);
        let original = ready_plan(binding.clone(), pending.clone());
        let encoded = encode_planning(&original).unwrap();
        for (offset, expected_kind) in [
            (0, RecordErrorKind::InvalidMagic),
            (8, RecordErrorKind::UnsupportedVersion),
            (10, RecordErrorKind::UnexpectedKind),
            (11, RecordErrorKind::ReservedNonZero),
        ] {
            let mut mutated = encoded.clone();
            mutated[offset] ^= 0x7f;
            assert_eq!(
                decode_plan(&mutated, &binding, &bytes).unwrap_err().kind,
                expected_kind
            );
        }

        let mut variants = Vec::new();
        let mut operation = original.clone();
        operation.binding.operation_id[0] ^= 1;
        variants.push(operation);
        let mut policy = original.clone();
        policy.binding.policy_sha256[0] ^= 1;
        variants.push(policy);
        let mut policy_id = original.clone();
        policy_id.binding.policy_id.push_str("-alternate");
        variants.push(policy_id);
        let mut budget = original.clone();
        budget.binding.budget.max_files += 1;
        variants.push(budget);
        let mut archive_budget = original.clone();
        archive_budget.binding.budget.max_archive_bytes += 1;
        variants.push(archive_budget);
        let mut member_budget = original.clone();
        member_budget.binding.budget.max_member_bytes += 1;
        variants.push(member_budget);
        let mut total_budget = original.clone();
        total_budget.binding.budget.max_total_bytes += 1;
        variants.push(total_budget);
        let mut ratio_budget = original.clone();
        ratio_budget.binding.budget.max_ratio = Some(
            ratio_budget
                .binding
                .budget
                .max_ratio
                .unwrap_or_default()
                .saturating_add(1),
        );
        variants.push(ratio_budget);
        let mut depth_budget = original.clone();
        depth_budget.binding.budget.max_path_depth += 1;
        variants.push(depth_budget);
        let mut metadata_budget = original.clone();
        metadata_budget.binding.budget.max_metadata_bytes += 1;
        variants.push(metadata_budget);
        let mut target = original.clone();
        target.binding.requested_effect = RequestedEffect::Materialize;
        target.binding.target_sha256 = Some([0x55; 32]);
        variants.push(target);
        let mut sync = original.clone();
        sync.binding.member_sync = !sync.binding.member_sync;
        variants.push(sync);
        let mut retention = original;
        retention.binding.retention = RetentionBinding::Plan {
            paths: Vec::new(),
            max_member_bytes: 0,
            max_total_bytes: 0,
        };
        variants.push(retention);
        for variant in variants {
            let mutated = encode_planning(&variant).unwrap();
            assert_eq!(
                decode_plan(&mutated, &binding, &bytes).unwrap_err().kind,
                RecordErrorKind::BindingMismatch
            );
        }

        let alternate_bytes = make_zip(&[("a.txt", b"alternate")]);
        let (alternate_binding, alternate_pending, _) =
            reference(&alternate_bytes, ZipInterpretationProfile::StrictAsciiV1);
        let alternate_source =
            encode_planning(&ready_plan(alternate_binding, alternate_pending)).unwrap();
        assert_eq!(
            decode_plan(&alternate_source, &binding, &bytes)
                .unwrap_err()
                .kind,
            RecordErrorKind::BindingMismatch
        );

        let (v2_binding, v2_pending, _) =
            reference(&bytes, ZipInterpretationProfile::StrictAsciiV2);
        let alternate_profile = encode_planning(&ready_plan(v2_binding, v2_pending)).unwrap();
        assert_eq!(
            decode_plan(&alternate_profile, &binding, &bytes)
                .unwrap_err()
                .kind,
            RecordErrorKind::BindingMismatch
        );
    }

    #[test]
    fn stale_completion_correlation_and_impossible_frontiers_fail() {
        let bytes = make_zip(&[("a.txt", b"a"), ("b.txt", b"b")]);
        let (binding, pending, completed) =
            reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);
        let plan_bytes = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
        let plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
        let valid = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: plan.request_id,
            plan_id: plan.plan_id,
            disposition: CompletionDisposition::Complete,
            members: complete_states(&completed),
            findings: Vec::new(),
        };
        reset_completion_materializations();
        let mut stale_bytes = encode_completion(&valid, &plan).unwrap();
        assert_eq!(completion_materializations(), 0);
        stale_bytes[HEADER_BYTES + 16 + 32] ^= 1;
        assert_eq!(
            decode_completion(&stale_bytes, &plan).unwrap_err().kind,
            RecordErrorKind::BindingMismatch
        );
        assert_eq!(completion_materializations(), 0);

        let impossible = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: plan.request_id,
            plan_id: plan.plan_id,
            disposition: CompletionDisposition::Stopped {
                verified_members: 0,
                pending_members: 2,
            },
            members: vec![
                MemberCompletion::Pending,
                MemberCompletion::Failed {
                    cause: FindingCode::CrcMismatch,
                },
            ],
            findings: vec![Finding::error(FindingCode::CrcMismatch, "mismatch")],
        };
        assert_eq!(
            encode_completion(&impossible, &plan).unwrap_err().kind,
            RecordErrorKind::InvalidSemanticState
        );
        assert_eq!(completion_materializations(), 0);
        let impossible_bytes = encode_completion_validated(&impossible).unwrap();
        assert_eq!(
            decode_completion(&impossible_bytes, &plan)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );
        assert_eq!(completion_materializations(), 0);

        let supervisor_owned = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: plan.request_id,
            plan_id: plan.plan_id,
            disposition: CompletionDisposition::Stopped {
                verified_members: 0,
                pending_members: 2,
            },
            members: vec![
                MemberCompletion::Failed {
                    cause: FindingCode::MaterializeAudit,
                },
                MemberCompletion::Pending,
            ],
            findings: vec![Finding::error(
                FindingCode::MaterializeAudit,
                "worker cannot claim audit",
            )],
        };
        assert_eq!(
            encode_completion(&supervisor_owned, &plan)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );
    }

    #[test]
    fn structural_ir_mutation_and_range_overflow_fail_before_encoding() {
        let bytes = make_zip(&[("z.txt", b"z"), ("a.txt", b"a")]);
        let (binding, pending, _) = reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);

        let mut reordered = pending.clone();
        reordered.members.swap(0, 1);
        assert_eq!(
            encode_planning(&ready_plan(binding.clone(), reordered))
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );

        let mut overflow = pending;
        test_zip_evidence_mut(&mut overflow.members[0])
            .source_ranges
            .local_header
            .offset = u64::MAX;
        assert_eq!(
            encode_planning(&ready_plan(binding, overflow))
                .unwrap_err()
                .kind,
            RecordErrorKind::IntegerOverflow
        );
    }

    #[test]
    fn semantic_records_reject_non_zip_archive_and_member_evidence() {
        let bytes = make_zip(&[("a.txt", b"a")]);
        let (binding, pending, _) = reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);

        let mut tar_archive = pending.clone();
        tar_archive.evidence = ArchiveEvidence::Tar(crate::ir::TarArchiveCovering {
            member_records: ByteRange { offset: 0, len: 0 },
            terminator: ByteRange { offset: 0, len: 0 },
            trailing_zeros: ByteRange { offset: 0, len: 0 },
        });
        assert_eq!(
            encode_planning(&ready_plan(binding.clone(), tar_archive))
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );

        let mut tar_member = pending;
        tar_member.members[0].evidence = MemberEvidence::Tar(crate::ir::TarMemberEvidence {
            header: ByteRange {
                offset: 0,
                len: 512,
            },
            payload: ByteRange {
                offset: 512,
                len: 1,
            },
            padding: ByteRange {
                offset: 513,
                len: 511,
            },
            mode: 0o644,
            mtime: 0,
            header_checksum: 0,
            header_sha256: "0".repeat(64),
        });
        assert_eq!(
            encode_planning(&ready_plan(binding, tar_member))
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );
    }

    #[test]
    fn planning_metadata_budget_matches_the_parser_aggregate() {
        let mut bytes = make_zip(&[("a.txt", b"a")]);
        add_matching_extra_fields(&mut bytes, &[0x55, 0x78, 0x00, 0x00]);
        let (binding, pending, _) = reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);
        let required = planning_metadata_bytes(&pending).unwrap();
        let parsed = crate::zip::parse_zip(&bytes, u64::MAX, u64::MAX).unwrap();
        assert_eq!(required, parsed.metadata_bytes);
        assert!(test_zip_evidence(&pending.members[0])
            .extra_fields
            .iter()
            .any(|extra| extra.site == ExtraSite::Local));

        let mut omitted = pending.clone();
        test_zip_evidence_mut(&mut omitted.members[0])
            .extra_fields
            .retain(|extra| extra.site != ExtraSite::Local);
        assert_eq!(
            encode_planning(&ready_plan(binding.clone(), omitted))
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );

        let mut fabricated = pending.clone();
        let zip = test_zip_evidence_mut(&mut fabricated.members[0]);
        zip.extra_fields
            .retain(|extra| extra.site != ExtraSite::Local);
        zip.source_ranges.local_header.len -= 4;
        zip.source_ranges.compressed_payload.offset -= 4;
        zip.source_ranges.compressed_payload.len += 4;
        zip.declared_comp_size += 4;
        let understated = planning_metadata_bytes(&fabricated).unwrap();
        assert_eq!(understated + 4, required);
        let mut fabricated_binding = binding.clone();
        fabricated_binding.budget.max_metadata_bytes = understated;
        let fabricated_record = ready_plan(fabricated_binding.clone(), fabricated);
        let fabricated_bytes = encode_ready_planning_unchecked(&fabricated_record);
        assert_eq!(
            decode_plan(&fabricated_bytes, &fabricated_binding, &bytes)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );

        let mut relabeled = pending.clone();
        test_zip_evidence_mut(&mut relabeled.members[0])
            .extra_fields
            .iter_mut()
            .find(|extra| extra.site == ExtraSite::Local)
            .unwrap()
            .id ^= 1;
        let relabeled_bytes = encode_planning(&ready_plan(binding.clone(), relabeled)).unwrap();
        assert_eq!(
            decode_plan(&relabeled_bytes, &binding, &bytes)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );

        let mut exact_binding = binding;
        exact_binding.budget.max_metadata_bytes = required;
        let encoded = encode_planning(&ready_plan(exact_binding.clone(), pending.clone())).unwrap();
        assert!(decode_plan(&encoded, &exact_binding, &bytes).is_ok());

        let mut under_binding = exact_binding.clone();
        under_binding.budget.max_metadata_bytes = required - 1;
        assert_eq!(
            encode_planning(&ready_plan(under_binding.clone(), pending))
                .unwrap_err()
                .kind,
            RecordErrorKind::LimitExceeded
        );

        let offset = encoded_max_metadata_offset(&exact_binding);
        assert_eq!(
            &encoded[offset..offset + 8],
            required.to_le_bytes().as_slice()
        );
        let mut hostile = encoded;
        hostile[offset..offset + 8].copy_from_slice(&(required - 1).to_le_bytes());
        assert_eq!(
            decode_plan(&hostile, &under_binding, &bytes)
                .unwrap_err()
                .kind,
            RecordErrorKind::LimitExceeded
        );
    }

    #[test]
    fn ready_record_binds_fixed_header_semantics_to_the_snapshot() {
        let bytes = make_zip(&[("a.txt", b"a")]);
        let (binding, pending, _) = reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);

        let mut forged_crc = pending.clone();
        test_zip_evidence_mut(&mut forged_crc.members[0]).declared_crc ^= 1;
        let encoded = encode_planning(&ready_plan(binding.clone(), forged_crc)).unwrap();
        assert_eq!(
            decode_plan(&encoded, &binding, &bytes).unwrap_err().kind,
            RecordErrorKind::InvalidSemanticState
        );

        let local = signature_offset(&bytes, [0x50, 0x4b, 0x03, 0x04]);
        let central = signature_offset(&bytes, [0x50, 0x4b, 0x01, 0x02]);
        let eocd = signature_offset(&bytes, [0x50, 0x4b, 0x05, 0x06]);
        let mutations = [
            (local + 8, 2_usize, 8_u32),
            (local + 14, 4, u32_at(&bytes, local + 14) ^ 1),
            (local + 18, 4, u32_at(&bytes, local + 18) + 1),
            (central + 10, 2, 8),
            (central + 16, 4, u32_at(&bytes, central + 16) ^ 1),
            (central + 20, 4, u32_at(&bytes, central + 20) + 1),
            (central + 34, 2, 1),
            (central + 38, 4, 0x10),
            (central + 42, 4, 1),
            (eocd + 4, 2, 1),
            (eocd + 6, 2, 1),
            (eocd + 8, 2, 0),
            (eocd + 10, 2, 0),
            (eocd + 12, 4, u32_at(&bytes, eocd + 12) + 1),
            (eocd + 16, 4, u32_at(&bytes, eocd + 16) + 1),
            (eocd + 20, 2, 1),
        ];
        for (offset, width, value) in mutations {
            let mut hostile_source = bytes.clone();
            match width {
                2 => put_u16(&mut hostile_source, offset, value as u16),
                4 => put_u32(&mut hostile_source, offset, value),
                _ => unreachable!(),
            }
            let mut hostile_binding = binding.clone();
            let mut hostile_ir = pending.clone();
            rebind_source(&mut hostile_binding, &mut hostile_ir, &hostile_source);
            let encoded =
                encode_planning(&ready_plan(hostile_binding.clone(), hostile_ir)).unwrap();
            assert_eq!(
                decode_plan(&encoded, &hostile_binding, &hostile_source)
                    .unwrap_err()
                    .kind,
                RecordErrorKind::InvalidSemanticState,
                "source mutation at {offset} was accepted"
            );
        }

        let mut zip64_source = bytes.clone();
        put_u32(&mut zip64_source, local + 22, u32::MAX);
        put_u32(&mut zip64_source, central + 24, u32::MAX);
        let mut zip64_binding = binding;
        let mut zip64_ir = pending;
        zip64_binding.budget.max_member_bytes = u64::MAX;
        zip64_binding.budget.max_total_bytes = u64::MAX;
        zip64_binding.budget.max_ratio = None;
        zip64_ir.members[0].declared_uncomp_size = u64::from(u32::MAX);
        rebind_source(&mut zip64_binding, &mut zip64_ir, &zip64_source);
        let encoded = encode_planning(&ready_plan(zip64_binding.clone(), zip64_ir)).unwrap();
        assert_eq!(
            decode_plan(&encoded, &zip64_binding, &zip64_source)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );
    }

    #[test]
    fn ready_record_reproduces_descriptor_and_comment_rejections() {
        let mut descriptor_source = make_zip(&[("descriptor.txt", b"descriptor")]);
        add_matching_data_descriptor(&mut descriptor_source);
        let (descriptor_binding, descriptor_ir, _) =
            reference(&descriptor_source, ZipInterpretationProfile::StrictAsciiV1);
        let descriptor = test_zip_evidence(&descriptor_ir.members[0])
            .source_ranges
            .data_descriptor
            .unwrap();
        let mut hostile_descriptor_source = descriptor_source.clone();
        let descriptor_crc = usize::try_from(descriptor.offset).unwrap() + 4;
        hostile_descriptor_source[descriptor_crc] ^= 1;
        let mut hostile_binding = descriptor_binding.clone();
        let mut hostile_ir = descriptor_ir.clone();
        rebind_source(
            &mut hostile_binding,
            &mut hostile_ir,
            &hostile_descriptor_source,
        );
        let encoded = encode_planning(&ready_plan(hostile_binding.clone(), hostile_ir)).unwrap();
        assert_eq!(
            decode_plan(&encoded, &hostile_binding, &hostile_descriptor_source)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );

        let mut ambiguous_source = descriptor_source.clone();
        let descriptor_start = usize::try_from(descriptor.offset).unwrap();
        ambiguous_source.drain(descriptor_start..descriptor_start + 4);
        put_u32(&mut ambiguous_source, descriptor_start, 0x0807_4b50);
        let ambiguous_central = signature_offset(&ambiguous_source, [0x50, 0x4b, 0x01, 0x02]);
        let ambiguous_eocd = signature_offset(&ambiguous_source, [0x50, 0x4b, 0x05, 0x06]);
        put_u32(&mut ambiguous_source, ambiguous_central + 16, 0x0807_4b50);
        put_u32(
            &mut ambiguous_source,
            ambiguous_eocd + 16,
            u32::try_from(ambiguous_central).unwrap(),
        );
        let mut ambiguous_binding = descriptor_binding;
        let mut ambiguous_ir = descriptor_ir;
        {
            let zip = test_zip_evidence_mut(&mut ambiguous_ir.members[0]);
            zip.declared_crc = 0x0807_4b50;
            zip.source_ranges.data_descriptor.as_mut().unwrap().len = 12;
            zip.source_ranges.central_header.offset -= 4;
        }
        let covering = test_zip_covering_mut(&mut ambiguous_ir);
        covering.local_records.len -= 4;
        covering.central_directory.offset -= 4;
        covering.eocd.offset -= 4;
        covering.comment.offset -= 4;
        rebind_source(&mut ambiguous_binding, &mut ambiguous_ir, &ambiguous_source);
        let encoded =
            encode_planning(&ready_plan(ambiguous_binding.clone(), ambiguous_ir)).unwrap();
        assert_eq!(
            decode_plan(&encoded, &ambiguous_binding, &ambiguous_source)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );

        let mut comment_source = make_zip(&[("comment.txt", b"content")]);
        add_central_comment(&mut comment_source, b"safe");
        let (comment_binding, comment_ir, _) =
            reference(&comment_source, ZipInterpretationProfile::StrictAsciiV1);
        let comment_range = test_zip_evidence(&comment_ir.members[0])
            .source_ranges
            .central_header;
        let comment_offset = usize::try_from(checked_end(comment_range).unwrap() - 4).unwrap();
        let mut hostile_comment_source = comment_source.clone();
        hostile_comment_source[comment_offset..comment_offset + 4]
            .copy_from_slice(&0x0605_4b50_u32.to_le_bytes());
        let mut hostile_binding = comment_binding;
        let mut hostile_ir = comment_ir;
        rebind_source(
            &mut hostile_binding,
            &mut hostile_ir,
            &hostile_comment_source,
        );
        let encoded = encode_planning(&ready_plan(hostile_binding.clone(), hostile_ir)).unwrap();
        assert_eq!(
            decode_plan(&encoded, &hostile_binding, &hostile_comment_source)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );
    }

    #[test]
    fn finding_codes_are_rejected_outside_their_execution_phase() {
        let bytes = make_zip(&[("a.txt", b"a"), ("b.txt", b"b")]);
        let (binding, pending, _) = reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);
        let invalid_structure = PlanningRecord {
            binding: binding.clone(),
            disposition: PlanningDisposition::Terminal(TerminalPlanningAxes {
                interpretation: InterpretationStatus::Malformed,
                admission: AdmissionStatus::NotEvaluated,
                verification: VerificationStatus::StructureOnly,
                view_completeness: ViewCompleteness::Partial {
                    phase: StoppingPhase::Structure,
                    cause: FindingCode::CrcMismatch.as_str().into(),
                },
            }),
            ir: None,
            findings: vec![Finding::error(FindingCode::CrcMismatch, "wrong phase")],
        };
        assert_eq!(
            encode_planning(&invalid_structure).unwrap_err().kind,
            RecordErrorKind::InvalidSemanticState
        );

        let multiple_structure_errors = PlanningRecord {
            binding: binding.clone(),
            disposition: PlanningDisposition::Terminal(TerminalPlanningAxes {
                interpretation: InterpretationStatus::Malformed,
                admission: AdmissionStatus::NotEvaluated,
                verification: VerificationStatus::StructureOnly,
                view_completeness: ViewCompleteness::Partial {
                    phase: StoppingPhase::Structure,
                    cause: FindingCode::ZipDiffC3Count.as_str().into(),
                },
            }),
            ir: None,
            findings: vec![
                Finding::error(FindingCode::ZipDiffC3Count, "first"),
                Finding::error(FindingCode::ZipDiffC4Offset, "second"),
            ],
        };
        assert_eq!(
            encode_planning(&multiple_structure_errors)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );

        let structure_with_wrong_warning = PlanningRecord {
            binding: binding.clone(),
            disposition: PlanningDisposition::Terminal(TerminalPlanningAxes {
                interpretation: InterpretationStatus::Malformed,
                admission: AdmissionStatus::NotEvaluated,
                verification: VerificationStatus::StructureOnly,
                view_completeness: ViewCompleteness::Partial {
                    phase: StoppingPhase::Structure,
                    cause: FindingCode::ZipDiffC3Count.as_str().into(),
                },
            }),
            ir: None,
            findings: vec![
                Finding::error(FindingCode::ZipDiffC3Count, "structure"),
                Finding {
                    code: FindingCode::PathUnicode,
                    severity: Severity::Warn,
                    member: None,
                    detail: "wrong-phase diagnostic".into(),
                },
            ],
        };
        assert_eq!(
            encode_planning(&structure_with_wrong_warning)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );

        let unshipped_structure_code = PlanningRecord {
            binding: binding.clone(),
            disposition: PlanningDisposition::Terminal(TerminalPlanningAxes {
                interpretation: InterpretationStatus::Malformed,
                admission: AdmissionStatus::NotEvaluated,
                verification: VerificationStatus::StructureOnly,
                view_completeness: ViewCompleteness::Partial {
                    phase: StoppingPhase::Structure,
                    cause: FindingCode::FormatMagic.as_str().into(),
                },
            }),
            ir: None,
            findings: vec![Finding::error(FindingCode::FormatMagic, "unshipped")],
        };
        assert_eq!(
            encode_planning(&unshipped_structure_code).unwrap_err().kind,
            RecordErrorKind::InvalidSemanticState
        );

        let unshipped_admission_code = PlanningRecord {
            binding: binding.clone(),
            disposition: PlanningDisposition::Terminal(TerminalPlanningAxes {
                interpretation: InterpretationStatus::Interpreted,
                admission: AdmissionStatus::Denied,
                verification: VerificationStatus::StructureOnly,
                view_completeness: ViewCompleteness::Partial {
                    phase: StoppingPhase::Admission,
                    cause: FindingCode::ZipDiffB2Chars.as_str().into(),
                },
            }),
            ir: None,
            findings: vec![Finding::error(FindingCode::ZipDiffB2Chars, "unshipped")],
        };
        assert_eq!(
            encode_planning(&unshipped_admission_code).unwrap_err().kind,
            RecordErrorKind::InvalidSemanticState
        );

        let plan_bytes = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
        let plan = decode_plan(&plan_bytes, &binding, &bytes).unwrap();
        let invalid_completion = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: plan.request_id,
            plan_id: plan.plan_id,
            disposition: CompletionDisposition::Stopped {
                verified_members: 0,
                pending_members: 2,
            },
            members: vec![
                MemberCompletion::Failed {
                    cause: FindingCode::PathDotDot,
                },
                MemberCompletion::Pending,
            ],
            findings: vec![Finding::error(FindingCode::PathDotDot, "wrong phase")],
        };
        assert_eq!(
            encode_completion(&invalid_completion, &plan)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );

        let invalid_offset_completion = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: plan.request_id,
            plan_id: plan.plan_id,
            disposition: CompletionDisposition::Stopped {
                verified_members: 0,
                pending_members: 2,
            },
            members: vec![
                MemberCompletion::Failed {
                    cause: FindingCode::ZipDiffC4Offset,
                },
                MemberCompletion::Pending,
            ],
            findings: vec![Finding::error(
                FindingCode::ZipDiffC4Offset,
                "planning already proved ranges",
            )],
        };
        assert_eq!(
            encode_completion(&invalid_offset_completion, &plan)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );

        let completion_with_wrong_warning = CompletionRecord {
            operation_id: binding.operation_id,
            request_id: plan.request_id,
            plan_id: plan.plan_id,
            disposition: CompletionDisposition::Stopped {
                verified_members: 0,
                pending_members: 2,
            },
            members: vec![
                MemberCompletion::Failed {
                    cause: FindingCode::CrcMismatch,
                },
                MemberCompletion::Pending,
            ],
            findings: vec![
                Finding {
                    code: FindingCode::PathUnicode,
                    severity: Severity::Warn,
                    member: None,
                    detail: "wrong-phase diagnostic".into(),
                },
                Finding::error(FindingCode::CrcMismatch, "execution"),
            ],
        };
        assert_eq!(
            encode_completion(&completion_with_wrong_warning, &plan)
                .unwrap_err()
                .kind,
            RecordErrorKind::InvalidSemanticState
        );
    }

    #[test]
    fn record_path_bounds_preserve_current_apply_semantics() {
        let deep_name = format!("{}leaf.txt", "a/".repeat(256));
        let deep_source = make_zip(&[(&deep_name, b"deep")]);
        let mut deep_policy = Policy::default_v1();
        deep_policy.max_path_depth = 300;
        let (binding, pending, _) = reference_with_policy(
            &deep_source,
            ZipInterpretationProfile::StrictAsciiV1,
            &deep_policy,
        );
        assert_eq!(pending.members[0].components.len(), 257);
        let encoded = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
        assert!(decode_plan(&encoded, &binding, &deep_source).is_ok());

        let mut binding_cursor = Cursor::frame(&encoded, KIND_PLANNING).unwrap();
        let _: [u8; 16] = binding_cursor.fixed().unwrap();
        binding_cursor.u64().unwrap();
        let _: [u8; 32] = binding_cursor.fixed().unwrap();
        binding_cursor.u8().unwrap();
        let _: [u8; 32] = binding_cursor.fixed().unwrap();
        binding_cursor
            .string(
                MAX_POLICY_ID_BYTES,
                "policy identifier exceeds its byte limit",
            )
            .unwrap();
        let _: [u8; 32] = binding_cursor.fixed().unwrap();
        binding_cursor.u8().unwrap();
        for _ in 0..4 {
            binding_cursor.u64().unwrap();
        }
        binding_cursor.u8().unwrap();
        binding_cursor.u64().unwrap();
        let depth_offset = binding_cursor.offset();
        assert_eq!(binding_cursor.u32().unwrap(), 300);

        let mut restricted_binding = binding.clone();
        restricted_binding.budget.max_path_depth = 32;
        let mut restricted_encoded = encoded;
        restricted_encoded[depth_offset..depth_offset + 4]
            .copy_from_slice(&restricted_binding.budget.max_path_depth.to_le_bytes());
        assert_eq!(
            decode_plan(&restricted_encoded, &restricted_binding, &deep_source)
                .unwrap_err()
                .kind,
            RecordErrorKind::LimitExceeded
        );

        let normalized_name = format!("{}leaf.txt", "./".repeat(257));
        let normalized_source = make_zip(&[(&normalized_name, b"normalized")]);
        let (binding, pending, _) =
            reference(&normalized_source, ZipInterpretationProfile::StrictAsciiV1);
        assert_eq!(pending.members[0].normalization_actions.len(), 257);
        let encoded = encode_planning(&ready_plan(binding.clone(), pending)).unwrap();
        assert!(decode_plan(&encoded, &binding, &normalized_source).is_ok());
    }

    #[test]
    fn encoder_refuses_growth_before_exceeding_its_bound() {
        let mut encoder = Encoder::new_with_limit(KIND_PLANNING, 64);
        let oversized = [0x41_u8; 64];
        assert_eq!(
            encoder.bytes(&oversized).unwrap_err().kind,
            RecordErrorKind::TooLarge
        );
        assert_eq!(encoder.bytes.len(), HEADER_BYTES);
        assert_eq!(
            encoder.finish().unwrap_err().kind,
            RecordErrorKind::TooLarge
        );
    }

    #[cfg(feature = "__internal-fuzzing")]
    #[test]
    fn semantic_fuzz_entry_smoke_test() {
        for input in [b"".as_slice(), b"SEALRSEM", &[0x41, 0, 1, 0xff, 2, 3]] {
            exercise_fuzz_input(input);
        }
    }

    #[test]
    fn absent_and_present_empty_retention_are_distinct_bindings() {
        let bytes = make_zip(&[("a.txt", b"a")]);
        let (binding, pending, _) = reference(&bytes, ZipInterpretationProfile::StrictAsciiV1);
        let absent = encode_planning(&ready_plan(binding.clone(), pending.clone())).unwrap();
        let mut present_binding = binding;
        present_binding.retention = RetentionBinding::from_plan(Some(&RetentionPlan::new(0, 0)));
        let present = encode_planning(&ready_plan(present_binding.clone(), pending)).unwrap();
        assert_ne!(absent, present);
        assert_eq!(
            decode_plan(&absent, &present_binding, &bytes)
                .unwrap_err()
                .kind,
            RecordErrorKind::BindingMismatch
        );
        assert!(decode_plan(&present, &present_binding, &bytes).is_ok());
    }
}
