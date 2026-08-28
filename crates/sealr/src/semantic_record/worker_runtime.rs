//! Generic semantic execution adapter for the authenticated Linux worker.

use std::fs::File;
use std::io::{BufReader, Write};

use super::{
    decode_completion, decode_planning_binding, decode_planning_for_worker, encode_planning,
    parse_hex_32, retained_content, InvocationBinding, PlanningDisposition, PlanningRecord,
    RequestedEffect, RetentionBinding, ValidatedPlanningRecord,
};
use crate::apply::PlanningContext;
use crate::findings::Finding;
use crate::ir::{ArchiveIR, MemberVerification};
use crate::materialize::StageWriteRoot;
use crate::outcome::{AdmissionStatus, InterpretationStatus, VerificationStatus, ViewCompleteness};
use crate::snapshot::SourceSnapshot;
use crate::verification::{verify_payload, PayloadPlan};
use crate::verified::{RetentionBuild, RetentionPlan};
use crate::zip as zip_ranges;

/// Operation selected by the authenticated supervisor protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    Inspect,
    Materialize,
}

impl OperationKind {
    const fn requested_effect(self) -> RequestedEffect {
        match self {
            Self::Inspect => RequestedEffect::Inspect,
            Self::Materialize => RequestedEffect::Materialize,
        }
    }
}

enum ValidatedOperationInner {
    Inspect {
        planning: ValidatedPlanningRecord,
        snapshot: SourceSnapshot<'static>,
    },
    Materialize {
        planning: ValidatedPlanningRecord,
        snapshot: SourceSnapshot<'static>,
    },
}

/// A canonical supervisor-authored plan bound to the exact worker source.
pub struct ValidatedOperation {
    inner: ValidatedOperationInner,
}

enum ExecutedOperationInner {
    Inspect(super::executor::ExecutedInspectPlan<'static>),
    Materialize(super::executor::ExecutedMaterializePlan<'static>),
}

/// A completed worker execution that retains its plan and exact source until
/// the canonical outputs have been observed.
pub struct ExecutedOperation {
    inner: ExecutedOperationInner,
}

/// Bounded completion state observed inside the worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletionEvidence {
    pub complete: bool,
    pub member_count: u64,
    pub verified_members: u64,
}

/// Bounded retained-content state observed inside the worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionEvidence {
    pub requested_paths: u64,
    pub retained_members: u64,
    pub retained_bytes: u64,
}

/// Supervisor-owned authority needed to bind one isolated member read.
#[derive(Clone, Copy, Debug)]
pub struct MemberReadAuthority<'a> {
    operation_id: [u8; 16],
    planning: &'a [u8],
    completion: &'a [u8],
}

impl<'a> MemberReadAuthority<'a> {
    pub fn new(operation_id: [u8; 16], planning: &'a [u8], completion: &'a [u8]) -> Self {
        Self {
            operation_id,
            planning,
            completion,
        }
    }
}

/// A canonical one-shot read bound to an exact source, plan, and completion.
pub struct ValidatedMemberRead {
    planning: ValidatedPlanningRecord,
    snapshot: SourceSnapshot<'static>,
    request: super::member_read::MemberReadRequest,
}

/// Exact evidence for one isolated member-read result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberReadEvidence {
    pub member_index: u64,
    pub actual_bytes: u64,
    pub actual_crc: u32,
}

/// Source-derived supervisor authority for one exact semantic completion.
pub struct AuthorizedExecution {
    pub(crate) interpretation: InterpretationStatus,
    pub(crate) admission: AdmissionStatus,
    pub(crate) verification: VerificationStatus,
    pub(crate) view_completeness: ViewCompleteness,
    pub(crate) ir: ArchiveIR,
    pub(crate) findings: Vec<Finding>,
    pub(crate) retention: RetentionBuild,
    evidence: CompletionEvidence,
    retention_evidence: RetentionEvidence,
}

impl AuthorizedExecution {
    pub fn archive_ir(&self) -> &ArchiveIR {
        &self.ir
    }

    pub fn completion_evidence(&self) -> CompletionEvidence {
        self.evidence
    }

    pub fn retention_evidence(&self) -> RetentionEvidence {
        self.retention_evidence
    }
}

/// Encode one already admitted, effect-independent plan for the authenticated
/// worker without reparsing or weakening the public planning result.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_ready_plan(
    snapshot: &SourceSnapshot<'_>,
    ir: &ArchiveIR,
    findings: &[Finding],
    context: &PlanningContext,
    operation_id: [u8; 16],
    kind: OperationKind,
    target_sha256: Option<[u8; 32]>,
    retention: Option<&RetentionPlan>,
) -> Result<Vec<u8>, String> {
    let controls = context.controls();
    let source_sha256 = parse_hex_32(
        snapshot
            .digest()
            .sha256()
            .ok_or_else(|| "supervised snapshot digest is unavailable".to_owned())?,
    )
    .ok_or_else(|| "supervised snapshot digest is not SHA-256".to_owned())?;
    let profile_sha256 = parse_hex_32(&context.profile().digest())
        .ok_or_else(|| "supervised profile digest is not SHA-256".to_owned())?;
    let policy_sha256 = parse_hex_32(context.policy_sha256())
        .ok_or_else(|| "supervised policy digest is not SHA-256".to_owned())?;
    let binding = InvocationBinding {
        operation_id,
        source_len: snapshot.len(),
        source_sha256,
        profile: context.profile(),
        profile_sha256,
        policy_id: context.policy_id().to_owned(),
        policy_sha256,
        budget: controls.budget,
        target: controls.target,
        consumer: controls.consumer,
        requested_effect: kind.requested_effect(),
        target_sha256,
        member_sync: controls.effect.member_sync,
        retention: RetentionBinding::from_plan(retention),
    };
    encode_planning(&PlanningRecord {
        binding,
        disposition: PlanningDisposition::ReadyForVerification,
        ir: Some(ir.clone()),
        findings: findings.to_vec(),
    })
    .map_err(debug_error)
}

/// Decode the sealed plan's bounded invocation binding, construct an exact
/// read-only snapshot from the transferred descriptor, and require the
/// protocol-selected operation to match the plan before execution.
pub fn validate_operation(
    source: File,
    source_len: u64,
    operation_id: [u8; 16],
    planning: &[u8],
    kind: OperationKind,
) -> Result<ValidatedOperation, String> {
    let binding = decode_planning_binding(planning).map_err(debug_error)?;
    if binding.source_len != source_len {
        return Err(format!(
            "source descriptor length {source_len} differs from plan length {}",
            binding.source_len
        ));
    }
    let snapshot = SourceSnapshot::from_worker_file(
        source,
        Some("authenticated-worker-source".to_owned()),
        source_len,
        binding.budget.max_archive_bytes,
    )
    .map_err(debug_error)?;
    let planning =
        decode_planning_for_worker(planning, operation_id, kind.requested_effect(), &snapshot)
            .map_err(debug_error)?;
    let inner = match kind {
        OperationKind::Inspect => ValidatedOperationInner::Inspect { planning, snapshot },
        OperationKind::Materialize => ValidatedOperationInner::Materialize { planning, snapshot },
    };
    Ok(ValidatedOperation { inner })
}

/// Replay an accepted plan against the supervisor's exact retained source and
/// require both worker outputs to equal the canonical source-derived bytes.
/// Only this result may shape public semantic state or authorize a stage audit.
pub fn authorize_execution(
    source: File,
    source_len: u64,
    operation_id: [u8; 16],
    planning: &[u8],
    completion: &[u8],
    retained_content_bytes: &[u8],
    kind: OperationKind,
) -> Result<AuthorizedExecution, String> {
    let binding = decode_planning_binding(planning).map_err(debug_error)?;
    if binding.source_len != source_len {
        return Err(format!(
            "source descriptor length {source_len} differs from plan length {}",
            binding.source_len
        ));
    }
    let snapshot = SourceSnapshot::from_worker_file(
        source,
        Some("supervisor-replay-source".to_owned()),
        source_len,
        binding.budget.max_archive_bytes,
    )
    .map_err(debug_error)?;
    let planning =
        decode_planning_for_worker(planning, operation_id, kind.requested_effect(), &snapshot)
            .map_err(debug_error)?;
    let replayed = match kind {
        OperationKind::Inspect => {
            let executed = planning
                .bind_inspect_execution(snapshot)
                .map_err(debug_error)?
                .execute()
                .map_err(debug_error)?;
            ExecutedOperation {
                inner: ExecutedOperationInner::Inspect(executed),
            }
        }
        OperationKind::Materialize => {
            let executed = planning
                .bind_materialize_replay(snapshot)
                .map_err(debug_error)?
                .execute()
                .map_err(debug_error)?;
            ExecutedOperation {
                inner: ExecutedOperationInner::Materialize(executed),
            }
        }
    };
    if replayed.completion() != completion {
        return Err(
            "worker completion differs from the supervisor's source-derived replay".to_owned(),
        );
    }
    if replayed.retained_content() != retained_content_bytes {
        return Err(
            "worker retained content differs from the supervisor's source-derived replay"
                .to_owned(),
        );
    }
    let proposal =
        decode_completion(replayed.completion(), replayed.planning()).map_err(debug_error)?;
    let (retention, retained_evidence) = retained_content::decode(
        replayed.planning(),
        replayed.completion(),
        replayed.retained_content(),
    )
    .map_err(debug_error)?;
    let evidence = completion_evidence(&proposal);
    Ok(AuthorizedExecution {
        interpretation: proposal.interpretation,
        admission: proposal.admission,
        verification: proposal.verification,
        view_completeness: proposal.view_completeness,
        ir: proposal.ir,
        findings: proposal.findings,
        retention,
        evidence,
        retention_evidence: RetentionEvidence {
            requested_paths: retained_evidence.requested_paths,
            retained_members: retained_evidence.retained_members,
            retained_bytes: retained_evidence.retained_bytes,
        },
    })
}

impl ValidatedOperation {
    /// Read the existing authority probe byte through the bound snapshot.
    pub fn source_probe(&self) -> Result<u8, String> {
        let snapshot = match &self.inner {
            ValidatedOperationInner::Inspect { snapshot, .. }
            | ValidatedOperationInner::Materialize { snapshot, .. } => snapshot,
        };
        let mut byte = [0_u8; 1];
        snapshot.read_exact_at(0, &mut byte).map_err(debug_error)?;
        Ok(byte[0])
    }

    /// Execute only the planned payload ranges. Inspect discards any optional
    /// conformance-stage descriptor. Materialization requires one stage root.
    pub fn execute(self, stage: Option<File>) -> Result<ExecutedOperation, String> {
        let inner = match self.inner {
            ValidatedOperationInner::Inspect { planning, snapshot } => {
                drop(stage);
                let executed = planning
                    .bind_inspect_execution(snapshot)
                    .map_err(debug_error)?
                    .execute()
                    .map_err(debug_error)?;
                ExecutedOperationInner::Inspect(executed)
            }
            ValidatedOperationInner::Materialize { planning, snapshot } => {
                let stage = stage.ok_or_else(|| {
                    "validated materialization operation lost its stage authority".to_owned()
                })?;
                let stage = StageWriteRoot::from_worker_file(stage).map_err(debug_error)?;
                let executed = planning
                    .bind_materialize_execution(snapshot, stage)
                    .map_err(debug_error)?
                    .execute()
                    .map_err(debug_error)?;
                ExecutedOperationInner::Materialize(executed)
            }
        };
        Ok(ExecutedOperation { inner })
    }
}

impl ExecutedOperation {
    fn planning(&self) -> &ValidatedPlanningRecord {
        match &self.inner {
            ExecutedOperationInner::Inspect(executed) => executed.planning(),
            ExecutedOperationInner::Materialize(executed) => executed.planning(),
        }
    }

    pub fn completion(&self) -> &[u8] {
        match &self.inner {
            ExecutedOperationInner::Inspect(executed) => executed.completion(),
            ExecutedOperationInner::Materialize(executed) => executed.completion(),
        }
    }

    pub fn retained_content(&self) -> &[u8] {
        match &self.inner {
            ExecutedOperationInner::Inspect(executed) => executed.retained_content(),
            ExecutedOperationInner::Materialize(executed) => executed.retained_content(),
        }
    }

    pub fn completion_evidence(&self) -> Result<CompletionEvidence, String> {
        let (planning, completion) = match &self.inner {
            ExecutedOperationInner::Inspect(executed) => {
                (executed.planning(), executed.completion())
            }
            ExecutedOperationInner::Materialize(executed) => {
                (executed.planning(), executed.completion())
            }
        };
        let proposal = decode_completion(completion, planning).map_err(debug_error)?;
        Ok(completion_evidence(&proposal))
    }

    pub fn retention_evidence(&self) -> Result<RetentionEvidence, String> {
        let (planning, completion, retained) = match &self.inner {
            ExecutedOperationInner::Inspect(executed) => (
                executed.planning(),
                executed.completion(),
                executed.retained_content(),
            ),
            ExecutedOperationInner::Materialize(executed) => (
                executed.planning(),
                executed.completion(),
                executed.retained_content(),
            ),
        };
        let evidence =
            retained_content::validate(planning, completion, retained).map_err(debug_error)?;
        Ok(RetentionEvidence {
            requested_paths: evidence.requested_paths,
            retained_members: evidence.retained_members,
            retained_bytes: evidence.retained_bytes,
        })
    }
}

/// Create one canonical caller-bounded request from an already authorized
/// plan and completion. No codec executes during this preflight.
pub fn create_member_read_request(
    source: File,
    source_len: u64,
    authority: MemberReadAuthority<'_>,
    read_operation_id: [u8; 16],
    canonical_path: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    let (planning, _snapshot) = bind_member_read_source(source, source_len, authority)?;
    super::member_read::encode(
        &planning,
        authority.completion,
        read_operation_id,
        canonical_path,
        max_bytes,
    )
    .map_err(debug_error)
}

/// Bind a canonical request to the worker's exact source descriptor and the
/// supervisor-authorized original execution.
pub fn validate_member_read(
    source: File,
    source_len: u64,
    authority: MemberReadAuthority<'_>,
    request: &[u8],
    read_operation_id: [u8; 16],
) -> Result<ValidatedMemberRead, String> {
    let (planning, snapshot) = bind_member_read_source(source, source_len, authority)?;
    let request =
        super::member_read::decode(&planning, authority.completion, request, read_operation_id)
            .map_err(debug_error)?;
    Ok(ValidatedMemberRead {
        planning,
        snapshot,
        request,
    })
}

/// Preflight a request before allocating output or spawning a one-shot worker.
pub fn validate_member_read_request(
    source: File,
    source_len: u64,
    authority: MemberReadAuthority<'_>,
    request: &[u8],
    read_operation_id: [u8; 16],
) -> Result<MemberReadEvidence, String> {
    let (planning, _snapshot) = bind_member_read_source(source, source_len, authority)?;
    let request =
        super::member_read::decode(&planning, authority.completion, request, read_operation_id)
            .map_err(debug_error)?;
    Ok(member_read_evidence(&request))
}

/// Validate fully buffered worker output without executing a codec or parser.
pub fn validate_member_read_result(
    source: File,
    source_len: u64,
    authority: MemberReadAuthority<'_>,
    request: &[u8],
    read_operation_id: [u8; 16],
    bytes: &[u8],
) -> Result<MemberReadEvidence, String> {
    let (planning, _snapshot) = bind_member_read_source(source, source_len, authority)?;
    let request = super::member_read::validate_result(
        &planning,
        authority.completion,
        request,
        read_operation_id,
        bytes,
    )
    .map_err(debug_error)?;
    Ok(member_read_evidence(&request))
}

impl ValidatedMemberRead {
    /// Decode only the selected planned payload range into a backpressured
    /// output, then recheck complete authorized size, CRC32, and SHA-256.
    pub fn execute_into(self, output: &mut impl Write) -> Result<MemberReadEvidence, String> {
        let planned = self
            .planning
            .record
            .ir
            .as_ref()
            .and_then(|ir| ir.members().get(self.request.member_index))
            .ok_or_else(|| "validated member-read index is absent from its plan".to_owned())?;
        if planned.canonical_path != self.request.path {
            return Err("validated member-read path drifted from its plan".to_owned());
        }
        let payload =
            zip_ranges::planned_payload_reader(&self.snapshot, planned).map_err(debug_error)?;
        let payload = BufReader::with_capacity(64 * 1024, payload);
        let (actual, crc, sha256) = verify_payload(
            payload,
            PayloadPlan::from_ir(planned),
            self.planning.record.binding.budget,
            self.request.expected_size,
            output,
        )
        .map_err(debug_error)?;
        if actual != self.request.expected_size
            || crc != self.request.expected_crc
            || sha256 != self.request.expected_sha256
        {
            return Err(
                "isolated member read disagrees with authorized completion evidence".to_owned(),
            );
        }
        Ok(MemberReadEvidence {
            member_index: self.request.member_index as u64,
            actual_bytes: actual,
            actual_crc: crc,
        })
    }
}

fn bind_member_read_source(
    source: File,
    source_len: u64,
    authority: MemberReadAuthority<'_>,
) -> Result<(ValidatedPlanningRecord, SourceSnapshot<'static>), String> {
    let binding = decode_planning_binding(authority.planning).map_err(debug_error)?;
    if binding.operation_id != authority.operation_id || binding.source_len != source_len {
        return Err("member-read authority differs from its planning binding".to_owned());
    }
    let snapshot = SourceSnapshot::from_worker_file(
        source,
        Some("authenticated-member-read-source".to_owned()),
        source_len,
        binding.budget.max_archive_bytes,
    )
    .map_err(debug_error)?;
    let planning =
        super::decode_planning(authority.planning, &binding, &snapshot).map_err(debug_error)?;
    Ok((planning, snapshot))
}

fn member_read_evidence(request: &super::member_read::MemberReadRequest) -> MemberReadEvidence {
    MemberReadEvidence {
        member_index: request.member_index as u64,
        actual_bytes: request.expected_size,
        actual_crc: request.expected_crc,
    }
}

fn completion_evidence(proposal: &super::BoundCompletionProposal) -> CompletionEvidence {
    let verified_members = proposal
        .ir
        .members
        .iter()
        .filter(|member| matches!(member.verification, MemberVerification::Verified))
        .count() as u64;
    CompletionEvidence {
        complete: proposal.verification == VerificationStatus::Complete,
        member_count: proposal.ir.members.len() as u64,
        verified_members,
    }
}

fn debug_error(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};
    use std::path::PathBuf;

    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;
    use crate::apply::{plan_source, PlanDecision, Source};
    use crate::ir::ZipInterpretationProfile;
    use crate::policy::Policy;

    struct TempSource {
        path: PathBuf,
    }

    impl TempSource {
        fn create(bytes: &[u8]) -> Self {
            let mut random = [0_u8; 12];
            getrandom::fill(&mut random).unwrap();
            let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir().join(format!("sealr-worker-runtime-{suffix}"));
            std::fs::write(&path, bytes).unwrap();
            Self { path }
        }

        fn open(&self) -> File {
            File::open(&self.path).unwrap()
        }
    }

    impl Drop for TempSource {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn source() -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .last_modified_time(zip::DateTime::default());
            writer.start_file("custom.txt", options).unwrap();
            writer.write_all(b"custom policy payload").unwrap();
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn source_with_bad_crc() -> Vec<u8> {
        let mut bytes = source();
        for (signature, crc_offset) in [
            ([0x50, 0x4b, 0x03, 0x04], 14_usize),
            ([0x50, 0x4b, 0x01, 0x02], 16_usize),
        ] {
            let header = bytes
                .windows(signature.len())
                .position(|window| window == signature)
                .unwrap();
            bytes[header + crc_offset] ^= 1;
        }
        bytes
    }

    #[test]
    fn worker_uses_the_supervisor_plan_policy_profile_budget_and_retention() {
        let source = source();
        let mut policy = Policy::default_v1();
        policy.id = "sealr:test/custom-worker-policy".to_owned();
        policy.max_archive_bytes = source.len() as u64;
        policy.max_files = 1;
        policy.max_member_bytes = 21;
        policy.max_total_bytes = 21;
        policy.max_ratio = None;
        policy.max_path_depth = 1;
        policy.max_metadata_bytes = source.len() as u64;
        let context =
            PlanningContext::compile(&policy, ZipInterpretationProfile::StrictAsciiV1).unwrap();
        let request = Source::Bytes {
            path: Some("custom-worker.zip"),
            data: &source,
        };
        let ready = match plan_source(&request, context).unwrap() {
            PlanDecision::Ready(ready) => ready,
            PlanDecision::Terminal(terminal) => panic!("unexpected terminal plan: {terminal:?}"),
        };
        let (snapshot, ir, _payloads, findings, context) = ready.into_parts();
        let retention = RetentionPlan::new(21, 21).with_path("custom.txt").unwrap();
        let operation_id = [0x5a; 16];
        let planning = prepare_ready_plan(
            &snapshot,
            &ir,
            &findings,
            &context,
            operation_id,
            OperationKind::Inspect,
            None,
            Some(&retention),
        )
        .unwrap();
        let materialize_planning = prepare_ready_plan(
            &snapshot,
            &ir,
            &findings,
            &context,
            operation_id,
            OperationKind::Materialize,
            Some([0x54; 32]),
            Some(&retention),
        )
        .unwrap();
        let temp = TempSource::create(&source);

        let materialize_operation = validate_operation(
            temp.open(),
            source.len() as u64,
            operation_id,
            &materialize_planning,
            OperationKind::Materialize,
        )
        .unwrap();
        assert!(materialize_operation.execute(None).is_err());
        assert!(validate_operation(
            temp.open(),
            source.len() as u64,
            operation_id,
            &materialize_planning,
            OperationKind::Inspect,
        )
        .is_err());

        let operation = validate_operation(
            temp.open(),
            source.len() as u64,
            operation_id,
            &planning,
            OperationKind::Inspect,
        )
        .unwrap();
        let executed = operation.execute(None).unwrap();
        assert_eq!(
            executed.completion_evidence().unwrap(),
            CompletionEvidence {
                complete: true,
                member_count: 1,
                verified_members: 1,
            }
        );
        assert_eq!(
            executed.retention_evidence().unwrap(),
            RetentionEvidence {
                requested_paths: 1,
                retained_members: 1,
                retained_bytes: 21,
            }
        );
        let authorized = authorize_execution(
            temp.open(),
            source.len() as u64,
            operation_id,
            &planning,
            executed.completion(),
            executed.retained_content(),
            OperationKind::Inspect,
        )
        .unwrap();
        assert_eq!(authorized.ir.profile(), "sealr.profile.zip.strict-ascii.v1");
        assert_eq!(authorized.completion_evidence().member_count, 1);
        assert_eq!(authorized.retention_evidence().retained_bytes, 21);
        assert!(matches!(
            authorized
                .retention
                .into_entries()
                .get("custom.txt"),
            Some(crate::verified::RetentionEntry::Retained(bytes))
                if bytes == b"custom policy payload"
        ));
        let mut altered_completion = executed.completion().to_vec();
        let last = altered_completion.len() - 1;
        altered_completion[last] ^= 1;
        assert!(authorize_execution(
            temp.open(),
            source.len() as u64,
            operation_id,
            &planning,
            &altered_completion,
            executed.retained_content(),
            OperationKind::Inspect,
        )
        .is_err());
        let completion = executed.completion().to_vec();
        let read_operation_id = [0x7c; 16];
        let authority = MemberReadAuthority::new(operation_id, &planning, &completion);
        let request = create_member_read_request(
            temp.open(),
            source.len() as u64,
            authority,
            read_operation_id,
            "custom.txt",
            21,
        )
        .unwrap();
        assert_eq!(
            validate_member_read_request(
                temp.open(),
                source.len() as u64,
                authority,
                &request,
                read_operation_id,
            )
            .unwrap(),
            MemberReadEvidence {
                member_index: 0,
                actual_bytes: 21,
                actual_crc: crc32fast::hash(b"custom policy payload"),
            }
        );
        let read = validate_member_read(
            temp.open(),
            source.len() as u64,
            authority,
            &request,
            read_operation_id,
        )
        .unwrap();
        let mut output = Vec::new();
        let read_evidence = read.execute_into(&mut output).unwrap();
        assert_eq!(output, b"custom policy payload");
        assert_eq!(
            validate_member_read_result(
                temp.open(),
                source.len() as u64,
                authority,
                &request,
                read_operation_id,
                &output,
            )
            .unwrap(),
            read_evidence
        );
        assert!(validate_operation(
            temp.open(),
            source.len() as u64,
            operation_id,
            &planning,
            OperationKind::Materialize,
        )
        .is_err());
        assert!(validate_operation(
            temp.open(),
            source.len() as u64,
            [0x6b; 16],
            &planning,
            OperationKind::Inspect,
        )
        .is_err());
    }

    #[test]
    fn worker_returns_a_source_authorized_stopped_completion() {
        let source = source_with_bad_crc();
        let policy = Policy::default_v1();
        let context =
            PlanningContext::compile(&policy, ZipInterpretationProfile::StrictAsciiV2).unwrap();
        let request = Source::Bytes {
            path: Some("stopped-worker.zip"),
            data: &source,
        };
        let ready = match plan_source(&request, context).unwrap() {
            PlanDecision::Ready(ready) => ready,
            PlanDecision::Terminal(terminal) => panic!("unexpected terminal plan: {terminal:?}"),
        };
        let (snapshot, ir, _payloads, findings, context) = ready.into_parts();
        let operation_id = [0x8d; 16];
        let planning = prepare_ready_plan(
            &snapshot,
            &ir,
            &findings,
            &context,
            operation_id,
            OperationKind::Inspect,
            None,
            None,
        )
        .unwrap();
        let temp = TempSource::create(&source);
        let executed = validate_operation(
            temp.open(),
            source.len() as u64,
            operation_id,
            &planning,
            OperationKind::Inspect,
        )
        .unwrap()
        .execute(None)
        .unwrap();
        assert_eq!(
            executed.completion_evidence().unwrap(),
            CompletionEvidence {
                complete: false,
                member_count: 1,
                verified_members: 0,
            }
        );
        let authorized = authorize_execution(
            temp.open(),
            source.len() as u64,
            operation_id,
            &planning,
            executed.completion(),
            executed.retained_content(),
            OperationKind::Inspect,
        )
        .unwrap();
        assert!(matches!(
            authorized.verification,
            VerificationStatus::Partial {
                verified_members: 0,
                pending_members: 1,
            }
        ));
        assert_eq!(
            authorized.findings.last().map(|finding| finding.code),
            Some(crate::FindingCode::CrcMismatch)
        );
    }
}
