//! Feature-gated bridge for the repository-only Linux worker lab.

use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use super::{
    decode_completion, decode_planning, encode_planning, parse_hex_32, InvocationBinding,
    PlanningDisposition, PlanningRecord, RequestedEffect, RetentionBinding,
};
use crate::apply::{plan_source, PlanDecision, PlanningContext, Source};
use crate::ir::{MemberVerification, ZipInterpretationProfile};
use crate::materialize::{CapabilityMaterializer, StageWriteRoot};
use crate::outcome::VerificationStatus;
use crate::policy::Policy;
use crate::snapshot::SourceSnapshot;
use crate::verification::{verify_payload, PayloadSpec};
use crate::verified::RetentionPlan;
use crate::zip as zip_ranges;

/// A canonical planning record bound to the exact worker source descriptor.
#[derive(Debug)]
pub struct ValidatedInspectOperation {
    planning: super::ValidatedPlanningRecord,
    snapshot: SourceSnapshot<'static>,
}

/// Completed execution that retains the exact source through observation.
#[derive(Debug)]
pub struct ExecutedInspectOperation {
    executed: super::executor::ExecutedInspectPlan<'static>,
}

/// A validated materialization plan bound to the exact worker source.
#[derive(Debug)]
pub struct ValidatedMaterializeOperation {
    planning: super::ValidatedPlanningRecord,
    snapshot: SourceSnapshot<'static>,
}

/// A completed materialization execution that retains source and stage
/// authority until its canonical result has been observed.
#[derive(Debug)]
pub struct ExecutedMaterializeOperation {
    executed: super::executor::ExecutedMaterializePlan<'static>,
}

/// Supervisor-owned staging and publication authority for the repository lab.
pub struct WorkerLabStage {
    materializer: CapabilityMaterializer,
}

/// A stage that passed the exact source-authorized tree audit.
pub struct AuditedWorkerLabStage {
    materializer: CapabilityMaterializer,
}

/// Scoped cleanup-failure injection for the repository conformance lab.
pub struct WorkerLabCleanupFailureGuard {
    _guard: crate::materialize::CleanupFailureGuard,
}

/// Opaque source-derived authority for one exact materialized tree.
pub struct AuthorizedStageManifest {
    ir: crate::ir::ArchiveIR,
    evidence: InspectCompletionEvidence,
}

/// One exact, caller-bounded non-retained member read validated against a
/// supervisor-authorized plan and completion.
#[derive(Debug)]
pub struct ValidatedInspectMemberRead {
    planning: super::ValidatedPlanningRecord,
    snapshot: SourceSnapshot<'static>,
    request: super::member_read::MemberReadRequest,
}

/// Bounded semantic result observed by the repository worker lab.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InspectCompletionEvidence {
    /// Whether every planned member completed verification.
    pub complete: bool,
    /// Total members carried by the validated planning record.
    pub member_count: u64,
    /// Members with a completed verification state.
    pub verified_members: u64,
}

/// Bounded retention request supplied independently by the repository lab's
/// trusted supervisor and bound into the semantic plan.
#[derive(Clone, Debug)]
pub struct InspectRetentionRequest {
    plan: RetentionPlan,
}

/// Bounded retained-content result observed by the repository worker lab.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InspectRetentionEvidence {
    /// Exact paths represented by the canonical retention bundle.
    pub requested_paths: u64,
    /// Requested file members retained during the verification pass.
    pub retained_members: u64,
    /// Aggregate logical bytes in the immutable retention bundle.
    pub retained_bytes: u64,
}

/// Exact evidence for one isolated member-read result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InspectMemberReadEvidence {
    /// Source-order member index bound into the canonical request.
    pub member_index: u64,
    /// Exact verified logical bytes returned by the isolated worker.
    pub actual_bytes: u64,
    /// CRC32 recomputed while the selected planned range was decoded.
    pub actual_crc: u32,
}

/// Borrowed supervisor-owned authority needed to bind one isolated read.
#[derive(Clone, Copy, Debug)]
pub struct InspectMemberReadAuthority<'a> {
    operation_id: [u8; 16],
    planning: &'a [u8],
    completion: &'a [u8],
    retention: &'a InspectRetentionRequest,
}

impl<'a> InspectMemberReadAuthority<'a> {
    /// Bind an already authorized plan and completion for one-shot reads.
    pub fn new(
        operation_id: [u8; 16],
        planning: &'a [u8],
        completion: &'a [u8],
        retention: &'a InspectRetentionRequest,
    ) -> Self {
        Self {
            operation_id,
            planning,
            completion,
            retention,
        }
    }
}

impl InspectRetentionRequest {
    /// Create an empty bounded request.
    pub fn new(max_member_bytes: u64, max_total_bytes: u64) -> Self {
        Self {
            plan: RetentionPlan::new(max_member_bytes, max_total_bytes),
        }
    }

    /// Add one exact canonical path.
    pub fn add_path(&mut self, path: impl Into<String>) -> Result<(), String> {
        self.plan.add_path(path).map_err(debug_error)
    }
}

/// Plan one inspect operation and return its canonical semantic record.
pub fn plan_inspect(source: &[u8], operation_id: [u8; 16]) -> Result<Vec<u8>, String> {
    plan_inspect_with_retention(source, operation_id, None)
}

/// Plan one private materialization operation for the repository lab.
pub fn plan_materialize(source: &[u8], operation_id: [u8; 16]) -> Result<Vec<u8>, String> {
    plan_materialize_with_retention(source, operation_id, None)
}

/// Plan one private materialization operation with retained-content transfer.
pub fn plan_materialize_retaining(
    source: &[u8],
    operation_id: [u8; 16],
    retention: &InspectRetentionRequest,
) -> Result<Vec<u8>, String> {
    plan_materialize_with_retention(source, operation_id, Some(retention))
}

fn plan_materialize_with_retention(
    source: &[u8],
    operation_id: [u8; 16],
    retention: Option<&InspectRetentionRequest>,
) -> Result<Vec<u8>, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let source = Source::Bytes {
        path: Some("worker-lab.zip"),
        data: source,
    };
    let ready = match plan_source(&source, context).map_err(debug_error)? {
        PlanDecision::Ready(ready) => ready,
        PlanDecision::Terminal(terminal) => {
            return Err(format!(
                "worker-lab source reached terminal planning: {terminal:?}"
            ));
        }
    };
    let (snapshot, ir, findings, context) = ready.into_parts();
    let binding = materialize_binding(&snapshot, &context, operation_id, retention)?;
    encode_planning(&PlanningRecord {
        binding,
        disposition: PlanningDisposition::ReadyForVerification,
        ir: Some(ir),
        findings,
    })
    .map_err(debug_error)
}

/// Plan one inspect operation with a supervisor-authored retention request.
pub fn plan_inspect_retaining(
    source: &[u8],
    operation_id: [u8; 16],
    retention: &InspectRetentionRequest,
) -> Result<Vec<u8>, String> {
    plan_inspect_with_retention(source, operation_id, Some(retention))
}

fn plan_inspect_with_retention(
    source: &[u8],
    operation_id: [u8; 16],
    retention: Option<&InspectRetentionRequest>,
) -> Result<Vec<u8>, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let source = Source::Bytes {
        path: Some("worker-lab.zip"),
        data: source,
    };
    let ready = match plan_source(&source, context).map_err(debug_error)? {
        PlanDecision::Ready(ready) => ready,
        PlanDecision::Terminal(terminal) => {
            return Err(format!(
                "worker-lab source reached terminal planning: {terminal:?}"
            ));
        }
    };
    let (snapshot, ir, findings, context) = ready.into_parts();
    let binding = inspect_binding(&snapshot, &context, operation_id, retention)?;
    encode_planning(&PlanningRecord {
        binding,
        disposition: PlanningDisposition::ReadyForVerification,
        ir: Some(ir),
        findings,
    })
    .map_err(debug_error)
}

/// Validate one canonical plan against the exact read-only source descriptor.
pub fn validate_inspect(
    source: File,
    source_len: u64,
    operation_id: [u8; 16],
    planning: &[u8],
) -> Result<ValidatedInspectOperation, String> {
    validate_inspect_with_retention(source, source_len, operation_id, planning, None)
}

/// Validate one canonical materialization plan against the exact source.
pub fn validate_materialize(
    source: File,
    source_len: u64,
    operation_id: [u8; 16],
    planning: &[u8],
) -> Result<ValidatedMaterializeOperation, String> {
    validate_materialize_with_retention(source, source_len, operation_id, planning, None)
}

/// Validate one retained-content materialization plan against the exact source.
pub fn validate_materialize_retaining(
    source: File,
    source_len: u64,
    operation_id: [u8; 16],
    planning: &[u8],
    retention: &InspectRetentionRequest,
) -> Result<ValidatedMaterializeOperation, String> {
    validate_materialize_with_retention(source, source_len, operation_id, planning, Some(retention))
}

fn validate_materialize_with_retention(
    source: File,
    source_len: u64,
    operation_id: [u8; 16],
    planning: &[u8],
    retention: Option<&InspectRetentionRequest>,
) -> Result<ValidatedMaterializeOperation, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let snapshot = SourceSnapshot::worker_lab_from_file(
        source,
        Some("worker-lab.zip".into()),
        source_len,
        context.controls().budget.max_archive_bytes,
    )
    .map_err(debug_error)?;
    let binding = materialize_binding(&snapshot, &context, operation_id, retention)?;
    let planning = decode_planning(planning, &binding, &snapshot).map_err(debug_error)?;
    Ok(ValidatedMaterializeOperation { planning, snapshot })
}

/// Validate one canonical retained-content plan against the exact descriptor.
pub fn validate_inspect_retaining(
    source: File,
    source_len: u64,
    operation_id: [u8; 16],
    planning: &[u8],
    retention: &InspectRetentionRequest,
) -> Result<ValidatedInspectOperation, String> {
    validate_inspect_with_retention(source, source_len, operation_id, planning, Some(retention))
}

fn validate_inspect_with_retention(
    source: File,
    source_len: u64,
    operation_id: [u8; 16],
    planning: &[u8],
    retention: Option<&InspectRetentionRequest>,
) -> Result<ValidatedInspectOperation, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let snapshot = SourceSnapshot::worker_lab_from_file(
        source,
        Some("worker-lab.zip".into()),
        source_len,
        context.controls().budget.max_archive_bytes,
    )
    .map_err(debug_error)?;
    let binding = inspect_binding(&snapshot, &context, operation_id, retention)?;
    let planning = decode_planning(planning, &binding, &snapshot).map_err(debug_error)?;
    Ok(ValidatedInspectOperation { planning, snapshot })
}

/// Validate a canonical retained-content bundle as a plan- and
/// completion-bound worker proposal without granting source authority.
pub fn validate_inspect_retained_content(
    source: &[u8],
    operation_id: [u8; 16],
    planning: &[u8],
    completion: &[u8],
    retained_content: &[u8],
    retention: &InspectRetentionRequest,
) -> Result<InspectRetentionEvidence, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let snapshot = SourceSnapshot::borrowed(Some("worker-lab.zip".into()), source);
    let binding = inspect_binding(&snapshot, &context, operation_id, Some(retention))?;
    let planning = decode_planning(planning, &binding, &snapshot).map_err(debug_error)?;
    let evidence = super::retained_content::validate(&planning, completion, retained_content)
        .map_err(debug_error)?;
    Ok(retention_evidence(evidence))
}

/// Create one canonical request for a non-retained read from an already
/// accepted plan and completion.
pub fn create_inspect_member_read_request(
    source: &[u8],
    authority: InspectMemberReadAuthority<'_>,
    read_operation_id: [u8; 16],
    canonical_path: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let snapshot = SourceSnapshot::borrowed(Some("worker-lab.zip".into()), source);
    let binding = inspect_binding(
        &snapshot,
        &context,
        authority.operation_id,
        Some(authority.retention),
    )?;
    let planning = decode_planning(authority.planning, &binding, &snapshot).map_err(debug_error)?;
    super::member_read::encode(
        &planning,
        authority.completion,
        read_operation_id,
        canonical_path,
        max_bytes,
    )
    .map_err(debug_error)
}

/// Bind a canonical one-shot read request to the exact source descriptor,
/// accepted plan, and supervisor-authorized completion.
pub fn validate_inspect_member_read(
    source: File,
    source_len: u64,
    authority: InspectMemberReadAuthority<'_>,
    request: &[u8],
    read_operation_id: [u8; 16],
) -> Result<ValidatedInspectMemberRead, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let snapshot = SourceSnapshot::worker_lab_from_file(
        source,
        Some("worker-lab-read.zip".into()),
        source_len,
        context.controls().budget.max_archive_bytes,
    )
    .map_err(debug_error)?;
    let binding = inspect_binding(
        &snapshot,
        &context,
        authority.operation_id,
        Some(authority.retention),
    )?;
    let planning = decode_planning(authority.planning, &binding, &snapshot).map_err(debug_error)?;
    let request =
        super::member_read::decode(&planning, authority.completion, request, read_operation_id)
            .map_err(debug_error)?;
    Ok(ValidatedInspectMemberRead {
        planning,
        snapshot,
        request,
    })
}

/// Validate buffered worker output against the exact request and authorized
/// completion without executing a codec or structural parser.
pub fn validate_inspect_member_read_result(
    source: &[u8],
    authority: InspectMemberReadAuthority<'_>,
    request: &[u8],
    read_operation_id: [u8; 16],
    bytes: &[u8],
) -> Result<InspectMemberReadEvidence, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let snapshot = SourceSnapshot::borrowed(Some("worker-lab.zip".into()), source);
    let binding = inspect_binding(
        &snapshot,
        &context,
        authority.operation_id,
        Some(authority.retention),
    )?;
    let planning = decode_planning(authority.planning, &binding, &snapshot).map_err(debug_error)?;
    let request = super::member_read::validate_result(
        &planning,
        authority.completion,
        request,
        read_operation_id,
        bytes,
    )
    .map_err(debug_error)?;
    Ok(InspectMemberReadEvidence {
        member_index: request.member_index as u64,
        actual_bytes: request.expected_size,
        actual_crc: request.expected_crc,
    })
}

/// Preflight one canonical member-read request against local authorized
/// evidence before allocation or worker spawn.
pub fn validate_inspect_member_read_request(
    source: &[u8],
    authority: InspectMemberReadAuthority<'_>,
    request: &[u8],
    read_operation_id: [u8; 16],
) -> Result<InspectMemberReadEvidence, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let snapshot = SourceSnapshot::borrowed(Some("worker-lab.zip".into()), source);
    let binding = inspect_binding(
        &snapshot,
        &context,
        authority.operation_id,
        Some(authority.retention),
    )?;
    let planning = decode_planning(authority.planning, &binding, &snapshot).map_err(debug_error)?;
    let request =
        super::member_read::decode(&planning, authority.completion, request, read_operation_id)
            .map_err(debug_error)?;
    Ok(InspectMemberReadEvidence {
        member_index: request.member_index as u64,
        actual_bytes: request.expected_size,
        actual_crc: request.expected_crc,
    })
}

/// Validate a worker completion as a canonical, plan-bound proposal. This does
/// not grant independent content authority or activate public semantic state.
pub fn validate_inspect_completion(
    source: &[u8],
    operation_id: [u8; 16],
    planning: &[u8],
    completion: &[u8],
) -> Result<InspectCompletionEvidence, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let snapshot = SourceSnapshot::borrowed(Some("worker-lab.zip".into()), source);
    let binding = inspect_binding(&snapshot, &context, operation_id, None)?;
    let planning = decode_planning(planning, &binding, &snapshot).map_err(debug_error)?;
    let proposal = decode_completion(completion, &planning).map_err(debug_error)?;
    Ok(completion_evidence(proposal))
}

/// Replay a retained-content execution against the supervisor's exact source
/// and require both canonical worker outputs to match the source-derived
/// completion and retention bundle byte for byte.
pub fn authorize_inspect_retained_execution(
    source: File,
    source_len: u64,
    operation_id: [u8; 16],
    planning: &[u8],
    completion: &[u8],
    retained_content: &[u8],
    retention: &InspectRetentionRequest,
) -> Result<(InspectCompletionEvidence, InspectRetentionEvidence), String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let snapshot = SourceSnapshot::worker_lab_from_file(
        source,
        Some("worker-lab-supervisor.zip".into()),
        source_len,
        context.controls().budget.max_archive_bytes,
    )
    .map_err(debug_error)?;
    let binding = inspect_binding(&snapshot, &context, operation_id, Some(retention))?;
    let planning = decode_planning(planning, &binding, &snapshot).map_err(debug_error)?;
    let executed = planning
        .bind_inspect_execution(snapshot)
        .map_err(debug_error)?
        .execute()
        .map_err(debug_error)?;
    if executed.completion() != completion {
        return Err(
            "worker completion differs from the supervisor's source-derived replay".to_owned(),
        );
    }
    if executed.retained_content() != retained_content {
        return Err(
            "worker retained content differs from the supervisor's source-derived replay"
                .to_owned(),
        );
    }
    let proposal =
        decode_completion(executed.completion(), executed.planning()).map_err(debug_error)?;
    let retained = super::retained_content::validate(
        executed.planning(),
        executed.completion(),
        executed.retained_content(),
    )
    .map_err(debug_error)?;
    Ok((completion_evidence(proposal), retention_evidence(retained)))
}

/// Replay one accepted plan against the supervisor's exact retained source and
/// require the worker completion to equal the source-derived canonical bytes.
/// This is independent of worker output, but deliberately reuses the same
/// bounded verifier implementation.
pub fn authorize_inspect_completion(
    source: File,
    source_len: u64,
    operation_id: [u8; 16],
    planning: &[u8],
    completion: &[u8],
) -> Result<InspectCompletionEvidence, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let snapshot = SourceSnapshot::worker_lab_from_file(
        source,
        Some("worker-lab-supervisor.zip".into()),
        source_len,
        context.controls().budget.max_archive_bytes,
    )
    .map_err(debug_error)?;
    let binding = inspect_binding(&snapshot, &context, operation_id, None)?;
    let planning = decode_planning(planning, &binding, &snapshot).map_err(debug_error)?;
    let executed = planning
        .bind_inspect_execution(snapshot)
        .map_err(debug_error)?
        .execute()
        .map_err(debug_error)?;
    if executed.completion() != completion {
        return Err(
            "worker completion differs from the supervisor's source-derived replay".to_owned(),
        );
    }
    let proposal =
        decode_completion(executed.completion(), executed.planning()).map_err(debug_error)?;
    Ok(completion_evidence(proposal))
}

/// Replay a materialization plan against the supervisor's retained source and
/// authorize an exact stage manifest only when the worker completion matches.
pub fn authorize_materialize_execution(
    source: File,
    source_len: u64,
    operation_id: [u8; 16],
    planning: &[u8],
    completion: &[u8],
    retained_content: &[u8],
) -> Result<AuthorizedStageManifest, String> {
    let (manifest, retention) = authorize_materialize_with_retention(
        source,
        source_len,
        operation_id,
        planning,
        completion,
        retained_content,
        None,
    )?;
    if retention.requested_paths != 0
        || retention.retained_members != 0
        || retention.retained_bytes != 0
    {
        return Err("materialization without retention produced retained content".to_owned());
    }
    Ok(manifest)
}

/// Replay a retained-content materialization against the supervisor source.
/// Both worker outputs must equal the canonical source-derived replay before
/// the stage manifest or retained-content evidence is authorized.
pub fn authorize_materialize_retained_execution(
    source: File,
    source_len: u64,
    operation_id: [u8; 16],
    planning: &[u8],
    completion: &[u8],
    retained_content: &[u8],
    retention: &InspectRetentionRequest,
) -> Result<(AuthorizedStageManifest, InspectRetentionEvidence), String> {
    authorize_materialize_with_retention(
        source,
        source_len,
        operation_id,
        planning,
        completion,
        retained_content,
        Some(retention),
    )
}

#[allow(clippy::too_many_arguments)]
fn authorize_materialize_with_retention(
    source: File,
    source_len: u64,
    operation_id: [u8; 16],
    planning: &[u8],
    completion: &[u8],
    retained_content: &[u8],
    retention: Option<&InspectRetentionRequest>,
) -> Result<(AuthorizedStageManifest, InspectRetentionEvidence), String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let snapshot = SourceSnapshot::worker_lab_from_file(
        source,
        Some("worker-lab-supervisor.zip".into()),
        source_len,
        context.controls().budget.max_archive_bytes,
    )
    .map_err(debug_error)?;
    let binding = materialize_binding(&snapshot, &context, operation_id, retention)?;
    let planning = decode_planning(planning, &binding, &snapshot).map_err(debug_error)?;
    let executed = planning
        .bind_materialize_replay(snapshot)
        .map_err(debug_error)?
        .execute()
        .map_err(debug_error)?;
    if executed.completion() != completion {
        return Err(
            "worker completion differs from the supervisor's source-derived replay".to_owned(),
        );
    }
    if executed.retained_content() != retained_content {
        return Err(
            "worker retained content differs from the supervisor's source-derived replay"
                .to_owned(),
        );
    }
    let proposal =
        decode_completion(executed.completion(), executed.planning()).map_err(debug_error)?;
    let evidence = completion_evidence(proposal.clone());
    if !evidence.complete {
        return Err("only a complete source-derived execution can authorize a stage".to_owned());
    }
    let retained = super::retained_content::validate(
        executed.planning(),
        executed.completion(),
        executed.retained_content(),
    )
    .map_err(debug_error)?;
    Ok((
        AuthorizedStageManifest {
            ir: proposal.ir,
            evidence,
        },
        retention_evidence(retained),
    ))
}

impl WorkerLabStage {
    /// Create the real production stage while retaining publication authority.
    pub fn create(destination: &Path) -> Result<Self, String> {
        CapabilityMaterializer::create(destination, false)
            .map(|materializer| Self { materializer })
            .map_err(debug_error)
    }

    /// Duplicate only the retained stage root for transfer to a worker.
    pub fn try_clone_writer_file(&self) -> Result<File, String> {
        self.materializer
            .try_clone_worker_file()
            .map_err(debug_error)
    }

    /// Consume a reaped stage and require an exact source-authorized audit.
    pub fn audit(
        self,
        manifest: &AuthorizedStageManifest,
    ) -> Result<AuditedWorkerLabStage, String> {
        self.materializer
            .audit_against(&manifest.ir)
            .map_err(debug_error)?;
        Ok(AuditedWorkerLabStage {
            materializer: self.materializer,
        })
    }

    /// Abort a stage after the supervisor has proved writer quiescence.
    pub fn abort(mut self) -> Result<(), String> {
        self.materializer.abort().map_err(debug_error)
    }

    /// Deliberately retain an uncleaned stage when writer quiescence is not
    /// proved. This prevents Drop from recursively removing a live namespace.
    pub fn abandon(self) {
        std::mem::forget(self);
    }
}

/// Inject a bounded number of stage cleanup failures on the current thread.
pub fn inject_worker_lab_cleanup_failures(count: u32) -> WorkerLabCleanupFailureGuard {
    WorkerLabCleanupFailureGuard {
        _guard: crate::materialize::inject_cleanup_failures_for_current_thread(count),
    }
}

impl AuditedWorkerLabStage {
    /// Publish through the retained parent with no replacement.
    pub fn publish(mut self) -> Result<(), String> {
        self.materializer.commit().map_err(debug_error)
    }
}

impl AuthorizedStageManifest {
    /// Return bounded completion evidence for conformance assertions.
    pub fn evidence(&self) -> InspectCompletionEvidence {
        self.evidence
    }
}

fn context(policy: &Policy) -> Result<PlanningContext, String> {
    PlanningContext::compile(policy, ZipInterpretationProfile::StrictAsciiV2).map_err(debug_error)
}

fn inspect_binding(
    snapshot: &SourceSnapshot<'_>,
    context: &PlanningContext,
    operation_id: [u8; 16],
    retention: Option<&InspectRetentionRequest>,
) -> Result<InvocationBinding, String> {
    let controls = context.controls();
    let source_sha256 = parse_hex_32(
        snapshot
            .digest()
            .sha256()
            .ok_or_else(|| "worker-lab snapshot digest is unavailable".to_owned())?,
    )
    .ok_or_else(|| "worker-lab snapshot digest is not SHA-256".to_owned())?;
    let profile_sha256 = parse_hex_32(&context.profile().digest())
        .ok_or_else(|| "worker-lab profile digest is not SHA-256".to_owned())?;
    let policy_sha256 = parse_hex_32(context.policy_sha256())
        .ok_or_else(|| "worker-lab policy digest is not SHA-256".to_owned())?;
    Ok(InvocationBinding {
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
        requested_effect: RequestedEffect::Inspect,
        target_sha256: None,
        member_sync: controls.effect.member_sync,
        retention: retention.map_or(RetentionBinding::None, |retention| {
            RetentionBinding::from_plan(Some(&retention.plan))
        }),
    })
}

fn materialize_binding(
    snapshot: &SourceSnapshot<'_>,
    context: &PlanningContext,
    operation_id: [u8; 16],
    retention: Option<&InspectRetentionRequest>,
) -> Result<InvocationBinding, String> {
    let controls = context.controls();
    let source_sha256 = parse_hex_32(
        snapshot
            .digest()
            .sha256()
            .ok_or_else(|| "worker-lab snapshot digest is unavailable".to_owned())?,
    )
    .ok_or_else(|| "worker-lab snapshot digest is not SHA-256".to_owned())?;
    let profile_sha256 = parse_hex_32(&context.profile().digest())
        .ok_or_else(|| "worker-lab profile digest is not SHA-256".to_owned())?;
    let policy_sha256 = parse_hex_32(context.policy_sha256())
        .ok_or_else(|| "worker-lab policy digest is not SHA-256".to_owned())?;
    let target_sha256 = Sha256::digest(b"sealr.worker-lab.materialize-target.v1\0").into();
    Ok(InvocationBinding {
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
        requested_effect: RequestedEffect::Materialize,
        target_sha256: Some(target_sha256),
        member_sync: controls.effect.member_sync,
        retention: retention.map_or(RetentionBinding::None, |retention| {
            RetentionBinding::from_plan(Some(&retention.plan))
        }),
    })
}

fn debug_error(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

impl ValidatedInspectOperation {
    /// Read the existing authority probe byte through the bound snapshot.
    pub fn source_probe(&self) -> Result<u8, String> {
        let mut byte = [0_u8; 1];
        self.snapshot
            .read_exact_at(0, &mut byte)
            .map_err(debug_error)?;
        Ok(byte[0])
    }

    /// Consume the validated plan and execute only its planned payload ranges.
    pub fn execute(self) -> Result<ExecutedInspectOperation, String> {
        let executed = self
            .planning
            .bind_inspect_execution(self.snapshot)
            .map_err(debug_error)?
            .execute()
            .map_err(debug_error)?;
        Ok(ExecutedInspectOperation { executed })
    }
}

impl ExecutedInspectOperation {
    /// Return the canonical semantic completion bytes.
    pub fn completion(&self) -> &[u8] {
        self.executed.completion()
    }

    /// Return the canonical retained-content transfer captured during the
    /// same verification pass as the completion.
    pub fn retained_content(&self) -> &[u8] {
        self.executed.retained_content()
    }

    /// Revalidate the generated completion against its retained planning state.
    pub fn evidence(&self) -> Result<InspectCompletionEvidence, String> {
        let proposal = decode_completion(self.executed.completion(), self.executed.planning())
            .map_err(debug_error)?;
        Ok(completion_evidence(proposal))
    }

    /// Revalidate the canonical retained-content transfer against the
    /// completion and retained planning state.
    pub fn retention_evidence(&self) -> Result<InspectRetentionEvidence, String> {
        let evidence = super::retained_content::validate(
            self.executed.planning(),
            self.executed.completion(),
            self.executed.retained_content(),
        )
        .map_err(debug_error)?;
        Ok(retention_evidence(evidence))
    }
}

impl ValidatedMaterializeOperation {
    /// Read the existing source probe byte through the bound snapshot.
    pub fn source_probe(&self) -> Result<u8, String> {
        let mut byte = [0_u8; 1];
        self.snapshot
            .read_exact_at(0, &mut byte)
            .map_err(debug_error)?;
        Ok(byte[0])
    }

    /// Consume the validated plan and write only its planned member ranges.
    pub fn execute_into(self, stage: File) -> Result<ExecutedMaterializeOperation, String> {
        let stage = StageWriteRoot::from_worker_file(stage).map_err(debug_error)?;
        let executed = self
            .planning
            .bind_materialize_execution(self.snapshot, stage)
            .map_err(debug_error)?
            .execute()
            .map_err(debug_error)?;
        Ok(ExecutedMaterializeOperation { executed })
    }
}

impl ExecutedMaterializeOperation {
    /// Return the canonical semantic completion bytes.
    pub fn completion(&self) -> &[u8] {
        self.executed.completion()
    }

    /// Return the canonical retention bundle captured during execution.
    pub fn retained_content(&self) -> &[u8] {
        self.executed.retained_content()
    }

    /// Revalidate the generated completion against its retained planning state.
    pub fn evidence(&self) -> Result<InspectCompletionEvidence, String> {
        let proposal = decode_completion(self.executed.completion(), self.executed.planning())
            .map_err(debug_error)?;
        Ok(completion_evidence(proposal))
    }

    /// Revalidate the canonical retained-content transfer against the
    /// completion and retained planning state.
    pub fn retention_evidence(&self) -> Result<InspectRetentionEvidence, String> {
        let evidence = super::retained_content::validate(
            self.executed.planning(),
            self.executed.completion(),
            self.executed.retained_content(),
        )
        .map_err(debug_error)?;
        Ok(retention_evidence(evidence))
    }
}

impl ValidatedInspectMemberRead {
    /// Decode only the selected planned payload range into the supplied
    /// backpressured output and recheck complete authorized content evidence.
    pub fn execute_into(
        self,
        output: &mut impl Write,
    ) -> Result<InspectMemberReadEvidence, String> {
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
            PayloadSpec::from_ir(planned),
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
        Ok(InspectMemberReadEvidence {
            member_index: self.request.member_index as u64,
            actual_bytes: actual,
            actual_crc: crc,
        })
    }
}

fn retention_evidence(
    evidence: super::retained_content::RetainedContentEvidence,
) -> InspectRetentionEvidence {
    InspectRetentionEvidence {
        requested_paths: evidence.requested_paths,
        retained_members: evidence.retained_members,
        retained_bytes: evidence.retained_bytes,
    }
}

fn completion_evidence(proposal: super::BoundCompletionProposal) -> InspectCompletionEvidence {
    let verified_members = proposal
        .ir
        .members
        .iter()
        .filter(|member| matches!(member.verification, MemberVerification::Verified))
        .count() as u64;
    InspectCompletionEvidence {
        complete: proposal.verification == VerificationStatus::Complete,
        member_count: proposal.ir.members.len() as u64,
        verified_members,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::{Cursor, Write};
    use std::path::PathBuf;

    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;

    fn source() -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .last_modified_time(zip::DateTime::default());
            writer.start_file("planned.txt", options).unwrap();
            writer.write_all(b"planned payload").unwrap();
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn materialize_source() -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let stored = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .last_modified_time(zip::DateTime::default());
            writer.add_directory("nested/", stored).unwrap();
            writer.start_file("stored.txt", stored).unwrap();
            writer.write_all(b"stored payload").unwrap();
            writer.start_file("empty.txt", stored).unwrap();
            let deflated = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .last_modified_time(zip::DateTime::default());
            writer.start_file("nested/deflated.txt", deflated).unwrap();
            writer.write_all(b"deflated payload").unwrap();
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn source_file(source: &[u8]) -> (File, PathBuf) {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("sealr-worker-lab-{suffix}.zip"));
        let mut writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        writer.write_all(source).unwrap();
        drop(writer);
        (File::open(&path).unwrap(), path)
    }

    #[test]
    fn bridge_executes_real_plan_without_structural_reparse() {
        let source = source();
        let operation_id = [0x41; 16];
        let planning = plan_inspect(&source, operation_id).unwrap();

        crate::zip::reset_parse_calls();
        crate::verification::reset_verify_payload_calls();
        let (file, path) = source_file(&source);
        let operation =
            validate_inspect(file, source.len() as u64, operation_id, &planning).unwrap();
        assert_eq!(operation.source_probe().unwrap(), source[0]);
        let executed = operation.execute().unwrap();
        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(crate::verification::verify_payload_calls(), 1);

        let evidence = executed.evidence().unwrap();
        assert_eq!(
            evidence,
            InspectCompletionEvidence {
                complete: true,
                member_count: 1,
                verified_members: 1,
            }
        );
        assert_eq!(crate::zip::parse_calls(), 0);
        validate_inspect_completion(&source, operation_id, &planning, executed.completion())
            .unwrap();
        let authority = authorize_inspect_completion(
            File::open(&path).unwrap(),
            source.len() as u64,
            operation_id,
            &planning,
            executed.completion(),
        )
        .unwrap();
        assert_eq!(authority, evidence);
        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(crate::verification::verify_payload_calls(), 2);
        drop(executed);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn materialize_bridge_replays_audits_and_publishes_exact_tree() {
        let source = materialize_source();
        let operation_id = [0x51; 16];
        let mut retention = InspectRetentionRequest::new(64, 64);
        retention.add_path("nested/deflated.txt").unwrap();
        retention.add_path("stored.txt").unwrap();
        let planning = plan_materialize_retaining(&source, operation_id, &retention).unwrap();
        let (file, source_path) = source_file(&source);
        let root = unique_directory("materialize-success");
        let destination = root.join("published");
        let stage = WorkerLabStage::create(&destination).unwrap();
        let writer = stage.try_clone_writer_file().unwrap();

        crate::zip::reset_parse_calls();
        crate::verification::reset_verify_payload_calls();
        let executed = validate_materialize_retaining(
            file,
            source.len() as u64,
            operation_id,
            &planning,
            &retention,
        )
        .unwrap()
        .execute_into(writer)
        .unwrap();
        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(crate::verification::verify_payload_calls(), 3);
        let completion = executed.completion().to_vec();
        assert_eq!(
            executed.evidence().unwrap(),
            InspectCompletionEvidence {
                complete: true,
                member_count: 4,
                verified_members: 4,
            }
        );
        assert_eq!(
            executed.retention_evidence().unwrap(),
            InspectRetentionEvidence {
                requested_paths: 2,
                retained_members: 2,
                retained_bytes: 30,
            }
        );
        let retained_content = executed.retained_content().to_vec();
        drop(executed);

        let (manifest, retained) = authorize_materialize_retained_execution(
            File::open(&source_path).unwrap(),
            source.len() as u64,
            operation_id,
            &planning,
            &completion,
            &retained_content,
            &retention,
        )
        .unwrap();
        assert_eq!(
            retained,
            InspectRetentionEvidence {
                requested_paths: 2,
                retained_members: 2,
                retained_bytes: 30,
            }
        );
        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(crate::verification::verify_payload_calls(), 6);
        let mut changed_retained = retained_content.clone();
        *changed_retained.last_mut().unwrap() ^= 1;
        assert!(authorize_materialize_retained_execution(
            File::open(&source_path).unwrap(),
            source.len() as u64,
            operation_id,
            &planning,
            &completion,
            &changed_retained,
            &retention,
        )
        .is_err());
        stage.audit(&manifest).unwrap().publish().unwrap();

        verify_materialized_tree(&destination);
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(source_path).unwrap();
    }

    #[test]
    fn materialize_without_retention_authorizes_the_canonical_empty_bundle() {
        let source = materialize_source();
        let operation_id = [0x52; 16];
        let planning = plan_materialize(&source, operation_id).unwrap();
        let (file, source_path) = source_file(&source);
        let root = unique_directory("materialize-no-retention");
        let destination = root.join("published");
        let stage = WorkerLabStage::create(&destination).unwrap();
        let writer = stage.try_clone_writer_file().unwrap();
        let executed = validate_materialize(file, source.len() as u64, operation_id, &planning)
            .unwrap()
            .execute_into(writer)
            .unwrap();
        assert_eq!(
            executed.retention_evidence().unwrap(),
            InspectRetentionEvidence {
                requested_paths: 0,
                retained_members: 0,
                retained_bytes: 0,
            }
        );
        let completion = executed.completion().to_vec();
        let retained_content = executed.retained_content().to_vec();
        drop(executed);

        let manifest = authorize_materialize_execution(
            File::open(&source_path).unwrap(),
            source.len() as u64,
            operation_id,
            &planning,
            &completion,
            &retained_content,
        )
        .unwrap();
        stage.audit(&manifest).unwrap().publish().unwrap();
        verify_materialized_tree(&destination);
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(source_path).unwrap();
    }

    fn verify_materialized_tree(destination: &Path) {
        assert_eq!(
            fs::read(destination.join("stored.txt")).unwrap(),
            b"stored payload"
        );
        assert_eq!(fs::read(destination.join("empty.txt")).unwrap(), b"");
        assert_eq!(
            fs::read(destination.join("nested/deflated.txt")).unwrap(),
            b"deflated payload"
        );
    }

    fn unique_directory(label: &str) -> PathBuf {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("sealr-worker-lab-{label}-{suffix}"));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    #[test]
    fn bridge_rejects_operation_and_source_drift() {
        let source = source();
        let operation_id = [0x41; 16];
        let planning = plan_inspect(&source, operation_id).unwrap();
        let (file, path) = source_file(&source);
        assert!(validate_inspect(file, source.len() as u64, [0x42; 16], &planning).is_err());
        fs::remove_file(path).unwrap();

        let mut drifted = source;
        drifted[0] ^= 1;
        let (file, path) = source_file(&drifted);
        assert!(validate_inspect(file, drifted.len() as u64, operation_id, &planning).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn retained_content_is_captured_once_and_transferred_canonically() {
        let source = source();
        let operation_id = [0x61; 16];
        let mut retention = InspectRetentionRequest::new(64, 64);
        retention.add_path("missing.txt").unwrap();
        retention.add_path("planned.txt").unwrap();
        let planning = plan_inspect_retaining(&source, operation_id, &retention).unwrap();
        let (file, path) = source_file(&source);

        crate::zip::reset_parse_calls();
        crate::verification::reset_verify_payload_calls();
        let executed = validate_inspect_retaining(
            file,
            source.len() as u64,
            operation_id,
            &planning,
            &retention,
        )
        .unwrap()
        .execute()
        .unwrap();
        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(crate::verification::verify_payload_calls(), 1);

        let proposal = validate_inspect_retained_content(
            &source,
            operation_id,
            &planning,
            executed.completion(),
            executed.retained_content(),
            &retention,
        )
        .unwrap();
        assert_eq!(
            proposal,
            InspectRetentionEvidence {
                requested_paths: 2,
                retained_members: 1,
                retained_bytes: b"planned payload".len() as u64,
            }
        );
        assert_eq!(crate::verification::verify_payload_calls(), 1);

        let (completion, authorized) = authorize_inspect_retained_execution(
            File::open(&path).unwrap(),
            source.len() as u64,
            operation_id,
            &planning,
            executed.completion(),
            executed.retained_content(),
            &retention,
        )
        .unwrap();
        assert!(completion.complete);
        assert_eq!(authorized, proposal);
        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(crate::verification::verify_payload_calls(), 2);

        let mut mutated = executed.retained_content().to_vec();
        *mutated.last_mut().unwrap() ^= 1;
        assert!(validate_inspect_retained_content(
            &source,
            operation_id,
            &planning,
            executed.completion(),
            &mutated,
            &retention,
        )
        .is_err());
        for length in 0..executed.retained_content().len() {
            assert!(validate_inspect_retained_content(
                &source,
                operation_id,
                &planning,
                executed.completion(),
                &executed.retained_content()[..length],
                &retention,
            )
            .is_err());
        }
        drop(executed);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn member_read_request_executes_one_planned_range_and_validates_output() {
        let source = source();
        let operation_id = [0x71; 16];
        let read_operation_id = [0x72; 16];
        let retention = InspectRetentionRequest::new(0, 0);
        let planning = plan_inspect_retaining(&source, operation_id, &retention).unwrap();
        let (file, path) = source_file(&source);
        let executed = validate_inspect_retaining(
            file,
            source.len() as u64,
            operation_id,
            &planning,
            &retention,
        )
        .unwrap()
        .execute()
        .unwrap();
        let authority = InspectMemberReadAuthority::new(
            operation_id,
            &planning,
            executed.completion(),
            &retention,
        );
        let request = create_inspect_member_read_request(
            &source,
            authority,
            read_operation_id,
            "planned.txt",
            b"planned payload".len() as u64,
        )
        .unwrap();

        crate::zip::reset_parse_calls();
        crate::verification::reset_verify_payload_calls();
        let read = validate_inspect_member_read(
            File::open(&path).unwrap(),
            source.len() as u64,
            authority,
            &request,
            read_operation_id,
        )
        .unwrap();
        let mut bytes = Vec::new();
        let evidence = read.execute_into(&mut bytes).unwrap();
        assert_eq!(bytes, b"planned payload");
        assert_eq!(evidence.member_index, 0);
        assert_eq!(evidence.actual_bytes, bytes.len() as u64);
        assert_eq!(evidence.actual_crc, crc32fast::hash(&bytes));
        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(crate::verification::verify_payload_calls(), 1);
        assert_eq!(
            validate_inspect_member_read_result(
                &source,
                authority,
                &request,
                read_operation_id,
                &bytes,
            )
            .unwrap(),
            evidence
        );
        assert!(create_inspect_member_read_request(
            &source,
            authority,
            [0x73; 16],
            "planned.txt",
            bytes.len() as u64 - 1,
        )
        .is_err());
        assert!(create_inspect_member_read_request(
            &source,
            authority,
            [0x74; 16],
            "missing.txt",
            64,
        )
        .is_err());
        assert!(create_inspect_member_read_request(
            &source,
            authority,
            [0x75; 16],
            "planned.txt",
            super::super::member_read::MAX_ISOLATED_READ_BYTES + 1,
        )
        .is_err());
        let mut mutated = bytes.clone();
        mutated[0] ^= 1;
        assert!(validate_inspect_member_read_result(
            &source,
            authority,
            &request,
            read_operation_id,
            &mutated,
        )
        .is_err());

        let policy = Policy::default_v1();
        let context = context(&policy).unwrap();
        let snapshot = SourceSnapshot::borrowed(Some("worker-lab.zip".into()), &source);
        let binding = inspect_binding(&snapshot, &context, operation_id, Some(&retention)).unwrap();
        let decoded = decode_planning(&planning, &binding, &snapshot).unwrap();
        let mut wrong_read_operation = request.clone();
        wrong_read_operation[16] ^= 1;
        assert!(super::super::member_read::decode(
            &decoded,
            executed.completion(),
            &wrong_read_operation,
            read_operation_id,
        )
        .is_err());
        let mut wrong_completion = request.clone();
        wrong_completion[16 + 16 + 16 + 32 + 32] ^= 1;
        assert!(super::super::member_read::decode(
            &decoded,
            executed.completion(),
            &wrong_completion,
            read_operation_id,
        )
        .is_err());

        for length in 0..request.len() {
            assert!(super::super::member_read::decode(
                &decoded,
                executed.completion(),
                &request[..length],
                read_operation_id,
            )
            .is_err());
        }
        let mut trailing = request.clone();
        trailing.push(0);
        assert!(super::super::member_read::decode(
            &decoded,
            executed.completion(),
            &trailing,
            read_operation_id,
        )
        .is_err());
        drop(executed);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn retained_content_transfer_rejects_an_oversized_request_before_execution() {
        let source = source();
        let operation_id = [0x62; 16];
        let mut retention = InspectRetentionRequest::new(
            super::super::retained_content::MAX_TRANSFER_CONTENT_BYTES as u64 + 1,
            super::super::retained_content::MAX_TRANSFER_CONTENT_BYTES as u64 + 1,
        );
        retention.add_path("planned.txt").unwrap();
        let planning = plan_inspect_retaining(&source, operation_id, &retention).unwrap();
        let (file, path) = source_file(&source);
        let validated = validate_inspect_retaining(
            file,
            source.len() as u64,
            operation_id,
            &planning,
            &retention,
        )
        .unwrap();
        let error = validated.execute().unwrap_err();
        assert!(error.contains("transfer content bound"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn materialize_retention_rejects_an_oversized_request_before_stage_writes() {
        let source = materialize_source();
        let operation_id = [0x63; 16];
        let mut retention = InspectRetentionRequest::new(
            super::super::retained_content::MAX_TRANSFER_CONTENT_BYTES as u64 + 1,
            super::super::retained_content::MAX_TRANSFER_CONTENT_BYTES as u64 + 1,
        );
        retention.add_path("stored.txt").unwrap();
        let planning = plan_materialize_retaining(&source, operation_id, &retention).unwrap();
        let (file, source_path) = source_file(&source);
        let root = unique_directory("materialize-oversized-retention");
        let destination = root.join("published");
        let stage = WorkerLabStage::create(&destination).unwrap();
        let writer = stage.try_clone_writer_file().unwrap();
        let validated = validate_materialize_retaining(
            file,
            source.len() as u64,
            operation_id,
            &planning,
            &retention,
        )
        .unwrap();

        crate::verification::reset_verify_payload_calls();
        let error = validated.execute_into(writer).unwrap_err();
        assert!(error.contains("transfer content bound"));
        assert_eq!(crate::verification::verify_payload_calls(), 0);
        stage.abort().unwrap();
        assert!(!destination.try_exists().unwrap());
        fs::remove_dir_all(root).unwrap();
        fs::remove_file(source_path).unwrap();
    }

    #[test]
    fn supervisor_replay_rejects_a_canonical_forged_content_digest() {
        use crate::semantic_record::{
            encode_completion, CompletionDisposition, CompletionRecord, MemberCompletion,
        };

        let source = source();
        let operation_id = [0x41; 16];
        let planning_bytes = plan_inspect(&source, operation_id).unwrap();
        let (file, path) = source_file(&source);
        let executed = validate_inspect(file, source.len() as u64, operation_id, &planning_bytes)
            .unwrap()
            .execute()
            .unwrap();
        let planning = executed.executed.planning();
        let forged = encode_completion(
            &CompletionRecord {
                operation_id,
                request_id: planning.request_id,
                plan_id: planning.plan_id,
                disposition: CompletionDisposition::Complete,
                members: vec![MemberCompletion::Verified {
                    actual_uncomp_size: b"planned payload".len() as u64,
                    actual_crc: crc32fast::hash(b"planned payload"),
                    content_sha256: [0xA5; 32],
                }],
                findings: Vec::new(),
            },
            planning,
        )
        .unwrap();
        assert!(
            validate_inspect_completion(&source, operation_id, &planning_bytes, &forged)
                .unwrap()
                .complete
        );
        let error = authorize_inspect_completion(
            File::open(&path).unwrap(),
            source.len() as u64,
            operation_id,
            &planning_bytes,
            &forged,
        )
        .unwrap_err();
        assert!(error.contains("source-derived replay"));
        drop(executed);
        fs::remove_file(path).unwrap();
    }
}
