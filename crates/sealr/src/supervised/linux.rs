use std::fs::{self, File};
use std::io;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::fs::OFlags;
use rustix::net::{AddressFamily, SocketFlags, SocketType};
use rustix::pipe::PipeFlags;
use rustix::process::{PidfdFlags, Signal};

use super::{LinuxWorker, SupervisionError, SupervisionErrorKind};
use crate::apply::{
    finish_with_jail, member_view, plan_supervised_source, reject_only, with_ir,
    with_verified_archive, ApplyOptions, PlanDecision, PlanningContext, Request, Source,
};
use crate::identity::OutcomeIdentities;
use crate::materialize::MaterializationMeta;
use crate::outcome::{
    AdmissionStatus, EffectStatus, SemanticAxes, SourceDigest, VerificationStatus,
};
use crate::semantic_record::worker_runtime::{
    self, MemberReadAuthority, MemberReadEvidence, OperationKind,
};
use crate::snapshot::{SnapshotKind, SourceSnapshot};
use crate::verified::VerifiedArchive;
use crate::worker_protocol::frame::{Frame, Kind};
use crate::worker_protocol::helper::HelperArtifact;
use crate::worker_protocol::linux::{
    configure_timeout, receive_packet, send_packet, TransportError, ERROR_RESTRICTION,
    FLAG_MATERIALIZE, FLAG_MEMBER_READ, FLAG_STAGE, READY_FLAGS,
};
use crate::worker_protocol::sealed::{self, BlobRole};
use crate::worker_protocol::{HELPER_BOOTSTRAP_ABI, HELPER_FEATURE_ID};
use crate::Policy;

mod materialize;

const AUTHORITY_EPOCH_TIMEOUT: Duration = Duration::from_secs(5);
const KILL_REAP_TIMEOUT: Duration = Duration::from_secs(1);
const MEMBER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const SUPERVISED_JAIL: &str = "landlock-abi3+seccomp-v1";
const NOT_ENTERED_JAIL: &str = "not-entered";

#[derive(Clone, Copy, Debug)]
enum AuthorityEpoch {
    HelperAuthentication,
    BootstrapRestriction,
    SourceTransfer,
    Execution,
    WorkerExit,
}

#[derive(Clone, Copy)]
struct EpochDeadline {
    epoch: AuthorityEpoch,
    expires_at: Instant,
}

impl EpochDeadline {
    fn start(epoch: AuthorityEpoch) -> Self {
        Self {
            epoch,
            expires_at: Instant::now() + AUTHORITY_EPOCH_TIMEOUT,
        }
    }

    fn ending_at(epoch: AuthorityEpoch, expires_at: Instant) -> Self {
        Self { epoch, expires_at }
    }

    fn poll_timeout_ms(self) -> Option<libc::c_int> {
        let remaining = self.expires_at.checked_duration_since(Instant::now())?;
        if remaining.is_zero() {
            return None;
        }
        let milliseconds = remaining.as_nanos().div_ceil(1_000_000);
        Some(
            libc::c_int::try_from(milliseconds)
                .unwrap_or(libc::c_int::MAX)
                .max(1),
        )
    }
}

pub(super) fn apply(
    request: Request<'_>,
    options: &ApplyOptions,
    worker: &LinuxWorker,
) -> Result<crate::Outcome, SupervisionError> {
    let Request {
        source,
        policy,
        dest,
    } = request;
    match dest {
        Some(destination) => materialize::run(source, destination, policy, options, worker),
        None => inspect(source, policy, options, worker),
    }
}

struct ReadyOperation {
    snapshot: SourceSnapshot<'static>,
    ir: crate::ArchiveIR,
    findings: Vec<crate::Finding>,
    context: PlanningContext,
}

enum PreparedOperation {
    Outcome(Box<crate::Outcome>),
    Ready(Box<ReadyOperation>),
}

fn prepare_operation(
    source: &Source<'_>,
    policy: &Policy,
    options: &ApplyOptions,
    materialization_requested: bool,
) -> PreparedOperation {
    let context = match PlanningContext::compile(policy, options.interpretation_profile()) {
        Ok(context) => context,
        Err(finding) => {
            return PreparedOperation::Outcome(Box::new(reject_only(
                (None, SourceDigest::unavailable(), policy.clone()),
                vec![finding.clone()],
                None,
                MaterializationMeta::not_started(materialization_requested, policy.atomic),
                SemanticAxes::policy_compile_failed(&finding),
                SnapshotKind::Unavailable,
                OutcomeIdentities::without_source_for(options.interpretation_profile()),
            )));
        }
    };
    let planning = match plan_supervised_source(source, context) {
        Ok(planning) => planning,
        Err(failure) => {
            let admission = if failure.finding.code == crate::FindingCode::QuotaArchive {
                AdmissionStatus::Denied
            } else {
                AdmissionStatus::NotEvaluated
            };
            let digest = failure.digest.clone();
            return PreparedOperation::Outcome(Box::new(reject_only(
                (failure.path, failure.digest, policy.clone()),
                vec![failure.finding.clone()],
                None,
                MaterializationMeta::not_started(materialization_requested, policy.atomic),
                SemanticAxes::source_failure(&failure.finding, admission),
                failure.snapshot_kind,
                OutcomeIdentities::unavailable_for(digest, options.interpretation_profile()),
            )));
        }
    };

    match planning {
        PlanDecision::Ready(ready) => {
            let (snapshot, ir, findings, context) = ready.into_parts();
            PreparedOperation::Ready(Box::new(ReadyOperation {
                snapshot,
                ir,
                findings,
                context,
            }))
        }
        PlanDecision::Terminal(terminal) => {
            let (snapshot, magic, ir, findings, axes, context) = terminal.into_parts();
            let source_digest = snapshot.digest().clone();
            let outcome = finish_with_jail(
                (
                    snapshot.path_owned(),
                    source_digest.clone(),
                    snapshot.kind(),
                ),
                magic,
                policy,
                findings,
                Vec::new(),
                MaterializationMeta::not_started(materialization_requested, policy.atomic),
                axes,
                OutcomeIdentities::unavailable_for(source_digest, context.profile()),
                NOT_ENTERED_JAIL,
            );
            PreparedOperation::Outcome(Box::new(match ir {
                Some(ir) => with_ir(outcome, ir),
                None => outcome,
            }))
        }
    }
}

fn inspect(
    source: Source<'_>,
    policy: &Policy,
    options: &ApplyOptions,
    worker: &LinuxWorker,
) -> Result<crate::Outcome, SupervisionError> {
    let ready = match prepare_operation(&source, policy, options, false) {
        PreparedOperation::Outcome(outcome) => return Ok(*outcome),
        PreparedOperation::Ready(ready) => *ready,
    };

    let ReadyOperation {
        snapshot,
        ir,
        findings,
        context,
    } = ready;
    let operation_id = random_operation_id()?;
    let planning = worker_runtime::prepare_ready_plan(
        &snapshot,
        &ir,
        &findings,
        &context,
        operation_id,
        OperationKind::Inspect,
        None,
        options.retention_plan(),
    )
    .map_err(|detail| SupervisionError::new(SupervisionErrorKind::Internal, detail))?;
    let source_len = snapshot.len();
    let result = execute_initial(
        worker,
        &snapshot,
        operation_id,
        &planning,
        None,
        OperationKind::Inspect,
    )?;
    let authorized = worker_runtime::authorize_execution(
        clone_source(&snapshot)?,
        source_len,
        operation_id,
        &planning,
        &result.completion,
        &result.retained,
        OperationKind::Inspect,
    )
    .map_err(|detail| SupervisionError::new(SupervisionErrorKind::IntegrityMismatch, detail))?;

    let evidence = authorized.completion_evidence();
    if evidence.member_count != authorized.archive_ir().members().len() as u64 {
        return Err(SupervisionError::new(
            SupervisionErrorKind::IntegrityMismatch,
            "authorized member count differs from the authorized IR",
        ));
    }
    let mut members = authorized
        .archive_ir()
        .members()
        .iter()
        .filter(|member| matches!(member.verification, crate::MemberVerification::Verified))
        .map(member_view)
        .collect::<Vec<_>>();
    members.sort_by(|left, right| left.path.cmp(&right.path));

    let source_meta = (
        snapshot.path_owned(),
        snapshot.digest().clone(),
        snapshot.kind(),
    );
    let identities =
        OutcomeIdentities::unavailable_for(snapshot.digest().clone(), context.profile());
    let axes = SemanticAxes {
        interpretation: authorized.interpretation.clone(),
        admission: authorized.admission.clone(),
        verification: authorized.verification.clone(),
        effect: EffectStatus::NotRequested,
        view_completeness: authorized.view_completeness.clone(),
    };
    let outcome = finish_with_jail(
        source_meta,
        "zip",
        policy,
        authorized.findings.clone(),
        members,
        MaterializationMeta::not_started(false, policy.atomic),
        axes,
        identities,
        SUPERVISED_JAIL,
    );

    if matches!(authorized.verification, VerificationStatus::Complete) {
        if !evidence.complete
            || evidence.verified_members != evidence.member_count
            || authorized
                .archive_ir()
                .members()
                .iter()
                .any(|member| !matches!(member.verification, crate::MemberVerification::Verified))
        {
            return Err(SupervisionError::new(
                SupervisionErrorKind::IntegrityMismatch,
                "complete worker evidence contains an unverified member",
            ));
        }
        let authority = WorkerReadAuthority::new(
            snapshot,
            worker.clone(),
            operation_id,
            planning,
            result.completion,
        );
        let archive = VerifiedArchive::new_supervised(
            authority,
            authorized.ir,
            context.controls().budget,
            authorized.retention,
        );
        Ok(with_verified_archive(outcome, archive))
    } else {
        Ok(with_ir(outcome, authorized.ir))
    }
}

struct InitialResult {
    completion: Vec<u8>,
    retained: Vec<u8>,
}

fn execute_initial(
    worker: &LinuxWorker,
    snapshot: &SourceSnapshot<'_>,
    operation_id: [u8; 16],
    planning: &[u8],
    stage: Option<&File>,
    kind: OperationKind,
) -> Result<InitialResult, SupervisionError> {
    if matches!(kind, OperationKind::Materialize) != stage.is_some() {
        return Err(fail(
            SupervisionErrorKind::Internal,
            "materialization mode and stage authority disagree",
        ));
    }
    let (control, child_socket) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|error| fail(SupervisionErrorKind::Spawn, error))?;
    configure_supervisor_control(&control)?;
    let child = spawn_child(&worker.artifact, child_socket)?;
    let mut child = ChildBoundary::bind_authenticated(child, &control, &worker.artifact)?;
    let result = execute_initial_active(
        snapshot,
        operation_id,
        planning,
        stage,
        kind,
        &control,
        &mut child,
    );
    finish_active_result(result, &mut child)
}

fn execute_initial_active(
    snapshot: &SourceSnapshot<'_>,
    operation_id: [u8; 16],
    planning: &[u8],
    stage: Option<&File>,
    kind: OperationKind,
    control: &OwnedFd,
    child: &mut ChildBoundary,
) -> Result<InitialResult, SupervisionError> {
    let restriction = EpochDeadline::start(AuthorityEpoch::BootstrapRestriction);
    let mut bootstrap = Frame::new(Kind::Bootstrap, operation_id);
    if let Some(stage) = stage {
        bootstrap.flags = FLAG_STAGE | FLAG_MATERIALIZE;
        bootstrap.values = stage_identity(stage)?;
    }
    transport_until(control, child, restriction, libc::POLLOUT, || match stage {
        Some(stage) => send_packet(control, bootstrap, &[stage.as_fd()]),
        None => send_packet(control, bootstrap, &[]),
    })?;
    let (ready, descriptors) = receive_until(control, child, restriction)?;
    require_no_descriptors(&descriptors, "restriction readiness")?;
    if ready.kind == Kind::Error {
        return Err(worker_error(ready));
    }
    let expected_flags = READY_FLAGS
        | if matches!(kind, OperationKind::Materialize) {
            FLAG_STAGE | FLAG_MATERIALIZE
        } else {
            0
        };
    if ready.kind != Kind::RestrictedReady
        || ready.operation_id != operation_id
        || ready.flags != expected_flags
        || ready.values[0] < 3
        || ready.values[1] == 0
        || ready.values[2] == 0
        || ready.values[1] & ready.values[2] != ready.values[2]
        || (stage.is_none() && ready.values[3] != u64::MAX)
        || (stage.is_some() && ready.values[3] > i32::MAX as u64)
    {
        return Err(protocol(
            "worker restriction-ready evidence is inconsistent",
        ));
    }
    observe_restricted_child(child.child.id(), &ready, stage)?;

    let source_file = clone_source(snapshot)?;
    let source_values = source_identity(&source_file)?;
    let source_epoch = EpochDeadline::start(AuthorityEpoch::SourceTransfer);
    let mut source = Frame::new(Kind::Source, operation_id);
    source.values = source_values;
    transport_until(control, child, source_epoch, libc::POLLOUT, || {
        send_packet(control, source, &[source_file.as_fd()])
    })?;
    let (accepted, descriptors) = receive_until(control, child, source_epoch)?;
    require_no_descriptors(&descriptors, "source acceptance")?;
    if accepted.kind == Kind::Error {
        return Err(worker_error(accepted));
    }
    if accepted.kind != Kind::Accepted
        || accepted.operation_id != operation_id
        || accepted.flags != 0
        || accepted.values[..3] != source_values[..3]
        || accepted.values[3] > i32::MAX as u64
    {
        return Err(protocol("worker source acceptance is inconsistent"));
    }

    let planning_descriptor = sealed::create(BlobRole::Planning, planning)
        .map_err(|error| fail(SupervisionErrorKind::Protocol, error))?;
    let planning_len = sealed::total_len(planning.len())
        .ok_or_else(|| protocol("planning record exceeds its sealed envelope"))?;
    let mut plan = Frame::new(Kind::Plan, operation_id);
    plan.values[0] = planning_len;
    transport_until(control, child, source_epoch, libc::POLLOUT, || {
        send_packet(control, plan, &[planning_descriptor.as_fd()])
    })?;
    let (accepted_plan, descriptors) = receive_until(control, child, source_epoch)?;
    require_no_descriptors(&descriptors, "plan acceptance")?;
    if accepted_plan.kind == Kind::Error {
        return Err(worker_error(accepted_plan));
    }
    if accepted_plan.kind != Kind::PlanAccepted
        || accepted_plan.operation_id != operation_id
        || accepted_plan.flags != 0
        || accepted_plan.values[0] != planning_len
        || accepted_plan.values[1] > i32::MAX as u64
        || accepted_plan.values[2..] != [0; 2]
    {
        return Err(protocol("worker plan acceptance is inconsistent"));
    }

    let execution = EpochDeadline::start(AuthorityEpoch::Execution);
    transport_until(control, child, execution, libc::POLLOUT, || {
        send_packet(control, Frame::new(Kind::Proceed, operation_id), &[])
    })?;
    let (result, mut descriptors) = receive_until(control, child, execution)?;
    if result.kind == Kind::Error {
        drop(descriptors);
        return Err(worker_error(result));
    }
    if result.kind != Kind::Result
        || result.operation_id != operation_id
        || result.flags
            != if matches!(kind, OperationKind::Materialize) {
                FLAG_STAGE | FLAG_MATERIALIZE
            } else {
                0
            }
        || result.values[0] == 0
        || result.values[1] == 0
        || result.values[2] & 0xffff_ffff == 0
        || result.values[2] >> 32 == 0
        || result.values[3] & 0xff == 0
        || (result.values[3] >> 8) & 0xffff_ffff != libc::EACCES as u64
        || result.values[3] >> 40 != 0
        || descriptors.len() != 2
    {
        return Err(protocol("worker result envelope is inconsistent"));
    }
    let retained_descriptor = descriptors.pop().expect("descriptor count checked");
    let completion_descriptor = descriptors.pop().expect("descriptor count checked");
    let completion = sealed::validate(
        &completion_descriptor,
        BlobRole::Completion,
        result.values[0],
    )
    .map_err(|error| fail(SupervisionErrorKind::Protocol, error))?;
    let retained = sealed::validate(
        &retained_descriptor,
        BlobRole::RetainedContent,
        result.values[1],
    )
    .map_err(|error| fail(SupervisionErrorKind::Protocol, error))?;

    let exit = EpochDeadline::start(AuthorityEpoch::WorkerExit);
    transport_until(control, child, exit, libc::POLLOUT, || {
        send_packet(control, Frame::new(Kind::ExitAck, operation_id), &[])
    })?;
    let status = child.wait_for_exit(exit)?;
    if !status.success() {
        return Err(fail(
            SupervisionErrorKind::WorkerExit,
            format!("worker exited unsuccessfully as {status}"),
        ));
    }
    Ok(InitialResult {
        completion: completion.bytes().to_vec(),
        retained: retained.bytes().to_vec(),
    })
}

fn finish_active_result<T>(
    result: Result<T, SupervisionError>,
    child: &mut ChildBoundary,
) -> Result<T, SupervisionError> {
    if result.is_ok() || child.is_reaped() {
        return result;
    }
    match child.terminate_and_reap_bounded() {
        Ok(_) => result,
        Err(reap) => Err(SupervisionError::new(
            SupervisionErrorKind::Reap,
            match result {
                Ok(_) => format!("bounded worker termination failed: {reap}"),
                Err(error) => format!("{error}; bounded worker termination also failed: {reap}"),
            },
        )),
    }
}

#[derive(Clone)]
pub(crate) struct WorkerReadAuthority {
    inner: Arc<WorkerReadAuthorityInner>,
}

struct WorkerReadAuthorityInner {
    snapshot: SourceSnapshot<'static>,
    worker: LinuxWorker,
    operation_id: [u8; 16],
    planning: Arc<[u8]>,
    completion: Arc<[u8]>,
    coordinator: ReadCoordinator,
}

struct ReadCoordinator {
    active: Mutex<bool>,
    changed: Condvar,
}

struct ReadPermit<'a> {
    coordinator: &'a ReadCoordinator,
}

impl WorkerReadAuthority {
    fn new(
        snapshot: SourceSnapshot<'static>,
        worker: LinuxWorker,
        operation_id: [u8; 16],
        planning: Vec<u8>,
        completion: Vec<u8>,
    ) -> Self {
        Self {
            inner: Arc::new(WorkerReadAuthorityInner {
                snapshot,
                worker,
                operation_id,
                planning: Arc::from(planning),
                completion: Arc::from(completion),
                coordinator: ReadCoordinator {
                    active: Mutex::new(false),
                    changed: Condvar::new(),
                },
            }),
        }
    }

    pub(crate) fn source_digest(&self) -> &SourceDigest {
        self.inner.snapshot.digest()
    }

    pub(crate) fn read_member(
        &self,
        canonical_path: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, SupervisionError> {
        let deadline = Instant::now() + MEMBER_READ_TIMEOUT;
        let read_operation_id = random_operation_id()?;
        let authority = MemberReadAuthority::new(
            self.inner.operation_id,
            &self.inner.planning,
            &self.inner.completion,
        );
        let request = worker_runtime::create_member_read_request(
            clone_source(&self.inner.snapshot)?,
            self.inner.snapshot.len(),
            authority,
            read_operation_id,
            canonical_path,
            max_bytes,
        )
        .map_err(|detail| SupervisionError::new(SupervisionErrorKind::IntegrityMismatch, detail))?;
        let expected = worker_runtime::validate_member_read_request(
            clone_source(&self.inner.snapshot)?,
            self.inner.snapshot.len(),
            authority,
            &request,
            read_operation_id,
        )
        .map_err(|detail| SupervisionError::new(SupervisionErrorKind::IntegrityMismatch, detail))?;
        let _permit = self.inner.coordinator.acquire(deadline)?;
        let capacity = usize::try_from(expected.actual_bytes).map_err(|_| {
            SupervisionError::new(
                SupervisionErrorKind::Internal,
                "authorized member size does not fit this platform",
            )
        })?;
        let mut output = Vec::new();
        output.try_reserve_exact(capacity).map_err(|error| {
            SupervisionError::new(
                SupervisionErrorKind::Internal,
                format!("could not reserve {capacity} authorized member bytes: {error}"),
            )
        })?;
        execute_member_read(
            &self.inner,
            read_operation_id,
            &request,
            expected,
            deadline,
            &mut output,
        )?;
        Ok(output)
    }
}

impl ReadCoordinator {
    fn acquire(&self, deadline: Instant) -> Result<ReadPermit<'_>, SupervisionError> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| protocol("member-read coordinator mutex was poisoned"))?;
        while *active {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    fail(
                        SupervisionErrorKind::TimedOut,
                        "member read expired while queued",
                    )
                })?;
            let (guard, wait) = self
                .changed
                .wait_timeout(active, remaining)
                .map_err(|_| protocol("member-read coordinator wait was poisoned"))?;
            active = guard;
            if wait.timed_out() && *active {
                return Err(fail(
                    SupervisionErrorKind::TimedOut,
                    "member read expired while queued",
                ));
            }
        }
        *active = true;
        Ok(ReadPermit { coordinator: self })
    }
}

impl Drop for ReadPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.coordinator.active.lock() {
            *active = false;
            self.coordinator.changed.notify_one();
        }
    }
}

fn execute_member_read(
    authority: &WorkerReadAuthorityInner,
    read_operation_id: [u8; 16],
    request: &[u8],
    expected: MemberReadEvidence,
    deadline: Instant,
    output: &mut Vec<u8>,
) -> Result<(), SupervisionError> {
    let (control, child_socket) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|error| fail(SupervisionErrorKind::Spawn, error))?;
    configure_supervisor_control(&control)?;
    let child = spawn_child(&authority.worker.artifact, child_socket)?;
    let mut child = ChildBoundary::bind_authenticated(child, &control, &authority.worker.artifact)?;
    let result = execute_member_read_active(
        authority,
        read_operation_id,
        request,
        expected,
        deadline,
        output,
        &control,
        &mut child,
    );
    finish_active_result(result, &mut child)
}

#[allow(clippy::too_many_arguments)]
fn execute_member_read_active(
    authority: &WorkerReadAuthorityInner,
    read_operation_id: [u8; 16],
    request: &[u8],
    expected: MemberReadEvidence,
    deadline: Instant,
    output: &mut Vec<u8>,
    control: &OwnedFd,
    child: &mut ChildBoundary,
) -> Result<(), SupervisionError> {
    let epoch = EpochDeadline::ending_at(AuthorityEpoch::Execution, deadline);
    let mut bootstrap = Frame::new(Kind::Bootstrap, read_operation_id);
    bootstrap.flags = FLAG_MEMBER_READ;
    transport_until(control, child, epoch, libc::POLLOUT, || {
        send_packet(control, bootstrap, &[])
    })?;
    let (ready, descriptors) = receive_until(control, child, epoch)?;
    require_no_descriptors(&descriptors, "member-read restriction readiness")?;
    if ready.kind == Kind::Error {
        return Err(worker_error(ready));
    }
    if ready.kind != Kind::RestrictedReady
        || ready.operation_id != read_operation_id
        || ready.flags != READY_FLAGS | FLAG_MEMBER_READ
        || ready.values[0] < 3
        || ready.values[1] == 0
        || ready.values[2] == 0
        || ready.values[1] & ready.values[2] != ready.values[2]
        || ready.values[3] != u64::MAX
    {
        return Err(protocol(
            "member-read restriction-ready evidence is inconsistent",
        ));
    }
    observe_restricted_child(child.child.id(), &ready, None)?;

    let source = clone_source(&authority.snapshot)?;
    let source_values = source_identity(&source)?;
    let mut source_frame = Frame::new(Kind::Source, read_operation_id);
    source_frame.values = source_values;
    transport_until(control, child, epoch, libc::POLLOUT, || {
        send_packet(control, source_frame, &[source.as_fd()])
    })?;
    let (accepted, descriptors) = receive_until(control, child, epoch)?;
    require_no_descriptors(&descriptors, "member-read source acceptance")?;
    if accepted.kind == Kind::Error {
        return Err(worker_error(accepted));
    }
    if accepted.kind != Kind::Accepted
        || accepted.operation_id != read_operation_id
        || accepted.flags != 0
        || accepted.values[..3] != source_values[..3]
        || accepted.values[3] > i32::MAX as u64
    {
        return Err(protocol("member-read source acceptance is inconsistent"));
    }

    let planning_descriptor = sealed::create(BlobRole::Planning, &authority.planning)
        .map_err(|error| fail(SupervisionErrorKind::Protocol, error))?;
    let planning_len = sealed::total_len(authority.planning.len())
        .ok_or_else(|| protocol("member-read planning blob exceeds its envelope"))?;
    let mut plan = Frame::new(Kind::Plan, read_operation_id);
    plan.values = [
        planning_len,
        u64::from_le_bytes(
            authority.operation_id[..8]
                .try_into()
                .expect("operation ID half has fixed width"),
        ),
        u64::from_le_bytes(
            authority.operation_id[8..]
                .try_into()
                .expect("operation ID half has fixed width"),
        ),
        0,
    ];
    transport_until(control, child, epoch, libc::POLLOUT, || {
        send_packet(control, plan, &[planning_descriptor.as_fd()])
    })?;
    let (accepted_plan, descriptors) = receive_until(control, child, epoch)?;
    require_no_descriptors(&descriptors, "member-read plan acceptance")?;
    if accepted_plan.kind == Kind::Error {
        return Err(worker_error(accepted_plan));
    }
    if accepted_plan.kind != Kind::PlanAccepted
        || accepted_plan.operation_id != read_operation_id
        || accepted_plan.flags != 0
        || accepted_plan.values[0] != planning_len
        || accepted_plan.values[1] > i32::MAX as u64
        || accepted_plan.values[2] != plan.values[1]
        || accepted_plan.values[3] != plan.values[2]
    {
        return Err(protocol("member-read plan acceptance is inconsistent"));
    }

    let completion_descriptor = sealed::create(BlobRole::Completion, &authority.completion)
        .map_err(|error| fail(SupervisionErrorKind::Protocol, error))?;
    let request_descriptor = sealed::create(BlobRole::MemberReadRequest, request)
        .map_err(|error| fail(SupervisionErrorKind::Protocol, error))?;
    let completion_len = sealed::total_len(authority.completion.len())
        .ok_or_else(|| protocol("member-read completion blob exceeds its envelope"))?;
    let request_len = sealed::total_len(request.len())
        .ok_or_else(|| protocol("member-read request blob exceeds its envelope"))?;
    let mut read = Frame::new(Kind::MemberRead, read_operation_id);
    read.values = [completion_len, request_len, 0, 0];
    transport_until(control, child, epoch, libc::POLLOUT, || {
        send_packet(
            control,
            read,
            &[completion_descriptor.as_fd(), request_descriptor.as_fd()],
        )
    })?;
    let (read_accepted, descriptors) = receive_until(control, child, epoch)?;
    require_no_descriptors(&descriptors, "member-read authority acceptance")?;
    if read_accepted.kind == Kind::Error {
        return Err(worker_error(read_accepted));
    }
    if read_accepted.kind != Kind::MemberReadAccepted
        || read_accepted.operation_id != read_operation_id
        || read_accepted.flags != 0
        || read_accepted.values[0] != completion_len
        || read_accepted.values[1] > i32::MAX as u64
        || read_accepted.values[2] != request_len
        || read_accepted.values[3] > i32::MAX as u64
    {
        return Err(protocol("member-read authority acceptance is inconsistent"));
    }

    let (output_reader, output_writer) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC)
        .map_err(|error| fail(SupervisionErrorKind::Protocol, error))?;
    let flags = rustix::fs::fcntl_getfl(&output_reader)
        .map_err(|error| fail(SupervisionErrorKind::Protocol, error))?;
    rustix::fs::fcntl_setfl(&output_reader, flags | OFlags::NONBLOCK)
        .map_err(|error| fail(SupervisionErrorKind::Protocol, error))?;
    let mut proceed = Frame::new(Kind::Proceed, read_operation_id);
    proceed.values[0] = expected.actual_bytes;
    transport_until(control, child, epoch, libc::POLLOUT, || {
        send_packet(control, proceed, &[output_writer.as_fd()])
    })?;
    drop(output_writer);

    drain_member_read(
        authority,
        read_operation_id,
        request,
        expected,
        deadline,
        output,
        control,
        child,
        output_reader,
    )
}

#[allow(clippy::too_many_arguments)]
fn drain_member_read(
    authority: &WorkerReadAuthorityInner,
    read_operation_id: [u8; 16],
    request: &[u8],
    expected: MemberReadEvidence,
    deadline: Instant,
    output: &mut Vec<u8>,
    control: &OwnedFd,
    child: &mut ChildBoundary,
    output_reader: OwnedFd,
) -> Result<(), SupervisionError> {
    let mut eof = false;
    let mut result_observed = false;
    while !eof || !result_observed {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                fail(
                    SupervisionErrorKind::TimedOut,
                    "member read exceeded its absolute deadline",
                )
            })?;
        let timeout = libc::c_int::try_from(remaining.as_millis())
            .unwrap_or(libc::c_int::MAX)
            .max(1);
        let mut descriptors = [
            libc::pollfd {
                fd: output_reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: control.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: child.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: descriptors is a live pollfd array and timeout is finite.
        let polled = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                timeout,
            )
        };
        if polled < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(fail(SupervisionErrorKind::Protocol, error));
        }
        if polled == 0 {
            continue;
        }
        if descriptors[2].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
            let status = child
                .reap_until(deadline)
                .map_err(|error| fail(SupervisionErrorKind::Reap, error))?;
            return Err(fail(
                SupervisionErrorKind::WorkerExit,
                format!("member-read worker exited before finalization as {status}"),
            ));
        }
        if descriptors[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            loop {
                let mut chunk = [0_u8; 64 * 1024];
                match rustix::io::read(&output_reader, &mut chunk) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(read) => {
                        let next = output
                            .len()
                            .checked_add(read)
                            .ok_or_else(|| protocol("member-read output length overflowed"))?;
                        if next > expected.actual_bytes as usize {
                            return Err(protocol(
                                "member-read worker emitted more than the authorized size",
                            ));
                        }
                        output.extend_from_slice(&chunk[..read]);
                    }
                    Err(rustix::io::Errno::AGAIN) => break,
                    Err(rustix::io::Errno::INTR) => {}
                    Err(error) => return Err(fail(SupervisionErrorKind::Protocol, error)),
                }
            }
        }
        if descriptors[1].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
            let (frame, returned) = receive_packet(control, None)
                .map_err(|error| fail(SupervisionErrorKind::Protocol, error))?;
            require_no_descriptors(&returned, "member-read result")?;
            if frame.kind == Kind::Error {
                return Err(worker_error(frame));
            }
            if frame.kind != Kind::MemberReadResult
                || frame.operation_id != read_operation_id
                || frame.flags != 0
                || frame.values[0] != expected.member_index
                || frame.values[1] != expected.actual_bytes
                || frame.values[2] != u64::from(expected.actual_crc)
                || frame.values[3] != 0
                || result_observed
            {
                return Err(protocol(
                    "member-read result correlation is invalid or duplicated",
                ));
            }
            result_observed = true;
        }
    }
    if output.len() as u64 != expected.actual_bytes {
        return Err(SupervisionError::new(
            SupervisionErrorKind::IntegrityMismatch,
            "member-read output reached EOF at the wrong length",
        ));
    }

    let exit = EpochDeadline::ending_at(AuthorityEpoch::WorkerExit, deadline);
    transport_until(control, child, exit, libc::POLLOUT, || {
        send_packet(control, Frame::new(Kind::ExitAck, read_operation_id), &[])
    })?;
    let status = child.wait_for_exit(exit)?;
    if !status.success() {
        return Err(fail(
            SupervisionErrorKind::WorkerExit,
            format!("member-read worker exited unsuccessfully as {status}"),
        ));
    }
    let read_authority = MemberReadAuthority::new(
        authority.operation_id,
        &authority.planning,
        &authority.completion,
    );
    worker_runtime::validate_member_read_result(
        clone_source(&authority.snapshot)?,
        authority.snapshot.len(),
        read_authority,
        request,
        read_operation_id,
        output,
    )
    .map_err(|detail| SupervisionError::new(SupervisionErrorKind::IntegrityMismatch, detail))?;
    Ok(())
}

fn configure_supervisor_control(control: &OwnedFd) -> Result<(), SupervisionError> {
    configure_timeout(control).map_err(|error| fail(SupervisionErrorKind::Protocol, error))?;
    let flags = rustix::fs::fcntl_getfl(control)
        .map_err(|error| fail(SupervisionErrorKind::Protocol, error))?;
    rustix::fs::fcntl_setfl(control, flags | OFlags::NONBLOCK)
        .map_err(|error| fail(SupervisionErrorKind::Protocol, error))
}

fn observe_restricted_child(
    pid: u32,
    ready: &Frame,
    stage: Option<&File>,
) -> Result<(), SupervisionError> {
    let proc_root = PathBuf::from(format!("/proc/{pid}"));
    let status = fs::read_to_string(proc_root.join("status"))
        .map_err(|error| fail(SupervisionErrorKind::RestrictionUnavailable, error))?;
    let seccomp_filters = status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp_filters:\t"))
        .map(str::parse::<u64>)
        .transpose()
        .map_err(|error| fail(SupervisionErrorKind::RestrictionUnavailable, error))?;
    if !status.lines().any(|line| line == "NoNewPrivs:\t1")
        || !status.lines().any(|line| line == "Threads:\t1")
        || !status.lines().any(|line| line == "Seccomp:\t2")
        || seccomp_filters.is_none_or(|count| count == 0)
    {
        return Err(fail(
            SupervisionErrorKind::RestrictionUnavailable,
            "worker is not single-threaded with no_new_privs and an active seccomp filter",
        ));
    }
    let children = fs::read_to_string(proc_root.join(format!("task/{pid}/children")))
        .map_err(|error| fail(SupervisionErrorKind::RestrictionUnavailable, error))?;
    if !children.trim().is_empty() {
        return Err(fail(
            SupervisionErrorKind::RestrictionUnavailable,
            format!("restricted worker retained descendant PIDs {children:?}"),
        ));
    }
    let mut descriptors = fs::read_dir(proc_root.join("fd"))
        .map_err(|error| fail(SupervisionErrorKind::RestrictionUnavailable, error))?
        .map(|entry| {
            let entry =
                entry.map_err(|error| fail(SupervisionErrorKind::RestrictionUnavailable, error))?;
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
                .ok_or_else(|| {
                    fail(
                        SupervisionErrorKind::RestrictionUnavailable,
                        "worker descriptor entry is not numeric",
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    descriptors.sort_unstable();
    let mut expected = vec![0, 1, 2];
    if stage.is_some() {
        expected.push(
            i32::try_from(ready.values[3])
                .map_err(|error| fail(SupervisionErrorKind::RestrictionUnavailable, error))?,
        );
        expected.sort_unstable();
    }
    if descriptors != expected {
        return Err(fail(
            SupervisionErrorKind::RestrictionUnavailable,
            format!("restricted worker descriptor set is {descriptors:?}; expected {expected:?}"),
        ));
    }
    let flags = proc_descriptor_flags(&proc_root, 0)?;
    if flags & libc::O_CLOEXEC as u64 == 0 {
        return Err(fail(
            SupervisionErrorKind::RestrictionUnavailable,
            "worker control descriptor lacks close-on-exec",
        ));
    }
    if let Some(stage) = stage {
        let stage_fd = i32::try_from(ready.values[3])
            .map_err(|error| fail(SupervisionErrorKind::RestrictionUnavailable, error))?;
        let observed = File::open(proc_root.join(format!("fd/{stage_fd}")))
            .map_err(|error| fail(SupervisionErrorKind::RestrictionUnavailable, error))?;
        let observed_stat = rustix::fs::fstat(&observed)
            .map_err(|error| fail(SupervisionErrorKind::RestrictionUnavailable, error))?;
        let retained_stat = rustix::fs::fstat(stage)
            .map_err(|error| fail(SupervisionErrorKind::RestrictionUnavailable, error))?;
        if observed_stat.st_dev != retained_stat.st_dev
            || observed_stat.st_ino != retained_stat.st_ino
        {
            return Err(fail(
                SupervisionErrorKind::RestrictionUnavailable,
                "restricted worker stage identity differs from the retained stage",
            ));
        }
        let observed_flags = proc_descriptor_flags(&proc_root, stage_fd)?;
        let retained_flags = rustix::fs::fcntl_getfl(stage)
            .map_err(|error| fail(SupervisionErrorKind::RestrictionUnavailable, error))?
            .bits() as u64;
        if observed_flags & libc::O_ACCMODE as u64 != retained_flags & libc::O_ACCMODE as u64 {
            return Err(fail(
                SupervisionErrorKind::RestrictionUnavailable,
                "restricted worker stage access mode differs from the retained stage",
            ));
        }
        if observed_flags & libc::O_CLOEXEC as u64 == 0 {
            return Err(fail(
                SupervisionErrorKind::RestrictionUnavailable,
                "restricted worker stage descriptor lacks close-on-exec",
            ));
        }
    }
    Ok(())
}

fn proc_descriptor_flags(
    proc_root: &std::path::Path,
    descriptor: i32,
) -> Result<u64, SupervisionError> {
    let info = fs::read_to_string(proc_root.join(format!("fdinfo/{descriptor}")))
        .map_err(|error| fail(SupervisionErrorKind::RestrictionUnavailable, error))?;
    let flags = info
        .lines()
        .find_map(|line| line.strip_prefix("flags:\t"))
        .ok_or_else(|| {
            fail(
                SupervisionErrorKind::RestrictionUnavailable,
                "worker descriptor has no procfs flags",
            )
        })?;
    u64::from_str_radix(flags, 8)
        .map_err(|error| fail(SupervisionErrorKind::RestrictionUnavailable, error))
}

fn transport_until<T>(
    control: &OwnedFd,
    child: &mut ChildBoundary,
    deadline: EpochDeadline,
    events: libc::c_short,
    mut operation: impl FnMut() -> Result<T, TransportError>,
) -> Result<T, SupervisionError> {
    loop {
        child.wait_for_control(control, deadline, events)?;
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if error.is_would_block() => {}
            Err(error) => return Err(fail(SupervisionErrorKind::Protocol, error)),
        }
    }
}

fn receive_until(
    control: &OwnedFd,
    child: &mut ChildBoundary,
    deadline: EpochDeadline,
) -> Result<(Frame, Vec<OwnedFd>), SupervisionError> {
    transport_until(control, child, deadline, libc::POLLIN, || {
        receive_packet(control, None)
    })
}

fn require_no_descriptors(descriptors: &[OwnedFd], phase: &str) -> Result<(), SupervisionError> {
    if descriptors.is_empty() {
        Ok(())
    } else {
        Err(protocol(format!(
            "worker returned {} unexpected descriptors with {phase}",
            descriptors.len()
        )))
    }
}

fn worker_error(frame: Frame) -> SupervisionError {
    let kind = if frame.values[0] == ERROR_RESTRICTION {
        SupervisionErrorKind::RestrictionUnavailable
    } else {
        SupervisionErrorKind::Protocol
    };
    SupervisionError::new(
        kind,
        format!(
            "worker rejected authority with code {}, phase {}, detail {}",
            frame.values[0], frame.values[1], frame.values[2]
        ),
    )
}

fn source_identity(source: &File) -> Result<[u64; 4], SupervisionError> {
    let stat =
        rustix::fs::fstat(source).map_err(|error| fail(SupervisionErrorKind::Source, error))?;
    let length = u64::try_from(stat.st_size).map_err(|_| {
        fail(
            SupervisionErrorKind::Source,
            "private source descriptor has a negative length",
        )
    })?;
    Ok([length, stat.st_dev, stat.st_ino, 0])
}

fn stage_identity(stage: &File) -> Result<[u64; 4], SupervisionError> {
    let stat =
        rustix::fs::fstat(stage).map_err(|error| fail(SupervisionErrorKind::Internal, error))?;
    Ok([
        stat.st_dev,
        stat.st_ino,
        u64::from(stat.st_mode),
        u64::from(stat.st_uid),
    ])
}

fn clone_source(snapshot: &SourceSnapshot<'_>) -> Result<File, SupervisionError> {
    snapshot.try_clone_worker_file().map_err(|finding| {
        SupervisionError::new(
            SupervisionErrorKind::Source,
            format!("{}: {}", finding.code.as_str(), finding.detail),
        )
    })
}

fn random_operation_id() -> Result<[u8; 16], SupervisionError> {
    let mut operation_id = [0_u8; 16];
    loop {
        getrandom::fill(&mut operation_id)
            .map_err(|error| fail(SupervisionErrorKind::Internal, error))?;
        if operation_id != [0; 16] {
            return Ok(operation_id);
        }
    }
}

fn spawn_child(
    artifact: &HelperArtifact,
    child_socket: OwnedFd,
) -> Result<Child, SupervisionError> {
    let mut command = Command::new(artifact.execution_path());
    command
        .env_clear()
        .stdin(Stdio::from(child_socket))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the closure performs one async-signal-safe syscall, touches no
    // Rust-managed state, and returns only an errno-backed io::Error. The
    // close-on-exec mark preserves the standard library's exec-error pipe while
    // preventing unrelated authority from surviving a successful exec.
    unsafe {
        command.pre_exec(|| {
            let result = libc::syscall(
                libc::SYS_close_range,
                3_u32,
                u32::MAX,
                libc::CLOSE_RANGE_UNSHARE | libc::CLOSE_RANGE_CLOEXEC,
            );
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
    command
        .spawn()
        .map_err(|error| fail(SupervisionErrorKind::Spawn, error))
}

struct ChildBoundary {
    child: Child,
    pidfd: OwnedFd,
    reaped: bool,
    status: Option<ExitStatus>,
}

impl ChildBoundary {
    fn bind_authenticated(
        child: Child,
        control: &OwnedFd,
        artifact: &HelperArtifact,
    ) -> Result<Self, SupervisionError> {
        let mut boundary = Self::bind(child)?;
        if let Err(error) = boundary.authenticate(control, artifact) {
            return Err(boundary.reject_authentication(error));
        }
        Ok(boundary)
    }

    fn bind(mut child: Child) -> Result<Self, SupervisionError> {
        let pid = rustix::process::Pid::from_child(&child);
        match rustix::process::pidfd_open(pid, PidfdFlags::empty()) {
            Ok(pidfd) => Ok(Self {
                child,
                pidfd,
                reaped: false,
                status: None,
            }),
            Err(error) => match terminate_unbound_child_bounded(&mut child) {
                Ok(status) => Err(fail(
                    SupervisionErrorKind::Spawn,
                    format!(
                        "binding worker pidfd failed: {error}; bounded fallback reaped it as {status}"
                    ),
                )),
                Err(termination) => Err(fail(
                    SupervisionErrorKind::Reap,
                    format!(
                        "binding worker pidfd failed: {error}; bounded fallback termination also failed: {termination}"
                    ),
                )),
            },
        }
    }

    fn authenticate(
        &mut self,
        control: &OwnedFd,
        artifact: &HelperArtifact,
    ) -> Result<(), SupervisionError> {
        let operation_id = random_operation_id()?;
        let mut challenge = Frame::new(Kind::HelperChallenge, operation_id);
        challenge.values = [HELPER_BOOTSTRAP_ABI, HELPER_FEATURE_ID, 0, 0];
        let deadline = EpochDeadline::start(AuthorityEpoch::HelperAuthentication);
        transport_until(control, self, deadline, libc::POLLOUT, || {
            send_packet(control, challenge, &[])
        })?;
        let (hello, descriptors) = receive_until(control, self, deadline)?;
        if !descriptors.is_empty()
            || hello.kind != Kind::HelperHello
            || hello.flags != 0
            || hello.operation_id != operation_id
            || hello.values != [HELPER_BOOTSTRAP_ABI, HELPER_FEATURE_ID, 0, 0]
        {
            return Err(fail(
                SupervisionErrorKind::Authentication,
                "worker authentication hello is invalid",
            ));
        }
        artifact
            .verify_process_executable(self.child.id())
            .map_err(|error| fail(SupervisionErrorKind::Authentication, error))?;
        Ok(())
    }

    fn reject_authentication(&mut self, error: SupervisionError) -> SupervisionError {
        match self.terminate_and_reap_bounded() {
            Ok(status) => fail(
                SupervisionErrorKind::Authentication,
                format!("{error}; bounded termination reaped worker as {status}"),
            ),
            Err(termination) => fail(
                SupervisionErrorKind::Reap,
                format!("{error}; bounded termination also failed: {termination}"),
            ),
        }
    }

    fn is_reaped(&self) -> bool {
        self.reaped
    }

    fn record_status(&mut self, status: ExitStatus) -> ExitStatus {
        self.reaped = true;
        self.status = Some(status);
        status
    }

    fn expire_epoch<T>(&mut self, deadline: EpochDeadline) -> Result<T, SupervisionError> {
        let status = self.terminate_and_reap_bounded().map_err(|error| {
            fail(
                SupervisionErrorKind::Reap,
                format!(
                    "authority epoch {:?} expired and worker termination failed: {error}",
                    deadline.epoch
                ),
            )
        })?;
        Err(fail(
            SupervisionErrorKind::TimedOut,
            format!(
                "authority epoch {:?} exceeded its absolute deadline and was reaped as {status}",
                deadline.epoch
            ),
        ))
    }

    fn wait_for_control(
        &mut self,
        control: &OwnedFd,
        deadline: EpochDeadline,
        events: libc::c_short,
    ) -> Result<(), SupervisionError> {
        loop {
            let Some(timeout) = deadline.poll_timeout_ms() else {
                return self.expire_epoch(deadline);
            };
            let mut descriptors = [
                libc::pollfd {
                    fd: control.as_raw_fd(),
                    events,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.pidfd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: descriptors is a live two-element pollfd array and the
            // timeout is recomputed from one finite absolute deadline.
            let result = unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptors.len() as libc::nfds_t,
                    timeout,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(fail(SupervisionErrorKind::Protocol, error));
            }
            if result == 0 {
                continue;
            }
            let control_events = descriptors[0].revents;
            if control_events & libc::POLLNVAL != 0 {
                return Err(protocol("worker control descriptor became invalid"));
            }
            if control_events & (events | libc::POLLERR | libc::POLLHUP) != 0 {
                return Ok(());
            }
            let pidfd_events = descriptors[1].revents;
            if pidfd_events & libc::POLLNVAL != 0 {
                return Err(protocol("worker pidfd became invalid"));
            }
            if pidfd_events & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
                let status = self
                    .reap_until(deadline.expires_at)
                    .map_err(|error| fail(SupervisionErrorKind::Reap, error))?;
                return Err(fail(
                    SupervisionErrorKind::WorkerExit,
                    format!(
                        "worker exited as {status} during authority epoch {:?}",
                        deadline.epoch
                    ),
                ));
            }
        }
    }

    fn wait_for_exit(&mut self, deadline: EpochDeadline) -> Result<ExitStatus, SupervisionError> {
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|error| fail(SupervisionErrorKind::Reap, error))?
            {
                return Ok(self.record_status(status));
            }
            let Some(timeout) = deadline.poll_timeout_ms() else {
                return self.expire_epoch(deadline);
            };
            let mut descriptor = libc::pollfd {
                fd: self.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: descriptor is one live pollfd and timeout is finite.
            let result = unsafe { libc::poll(std::ptr::from_mut(&mut descriptor), 1, timeout) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(fail(SupervisionErrorKind::Reap, error));
            }
            if result == 0 {
                continue;
            }
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(fail(
                    SupervisionErrorKind::Reap,
                    "worker pidfd became invalid",
                ));
            }
            if descriptor.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
                return self
                    .reap_until(deadline.expires_at)
                    .map_err(|error| fail(SupervisionErrorKind::Reap, error));
            }
        }
    }

    fn reap_until(&mut self, deadline: Instant) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(self.record_status(status));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "worker reap could not be proved within the deadline",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn terminate_and_reap_bounded(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.child.try_wait()? {
            return Ok(self.record_status(status));
        }
        match rustix::process::pidfd_send_signal(&self.pidfd, Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(error) => return Err(io::Error::from(error)),
        }
        self.reap_until(Instant::now() + KILL_REAP_TIMEOUT)
    }
}

impl Drop for ChildBoundary {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            self.reaped = true;
            return;
        }
        let _ = rustix::process::pidfd_send_signal(&self.pidfd, Signal::KILL);
        let deadline = Instant::now() + Duration::from_millis(100);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                self.reaped = true;
                return;
            }
            thread::yield_now();
        }
    }
}

fn terminate_unbound_child_bounded(child: &mut Child) -> io::Result<ExitStatus> {
    match child.kill() {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
        Err(error) => return Err(error),
    }
    let deadline = Instant::now() + KILL_REAP_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "unbound worker could not be reaped within the deadline",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn protocol(detail: impl Into<String>) -> SupervisionError {
    SupervisionError::new(SupervisionErrorKind::Protocol, detail)
}

fn fail(kind: SupervisionErrorKind, detail: impl std::fmt::Display) -> SupervisionError {
    SupervisionError::new(kind, detail.to_string())
}
