use super::{
    configure_supervisor_control, descriptor_identity, finish_fixture, observe_accepted_child,
    observe_completed_child, observe_plan_accepted_child, observe_restricted_child,
    random_operation_id, require_no_supervisor_children, source_bytes, source_identity,
    spawn_child, supervisor_descriptor_count, transport_until, AuthorityEpoch, ChildBoundary,
    EpochDeadline, Fixture, SOURCE_MEMBER_COUNT,
};
use crate::fault::{ChildMode, FaultPoint, StallPoint};
use crate::frame::{Frame, Kind};
use crate::linux::{receive_packet, send_packet, FLAG_MATERIALIZE, FLAG_STAGE, READY_FLAGS};
use crate::sealed::{self, BlobRole};
use landlock::{make_bitflags, Access, AccessFs, ABI};
use rustix::fd::{AsFd, OwnedFd};
use std::fs::{self, File};
use std::io;
use std::path::Path;

struct ActiveWriter<'fixture> {
    child: ChildBoundary,
    stage: Option<sealr::__worker_lab::WorkerLabStage>,
    fixture: &'fixture Fixture,
}

struct ReapedWriter {
    stage: sealr::__worker_lab::WorkerLabStage,
    planning: Vec<u8>,
    completion: OwnedFd,
    completion_len: u64,
}

struct AuthorizedWriter {
    stage: sealr::__worker_lab::WorkerLabStage,
    manifest: sealr::__worker_lab::AuthorizedStageManifest,
}

struct AuditedWriter {
    stage: sealr::__worker_lab::AuditedWorkerLabStage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriterCase {
    Publish,
    AuditMutation,
    DestinationRace,
    CleanupFailure,
}

const WRITER_STRESS_ITERATIONS: usize = 500;

impl Drop for ActiveWriter<'_> {
    fn drop(&mut self) {
        if self.child.is_reaped() {
            self.fixture.authorize_cleanup();
        } else {
            if self.child.terminate_and_reap_bounded().is_ok() {
                self.fixture.authorize_cleanup();
            } else if let Some(stage) = self.stage.take() {
                stage.abandon();
                return;
            }
        }
        if let Some(stage) = self.stage.take() {
            let _ = stage.abort();
        }
    }
}

impl ReapedWriter {
    fn authorize(
        self,
        source: &File,
        source_len: u64,
        operation_id: [u8; 16],
    ) -> Result<AuthorizedWriter, Box<dyn std::error::Error>> {
        let completion =
            sealed::validate(&self.completion, BlobRole::Completion, self.completion_len)?;
        let manifest = sealr::__worker_lab::authorize_materialize_execution(
            source.try_clone()?,
            source_len,
            operation_id,
            &self.planning,
            completion.bytes(),
        )
        .map_err(|error| io::Error::other(format!("authorizing materialized stage: {error}")))?;
        let evidence = manifest.evidence();
        if !evidence.complete
            || evidence.member_count != SOURCE_MEMBER_COUNT
            || evidence.verified_members != SOURCE_MEMBER_COUNT
        {
            return Err(io::Error::other(format!(
                "materialization completion evidence is incomplete: {evidence:?}"
            ))
            .into());
        }
        Ok(AuthorizedWriter {
            stage: self.stage,
            manifest,
        })
    }
}

impl AuthorizedWriter {
    fn audit(self) -> Result<AuditedWriter, Box<dyn std::error::Error>> {
        let stage = self
            .stage
            .audit(&self.manifest)
            .map_err(|error| io::Error::other(format!("auditing materialized stage: {error}")))?;
        Ok(AuditedWriter { stage })
    }
}

impl AuditedWriter {
    fn publish(self) -> Result<(), Box<dyn std::error::Error>> {
        self.stage
            .publish()
            .map_err(|error| io::Error::other(format!("publishing materialized stage: {error}")))?;
        Ok(())
    }
}

pub(super) fn run_conformance() -> Result<(), Box<dyn std::error::Error>> {
    run_fixture(WriterCase::Publish)?;
    run_fixture(WriterCase::AuditMutation)?;
    run_fixture(WriterCase::DestinationRace)?;
    run_fixture(WriterCase::CleanupFailure)?;
    run_expected_worker_failure(ChildMode::ExitAt(FaultPoint::CompletionSeal))?;
    run_expected_worker_failure(ChildMode::ExitAt(FaultPoint::StageCreate))?;
    run_expected_worker_failure(ChildMode::ExitAt(FaultPoint::Result))?;
    run_expected_worker_failure(ChildMode::ExitAt(FaultPoint::ExitAck))?;
    run_expected_worker_failure(ChildMode::StallAt(StallPoint::ProbeExecution))?;
    run_expected_worker_failure(ChildMode::StallAt(StallPoint::ExitCompletion))?;
    run_repeated_writer_stress()?;
    Ok(())
}

fn run_repeated_writer_stress() -> Result<(), Box<dyn std::error::Error>> {
    require_no_supervisor_children("before writer stress")?;
    let expected_descriptors = supervisor_descriptor_count()?;
    for iteration in 0..WRITER_STRESS_ITERATIONS {
        let result = match iteration % 6 {
            0 => run_fixture(WriterCase::Publish),
            1 => run_fixture(WriterCase::AuditMutation),
            2 => run_fixture(WriterCase::DestinationRace),
            3 => run_fixture(WriterCase::CleanupFailure),
            4 => run_expected_worker_failure(ChildMode::ExitAt(FaultPoint::CompletionSeal)),
            5 => run_expected_worker_failure(ChildMode::ExitAt(FaultPoint::Result)),
            _ => unreachable!("writer stress modulus is closed"),
        };
        if let Err(error) = result {
            return Err(io::Error::other(format!(
                "writer stress iteration {iteration} failed: {error}"
            ))
            .into());
        }
        require_no_supervisor_children(&format!("after writer stress iteration {iteration}"))?;
        let descriptors = supervisor_descriptor_count()?;
        if descriptors != expected_descriptors {
            return Err(io::Error::other(format!(
                "writer stress changed supervisor descriptor count from {expected_descriptors} to {descriptors} at iteration {iteration}"
            ))
            .into());
        }
    }
    Ok(())
}

fn run_fixture(case: WriterCase) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(false, false, false)?;
    let result = run_case(&fixture, ChildMode::Normal, case);
    finish_fixture(&fixture, result)
}

fn run_expected_worker_failure(mode: ChildMode) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(false, false, false)?;
    let result = match run_case(&fixture, mode, WriterCase::Publish) {
        Ok(()) => Err(io::Error::other(format!(
            "writer unexpectedly published through injected mode {mode:?}"
        ))
        .into()),
        Err(error) => {
            match mode {
                ChildMode::ExitAt(point) => {
                    let expected = format!(
                        "injected crash {point:?} with exit status {}",
                        point.exit_code()
                    );
                    if !error.to_string().contains(&expected) {
                        return finish_fixture(
                            &fixture,
                            Err(io::Error::other(format!(
                                "writer crash at {point:?} produced unexpected evidence: {error}"
                            ))
                            .into()),
                        );
                    }
                }
                ChildMode::StallAt(point) => {
                    let timeout = error.downcast_ref::<super::EpochTimeout>().ok_or_else(|| {
                        io::Error::other(format!(
                            "writer stall did not produce a typed epoch timeout: {error}"
                        ))
                    })?;
                    let expected_epoch = AuthorityEpoch::for_stall(point);
                    if timeout.epoch != expected_epoch || timeout.signal != libc::SIGKILL {
                        return finish_fixture(
                            &fixture,
                            Err(io::Error::other(format!(
                                "writer stall ended with unexpected timeout evidence: {timeout}"
                            ))
                            .into()),
                        );
                    }
                }
                _ => {
                    return finish_fixture(
                        &fixture,
                        Err(io::Error::other("unsupported writer failure mode").into()),
                    );
                }
            }
            if fixture.root.join("published").try_exists()? {
                Err(io::Error::other("failed writer published a destination").into())
            } else {
                Ok(())
            }
        }
    };
    finish_fixture(&fixture, result)
}

fn run_case(
    fixture: &Fixture,
    mode: ChildMode,
    case: WriterCase,
) -> Result<(), Box<dyn std::error::Error>> {
    let operation_id = random_operation_id()?;
    let destination = fixture.root.join("published");
    let stage = sealr::__worker_lab::WorkerLabStage::create(&destination)
        .map_err(|error| io::Error::other(format!("creating writer stage: {error}")))?;
    let stage_descriptor = stage
        .try_clone_writer_file()
        .map_err(|error| io::Error::other(format!("cloning writer stage: {error}")))?;
    let stage_values = descriptor_identity(&stage_descriptor)?;
    let source_values = source_identity(&fixture.source)?;
    let planning = sealr::__worker_lab::plan_materialize(source_bytes(), operation_id)
        .map_err(|error| io::Error::other(format!("planning materialization: {error}")))?;
    let plan_descriptor = sealed::create(BlobRole::Planning, &planning)?;
    let plan_total_len = sealed::total_len(planning.len())
        .ok_or("materialization planning record is outside the sealed-blob bound")?;

    let (control, child_socket) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::SEQPACKET,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )?;
    configure_supervisor_control(&control)?;
    let child = spawn_child(child_socket, mode)?;
    fixture.revoke_cleanup();
    let child = match ChildBoundary::bind_authenticated(child, &control, mode) {
        Ok(child) => child,
        Err(error) => {
            if error.reaped {
                fixture.authorize_cleanup();
            }
            return Err(io::Error::other(error.to_string()).into());
        }
    };
    let mut active = ActiveWriter {
        child,
        stage: Some(stage),
        fixture,
    };

    let restriction_deadline = EpochDeadline::start(AuthorityEpoch::BootstrapRestriction);
    let mut bootstrap = Frame::new(Kind::Bootstrap, operation_id);
    bootstrap.flags = FLAG_STAGE | FLAG_MATERIALIZE;
    bootstrap.values = stage_values;
    transport_until(
        &control,
        &mut active.child,
        restriction_deadline,
        libc::POLLOUT,
        || send_packet(&control, bootstrap, &[stage_descriptor.as_fd()]),
    )?;
    let (ready, descriptors) = transport_until(
        &control,
        &mut active.child,
        restriction_deadline,
        libc::POLLIN,
        || receive_packet(&control, Some(0)),
    )?;
    if !descriptors.is_empty() {
        return Err(io::Error::other("writer returned authority with readiness").into());
    }
    validate_writer_ready(&ready, operation_id)?;
    observe_restricted_child(
        active.child.pid(),
        &ready,
        Some(&stage_descriptor),
        &fixture.outside_sentinel,
    )?;

    let source_deadline = EpochDeadline::start(AuthorityEpoch::SourceTransfer);
    let mut source = Frame::new(Kind::Source, operation_id);
    source.values = source_values;
    transport_until(
        &control,
        &mut active.child,
        source_deadline,
        libc::POLLOUT,
        || send_packet(&control, source, &[fixture.source.as_fd()]),
    )?;
    let (accepted, descriptors) = transport_until(
        &control,
        &mut active.child,
        source_deadline,
        libc::POLLIN,
        || receive_packet(&control, Some(0)),
    )?;
    if !descriptors.is_empty()
        || accepted.kind != Kind::Accepted
        || accepted.operation_id != operation_id
        || accepted.flags != 0
        || accepted.values[..3] != source_values[..3]
    {
        return Err(io::Error::other("writer source acceptance is inconsistent").into());
    }
    observe_accepted_child(
        active.child.pid(),
        &ready,
        &accepted,
        Some(&stage_descriptor),
        &fixture.source,
        &fixture.outside_sentinel,
    )?;

    let mut plan_frame = Frame::new(Kind::Plan, operation_id);
    plan_frame.values[0] = plan_total_len;
    transport_until(
        &control,
        &mut active.child,
        source_deadline,
        libc::POLLOUT,
        || send_packet(&control, plan_frame, &[plan_descriptor.as_fd()]),
    )?;
    let (plan_accepted, descriptors) = transport_until(
        &control,
        &mut active.child,
        source_deadline,
        libc::POLLIN,
        || receive_packet(&control, Some(0)),
    )?;
    if !descriptors.is_empty()
        || plan_accepted.kind != Kind::PlanAccepted
        || plan_accepted.operation_id != operation_id
        || plan_accepted.flags != 0
        || plan_accepted.values[0] != plan_total_len
        || plan_accepted.values[2..] != [0; 2]
    {
        return Err(io::Error::other("writer plan acceptance is inconsistent").into());
    }
    observe_plan_accepted_child(
        active.child.pid(),
        &ready,
        &accepted,
        &plan_accepted,
        Some(&stage_descriptor),
        &fixture.source,
        &plan_descriptor,
        &fixture.outside_sentinel,
    )?;

    let execution_deadline = EpochDeadline::start(AuthorityEpoch::ProbeExecution);
    transport_until(
        &control,
        &mut active.child,
        execution_deadline,
        libc::POLLOUT,
        || send_packet(&control, Frame::new(Kind::Proceed, operation_id), &[]),
    )?;
    let result_packet = transport_until(
        &control,
        &mut active.child,
        execution_deadline,
        libc::POLLIN,
        || receive_packet(&control, Some(2)),
    );
    let (result, mut descriptors) = match result_packet {
        Ok(packet) => packet,
        Err(error) => {
            if let ChildMode::ExitAt(point) = mode {
                let status = active.child.wait_bounded()?;
                if status.code() == Some(point.exit_code()) {
                    return Err(io::Error::other(format!(
                        "writer reached injected crash {point:?} with exit status {}",
                        point.exit_code()
                    ))
                    .into());
                }
                return Err(io::Error::other(format!(
                    "writer expected crash {point:?}, but exited as {status}: {error}"
                ))
                .into());
            }
            return Err(error);
        }
    };
    if result.kind != Kind::Result
        || result.operation_id != operation_id
        || result.flags != (FLAG_STAGE | FLAG_MATERIALIZE)
        || result.values[0] == 0
        || result.values[1] == 0
        || result.values[2] & 0xffff_ffff == 0
        || result.values[2] >> 32 == 0
    {
        return Err(io::Error::other("writer result envelope is inconsistent").into());
    }
    let retained_descriptor = descriptors
        .pop()
        .expect("writer result descriptor count was transport-validated");
    let completion_descriptor = descriptors
        .pop()
        .expect("writer result descriptor count was transport-validated");
    observe_completed_child(
        active.child.pid(),
        &ready,
        &accepted,
        &plan_accepted,
        &result,
        Some(&stage_descriptor),
        &fixture.source,
        &plan_descriptor,
        &completion_descriptor,
        &retained_descriptor,
        &fixture.outside_sentinel,
    )?;

    if mode == ChildMode::ExitAt(FaultPoint::Result) {
        transport_until(
            &control,
            &mut active.child,
            EpochDeadline::start(AuthorityEpoch::WorkerExit),
            libc::POLLOUT,
            || send_packet(&control, Frame::new(Kind::Checkpoint, operation_id), &[]),
        )?;
        let status = active.child.wait_bounded()?;
        if status.code() != Some(FaultPoint::Result.exit_code()) {
            return Err(io::Error::other(format!(
                "writer result crash checkpoint exited as {status}"
            ))
            .into());
        }
        return Err(io::Error::other(format!(
            "writer reached injected crash {:?} with exit status {}",
            FaultPoint::Result,
            FaultPoint::Result.exit_code()
        ))
        .into());
    }

    let exit_deadline = EpochDeadline::start(AuthorityEpoch::WorkerExit);
    transport_until(
        &control,
        &mut active.child,
        exit_deadline,
        libc::POLLOUT,
        || send_packet(&control, Frame::new(Kind::ExitAck, operation_id), &[]),
    )?;
    let status = active.child.wait_for_exit(exit_deadline)?;
    if mode == ChildMode::ExitAt(FaultPoint::ExitAck)
        && status.code() == Some(FaultPoint::ExitAck.exit_code())
    {
        return Err(io::Error::other(format!(
            "writer reached injected crash {:?} with exit status {}",
            FaultPoint::ExitAck,
            FaultPoint::ExitAck.exit_code()
        ))
        .into());
    }
    if !status.success() {
        return Err(io::Error::other(format!("writer exited unsuccessfully: {status}")).into());
    }
    fixture.authorize_cleanup();
    let reaped = ReapedWriter {
        stage: active
            .stage
            .take()
            .expect("active writer retains its stage until clean reap"),
        planning,
        completion: completion_descriptor,
        completion_len: result.values[0],
    };
    drop(active);
    drop(retained_descriptor);

    if case == WriterCase::CleanupFailure {
        let _guard = sealr::__worker_lab::inject_worker_lab_cleanup_failures(1);
        let error = reaped
            .stage
            .abort()
            .expect_err("injected writer cleanup failure must be reported");
        if !error.contains("injected staging cleanup failure") {
            return Err(io::Error::other(format!(
                "writer cleanup failure lost its distinct evidence: {error}"
            ))
            .into());
        }
        if destination.try_exists()? {
            return Err(io::Error::other("cleanup failure published a destination").into());
        }
        return Ok(());
    }
    let authorized = reaped.authorize(&fixture.source, source_values[0], operation_id)?;
    if case == WriterCase::AuditMutation {
        create_extra_stage_file(&stage_descriptor)?;
        if authorized.audit().is_ok() {
            return Err(io::Error::other("mutated writer stage passed exact audit").into());
        }
        if destination.try_exists()? {
            return Err(io::Error::other("audit failure published a destination").into());
        }
        return Ok(());
    }
    let audited = authorized.audit()?;
    if case == WriterCase::DestinationRace {
        fs::create_dir(&destination)?;
        fs::write(destination.join("sentinel"), b"existing")?;
        if audited.publish().is_ok() {
            return Err(io::Error::other("writer replaced a raced destination").into());
        }
        if fs::read(destination.join("sentinel"))? != b"existing" {
            return Err(io::Error::other("writer changed a raced destination").into());
        }
        return Ok(());
    }
    audited.publish()?;
    verify_published_tree(&destination)
}

fn create_extra_stage_file(stage: &File) -> io::Result<()> {
    let extra = rustix::fs::openat(
        stage,
        "unexpected.txt",
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?;
    rustix::io::write(&extra, b"unexpected")?;
    Ok(())
}

fn validate_writer_ready(
    ready: &Frame,
    operation_id: [u8; 16],
) -> Result<(), Box<dyn std::error::Error>> {
    let handled = AccessFs::from_all(ABI::V3).bits();
    let granted = make_bitflags!(AccessFs::{ReadDir | WriteFile | MakeDir | MakeReg}).bits();
    if ready.kind != Kind::RestrictedReady
        || ready.operation_id != operation_id
        || ready.flags != (READY_FLAGS | FLAG_STAGE | FLAG_MATERIALIZE)
        || ready.values[0] < ABI::V3 as u64
        || ready.values[1] != handled
        || ready.values[2] != granted
        || ready.values[3] > i32::MAX as u64
    {
        return Err(io::Error::other(format!(
            "writer restriction-ready evidence is inconsistent: {ready:?}; expected flags {}, handled {handled}, granted {granted}",
            READY_FLAGS | FLAG_STAGE | FLAG_MATERIALIZE
        ))
        .into());
    }
    Ok(())
}

fn verify_published_tree(destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if fs::read(destination.join("stored.txt"))? != b"stored payload" {
        return Err(io::Error::other("published Store member is invalid").into());
    }
    if fs::read(destination.join("deflated.txt"))? != b"deflated payload" {
        return Err(io::Error::other("published Deflate member is invalid").into());
    }
    let mut entries = fs::read_dir(destination)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    entries.sort_unstable();
    if entries != ["deflated.txt", "stored.txt"] {
        return Err(io::Error::other(format!(
            "published writer tree contains unexpected entries: {entries:?}"
        ))
        .into());
    }
    Ok(())
}
