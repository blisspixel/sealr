//! One-shot isolated non-retained member reads for the repository lab.

use super::*;
use crate::linux::FLAG_MEMBER_READ;
use rustix::pipe::PipeFlags;
use std::os::fd::FromRawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

const READ_DEADLINE: Duration = Duration::from_secs(5);
const READ_STRESS_ITERATIONS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadFailureKind {
    Cancelled,
    TimedOut,
    Preflight,
    Allocation,
    Spawn,
    Protocol,
    WorkerCrashed,
    Transport,
    Integrity,
    Reap,
}

#[derive(Debug)]
struct ReadFailure {
    kind: ReadFailureKind,
    detail: String,
}

impl std::fmt::Display for ReadFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for ReadFailure {}

fn failure(kind: ReadFailureKind, detail: impl std::fmt::Display) -> ReadFailure {
    ReadFailure {
        kind,
        detail: detail.to_string(),
    }
}

#[derive(Clone)]
struct ReadCancellation {
    state: Arc<CancellationState>,
}

struct CancellationState {
    cancelled: AtomicBool,
    event: OwnedFd,
}

impl ReadCancellation {
    fn new() -> io::Result<Self> {
        // SAFETY: eventfd has no pointer arguments. The returned descriptor is
        // immediately wrapped in OwnedFd and remains private to this token.
        let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a fresh owned descriptor from successful eventfd.
        let event = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self {
            state: Arc::new(CancellationState {
                cancelled: AtomicBool::new(false),
                event,
            }),
        })
    }

    fn cancel(&self) {
        if self.state.cancelled.swap(true, Ordering::AcqRel) {
            return;
        }
        let value = 1_u64.to_ne_bytes();
        // SAFETY: event is a live eventfd and value is a live eight-byte
        // buffer. A nonblocking EAGAIN is harmless because cancellation is
        // also sticky in the atomic flag.
        let _ = unsafe {
            libc::write(
                self.state.event.as_raw_fd(),
                value.as_ptr().cast(),
                value.len(),
            )
        };
    }

    fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }
}

#[derive(Clone)]
struct IsolatedReadCapability {
    inner: Arc<ReadAuthority>,
}

struct ReadAuthority {
    source: File,
    source_bytes: Arc<[u8]>,
    outside_sentinel: File,
    operation_id: [u8; 16],
    planning: Arc<[u8]>,
    completion: Arc<[u8]>,
    retention: sealr::__worker_lab::InspectRetentionRequest,
    coordinator: ReadCoordinator,
    spawned: AtomicUsize,
}

struct ReadCoordinator {
    active: Mutex<bool>,
    changed: Condvar,
}

struct ReadPermit<'a> {
    coordinator: &'a ReadCoordinator,
}

impl ReadCoordinator {
    fn acquire(
        &self,
        cancellation: &ReadCancellation,
        deadline: Instant,
    ) -> Result<ReadPermit<'_>, ReadFailure> {
        let mut active = self.active.lock().map_err(|_| {
            failure(
                ReadFailureKind::Protocol,
                "member-read coordinator mutex is poisoned",
            )
        })?;
        while *active {
            if cancellation.is_cancelled() {
                return Err(failure(
                    ReadFailureKind::Cancelled,
                    "member read was cancelled while queued",
                ));
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    failure(
                        ReadFailureKind::TimedOut,
                        "member read expired while queued",
                    )
                })?;
            let wait = remaining.min(Duration::from_millis(10));
            let (guard, _) = self.changed.wait_timeout(active, wait).map_err(|_| {
                failure(
                    ReadFailureKind::Protocol,
                    "member-read coordinator wait is poisoned",
                )
            })?;
            active = guard;
        }
        if cancellation.is_cancelled() {
            return Err(failure(
                ReadFailureKind::Cancelled,
                "member read was cancelled before activation",
            ));
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

impl IsolatedReadCapability {
    fn prepare(fixture: &Fixture) -> Result<Self, Box<dyn std::error::Error>> {
        let operation_id = random_operation_id()?;
        let retention = crate::semantic_read_retention_request()
            .map_err(|error| io::Error::other(format!("building read retention plan: {error}")))?;
        let planning =
            sealr::__worker_lab::plan_inspect_retaining(source_bytes(), operation_id, &retention)
                .map_err(|error| io::Error::other(format!("planning read authority: {error}")))?;
        let executed = sealr::__worker_lab::validate_inspect_retaining(
            fixture.source.try_clone()?,
            source_bytes().len() as u64,
            operation_id,
            &planning,
            &retention,
        )
        .map_err(|error| io::Error::other(format!("validating read authority: {error}")))?
        .execute()
        .map_err(|error| io::Error::other(format!("executing read authority: {error}")))?;
        let completion = executed.completion().to_vec();
        let retained = executed.retained_content().to_vec();
        let (completion_evidence, retention_evidence) =
            sealr::__worker_lab::authorize_inspect_retained_execution(
                fixture.source.try_clone()?,
                source_bytes().len() as u64,
                operation_id,
                &planning,
                &completion,
                &retained,
                &retention,
            )
            .map_err(|error| {
                io::Error::other(format!("authorizing isolated read capability: {error}"))
            })?;
        if !completion_evidence.complete
            || completion_evidence.member_count != SOURCE_MEMBER_COUNT
            || retention_evidence.requested_paths != 0
            || retention_evidence.retained_members != 0
            || retention_evidence.retained_bytes != 0
        {
            return Err(io::Error::other(
                "isolated read capability authority is incomplete or unexpectedly retained",
            )
            .into());
        }
        Ok(Self {
            inner: Arc::new(ReadAuthority {
                source: fixture.source.try_clone()?,
                source_bytes: Arc::from(source_bytes()),
                outside_sentinel: fixture.outside_sentinel.try_clone()?,
                operation_id,
                planning: Arc::from(planning),
                completion: Arc::from(completion),
                retention,
                coordinator: ReadCoordinator {
                    active: Mutex::new(false),
                    changed: Condvar::new(),
                },
                spawned: AtomicUsize::new(0),
            }),
        })
    }

    fn spawned(&self) -> usize {
        self.inner.spawned.load(Ordering::Acquire)
    }

    fn read(
        &self,
        path: &str,
        max_bytes: u64,
        cancellation: &ReadCancellation,
        mode: ChildMode,
    ) -> Result<Vec<u8>, ReadFailure> {
        let started = Instant::now();
        let deadline = started + READ_DEADLINE;
        let read_operation_id =
            random_operation_id().map_err(|error| failure(ReadFailureKind::Preflight, error))?;
        let authority = sealr::__worker_lab::InspectMemberReadAuthority::new(
            self.inner.operation_id,
            &self.inner.planning,
            &self.inner.completion,
            &self.inner.retention,
        );
        let request = sealr::__worker_lab::create_inspect_member_read_request(
            &self.inner.source_bytes,
            authority,
            read_operation_id,
            path,
            max_bytes,
        )
        .map_err(|error| failure(ReadFailureKind::Preflight, error))?;
        let expected = sealr::__worker_lab::validate_inspect_member_read_request(
            &self.inner.source_bytes,
            authority,
            &request,
            read_operation_id,
        )
        .map_err(|error| failure(ReadFailureKind::Preflight, error))?;
        let _permit = self.inner.coordinator.acquire(cancellation, deadline)?;
        let capacity = usize::try_from(expected.actual_bytes).map_err(|_| {
            failure(
                ReadFailureKind::Preflight,
                "member-read size does not fit this platform",
            )
        })?;
        let mut output = Vec::new();
        output.try_reserve_exact(capacity).map_err(|error| {
            failure(
                ReadFailureKind::Allocation,
                format!("reserving {capacity} member-read bytes failed: {error}"),
            )
        })?;
        if cancellation.is_cancelled() {
            return Err(failure(
                ReadFailureKind::Cancelled,
                "member read was cancelled before spawn",
            ));
        }
        run_worker(
            &self.inner,
            read_operation_id,
            &request,
            expected,
            cancellation,
            deadline,
            mode,
            &mut output,
        )?;
        Ok(output)
    }
}

pub(super) fn run_conformance() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(false, false, false)?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let expected_descriptors = supervisor_descriptor_count()?;
        let capability = IsolatedReadCapability::prepare(&fixture)?;
        let stored = capability.read(
            "stored.txt",
            b"stored payload".len() as u64,
            &ReadCancellation::new()?,
            ChildMode::Normal,
        )?;
        let deflated = capability.read(
            "deflated.txt",
            b"deflated payload".len() as u64,
            &ReadCancellation::new()?,
            ChildMode::Normal,
        )?;
        if stored != b"stored payload" || deflated != b"deflated payload" {
            return Err(io::Error::other("isolated member-read bytes are incorrect").into());
        }

        let before_preflight = capability.spawned();
        let under = capability
            .read(
                "deflated.txt",
                b"deflated payload".len() as u64 - 1,
                &ReadCancellation::new()?,
                ChildMode::Normal,
            )
            .expect_err("one-under caller cap must fail before spawn");
        if under.kind != ReadFailureKind::Preflight || capability.spawned() != before_preflight {
            return Err(io::Error::other("caller cap did not fail before worker spawn").into());
        }
        let cancelled = ReadCancellation::new()?;
        cancelled.cancel();
        let pre_cancel = capability
            .read(
                "stored.txt",
                b"stored payload".len() as u64,
                &cancelled,
                ChildMode::Normal,
            )
            .expect_err("pre-cancelled read must fail before spawn");
        if pre_cancel.kind != ReadFailureKind::Cancelled || capability.spawned() != before_preflight
        {
            return Err(io::Error::other("pre-cancellation spawned a worker").into());
        }

        let stalled_capability = capability.clone();
        let active_cancel = ReadCancellation::new()?;
        let active_cancel_worker = active_cancel.clone();
        let spawn_before_cancel = capability.spawned();
        let stalled = thread::spawn(move || {
            stalled_capability.read(
                "deflated.txt",
                b"deflated payload".len() as u64,
                &active_cancel_worker,
                ChildMode::StallAt(StallPoint::ProbeExecution),
            )
        });
        let wait_deadline = Instant::now() + READ_DEADLINE;
        while capability.spawned() == spawn_before_cancel {
            if Instant::now() >= wait_deadline {
                return Err(io::Error::other("cancel test worker did not spawn").into());
            }
            thread::yield_now();
        }
        let queued_capability = capability.clone();
        let queued_cancel = ReadCancellation::new()?;
        let queued_cancel_worker = queued_cancel.clone();
        let queued = thread::spawn(move || {
            queued_capability.read(
                "stored.txt",
                b"stored payload".len() as u64,
                &queued_cancel_worker,
                ChildMode::Normal,
            )
        });
        thread::sleep(Duration::from_millis(10));
        queued_cancel.cancel();
        let queued_result = queued
            .join()
            .map_err(|_| io::Error::other("queued-cancel test thread panicked"))?
            .expect_err("queued cancellation must fail before worker spawn");
        if queued_result.kind != ReadFailureKind::Cancelled
            || capability.spawned() != spawn_before_cancel + 1
        {
            return Err(io::Error::other(format!(
                "queued cancellation was not isolated before spawn: {queued_result}"
            ))
            .into());
        }
        active_cancel.cancel();
        let cancelled_result = stalled
            .join()
            .map_err(|_| io::Error::other("cancel test thread panicked"))?
            .expect_err("active cancellation must fail the read");
        if cancelled_result.kind != ReadFailureKind::Cancelled {
            return Err(io::Error::other(format!(
                "active cancellation returned {cancelled_result}"
            ))
            .into());
        }
        drop(cancelled);
        drop(queued_cancel);
        drop(active_cancel);

        let crash = capability
            .read(
                "stored.txt",
                b"stored payload".len() as u64,
                &ReadCancellation::new()?,
                ChildMode::ExitAt(FaultPoint::Result),
            )
            .expect_err("post-result crash must not release bytes");
        if crash.kind != ReadFailureKind::WorkerCrashed {
            return Err(io::Error::other(format!("post-result crash returned {crash}")).into());
        }
        if capability.read(
            "stored.txt",
            b"stored payload".len() as u64,
            &ReadCancellation::new()?,
            ChildMode::Normal,
        )? != b"stored payload"
        {
            return Err(io::Error::other("read after isolated crash did not recover").into());
        }

        for iteration in 0..READ_STRESS_ITERATIONS {
            let path = if iteration % 2 == 0 {
                "stored.txt"
            } else {
                "deflated.txt"
            };
            let expected = if iteration % 2 == 0 {
                b"stored payload".as_slice()
            } else {
                b"deflated payload".as_slice()
            };
            let bytes = capability.read(
                path,
                expected.len() as u64,
                &ReadCancellation::new()?,
                ChildMode::Normal,
            )?;
            if bytes != expected {
                return Err(io::Error::other(format!(
                    "isolated read stress iteration {iteration} returned wrong bytes"
                ))
                .into());
            }
            require_no_supervisor_children(&format!(
                "after isolated read stress iteration {iteration}"
            ))?;
        }
        drop(capability);
        require_no_supervisor_children("after isolated read capability last-owner drop")?;
        let descriptors = supervisor_descriptor_count()?;
        if descriptors != expected_descriptors {
            return Err(io::Error::other(format!(
                "isolated reads changed supervisor descriptor count from {expected_descriptors} to {descriptors}"
            ))
            .into());
        }
        Ok(())
    })();
    finish_fixture(&fixture, result)
}

#[allow(clippy::too_many_arguments)]
fn run_worker(
    authority: &ReadAuthority,
    read_operation_id: [u8; 16],
    request: &[u8],
    expected: sealr::__worker_lab::InspectMemberReadEvidence,
    cancellation: &ReadCancellation,
    deadline: Instant,
    mode: ChildMode,
    output: &mut Vec<u8>,
) -> Result<(), ReadFailure> {
    let (control, child_socket) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|error| failure(ReadFailureKind::Spawn, error))?;
    configure_supervisor_control(&control)
        .map_err(|error| failure(ReadFailureKind::Spawn, error))?;

    let sentinel_flags = rustix::io::fcntl_getfd(&authority.outside_sentinel)
        .map_err(|error| failure(ReadFailureKind::Spawn, error))?;
    rustix::io::fcntl_setfd(
        &authority.outside_sentinel,
        sentinel_flags - FdFlags::CLOEXEC,
    )
    .map_err(|error| failure(ReadFailureKind::Spawn, error))?;
    let spawned = spawn_child(child_socket, mode);
    let restored = rustix::io::fcntl_setfd(&authority.outside_sentinel, sentinel_flags);
    let child = match (spawned, restored) {
        (Ok(child), Ok(())) => child,
        (Err(spawn_error), Ok(())) => {
            return Err(failure(ReadFailureKind::Spawn, spawn_error));
        }
        (Ok(mut child), Err(restore_error)) => {
            let termination = terminate_unbound_child_bounded(&mut child);
            return Err(match termination {
                Ok(status) => failure(
                    ReadFailureKind::Spawn,
                    format!(
                        "restoring inherited-sentinel flags failed: {restore_error}; worker was reaped as {status}"
                    ),
                ),
                Err(termination_error) => failure(
                    ReadFailureKind::Reap,
                    format!(
                        "restoring inherited-sentinel flags failed: {restore_error}; worker termination also failed: {termination_error}"
                    ),
                ),
            });
        }
        (Err(spawn_error), Err(restore_error)) => {
            return Err(failure(
                ReadFailureKind::Spawn,
                format!(
                    "spawning member-read worker failed: {spawn_error}; restoring inherited-sentinel flags also failed: {restore_error}"
                ),
            ));
        }
    };
    let mut child =
        ChildBoundary::bind(child).map_err(|error| failure(ReadFailureKind::Spawn, error))?;
    authority.spawned.fetch_add(1, Ordering::AcqRel);

    let result = run_worker_active(
        authority,
        read_operation_id,
        request,
        expected,
        cancellation,
        deadline,
        mode,
        output,
        &control,
        &mut child,
    );
    match result {
        Err(read_error) if !child.is_reaped() => match child.terminate_and_reap_bounded() {
            Ok(_) => Err(read_error),
            Err(reap_error) => Err(failure(
                ReadFailureKind::Reap,
                format!("{read_error}; bounded termination also failed: {reap_error}"),
            )),
        },
        other => other,
    }
}

#[allow(clippy::too_many_arguments)]
fn run_worker_active(
    authority: &ReadAuthority,
    read_operation_id: [u8; 16],
    request: &[u8],
    expected: sealr::__worker_lab::InspectMemberReadEvidence,
    cancellation: &ReadCancellation,
    deadline: Instant,
    mode: ChildMode,
    output: &mut Vec<u8>,
    control: &OwnedFd,
    child: &mut ChildBoundary,
) -> Result<(), ReadFailure> {
    let epoch = EpochDeadline {
        epoch: AuthorityEpoch::ProbeExecution,
        expires_at: deadline,
    };
    let mut bootstrap = Frame::new(Kind::Bootstrap, read_operation_id);
    bootstrap.flags = FLAG_MEMBER_READ;
    transport_until(control, child, epoch, libc::POLLOUT, || {
        send_packet(control, bootstrap, &[])
    })
    .map_err(|error| failure(ReadFailureKind::Transport, error))?;
    let (ready, descriptors) = transport_until(control, child, epoch, libc::POLLIN, || {
        receive_packet(control, Some(0))
    })
    .map_err(|error| failure(classify_boundary(error.as_ref()), error))?;
    if !descriptors.is_empty()
        || ready.kind != Kind::RestrictedReady
        || ready.operation_id != read_operation_id
        || ready.flags != READY_FLAGS | FLAG_MEMBER_READ
        || ready.values[0] < ABI::V3 as u64
        || ready.values[3] != u64::MAX
    {
        return Err(failure(
            ReadFailureKind::Protocol,
            "member-read restriction-ready evidence is inconsistent",
        ));
    }
    observe_restricted_child(child.pid(), &ready, None, &authority.outside_sentinel)
        .map_err(|error| failure(ReadFailureKind::Protocol, error))?;

    let source_values = source_identity(&authority.source)
        .map_err(|error| failure(ReadFailureKind::Protocol, error))?;
    let mut source = Frame::new(Kind::Source, read_operation_id);
    source.values = source_values;
    transport_until(control, child, epoch, libc::POLLOUT, || {
        send_packet(control, source, &[authority.source.as_fd()])
    })
    .map_err(|error| failure(ReadFailureKind::Transport, error))?;
    let (accepted, descriptors) = transport_until(control, child, epoch, libc::POLLIN, || {
        receive_packet(control, Some(0))
    })
    .map_err(|error| failure(classify_boundary(error.as_ref()), error))?;
    if !descriptors.is_empty()
        || accepted.kind != Kind::Accepted
        || accepted.operation_id != read_operation_id
        || accepted.flags != 0
        || accepted.values[..3] != source_values[..3]
        || accepted.values[3] > i32::MAX as u64
    {
        return Err(failure(
            ReadFailureKind::Protocol,
            "member-read source acceptance is inconsistent",
        ));
    }

    let planning_descriptor = sealed::create(BlobRole::Planning, &authority.planning)
        .map_err(|error| failure(ReadFailureKind::Protocol, error))?;
    let planning_len = sealed::total_len(authority.planning.len()).ok_or_else(|| {
        failure(
            ReadFailureKind::Protocol,
            "member-read planning blob exceeds its envelope",
        )
    })?;
    let mut plan = Frame::new(Kind::Plan, read_operation_id);
    plan.values = [
        planning_len,
        u64::from_le_bytes(
            authority.operation_id[..8]
                .try_into()
                .expect("operation half"),
        ),
        u64::from_le_bytes(
            authority.operation_id[8..]
                .try_into()
                .expect("operation half"),
        ),
        0,
    ];
    transport_until(control, child, epoch, libc::POLLOUT, || {
        send_packet(control, plan, &[planning_descriptor.as_fd()])
    })
    .map_err(|error| failure(ReadFailureKind::Transport, error))?;
    let (plan_accepted, descriptors) = transport_until(control, child, epoch, libc::POLLIN, || {
        receive_packet(control, Some(0))
    })
    .map_err(|error| failure(classify_boundary(error.as_ref()), error))?;
    if !descriptors.is_empty()
        || plan_accepted.kind != Kind::PlanAccepted
        || plan_accepted.operation_id != read_operation_id
        || plan_accepted.flags != 0
        || plan_accepted.values[0] != planning_len
        || plan_accepted.values[1] > i32::MAX as u64
        || plan_accepted.values[2] != plan.values[1]
        || plan_accepted.values[3] != plan.values[2]
    {
        return Err(failure(
            ReadFailureKind::Protocol,
            "member-read plan acceptance is inconsistent",
        ));
    }

    let completion_descriptor = sealed::create(BlobRole::Completion, &authority.completion)
        .map_err(|error| failure(ReadFailureKind::Protocol, error))?;
    let request_descriptor = sealed::create(BlobRole::MemberReadRequest, request)
        .map_err(|error| failure(ReadFailureKind::Protocol, error))?;
    let completion_len = sealed::total_len(authority.completion.len()).ok_or_else(|| {
        failure(
            ReadFailureKind::Protocol,
            "member-read completion blob exceeds its envelope",
        )
    })?;
    let request_len = sealed::total_len(request.len()).ok_or_else(|| {
        failure(
            ReadFailureKind::Protocol,
            "member-read request blob exceeds its envelope",
        )
    })?;
    let mut read = Frame::new(Kind::MemberRead, read_operation_id);
    read.values = [completion_len, request_len, 0, 0];
    transport_until(control, child, epoch, libc::POLLOUT, || {
        send_packet(
            control,
            read,
            &[completion_descriptor.as_fd(), request_descriptor.as_fd()],
        )
    })
    .map_err(|error| failure(ReadFailureKind::Transport, error))?;
    let (read_accepted, descriptors) = transport_until(control, child, epoch, libc::POLLIN, || {
        receive_packet(control, Some(0))
    })
    .map_err(|error| failure(classify_boundary(error.as_ref()), error))?;
    if !descriptors.is_empty()
        || read_accepted.kind != Kind::MemberReadAccepted
        || read_accepted.operation_id != read_operation_id
        || read_accepted.flags != 0
        || read_accepted.values[0] != completion_len
        || read_accepted.values[1] > i32::MAX as u64
        || read_accepted.values[2] != request_len
        || read_accepted.values[3] > i32::MAX as u64
    {
        return Err(failure(
            ReadFailureKind::Protocol,
            "member-read authority acceptance is inconsistent",
        ));
    }

    let (output_reader, output_writer) =
        rustix::pipe::pipe_with(PipeFlags::CLOEXEC).map_err(|error| {
            failure(
                ReadFailureKind::Transport,
                format!("creating member-read output pipe failed: {error}"),
            )
        })?;
    let reader_flags = rustix::fs::fcntl_getfl(&output_reader)
        .map_err(|error| failure(ReadFailureKind::Transport, error))?;
    rustix::fs::fcntl_setfl(&output_reader, reader_flags | OFlags::NONBLOCK)
        .map_err(|error| failure(ReadFailureKind::Transport, error))?;
    let mut proceed = Frame::new(Kind::Proceed, read_operation_id);
    proceed.values[0] = expected.actual_bytes;
    transport_until(control, child, epoch, libc::POLLOUT, || {
        send_packet(control, proceed, &[output_writer.as_fd()])
    })
    .map_err(|error| failure(ReadFailureKind::Transport, error))?;
    drop(output_writer);

    drain_and_finalize(
        authority,
        read_operation_id,
        request,
        expected,
        cancellation,
        deadline,
        mode,
        output,
        control,
        child,
        output_reader,
    )
}

#[allow(clippy::too_many_arguments)]
fn drain_and_finalize(
    authority: &ReadAuthority,
    read_operation_id: [u8; 16],
    request: &[u8],
    expected: sealr::__worker_lab::InspectMemberReadEvidence,
    cancellation: &ReadCancellation,
    deadline: Instant,
    mode: ChildMode,
    output: &mut Vec<u8>,
    control: &OwnedFd,
    child: &mut ChildBoundary,
    output_reader: OwnedFd,
) -> Result<(), ReadFailure> {
    let mut eof = false;
    let mut result = None;
    while !eof || result.is_none() {
        if cancellation.is_cancelled() {
            return Err(failure(
                ReadFailureKind::Cancelled,
                "active member read was cancelled",
            ));
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                failure(
                    ReadFailureKind::TimedOut,
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
            libc::pollfd {
                fd: cancellation.state.event.as_raw_fd(),
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
            return Err(failure(ReadFailureKind::Transport, error));
        }
        if polled == 0 {
            continue;
        }
        if descriptors[3].revents & libc::POLLIN != 0 || cancellation.is_cancelled() {
            return Err(failure(
                ReadFailureKind::Cancelled,
                "active member read was cancelled",
            ));
        }
        if descriptors[2].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
            let status = child
                .reap_until(deadline)
                .map_err(|error| failure(ReadFailureKind::Reap, error))?;
            return Err(failure(
                ReadFailureKind::WorkerCrashed,
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
                        let next = output.len().checked_add(read).ok_or_else(|| {
                            failure(
                                ReadFailureKind::Protocol,
                                "member-read output length overflowed",
                            )
                        })?;
                        if next > expected.actual_bytes as usize {
                            return Err(failure(
                                ReadFailureKind::Protocol,
                                "member-read worker emitted more than the authorized size",
                            ));
                        }
                        output.extend_from_slice(&chunk[..read]);
                    }
                    Err(rustix::io::Errno::AGAIN) => break,
                    Err(rustix::io::Errno::INTR) => {}
                    Err(error) => return Err(failure(ReadFailureKind::Transport, error)),
                }
            }
        }
        if descriptors[1].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
            let (frame, returned) = receive_packet(control, Some(0))
                .map_err(|error| failure(ReadFailureKind::Transport, error))?;
            if !returned.is_empty()
                || frame.kind != Kind::MemberReadResult
                || frame.operation_id != read_operation_id
                || frame.flags != 0
                || frame.values[0] != expected.member_index
                || frame.values[1] != expected.actual_bytes
                || frame.values[2] != u64::from(expected.actual_crc)
                || frame.values[3] != 0
                || result.replace(frame).is_some()
            {
                return Err(failure(
                    ReadFailureKind::Protocol,
                    "member-read result correlation is invalid or duplicated",
                ));
            }
        }
    }
    if output.len() as u64 != expected.actual_bytes {
        return Err(failure(
            ReadFailureKind::Integrity,
            "member-read output reached EOF at the wrong length",
        ));
    }

    let exit_deadline = EpochDeadline {
        epoch: AuthorityEpoch::WorkerExit,
        expires_at: deadline,
    };
    if mode == ChildMode::ExitAt(FaultPoint::Result) {
        let checkpoint = Frame::new(Kind::Checkpoint, read_operation_id);
        transport_until(control, child, exit_deadline, libc::POLLOUT, || {
            send_packet(control, checkpoint, &[])
        })
        .map_err(|error| failure(ReadFailureKind::Transport, error))?;
        let status = child
            .wait_for_exit(exit_deadline)
            .map_err(|error| failure(ReadFailureKind::Reap, error))?;
        return Err(failure(
            ReadFailureKind::WorkerCrashed,
            format!("member-read worker exited after result as {status}"),
        ));
    }
    let ack = Frame::new(Kind::ExitAck, read_operation_id);
    transport_until(control, child, exit_deadline, libc::POLLOUT, || {
        send_packet(control, ack, &[])
    })
    .map_err(|error| failure(ReadFailureKind::Transport, error))?;
    let status = child
        .wait_for_exit(exit_deadline)
        .map_err(|error| failure(ReadFailureKind::Reap, error))?;
    if !status.success() {
        return Err(failure(
            ReadFailureKind::WorkerCrashed,
            format!("member-read worker exited unsuccessfully as {status}"),
        ));
    }
    if cancellation.is_cancelled() {
        return Err(failure(
            ReadFailureKind::Cancelled,
            "member read was cancelled before success linearization",
        ));
    }
    let read_authority = sealr::__worker_lab::InspectMemberReadAuthority::new(
        authority.operation_id,
        &authority.planning,
        &authority.completion,
        &authority.retention,
    );
    sealr::__worker_lab::validate_inspect_member_read_result(
        &authority.source_bytes,
        read_authority,
        request,
        read_operation_id,
        output,
    )
    .map_err(|error| failure(ReadFailureKind::Integrity, error))?;
    Ok(())
}

fn classify_boundary(error: &(dyn std::error::Error + 'static)) -> ReadFailureKind {
    if error.downcast_ref::<EpochTimeout>().is_some() {
        ReadFailureKind::TimedOut
    } else if error.downcast_ref::<io::Error>().is_some_and(|error| {
        matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
        )
    }) {
        ReadFailureKind::WorkerCrashed
    } else {
        ReadFailureKind::Transport
    }
}
