use crate::fault::{ChildMode, FaultPoint, StallPoint};
use crate::frame::{Frame, Kind};
use crate::linux::{
    close_inherited_authority, configure_timeout, receive_packet, send_packet,
    ERROR_AUTHORITY_CLOSE, ERROR_DESCRIPTOR, ERROR_PROBE, ERROR_PROTOCOL, ERROR_RESTRICTION,
    FLAG_STAGE, READY_FLAGS,
};
use crate::sealed::{self, BlobRole};
use crate::seccomp;
use landlock::{
    make_bitflags, Access, AccessFs, CompatLevel, Compatible, LandlockStatus, PathBeneath, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
};
use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::FdFlags;
use rustix::process::{Pid, Signal};
use std::ffi::OsString;
use std::fs::File;
use std::io;

const PHASE_BOOTSTRAP: u64 = 1;
const PHASE_STAGE: u64 = 2;
const PHASE_RESTRICTION: u64 = 3;
const PHASE_SOURCE: u64 = 4;
const PHASE_PROBE: u64 = 5;
const PHASE_EXIT: u64 = 6;
const PHASE_PLAN: u64 = 7;
const SOURCE_RETAINED_BYTES: u64 = 30;

pub(crate) fn entry(args: &[OsString]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 3 {
        return Err("internal child entry requires exactly three arguments".into());
    }
    let mode = ChildMode::parse(&args[2]).ok_or("internal child mode is invalid")?;
    mode.exit_at(FaultPoint::ExecEntry);

    let expected_parent = args
        .get(1)
        .and_then(|value| value.to_str())
        .ok_or("internal child entry requires an expected parent PID")?
        .parse::<i32>()?;
    let expected_parent = Pid::from_raw(expected_parent).ok_or("expected parent PID is zero")?;

    rustix::process::set_parent_process_death_signal(Some(Signal::KILL))?;
    if rustix::process::getppid() != Some(expected_parent) {
        return Err(io::Error::other("worker parent changed before bootstrap entry").into());
    }

    let stdin = std::io::stdin();
    let control = stdin.as_fd();
    if rustix::net::sockopt::socket_type(control)? != rustix::net::SocketType::SEQPACKET {
        return Err(io::Error::other("worker stdin is not a sequenced-packet socket").into());
    }
    if rustix::net::sockopt::socket_domain(control)? != rustix::net::AddressFamily::UNIX {
        return Err(io::Error::other("worker control socket is not Unix-domain").into());
    }
    if rustix::net::sockopt::socket_passcred(control)? {
        return Err(
            io::Error::other("worker control socket unexpectedly enables credentials").into(),
        );
    }
    if rustix::net::sockopt::socket_peercred(control)?.pid != expected_parent {
        return Err(io::Error::other("worker control peer is not the expected parent").into());
    }
    mode.exit_at(FaultPoint::PeerValidation);
    rustix::io::fcntl_setfd(control, FdFlags::CLOEXEC)?;
    close_inherited_authority(control).map_err(|error| {
        io::Error::other(format!(
            "authority closure failed with code {ERROR_AUTHORITY_CLOSE}: {error}"
        ))
    })?;
    mode.exit_at(FaultPoint::InheritedClosure);
    configure_timeout(control)?;

    mode.stall_at(StallPoint::BootstrapReceive);
    let (bootstrap, descriptors) = receive_packet(control, None)?;
    mode.exit_at(FaultPoint::BootstrapReceive);
    let operation_id = bootstrap.operation_id;
    match run(control, bootstrap, descriptors, mode) {
        Ok(()) => Ok(()),
        Err(failure) => {
            let mut error = Frame::new(Kind::Error, operation_id);
            error.values = [failure.code, failure.phase, failure.detail, 0];
            let _ = send_packet(control, error, &[]);
            Err(io::Error::other(failure.message).into())
        }
    }
}

fn run(
    control: rustix::fd::BorrowedFd<'_>,
    bootstrap: Frame,
    mut descriptors: Vec<OwnedFd>,
    mode: ChildMode,
) -> Result<(), WorkerFailure> {
    require_kind(&bootstrap, Kind::Bootstrap, PHASE_BOOTSTRAP)?;
    if bootstrap.flags & !FLAG_STAGE != 0 {
        return Err(protocol(PHASE_BOOTSTRAP, "bootstrap flags are invalid"));
    }
    let has_stage = bootstrap.flags == FLAG_STAGE;
    let expected = usize::from(has_stage);
    if descriptors.len() != expected {
        return Err(descriptor(PHASE_STAGE, "stage descriptor count is invalid"));
    }
    if !has_stage && bootstrap.values != [0; 4] {
        return Err(protocol(
            PHASE_BOOTSTRAP,
            "inspect bootstrap carries stage metadata",
        ));
    }

    let stage = if has_stage {
        let stage = descriptors
            .pop()
            .expect("stage count was validated before removal");
        validate_stage(&stage, bootstrap.values)?;
        Some(stage)
    } else {
        None
    };
    mode.exit_at(FaultPoint::StageValidation);
    mode.stall_at(StallPoint::RestrictionSetup);

    let probed_abi = probe_landlock_abi(mode)?;
    if probed_abi < ABI::V3 as u64 {
        return Err(restriction(format!(
            "Landlock ABI {probed_abi} is below the required ABI 3 floor"
        )));
    }

    rustix::thread::set_no_new_privs(true)
        .map_err(|error| restriction(format!("setting no_new_privs failed: {error}")))?;
    if !rustix::thread::no_new_privs()
        .map_err(|error| restriction(format!("reading no_new_privs failed: {error}")))?
    {
        return Err(restriction("no_new_privs did not remain enabled"));
    }
    mode.exit_at(FaultPoint::NoNewPrivs);

    let handled = AccessFs::from_all(ABI::V3);
    let stage_grant = make_bitflags!(AccessFs::{WriteFile | MakeDir | MakeReg});
    let created = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled)
        .map_err(|error| restriction(format!("declaring Landlock rights failed: {error}")))?
        .create()
        .map_err(|error| restriction(format!("creating Landlock ruleset failed: {error}")))?;
    let created = if let Some(stage) = &stage {
        created
            .add_rule(PathBeneath::new(stage.as_fd(), stage_grant))
            .map_err(|error| restriction(format!("granting stage rights failed: {error}")))?
    } else {
        created
    };
    let status = created
        .restrict_self()
        .map_err(|error| restriction(format!("installing Landlock failed: {error}")))?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(restriction("Landlock did not report full enforcement"));
    }
    let effective_abi = match status.landlock {
        LandlockStatus::Available { effective_abi, .. } if effective_abi >= ABI::V3 => {
            effective_abi as u64
        }
        _ => return Err(restriction("Landlock ABI 3 is unavailable")),
    };
    mode.exit_at(FaultPoint::Landlock);

    if mode == ChildMode::SeccompInstallationFailure {
        return Err(restriction(
            "deterministic conformance injection rejected seccomp installation",
        ));
    }
    seccomp::install_and_verify(stage.as_ref().map(AsFd::as_fd))
        .map_err(|error| restriction(format!("installing syscall restrictions failed: {error}")))?;
    mode.exit_at(FaultPoint::Seccomp);
    mode.stall_at(StallPoint::RestrictedReady);

    let operation_id = bootstrap.operation_id;
    let mut ready = Frame::new(Kind::RestrictedReady, operation_id);
    ready.flags = READY_FLAGS | (bootstrap.flags & FLAG_STAGE);
    ready.values = [
        effective_abi,
        handled.bits(),
        stage_grant.bits(),
        stage
            .as_ref()
            .map_or(u64::MAX, |descriptor| descriptor.as_raw_fd() as u64),
    ];
    send_packet(control, ready, &[])
        .map_err(|error| protocol(PHASE_RESTRICTION, format!("sending ready failed: {error}")))?;
    await_observation_checkpoint(control, mode, FaultPoint::Ready, operation_id)?;
    if mode == ChildMode::UnknownAncillary {
        enable_timestamp_ancillary(control)?;
    }

    mode.stall_at(StallPoint::SourceReceive);
    let (source_frame, mut source_descriptors) =
        receive_packet(control, Some(1)).map_err(|error| {
            let detail = error.protocol_detail();
            protocol_with_detail(
                PHASE_SOURCE,
                detail,
                format!("receiving source failed: {error}"),
            )
        })?;
    mode.exit_at(FaultPoint::SourceReceive);
    require_kind_and_operation(&source_frame, Kind::Source, operation_id, PHASE_SOURCE)?;
    if source_frame.flags != 0 || source_frame.values[3] != 0 {
        return Err(protocol(PHASE_SOURCE, "source frame fields are invalid"));
    }
    let source = source_descriptors
        .pop()
        .expect("source descriptor count was validated by the transport");
    validate_source(&source, source_frame.values, stage.as_ref())?;
    mode.exit_at(FaultPoint::SourceValidation);
    mode.stall_at(StallPoint::SourceAcceptance);

    let mut accepted = Frame::new(Kind::Accepted, operation_id);
    accepted.values = source_frame.values;
    accepted.values[3] = source.as_raw_fd() as u64;
    send_packet(control, accepted, &[])
        .map_err(|error| protocol(PHASE_SOURCE, format!("sending acceptance failed: {error}")))?;
    await_observation_checkpoint(control, mode, FaultPoint::Accepted, operation_id)?;

    mode.stall_at(StallPoint::PlanReceive);
    let (plan_frame, mut plan_descriptors) = receive_packet(control, Some(1))
        .map_err(|error| protocol(PHASE_PLAN, format!("receiving sealed plan failed: {error}")))?;
    mode.exit_at(FaultPoint::PlanReceive);
    require_kind_and_operation(&plan_frame, Kind::Plan, operation_id, PHASE_PLAN)?;
    if plan_frame.flags != 0 || plan_frame.values[0] == 0 || plan_frame.values[1..] != [0; 3] {
        return Err(protocol(PHASE_PLAN, "sealed plan frame fields are invalid"));
    }
    let plan_descriptor = plan_descriptors
        .pop()
        .expect("plan descriptor count was validated by the transport");
    let plan = sealed::validate(&plan_descriptor, BlobRole::Planning, plan_frame.values[0])
        .map_err(|error| {
            protocol(
                PHASE_PLAN,
                format!("validating sealed plan failed: {error}"),
            )
        })?;
    let retention = crate::semantic_retention_request().map_err(|error| {
        protocol(
            PHASE_PLAN,
            format!("constructing semantic retention request failed: {error}"),
        )
    })?;
    let validated_operation = sealr::__worker_lab::validate_inspect_retaining(
        File::from(source),
        source_frame.values[0],
        operation_id,
        plan.bytes(),
        &retention,
    )
    .map_err(|error| {
        protocol(
            PHASE_PLAN,
            format!("validating semantic plan failed: {error}"),
        )
    })?;
    mode.exit_at(FaultPoint::PlanValidation);
    mode.stall_at(StallPoint::PlanAcceptance);

    let mut plan_accepted = Frame::new(Kind::PlanAccepted, operation_id);
    plan_accepted.values = [
        plan_frame.values[0],
        plan_descriptor.as_raw_fd() as u64,
        0,
        0,
    ];
    send_packet(control, plan_accepted, &[]).map_err(|error| {
        protocol(
            PHASE_PLAN,
            format!("sending plan acceptance failed: {error}"),
        )
    })?;
    await_observation_checkpoint(control, mode, FaultPoint::PlanAccepted, operation_id)?;

    mode.stall_at(StallPoint::ProceedReceive);
    let (proceed, descriptors) = receive_packet(control, Some(0))
        .map_err(|error| protocol(PHASE_PROBE, format!("receiving proceed failed: {error}")))?;
    require_kind_and_operation(&proceed, Kind::Proceed, operation_id, PHASE_PROBE)?;
    if proceed.flags != 0 || proceed.values != [0; 4] || !descriptors.is_empty() {
        return Err(protocol(PHASE_PROBE, "proceed frame is not empty"));
    }
    mode.exit_at(FaultPoint::Proceed);

    let source_byte = validated_operation
        .source_probe()
        .map_err(|error| protocol(PHASE_PROBE, format!("reading source probe failed: {error}")))?;
    mode.exit_at(FaultPoint::SourceProbe);
    let outside_errno = verify_outside_denied(stage.as_ref())?;
    mode.exit_at(FaultPoint::OutsideDenial);
    if let Some(stage) = &stage {
        create_stage_probe(stage)?;
        mode.exit_at(FaultPoint::StageCreate);
    }
    mode.stall_at(StallPoint::ProbeExecution);

    let executed_operation = validated_operation.execute().map_err(|error| {
        protocol(
            PHASE_PROBE,
            format!("executing validated semantic plan failed: {error}"),
        )
    })?;
    let semantic_evidence = executed_operation.evidence().map_err(|error| {
        protocol(
            PHASE_PROBE,
            format!("revalidating semantic completion failed: {error}"),
        )
    })?;
    if !semantic_evidence.complete
        || semantic_evidence.member_count != 2
        || semantic_evidence.verified_members != 2
    {
        return Err(protocol(
            PHASE_PROBE,
            format!("semantic completion is incomplete: {semantic_evidence:?}"),
        ));
    }
    let retention_evidence = executed_operation.retention_evidence().map_err(|error| {
        protocol(
            PHASE_PROBE,
            format!("revalidating retained content failed: {error}"),
        )
    })?;
    if retention_evidence.requested_paths != 2
        || retention_evidence.retained_members != 2
        || retention_evidence.retained_bytes != SOURCE_RETAINED_BYTES
    {
        return Err(protocol(
            PHASE_PROBE,
            format!("retained-content evidence is incomplete: {retention_evidence:?}"),
        ));
    }
    let completion_payload = executed_operation.completion();
    let completion_descriptor =
        sealed::create(BlobRole::Completion, completion_payload).map_err(|error| {
            protocol(
                PHASE_PROBE,
                format!("sealing completion payload failed: {error}"),
            )
        })?;
    let completion_total_len = sealed::total_len(completion_payload.len())
        .ok_or_else(|| protocol(PHASE_PROBE, "completion payload length is invalid"))?;
    let validated_completion = sealed::validate(
        &completion_descriptor,
        BlobRole::Completion,
        completion_total_len,
    )
    .map_err(|error| {
        protocol(
            PHASE_PROBE,
            format!("revalidating sealed completion failed: {error}"),
        )
    })?;
    if validated_completion.bytes() != completion_payload {
        return Err(protocol(
            PHASE_PROBE,
            "sealed completion bytes differ after validation",
        ));
    }
    let retained_payload = executed_operation.retained_content();
    let retained_descriptor =
        sealed::create(BlobRole::RetainedContent, retained_payload).map_err(|error| {
            protocol(
                PHASE_PROBE,
                format!("sealing retained content failed: {error}"),
            )
        })?;
    let retained_total_len = sealed::total_len(retained_payload.len())
        .ok_or_else(|| protocol(PHASE_PROBE, "retained-content length is invalid"))?;
    let validated_retained = sealed::validate(
        &retained_descriptor,
        BlobRole::RetainedContent,
        retained_total_len,
    )
    .map_err(|error| {
        protocol(
            PHASE_PROBE,
            format!("revalidating sealed retained content failed: {error}"),
        )
    })?;
    if validated_retained.bytes() != retained_payload {
        return Err(protocol(
            PHASE_PROBE,
            "sealed retained-content bytes differ after validation",
        ));
    }
    mode.exit_at(FaultPoint::CompletionSeal);

    let completion_fd = u32::try_from(completion_descriptor.as_raw_fd())
        .map_err(|_| protocol(PHASE_PROBE, "completion descriptor is unrepresentable"))?;
    let retained_fd = u32::try_from(retained_descriptor.as_raw_fd())
        .map_err(|_| protocol(PHASE_PROBE, "retained descriptor is unrepresentable"))?;
    let outside_errno = u32::try_from(outside_errno)
        .map_err(|_| protocol(PHASE_PROBE, "outside errno is unrepresentable"))?;
    let mut result = Frame::new(Kind::Result, operation_id);
    result.flags = bootstrap.flags & FLAG_STAGE;
    result.values = [
        completion_total_len,
        retained_total_len,
        u64::from(completion_fd) | (u64::from(retained_fd) << 32),
        u64::from(source_byte) | (u64::from(outside_errno) << 8),
    ];
    send_packet(
        control,
        result,
        &[completion_descriptor.as_fd(), retained_descriptor.as_fd()],
    )
    .map_err(|error| protocol(PHASE_PROBE, format!("sending result failed: {error}")))?;
    await_observation_checkpoint(control, mode, FaultPoint::Result, operation_id)?;

    mode.stall_at(StallPoint::ExitAckReceive);
    let (ack, descriptors) = receive_packet(control, Some(0))
        .map_err(|error| protocol(PHASE_EXIT, format!("receiving exit ack failed: {error}")))?;
    require_kind_and_operation(&ack, Kind::ExitAck, operation_id, PHASE_EXIT)?;
    if ack.flags != 0 || ack.values != [0; 4] || !descriptors.is_empty() {
        return Err(protocol(PHASE_EXIT, "exit acknowledgement is not empty"));
    }
    drop(executed_operation);
    mode.exit_at(FaultPoint::ExitAck);
    mode.stall_at(StallPoint::ExitCompletion);
    Ok(())
}

fn await_observation_checkpoint(
    control: rustix::fd::BorrowedFd<'_>,
    mode: ChildMode,
    point: FaultPoint,
    operation_id: [u8; 16],
) -> Result<(), WorkerFailure> {
    if mode != ChildMode::ExitAt(point) {
        return Ok(());
    }
    let (checkpoint, descriptors) = receive_packet(control, Some(0)).map_err(|error| {
        protocol(
            PHASE_EXIT,
            format!("receiving observation checkpoint failed: {error}"),
        )
    })?;
    require_kind_and_operation(&checkpoint, Kind::Checkpoint, operation_id, PHASE_EXIT)?;
    if checkpoint.flags != 0 || checkpoint.values != [0; 4] || !descriptors.is_empty() {
        return Err(protocol(PHASE_EXIT, "observation checkpoint is not empty"));
    }
    mode.exit_at(point);
    unreachable!("fault injection exits the child process")
}

fn validate_stage(stage: &OwnedFd, expected: [u64; 4]) -> Result<(), WorkerFailure> {
    let stat = rustix::fs::fstat(stage)
        .map_err(|error| descriptor(PHASE_STAGE, format!("stage fstat failed: {error}")))?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err(descriptor(PHASE_STAGE, "stage is not a directory"));
    }
    let actual = [
        stat.st_dev,
        stat.st_ino,
        u64::from(stat.st_mode),
        u64::from(stat.st_uid),
    ];
    if actual != expected {
        return Err(descriptor(PHASE_STAGE, "stage identity metadata changed"));
    }
    if stat.st_mode & 0o7777 != 0o700 || stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(descriptor(
            PHASE_STAGE,
            "stage owner or private mode is invalid",
        ));
    }
    let flags = rustix::fs::fcntl_getfl(stage)
        .map_err(|error| descriptor(PHASE_STAGE, format!("stage flags failed: {error}")))?;
    if flags & OFlags::RWMODE != OFlags::RDONLY || flags.contains(OFlags::PATH) {
        return Err(descriptor(
            PHASE_STAGE,
            "stage is not a read-only directory fd",
        ));
    }
    Ok(())
}

fn validate_source(
    source: &OwnedFd,
    expected: [u64; 4],
    stage: Option<&OwnedFd>,
) -> Result<(), WorkerFailure> {
    let stat = rustix::fs::fstat(source)
        .map_err(|error| descriptor(PHASE_SOURCE, format!("source fstat failed: {error}")))?;
    if !FileType::from_raw_mode(stat.st_mode).is_file() {
        return Err(descriptor(PHASE_SOURCE, "source is not a regular file"));
    }
    let flags = rustix::fs::fcntl_getfl(source)
        .map_err(|error| descriptor(PHASE_SOURCE, format!("source flags failed: {error}")))?;
    if flags & OFlags::RWMODE != OFlags::RDONLY || flags.contains(OFlags::PATH) {
        return Err(descriptor(
            PHASE_SOURCE,
            "source is not a read-only data fd",
        ));
    }
    let length = u64::try_from(stat.st_size)
        .map_err(|_| descriptor(PHASE_SOURCE, "source length is negative"))?;
    if [length, stat.st_dev, stat.st_ino, 0] != expected {
        return Err(descriptor(PHASE_SOURCE, "source identity metadata changed"));
    }
    if let Some(stage) = stage {
        let stage_stat = rustix::fs::fstat(stage)
            .map_err(|error| descriptor(PHASE_SOURCE, format!("stage recheck failed: {error}")))?;
        if stat.st_dev == stage_stat.st_dev && stat.st_ino == stage_stat.st_ino {
            return Err(descriptor(PHASE_SOURCE, "source aliases the stage"));
        }
    }
    Ok(())
}

fn probe_landlock_abi(mode: ChildMode) -> Result<u64, WorkerFailure> {
    let observed = match mode {
        ChildMode::InsufficientLandlockAbi => 2_i64,
        ChildMode::RestrictionProbeFailure => {
            return Err(restriction(
                "deterministic conformance injection rejected the Landlock ABI probe",
            ));
        }
        ChildMode::Normal
        | ChildMode::SeccompInstallationFailure
        | ChildMode::UnknownAncillary
        | ChildMode::StallAt(_)
        | ChildMode::ExitAt(_) => {
            const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
            // SAFETY: a null attribute pointer and zero size are the kernel's
            // documented Landlock ABI query. No userspace memory is read or
            // written by this syscall form.
            unsafe {
                libc::syscall(
                    libc::SYS_landlock_create_ruleset,
                    std::ptr::null::<libc::c_void>(),
                    0_usize,
                    LANDLOCK_CREATE_RULESET_VERSION,
                ) as i64
            }
        }
    };
    if observed < 0 {
        let error = io::Error::last_os_error();
        return Err(restriction(format!(
            "querying the Landlock ABI failed: {error}"
        )));
    }
    u64::try_from(observed).map_err(|_| restriction("Landlock ABI query overflowed u64"))
}

fn enable_timestamp_ancillary(control: rustix::fd::BorrowedFd<'_>) -> Result<(), WorkerFailure> {
    let enabled: libc::c_int = 1;
    // SAFETY: the option value points to a live c_int of the supplied size.
    // This conformance-only mode asks the kernel to attach SCM_TIMESTAMP to
    // the next received source packet so the raw parser must reject it.
    let result = unsafe {
        libc::setsockopt(
            control.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMP,
            std::ptr::from_ref(&enabled).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(protocol(
            PHASE_SOURCE,
            format!(
                "enabling conformance timestamp ancillary failed: {}",
                io::Error::last_os_error()
            ),
        ))
    }
}

fn verify_outside_denied(stage: Option<&OwnedFd>) -> Result<u64, WorkerFailure> {
    let result = if let Some(stage) = stage {
        rustix::fs::openat(
            stage,
            "../outside-sentinel",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
    } else {
        rustix::fs::open(
            "/etc/passwd",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
    };
    match result {
        Err(error) if error == rustix::io::Errno::ACCESS => Ok(libc::EACCES as u64),
        Err(error) => Err(probe(format!(
            "outside open failed with unexpected errno: {error}"
        ))),
        Ok(_) => Err(probe("Landlock allowed an outside open")),
    }
}

fn create_stage_probe(stage: &OwnedFd) -> Result<(), WorkerFailure> {
    let probe_fd = rustix::fs::openat(
        stage,
        ".sealr-bootstrap-probe",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|error| probe(format!("stage-local create failed: {error}")))?;
    let written = rustix::io::write(&probe_fd, b"ok")
        .map_err(|error| probe(format!("stage-local write failed: {error}")))?;
    if written != 2 {
        return Err(probe("stage-local write was short"));
    }
    Ok(())
}

fn require_kind(frame: &Frame, kind: Kind, phase: u64) -> Result<(), WorkerFailure> {
    if frame.kind != kind {
        return Err(protocol(phase, "bootstrap frame kind is out of order"));
    }
    Ok(())
}

fn require_kind_and_operation(
    frame: &Frame,
    kind: Kind,
    operation_id: [u8; 16],
    phase: u64,
) -> Result<(), WorkerFailure> {
    require_kind(frame, kind, phase)?;
    if frame.operation_id != operation_id {
        return Err(protocol(phase, "bootstrap operation ID changed"));
    }
    Ok(())
}

fn protocol(phase: u64, message: impl Into<String>) -> WorkerFailure {
    WorkerFailure::new(ERROR_PROTOCOL, phase, message)
}

fn protocol_with_detail(phase: u64, detail: u64, message: impl Into<String>) -> WorkerFailure {
    WorkerFailure::with_detail(ERROR_PROTOCOL, phase, detail, message)
}

fn descriptor(phase: u64, message: impl Into<String>) -> WorkerFailure {
    WorkerFailure::new(ERROR_DESCRIPTOR, phase, message)
}

fn restriction(message: impl Into<String>) -> WorkerFailure {
    WorkerFailure::new(ERROR_RESTRICTION, PHASE_RESTRICTION, message)
}

fn probe(message: impl Into<String>) -> WorkerFailure {
    WorkerFailure::new(ERROR_PROBE, PHASE_PROBE, message)
}

struct WorkerFailure {
    code: u64,
    phase: u64,
    detail: u64,
    message: String,
}

impl WorkerFailure {
    fn new(code: u64, phase: u64, message: impl Into<String>) -> Self {
        Self {
            code,
            phase,
            detail: 0,
            message: message.into(),
        }
    }

    fn with_detail(code: u64, phase: u64, detail: u64, message: impl Into<String>) -> Self {
        Self {
            code,
            phase,
            detail,
            message: message.into(),
        }
    }
}
