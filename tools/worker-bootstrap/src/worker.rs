use crate::frame::{Frame, Kind};
use crate::linux::{
    close_inherited_authority, configure_timeout, receive_packet, send_packet,
    ERROR_AUTHORITY_CLOSE, ERROR_DESCRIPTOR, ERROR_PROBE, ERROR_PROTOCOL, ERROR_RESTRICTION,
    FLAG_STAGE, READY_FLAGS,
};
use landlock::{
    make_bitflags, Access, AccessFs, CompatLevel, Compatible, LandlockStatus, PathBeneath, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
};
use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::FdFlags;
use rustix::process::{Pid, Signal};
use std::ffi::OsString;
use std::io;

const PHASE_BOOTSTRAP: u64 = 1;
const PHASE_STAGE: u64 = 2;
const PHASE_RESTRICTION: u64 = 3;
const PHASE_SOURCE: u64 = 4;
const PHASE_PROBE: u64 = 5;
const PHASE_EXIT: u64 = 6;

pub(crate) fn entry(args: &[OsString]) -> Result<(), Box<dyn std::error::Error>> {
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
    rustix::io::fcntl_setfd(control, FdFlags::CLOEXEC)?;
    close_inherited_authority().map_err(|error| {
        io::Error::other(format!(
            "authority closure failed with code {ERROR_AUTHORITY_CLOSE}: {error}"
        ))
    })?;
    configure_timeout(control)?;

    let (bootstrap, descriptors) = receive_packet(control, None)?;
    let operation_id = bootstrap.operation_id;
    match run(control, bootstrap, descriptors) {
        Ok(()) => Ok(()),
        Err(failure) => {
            let mut error = Frame::new(Kind::Error, operation_id);
            error.values = [failure.code, failure.phase, 0, 0];
            let _ = send_packet(control, error, &[]);
            Err(io::Error::other(failure.message).into())
        }
    }
}

fn run(
    control: rustix::fd::BorrowedFd<'_>,
    bootstrap: Frame,
    mut descriptors: Vec<OwnedFd>,
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

    rustix::thread::set_no_new_privs(true)
        .map_err(|error| restriction(format!("setting no_new_privs failed: {error}")))?;
    if !rustix::thread::no_new_privs()
        .map_err(|error| restriction(format!("reading no_new_privs failed: {error}")))?
    {
        return Err(restriction("no_new_privs did not remain enabled"));
    }

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

    let (source_frame, mut source_descriptors) = receive_packet(control, Some(1))
        .map_err(|error| protocol(PHASE_SOURCE, format!("receiving source failed: {error}")))?;
    require_kind_and_operation(&source_frame, Kind::Source, operation_id, PHASE_SOURCE)?;
    if source_frame.flags != 0 || source_frame.values[3] != 0 {
        return Err(protocol(PHASE_SOURCE, "source frame fields are invalid"));
    }
    let source = source_descriptors
        .pop()
        .expect("source descriptor count was validated by the transport");
    validate_source(&source, source_frame.values, stage.as_ref())?;

    let mut accepted = Frame::new(Kind::Accepted, operation_id);
    accepted.values = source_frame.values;
    accepted.values[3] = source.as_raw_fd() as u64;
    send_packet(control, accepted, &[])
        .map_err(|error| protocol(PHASE_SOURCE, format!("sending acceptance failed: {error}")))?;

    let (proceed, descriptors) = receive_packet(control, Some(0))
        .map_err(|error| protocol(PHASE_PROBE, format!("receiving proceed failed: {error}")))?;
    require_kind_and_operation(&proceed, Kind::Proceed, operation_id, PHASE_PROBE)?;
    if proceed.flags != 0 || proceed.values != [0; 4] || !descriptors.is_empty() {
        return Err(protocol(PHASE_PROBE, "proceed frame is not empty"));
    }

    let source_byte = read_source_probe(&source)?;
    let outside_errno = verify_outside_denied(stage.as_ref())?;
    let stage_created = if let Some(stage) = &stage {
        create_stage_probe(stage)?;
        1
    } else {
        0
    };

    let mut result = Frame::new(Kind::Result, operation_id);
    result.flags = bootstrap.flags & FLAG_STAGE;
    result.values = [u64::from(source_byte), outside_errno, stage_created, 0];
    send_packet(control, result, &[])
        .map_err(|error| protocol(PHASE_PROBE, format!("sending result failed: {error}")))?;

    let (ack, descriptors) = receive_packet(control, Some(0))
        .map_err(|error| protocol(PHASE_EXIT, format!("receiving exit ack failed: {error}")))?;
    require_kind_and_operation(&ack, Kind::ExitAck, operation_id, PHASE_EXIT)?;
    if ack.flags != 0 || ack.values != [0; 4] || !descriptors.is_empty() {
        return Err(protocol(PHASE_EXIT, "exit acknowledgement is not empty"));
    }
    Ok(())
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

fn read_source_probe(source: &OwnedFd) -> Result<u8, WorkerFailure> {
    let mut byte = [0_u8; 1];
    let read = rustix::io::pread(source, &mut byte, 0)
        .map_err(|error| probe(format!("post-restriction source read failed: {error}")))?;
    if read != 1 {
        return Err(probe("source probe did not read exactly one byte"));
    }
    Ok(byte[0])
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
    message: String,
}

impl WorkerFailure {
    fn new(code: u64, phase: u64, message: impl Into<String>) -> Self {
        Self {
            code,
            phase,
            message: message.into(),
        }
    }
}
