use crate::frame::{Frame, Kind};
use crate::linux::{
    configure_timeout, receive_packet, send_packet, ERROR_DESCRIPTOR, ERROR_PROTOCOL, FLAG_STAGE,
    READY_FLAGS,
};
use crate::CHILD_MARKER;
use landlock::{make_bitflags, Access, AccessFs, ABI};
use rustix::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use rustix::io::FdFlags;
use rustix::net::{AddressFamily, SocketFlags, SocketType};
use rustix::process::{PidfdFlags, Signal};
use std::cell::Cell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SOURCE_BYTES: &[u8] = b"sealr authority bootstrap probe";
const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(1);
const KILL_REAP_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) fn run_conformance() -> Result<(), Box<dyn std::error::Error>> {
    run_success(false)?;
    run_success(true)?;
    run_rejection(CaseMutation::WritableSource, 4)?;
    run_rejection(CaseMutation::WrongSourceLength, 4)?;
    run_rejection(CaseMutation::FileAsStage, 2)?;
    run_rejection(CaseMutation::WrongStageIdentity, 2)?;
    run_rejection(CaseMutation::MissingStageDescriptor, 2)?;
    run_rejection(CaseMutation::ExtraInspectDescriptor, 2)?;
    run_rejection(CaseMutation::DirectoryAsSource, 4)?;
    run_protocol_rejection(CaseMutation::ExtraSourceDescriptor, 4)?;
    run_protocol_rejection(CaseMutation::WrongSourceOperation, 4)?;
    run_timeout_reap()?;
    println!(
        "sealr.worker-bootstrap-evidence.v1: 2 enforced probes, 7 fail-closed authority cases, 2 protocol cases, and bounded reap passed"
    );
    Ok(())
}

fn run_success(with_stage: bool) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(with_stage, false, false)?;
    let outcome = exchange(&fixture, CaseMutation::None)?;
    let result = match outcome {
        ExchangeOutcome::Complete(result) => result,
        ExchangeOutcome::Rejected { code, phase } => {
            return Err(io::Error::other(format!(
                "valid bootstrap was rejected with code {code} in phase {phase}"
            ))
            .into());
        }
    };
    if result.values
        != [
            u64::from(SOURCE_BYTES[0]),
            libc::EACCES as u64,
            u64::from(with_stage),
            0,
        ]
    {
        return Err(io::Error::other("worker probe evidence is inconsistent").into());
    }
    if with_stage {
        let mut contents = Vec::new();
        File::open(fixture.root.join("stage/.sealr-bootstrap-probe"))?
            .read_to_end(&mut contents)?;
        if contents != b"ok" {
            return Err(io::Error::other("stage-local probe content is invalid").into());
        }
    }
    fixture.cleanup()?;
    Ok(())
}

fn run_rejection(
    mutation: CaseMutation,
    expected_phase: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(
        matches!(
            mutation,
            CaseMutation::FileAsStage
                | CaseMutation::WrongStageIdentity
                | CaseMutation::MissingStageDescriptor
        ),
        mutation == CaseMutation::WritableSource,
        mutation == CaseMutation::FileAsStage,
    )?;
    let result = match exchange(&fixture, mutation)? {
        ExchangeOutcome::Rejected { code, phase }
            if code == ERROR_DESCRIPTOR && phase == expected_phase =>
        {
            Ok(())
        }
        ExchangeOutcome::Rejected { code, phase } => Err(io::Error::other(format!(
            "descriptor case returned code {code} in phase {phase}"
        ))
        .into()),
        ExchangeOutcome::Complete(_) => {
            Err(io::Error::other("invalid descriptor case was accepted").into())
        }
    };
    fixture.cleanup()?;
    result
}

fn run_protocol_rejection(
    mutation: CaseMutation,
    expected_phase: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(false, false, false)?;
    let result = match exchange(&fixture, mutation)? {
        ExchangeOutcome::Rejected { code, phase }
            if code == ERROR_PROTOCOL && phase == expected_phase =>
        {
            Ok(())
        }
        ExchangeOutcome::Rejected { code, phase } => Err(io::Error::other(format!(
            "protocol case returned code {code} in phase {phase}"
        ))
        .into()),
        ExchangeOutcome::Complete(_) => {
            Err(io::Error::other("invalid protocol case was accepted").into())
        }
    };
    fixture.cleanup()?;
    result
}

fn run_timeout_reap() -> Result<(), Box<dyn std::error::Error>> {
    let (control, child_socket) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?;
    configure_timeout(&control)?;
    let mut child = ChildBoundary::bind(spawn_child(child_socket)?)?;
    let error = child
        .wait_bounded()
        .expect_err("a worker awaiting bootstrap must exceed the supervisor deadline");
    if error.kind() != io::ErrorKind::TimedOut || !child.reaped {
        return Err(io::Error::other("timed-out worker was not reaped").into());
    }
    Ok(())
}

fn exchange(
    fixture: &Fixture,
    mutation: CaseMutation,
) -> Result<ExchangeOutcome, Box<dyn std::error::Error>> {
    let operation_id = random_operation_id()?;
    let (control, child_socket) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?;
    configure_timeout(&control)?;

    let sentinel_flags = rustix::io::fcntl_getfd(&fixture.outside_sentinel)?;
    rustix::io::fcntl_setfd(&fixture.outside_sentinel, sentinel_flags - FdFlags::CLOEXEC)?;
    let spawn_result = spawn_child(child_socket);
    let restore_result = rustix::io::fcntl_setfd(&fixture.outside_sentinel, sentinel_flags);
    let child = match (spawn_result, restore_result) {
        (Ok(child), Ok(())) => child,
        (Ok(mut child), Err(error)) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.into());
        }
        (Err(error), _) => return Err(error.into()),
    };
    let mut child = ChildBoundary::bind(child)?;

    let stage_values = match &fixture.stage {
        Some(stage) => descriptor_identity(stage)?,
        None => [0; 4],
    };
    let stage_values = if mutation == CaseMutation::WrongStageIdentity {
        let mut changed = stage_values;
        changed[1] = changed[1].wrapping_add(1);
        changed
    } else {
        stage_values
    };
    let mut bootstrap = Frame::new(Kind::Bootstrap, operation_id);
    bootstrap.flags = u8::from(fixture.stage.is_some()) * FLAG_STAGE;
    bootstrap.values = stage_values;
    let stage_descriptors: Vec<BorrowedFd<'_>> = match mutation {
        CaseMutation::MissingStageDescriptor => Vec::new(),
        CaseMutation::ExtraInspectDescriptor => vec![fixture.outside_sentinel.as_fd()],
        _ => fixture.stage.iter().map(AsFd::as_fd).collect(),
    };
    send_packet(&control, bootstrap, &stage_descriptors)?;

    let (first_response, descriptors) = receive_packet(&control, Some(0))?;
    if !descriptors.is_empty() {
        return Err(io::Error::other("worker returned authority in its response").into());
    }
    if first_response.kind == Kind::Error {
        return finish_rejection(&mut child, fixture, first_response, operation_id);
    }
    validate_ready(&first_response, operation_id, fixture.stage.is_some())?;
    observe_restricted_child(
        child.pid(),
        &first_response,
        fixture.stage.as_ref(),
        &fixture.outside_sentinel,
    )?;

    let directory_source = if mutation == CaseMutation::DirectoryAsSource {
        Some(File::open(&fixture.root)?)
    } else {
        None
    };
    let source_descriptor = directory_source.as_ref().unwrap_or(&fixture.source);
    let mut source_values = source_identity(source_descriptor)?;
    if mutation == CaseMutation::WrongSourceLength {
        source_values[0] = source_values[0].wrapping_add(1);
    }
    let source_operation = if mutation == CaseMutation::WrongSourceOperation {
        changed_operation_id(operation_id)
    } else {
        operation_id
    };
    let mut source = Frame::new(Kind::Source, source_operation);
    source.values = source_values;
    let source_descriptors = if mutation == CaseMutation::ExtraSourceDescriptor {
        vec![source_descriptor.as_fd(), fixture.outside_sentinel.as_fd()]
    } else {
        vec![source_descriptor.as_fd()]
    };
    send_packet(&control, source, &source_descriptors)?;

    let (second_response, descriptors) = receive_packet(&control, Some(0))?;
    if !descriptors.is_empty() {
        return Err(io::Error::other("worker returned a source capability").into());
    }
    if second_response.kind == Kind::Error {
        return finish_rejection(&mut child, fixture, second_response, operation_id);
    }
    if second_response.kind != Kind::Accepted
        || second_response.operation_id != operation_id
        || second_response.flags != 0
        || second_response.values[..3] != source_values[..3]
        || second_response.values[3] > i32::MAX as u64
    {
        return Err(io::Error::other("worker source acceptance is inconsistent").into());
    }
    observe_accepted_child(
        child.pid(),
        &first_response,
        &second_response,
        fixture.stage.as_ref(),
        source_descriptor,
        &fixture.outside_sentinel,
    )?;

    let proceed = Frame::new(Kind::Proceed, operation_id);
    send_packet(&control, proceed, &[])?;
    let (result, descriptors) = receive_packet(&control, Some(0))?;
    if !descriptors.is_empty()
        || result.kind != Kind::Result
        || result.operation_id != operation_id
        || result.flags != bootstrap.flags
    {
        return Err(io::Error::other("worker result is inconsistent").into());
    }

    let ack = Frame::new(Kind::ExitAck, operation_id);
    send_packet(&control, ack, &[])?;
    let wait_result = child.wait_bounded();
    if child.reaped {
        fixture.authorize_cleanup();
    }
    let status = wait_result?;
    if !status.success() {
        return Err(io::Error::other(format!("worker exited unsuccessfully: {status}")).into());
    }
    Ok(ExchangeOutcome::Complete(result))
}

fn finish_rejection(
    child: &mut ChildBoundary,
    fixture: &Fixture,
    response: Frame,
    operation_id: [u8; 16],
) -> Result<ExchangeOutcome, Box<dyn std::error::Error>> {
    if response.operation_id != operation_id
        || response.flags != 0
        || response.values[2] != 0
        || response.values[3] != 0
    {
        return Err(io::Error::other("worker error frame is inconsistent").into());
    }
    let wait_result = child.wait_bounded();
    if child.reaped {
        fixture.authorize_cleanup();
    }
    let status = wait_result?;
    if status.success() {
        return Err(io::Error::other("worker reported rejection but exited successfully").into());
    }
    Ok(ExchangeOutcome::Rejected {
        code: response.values[0],
        phase: response.values[1],
    })
}

fn validate_ready(
    ready: &Frame,
    operation_id: [u8; 16],
    has_stage: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let handled = AccessFs::from_all(ABI::V3).bits();
    let granted = make_bitflags!(AccessFs::{WriteFile | MakeDir | MakeReg}).bits();
    let expected_flags = READY_FLAGS | (u8::from(has_stage) * FLAG_STAGE);
    if ready.kind != Kind::RestrictedReady
        || ready.operation_id != operation_id
        || ready.flags != expected_flags
        || ready.values[0] < ABI::V3 as u64
        || ready.values[1] != handled
        || ready.values[2] != granted
        || (has_stage && ready.values[3] > i32::MAX as u64)
        || (!has_stage && ready.values[3] != u64::MAX)
    {
        return Err(io::Error::other("restriction-ready evidence is inconsistent").into());
    }
    Ok(())
}

fn observe_restricted_child(
    pid: u32,
    ready: &Frame,
    stage: Option<&File>,
    inherited_sentinel: &File,
) -> Result<(), Box<dyn std::error::Error>> {
    let proc_root = PathBuf::from(format!("/proc/{pid}"));
    let status = fs::read_to_string(proc_root.join("status"))?;
    if !status.lines().any(|line| line == "NoNewPrivs:\t1")
        || !status.lines().any(|line| line == "Threads:\t1")
    {
        return Err(io::Error::other("restricted worker status is not single-threaded NNP").into());
    }

    let mut descriptors = Vec::new();
    for entry in fs::read_dir(proc_root.join("fd"))? {
        let entry = entry?;
        let descriptor = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
            .ok_or("worker fd entry is not numeric")?;
        descriptors.push(descriptor);
    }
    descriptors.sort_unstable();
    let mut expected = vec![0, 1, 2];
    if ready.values[3] != u64::MAX {
        expected.push(i32::try_from(ready.values[3])?);
    }
    expected.sort_unstable();
    if descriptors != expected {
        return Err(io::Error::other(format!(
            "restricted worker descriptor set is {descriptors:?}; expected {expected:?}"
        ))
        .into());
    }

    verify_sentinel_absent(&proc_root, &descriptors, inherited_sentinel)?;
    verify_null_stdio(&proc_root)?;
    verify_cloexec(&proc_root, 0)?;
    if let (Some(stage), stage_fd) = (stage, ready.values[3]) {
        let stage_fd = i32::try_from(stage_fd)?;
        verify_same_object(&proc_root, stage_fd, stage)?;
        verify_access_mode(&proc_root, stage_fd, stage)?;
        verify_cloexec(&proc_root, stage_fd)?;
    }
    Ok(())
}

fn observe_accepted_child(
    pid: u32,
    ready: &Frame,
    accepted: &Frame,
    stage: Option<&File>,
    source: &File,
    inherited_sentinel: &File,
) -> Result<(), Box<dyn std::error::Error>> {
    let proc_root = PathBuf::from(format!("/proc/{pid}"));
    let source_fd = i32::try_from(accepted.values[3])?;
    let mut expected = vec![0, 1, 2, source_fd];
    if ready.values[3] != u64::MAX {
        expected.push(i32::try_from(ready.values[3])?);
    }
    expected.sort_unstable();
    let mut descriptors = proc_descriptors(&proc_root)?;
    descriptors.sort_unstable();
    if descriptors != expected {
        return Err(io::Error::other(format!(
            "accepted worker descriptor set is {descriptors:?}; expected {expected:?}"
        ))
        .into());
    }
    verify_sentinel_absent(&proc_root, &descriptors, inherited_sentinel)?;
    verify_same_object(&proc_root, source_fd, source)?;
    verify_access_mode(&proc_root, source_fd, source)?;
    verify_cloexec(&proc_root, source_fd)?;
    if let (Some(stage), stage_fd) = (stage, ready.values[3]) {
        verify_same_object(&proc_root, i32::try_from(stage_fd)?, stage)?;
    }
    Ok(())
}

fn proc_descriptors(proc_root: &Path) -> Result<Vec<i32>, Box<dyn std::error::Error>> {
    let mut descriptors = Vec::new();
    for entry in fs::read_dir(proc_root.join("fd"))? {
        let entry = entry?;
        descriptors.push(
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
                .ok_or("worker fd entry is not numeric")?,
        );
    }
    Ok(descriptors)
}

fn verify_sentinel_absent(
    proc_root: &Path,
    descriptors: &[i32],
    inherited_sentinel: &File,
) -> Result<(), Box<dyn std::error::Error>> {
    let own_link = fs::read_link(format!("/proc/self/fd/{}", inherited_sentinel.as_raw_fd()))?;
    for descriptor in descriptors {
        if fs::read_link(proc_root.join(format!("fd/{descriptor}")))? == own_link {
            return Err(io::Error::other("inherited sentinel authority survived exec").into());
        }
    }
    Ok(())
}

fn verify_null_stdio(proc_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for descriptor in [1, 2] {
        if fs::read_link(proc_root.join(format!("fd/{descriptor}")))? != Path::new("/dev/null") {
            return Err(io::Error::other("worker output stream is not /dev/null").into());
        }
    }
    Ok(())
}

fn verify_same_object(
    proc_root: &Path,
    descriptor: i32,
    retained: &File,
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = File::open(proc_root.join(format!("fd/{descriptor}")))?;
    let observed_stat = rustix::fs::fstat(&observed)?;
    let retained_stat = rustix::fs::fstat(retained)?;
    if observed_stat.st_dev != retained_stat.st_dev || observed_stat.st_ino != retained_stat.st_ino
    {
        return Err(io::Error::other("worker descriptor object identity is inconsistent").into());
    }
    Ok(())
}

fn verify_access_mode(
    proc_root: &Path,
    descriptor: i32,
    retained: &File,
) -> Result<(), Box<dyn std::error::Error>> {
    let flags = fdinfo_flags(proc_root, descriptor)?;
    let retained_flags = rustix::fs::fcntl_getfl(retained)?.bits() as u64;
    if flags & libc::O_ACCMODE as u64 != retained_flags & libc::O_ACCMODE as u64 {
        return Err(io::Error::other("worker descriptor access mode is inconsistent").into());
    }
    Ok(())
}

fn verify_cloexec(proc_root: &Path, descriptor: i32) -> Result<(), Box<dyn std::error::Error>> {
    let flags = fdinfo_flags(proc_root, descriptor)?;
    if flags & libc::O_CLOEXEC as u64 == 0 {
        return Err(io::Error::other("restricted worker descriptor lacks CLOEXEC").into());
    }
    Ok(())
}

fn fdinfo_flags(proc_root: &Path, descriptor: i32) -> Result<u64, Box<dyn std::error::Error>> {
    let info = fs::read_to_string(proc_root.join(format!("fdinfo/{descriptor}")))?;
    let raw_flags = info
        .lines()
        .find_map(|line| line.strip_prefix("flags:\t"))
        .ok_or("worker fdinfo has no flags")?;
    Ok(u64::from_str_radix(raw_flags, 8)?)
}

fn spawn_child(child_socket: OwnedFd) -> io::Result<Child> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg(CHILD_MARKER)
        .arg(std::process::id().to_string())
        .env_clear()
        .stdin(Stdio::from(child_socket))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: the closure performs one async-signal-safe syscall, touches no
    // Rust-managed state, and returns only an errno-backed io::Error. Marking
    // inherited fds close-on-exec preserves Rust's exec-error pipe while
    // preventing unrelated authority from crossing exec. The child repeats
    // closure with close_range after exec and before receiving capabilities.
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
    command.spawn()
}

fn descriptor_identity(descriptor: &File) -> Result<[u64; 4], rustix::io::Errno> {
    let stat = rustix::fs::fstat(descriptor)?;
    Ok([
        stat.st_dev,
        stat.st_ino,
        u64::from(stat.st_mode),
        u64::from(stat.st_uid),
    ])
}

fn source_identity(descriptor: &File) -> Result<[u64; 4], Box<dyn std::error::Error>> {
    let stat = rustix::fs::fstat(descriptor)?;
    Ok([u64::try_from(stat.st_size)?, stat.st_dev, stat.st_ino, 0])
}

fn random_operation_id() -> Result<[u8; 16], getrandom::Error> {
    let mut operation_id = [0_u8; 16];
    loop {
        getrandom::fill(&mut operation_id)?;
        if operation_id != [0; 16] {
            return Ok(operation_id);
        }
    }
}

fn changed_operation_id(mut operation_id: [u8; 16]) -> [u8; 16] {
    operation_id[0] ^= 1;
    if operation_id == [0; 16] {
        operation_id[0] = 1;
    }
    operation_id
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaseMutation {
    None,
    WritableSource,
    WrongSourceLength,
    FileAsStage,
    WrongStageIdentity,
    MissingStageDescriptor,
    ExtraInspectDescriptor,
    DirectoryAsSource,
    ExtraSourceDescriptor,
    WrongSourceOperation,
}

enum ExchangeOutcome {
    Complete(Frame),
    Rejected { code: u64, phase: u64 },
}

struct Fixture {
    root: PathBuf,
    source: File,
    stage: Option<File>,
    outside_sentinel: File,
    cleanup_authorized: Cell<bool>,
    cleanup_complete: Cell<bool>,
}

impl Fixture {
    fn new(
        with_stage: bool,
        writable_source: bool,
        file_as_stage: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let operation_id = random_operation_id()?;
        let suffix = u64::from_le_bytes(operation_id[..8].try_into()?);
        let root = std::env::temp_dir().join(format!(
            "sealr-worker-bootstrap-{}-{suffix:016x}",
            std::process::id()
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;

        let source_path = root.join("source.bin");
        let mut source_writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&source_path)?;
        source_writer.write_all(SOURCE_BYTES)?;
        source_writer.sync_all()?;
        drop(source_writer);
        let source = OpenOptions::new()
            .read(true)
            .write(writable_source)
            .open(&source_path)?;
        fs::remove_file(&source_path)?;

        let stage = if with_stage {
            let path = root.join("stage");
            if file_as_stage {
                Some(
                    OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)?,
                )
            } else {
                fs::create_dir(&path)?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                Some(File::open(path)?)
            }
        } else {
            None
        };

        let sentinel_path = root.join("outside-sentinel");
        let mut outside_sentinel = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(sentinel_path)?;
        outside_sentinel.write_all(b"outside")?;
        outside_sentinel.flush()?;

        Ok(Self {
            root,
            source,
            stage,
            outside_sentinel,
            cleanup_authorized: Cell::new(false),
            cleanup_complete: Cell::new(false),
        })
    }

    fn authorize_cleanup(&self) {
        self.cleanup_authorized.set(true);
    }

    fn cleanup(&self) -> io::Result<()> {
        if !self.cleanup_authorized.get() {
            return Err(io::Error::other(
                "fixture cleanup refused because worker reap is unproved",
            ));
        }
        fs::remove_dir_all(&self.root)?;
        self.cleanup_complete.set(true);
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.cleanup_authorized.get() && !self.cleanup_complete.get() {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

struct ChildBoundary {
    child: Child,
    pidfd: OwnedFd,
    reaped: bool,
}

impl ChildBoundary {
    fn bind(mut child: Child) -> Result<Self, Box<dyn std::error::Error>> {
        let pid = rustix::process::Pid::from_child(&child);
        match rustix::process::pidfd_open(pid, PidfdFlags::empty()) {
            Ok(pidfd) => Ok(Self {
                child,
                pidfd,
                reaped: false,
            }),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(error.into())
            }
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn wait_bounded(&mut self) -> io::Result<ExitStatus> {
        let deadline = Instant::now() + CHILD_EXIT_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.reaped = true;
                return Ok(status);
            }
            if Instant::now() >= deadline {
                match rustix::process::pidfd_send_signal(&self.pidfd, Signal::KILL) {
                    Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                    Err(error) => return Err(io::Error::from(error)),
                }
                let kill_deadline = Instant::now() + KILL_REAP_TIMEOUT;
                loop {
                    if let Some(status) = self.child.try_wait()? {
                        self.reaped = true;
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("worker exceeded deadline and was reaped as {status}"),
                        ));
                    }
                    if Instant::now() >= kill_deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "worker was killed but reap could not be proved within the deadline",
                        ));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
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
            thread::sleep(Duration::from_millis(5));
        }
    }
}
