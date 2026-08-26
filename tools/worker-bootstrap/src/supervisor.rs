use crate::fault::{ChildMode, FaultPoint, StallPoint};
use crate::frame::{Frame, Kind};
use crate::helper::{parse_digest, HelperArtifact};
use crate::linux::{
    configure_timeout, receive_packet, send_packet, send_raw_conformance_packet, TransportError,
    DETAIL_ANCILLARY_UNKNOWN, DETAIL_CONTROL_TRUNCATED, DETAIL_DATA_TRUNCATED, DETAIL_SHORT_FRAME,
    ERROR_DESCRIPTOR, ERROR_PROTOCOL, ERROR_RESTRICTION, FLAG_STAGE, READY_FLAGS,
};
use crate::sealed::{self, BlobRole};
use crate::{CHILD_MARKER, HELPER_BOOTSTRAP_ABI, HELPER_FEATURE_ID};
use landlock::{make_bitflags, Access, AccessFs, ABI};
use rustix::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use rustix::fs::OFlags;
use rustix::io::FdFlags;
use rustix::net::{AddressFamily, SocketFlags, SocketType};
use rustix::process::{PidfdFlags, Signal};
use std::cell::Cell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

mod read;
mod write;

const SOURCE_MEMBER_COUNT: u64 = 2;
const SOURCE_RETAINED_BYTES: u64 = 30;
const STRESS_CASES: usize = 44;
const STRESS_ITERATIONS: usize = 500;
const AUTHORITY_EPOCH_TIMEOUT: Duration = Duration::from_secs(1);
const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(1);
const KILL_REAP_TIMEOUT: Duration = Duration::from_secs(1);

static CHILD_PROGRAMS: OnceLock<ChildPrograms> = OnceLock::new();

struct ChildPrograms {
    production: HelperArtifact,
    public: sealr::LinuxWorker,
    fault_lab: PathBuf,
}

fn source_bytes() -> &'static [u8] {
    static SOURCE: OnceLock<Vec<u8>> = OnceLock::new();
    SOURCE
        .get_or_init(|| {
            let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
            let stored = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .last_modified_time(zip::DateTime::default());
            writer
                .start_file("stored.txt", stored)
                .expect("worker-lab stored member starts");
            writer
                .write_all(b"stored payload")
                .expect("worker-lab stored payload writes");
            let deflated = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .last_modified_time(zip::DateTime::default());
            writer
                .start_file("deflated.txt", deflated)
                .expect("worker-lab deflated member starts");
            writer
                .write_all(b"deflated payload")
                .expect("worker-lab deflated payload writes");
            writer
                .finish()
                .expect("worker-lab archive finishes")
                .into_inner()
        })
        .as_slice()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityEpoch {
    HelperAuthentication,
    BootstrapRestriction,
    SourceTransfer,
    ProbeExecution,
    WorkerExit,
}

impl AuthorityEpoch {
    const fn for_stall(point: StallPoint) -> Self {
        match point {
            StallPoint::BootstrapReceive
            | StallPoint::RestrictionSetup
            | StallPoint::RestrictedReady => Self::BootstrapRestriction,
            StallPoint::SourceReceive
            | StallPoint::SourceAcceptance
            | StallPoint::PlanReceive
            | StallPoint::PlanAcceptance => Self::SourceTransfer,
            StallPoint::ProceedReceive | StallPoint::ProbeExecution => Self::ProbeExecution,
            StallPoint::ExitAckReceive | StallPoint::ExitCompletion => Self::WorkerExit,
        }
    }
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

#[derive(Debug, thiserror::Error)]
#[error(
    "authority epoch {epoch:?} exceeded its absolute deadline and was reaped by signal {signal}"
)]
struct EpochTimeout {
    epoch: AuthorityEpoch,
    signal: libc::c_int,
}

pub(crate) fn dispatch(args: &[std::ffi::OsString]) -> Result<(), Box<dyn std::error::Error>> {
    let usage = "usage: sealr-worker-bootstrap-lab <conformance|package-smoke|kernel-floor> --worker <absolute-path> --bytes <length> --sha256 <digest>";
    if args.len() != 7
        || (args[0] != "conformance" && args[0] != "package-smoke" && args[0] != "kernel-floor")
        || args[1] != "--worker"
        || args[3] != "--bytes"
        || args[5] != "--sha256"
    {
        return Err(usage.into());
    }
    let worker_path = PathBuf::from(&args[2]);
    let expected_len = args[4]
        .to_str()
        .ok_or("worker byte length is not valid UTF-8")?
        .parse::<u64>()?;
    let digest = args[6]
        .to_str()
        .ok_or("worker SHA-256 is not valid UTF-8")?;
    let production = HelperArtifact::load(&worker_path, expected_len, parse_digest(digest)?)?;
    let public = sealr::LinuxWorker::load(&worker_path, expected_len, digest)?;
    let fault_lab = std::env::current_exe()?;
    if production.source_matches(&fault_lab)? {
        return Err("production helper and conformance lab identify the same file".into());
    }
    CHILD_PROGRAMS
        .set(ChildPrograms {
            production,
            public,
            fault_lab,
        })
        .map_err(|_| "worker child programs were already initialized")?;
    match args[0].to_str() {
        Some("conformance") => run_conformance(),
        Some("package-smoke") => run_package_smoke(),
        Some("kernel-floor") => run_kernel_floor(),
        _ => Err(usage.into()),
    }
}

fn run_kernel_floor() -> Result<(), Box<dyn std::error::Error>> {
    let abi = running_landlock_abi()?;
    if abi != 2 {
        return Err(io::Error::other(format!(
            "kernel-floor evidence requires Landlock ABI 2 exactly, observed {abi}"
        ))
        .into());
    }
    let programs = CHILD_PROGRAMS
        .get()
        .ok_or("worker child programs are not initialized")?;
    let options = sealr::ApplyOptions::new();
    let policy = sealr::Policy::default_v1();

    expect_real_kernel_restriction_failure(sealr::inspect_supervised(
        sealr::Source::Bytes {
            path: Some("kernel-floor-inspect.zip"),
            data: source_bytes(),
        },
        &policy,
        &options,
        &programs.public,
    ))?;
    require_no_supervisor_children("after real-kernel inspect setup failure")?;

    let fixture = Fixture::new(false, false, false)?;
    let destination = fixture.root.join("public-output");
    expect_real_kernel_restriction_failure(sealr::apply_supervised(
        sealr::Request {
            source: sealr::Source::Bytes {
                path: Some("kernel-floor-materialize.zip"),
                data: source_bytes(),
            },
            policy: &policy,
            dest: Some(&destination),
        },
        &options,
        &programs.public,
    ))?;
    require_no_supervisor_children("after real-kernel materialize setup failure")?;
    fixture.verify_retained_authority_state()?;
    if destination.try_exists()?
        || directory_entry_names(&fixture.root)? != vec!["outside-sentinel".to_owned()]
    {
        return Err(io::Error::other(
            "real-kernel materialize setup failure changed the destination namespace",
        )
        .into());
    }
    fixture.cleanup()?;

    println!(
        "sealr.kernel-floor.v1: authenticated helper sha256={} bytes={}, Landlock ABI {abi}, public inspect and materialize rejected before source transfer, no fallback, destination preservation, stage cleanup, and exact reap passed",
        programs.production.digest_hex(),
        programs.production.len()
    );
    Ok(())
}

fn expect_real_kernel_restriction_failure(
    result: Result<sealr::Outcome, sealr::SupervisionError>,
) -> Result<(), Box<dyn std::error::Error>> {
    let error = match result {
        Ok(_) => {
            return Err(io::Error::other(
                "a real Landlock ABI 2 kernel unexpectedly satisfied the ABI 3 supervisor floor",
            )
            .into());
        }
        Err(error) => error,
    };
    let expected_detail =
        format!("worker rejected authority with code {ERROR_RESTRICTION}, phase 3, detail 0");
    if error.kind() != sealr::SupervisionErrorKind::RestrictionUnavailable
        || error.detail() != expected_detail
    {
        return Err(io::Error::other(format!(
            "real-kernel setup failure returned the wrong boundary error: {error}"
        ))
        .into());
    }
    Ok(())
}

fn running_landlock_abi() -> io::Result<u64> {
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    // SAFETY: a null attribute pointer and zero size are the kernel's
    // documented Landlock ABI query. No userspace memory is read or written.
    let observed = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        ) as i64
    };
    if observed < 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(observed).map_err(|_| io::Error::other("Landlock ABI is unrepresentable"))
}

fn run_package_smoke() -> Result<(), Box<dyn std::error::Error>> {
    run_success(false)?;
    run_public_api_smoke()?;
    let helper = &CHILD_PROGRAMS
        .get()
        .expect("child programs remain initialized during package smoke")
        .production;
    println!(
        "sealr.worker-package-smoke.v1: authenticated helper sha256={} bytes={}, private inspect, public supervised inspect and materialize, retained borrow, cloned one-shot read, setup-failure preservation, and exact reap passed",
        helper.digest_hex(),
        helper.len()
    );
    Ok(())
}

fn run_conformance() -> Result<(), Box<dyn std::error::Error>> {
    run_success(false)?;
    run_public_api_smoke()?;
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
    run_restriction_rejection(ChildMode::InsufficientLandlockAbi)?;
    run_restriction_rejection(ChildMode::RestrictionProbeFailure)?;
    run_restriction_rejection(ChildMode::SeccompInstallationFailure)?;
    run_transport_rejection(CaseMutation::ShortSource, DETAIL_SHORT_FRAME)?;
    run_transport_rejection(CaseMutation::LongSource, DETAIL_DATA_TRUNCATED)?;
    run_transport_rejection(
        CaseMutation::TruncatedSourceControl,
        DETAIL_CONTROL_TRUNCATED,
    )?;
    run_transport_rejection_with_mode(
        CaseMutation::None,
        ChildMode::UnknownAncillary,
        DETAIL_ANCILLARY_UNKNOWN,
    )?;
    run_plan_rejection(CaseMutation::UnsealedPlan)?;
    run_plan_rejection(CaseMutation::WrongPlanLength)?;
    run_plan_rejection(CaseMutation::WrongPlanBinding)?;
    run_plan_rejection(CaseMutation::WrongPlanRole)?;
    for point in FaultPoint::ALL {
        run_crash_barrier(point)?;
    }
    for point in StallPoint::ALL {
        run_stall_epoch(point)?;
    }
    run_timeout_reap()?;
    read::run_conformance()?;
    write::run_conformance()?;
    run_repeated_stress()?;
    let helper = &CHILD_PROGRAMS
        .get()
        .expect("child programs remain initialized during conformance")
        .production;
    println!(
        "sealr.worker-bootstrap-evidence.v1: authenticated helper sha256={} bytes={}, 2 enforced probes, 7 authority cases, 2 protocol cases, 3 restriction failures, 3 process-boundary truncations, 1 raw ancillary rejection, 4 sealed-plan rejections, 1 isolated semantic Store-and-Deflate bridge, 1 supervisor content replay, 1 immutable inspect retention transfer, 1 public supervised inspect and materialize with retained borrow, cloned one-shot read, setup-failure preservation, and exact reap, 1 isolated one-shot Store-and-Deflate read boundary, 1 reaped and audited Store-and-Deflate writer publication with immutable retention transfer, 1 post-reap writer audit-mutation rejection, 1 writer destination-race rejection, 1 distinct writer cleanup failure, 4 writer crash barriers, 2 writer authority-epoch stalls, 22 bootstrap crash barriers, 11 bootstrap authority-epoch stalls, 500 bounded bootstrap stress iterations, 500 bounded writer lifecycle iterations, and bounded reap passed",
        helper.digest_hex(),
        helper.len()
    );
    Ok(())
}

fn run_public_api_smoke() -> Result<(), Box<dyn std::error::Error>> {
    let programs = CHILD_PROGRAMS
        .get()
        .ok_or("worker child programs are not initialized")?;
    let mut retention = sealr::RetentionPlan::new(64, 64);
    retention.add_path("stored.txt")?;
    let options = sealr::ApplyOptions::new().with_retention(retention);
    let policy = sealr::Policy::default_v1();
    let outcome = sealr::inspect_supervised(
        sealr::Source::Bytes {
            path: Some("public-supervised-fixture.zip"),
            data: source_bytes(),
        },
        &policy,
        &options,
        &programs.public,
    )?;
    if outcome.rejected()
        || outcome.wrote()
        || outcome.receipt.environment.kernel_jail != "landlock-abi3+seccomp-v1"
    {
        return Err(io::Error::other(format!(
            "public supervised inspect produced unexpected axes or jail evidence: {:?}",
            outcome.verdict
        ))
        .into());
    }
    let archive = outcome
        .into_verified_archive()
        .ok_or("public supervised inspect produced no verified capability")?;
    if archive.retained_member("stored.txt") != Some(b"stored payload".as_slice()) {
        return Err(io::Error::other("public retained borrow is incorrect").into());
    }
    let clone = archive.clone();
    drop(archive);
    if clone.read_member("deflated.txt", 16)? != b"deflated payload" {
        return Err(io::Error::other("public cloned one-shot read is incorrect").into());
    }
    drop(clone);
    require_no_supervisor_children("after public supervised capability last-owner drop")?;

    let fixture = Fixture::new(false, false, false)?;
    let destination = fixture.root.join("public-output");
    let outcome = sealr::apply_supervised(
        sealr::Request {
            source: sealr::Source::Bytes {
                path: Some("public-supervised-materialize.zip"),
                data: source_bytes(),
            },
            policy: &policy,
            dest: Some(&destination),
        },
        &options,
        &programs.public,
    )?;
    if outcome.rejected()
        || !outcome.wrote()
        || outcome.receipt.environment.kernel_jail != "landlock-abi3+seccomp-v1"
        || outcome.receipt.materialization.outcome != "committed"
        || outcome.receipt.materialization.cleanup != "not-applicable-after-commit"
    {
        return Err(io::Error::other(format!(
            "public supervised materialize produced unexpected axes or receipt: {:?}",
            outcome.verdict
        ))
        .into());
    }
    verify_public_materialized_tree(&destination)?;
    let archive = outcome
        .into_verified_archive()
        .ok_or("public supervised materialize produced no verified capability")?;
    if archive.retained_member("stored.txt") != Some(b"stored payload".as_slice())
        || archive.read_member("deflated.txt", 16)? != b"deflated payload"
    {
        return Err(io::Error::other(
            "public materialized capability returned incorrect retained or one-shot bytes",
        )
        .into());
    }
    drop(archive);
    require_no_supervisor_children("after public materialized capability last-owner drop")?;

    let setup_failure = sealr::apply_supervised(
        sealr::Request {
            source: sealr::Source::Bytes {
                path: Some("public-supervised-setup-failure.zip"),
                data: source_bytes(),
            },
            policy: &policy,
            dest: Some(&destination),
        },
        &options,
        &programs.public,
    )?;
    if !setup_failure.rejected()
        || setup_failure.wrote()
        || setup_failure.archive_ir().is_none()
        || setup_failure.verified_archive().is_some()
        || setup_failure.receipt.environment.kernel_jail != "not-entered"
        || setup_failure.receipt.materialization.outcome != "setup-failed"
        || setup_failure.receipt.materialization.cleanup != "not-created"
    {
        return Err(io::Error::other(
            "public supervised setup failure lost its pre-worker semantic contract",
        )
        .into());
    }
    verify_public_materialized_tree(&destination)?;
    if directory_entry_names(&fixture.root)?
        != vec!["outside-sentinel".to_owned(), "public-output".to_owned()]
    {
        return Err(io::Error::other(
            "public supervised materialization left an unexpected staging object",
        )
        .into());
    }
    require_no_supervisor_children("after public supervised setup failure")?;
    fixture.cleanup()?;
    Ok(())
}

fn verify_public_materialized_tree(destination: &Path) -> io::Result<()> {
    if fs::read(destination.join("stored.txt"))? != b"stored payload"
        || fs::read(destination.join("deflated.txt"))? != b"deflated payload"
    {
        return Err(io::Error::other(
            "public supervised materialized tree contains incorrect bytes",
        ));
    }
    Ok(())
}

fn run_success(with_stage: bool) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(with_stage, false, false)?;
    let exchange_result = exchange(&fixture, CaseMutation::None, ChildMode::Normal);
    let result = match exchange_result {
        Err(error) => Err(error),
        Ok(ExchangeOutcome::Complete(result)) => Ok(result),
        Ok(ExchangeOutcome::Crashed(point)) => {
            Err(io::Error::other(format!("valid bootstrap crashed at {point:?}")).into())
        }
        Ok(ExchangeOutcome::Rejected {
            code,
            phase,
            detail,
        }) => Err(io::Error::other(format!(
            "valid bootstrap was rejected with code {code}, phase {phase}, detail {detail}"
        ))
        .into()),
    };
    let result = match result {
        Ok(result) => result,
        Err(error) => return finish_fixture(&fixture, Err(error)),
    };
    let validation = (|| -> Result<(), Box<dyn std::error::Error>> {
        if result.values
            != [
                u64::from(source_bytes()[0]),
                libc::EACCES as u64,
                u64::from(with_stage),
                SOURCE_RETAINED_BYTES,
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
        Ok(())
    })();
    finish_fixture(&fixture, validation)
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
    let result = match exchange(&fixture, mutation, ChildMode::Normal) {
        Ok(ExchangeOutcome::Rejected {
            code,
            phase,
            detail: 0,
        }) if code == ERROR_DESCRIPTOR && phase == expected_phase => Ok(()),
        Ok(ExchangeOutcome::Rejected {
            code,
            phase,
            detail,
        }) => Err(io::Error::other(format!(
            "descriptor case returned code {code}, phase {phase}, detail {detail}"
        ))
        .into()),
        Ok(ExchangeOutcome::Complete(_)) => {
            Err(io::Error::other("invalid descriptor case was accepted").into())
        }
        Ok(ExchangeOutcome::Crashed(point)) => {
            Err(io::Error::other(format!("descriptor case crashed at {point:?}")).into())
        }
        Err(error) => Err(error),
    };
    finish_fixture(&fixture, result)
}

fn run_protocol_rejection(
    mutation: CaseMutation,
    expected_phase: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(false, false, false)?;
    let result = match exchange(&fixture, mutation, ChildMode::Normal) {
        Ok(ExchangeOutcome::Rejected {
            code,
            phase,
            detail: 0,
        }) if code == ERROR_PROTOCOL && phase == expected_phase => Ok(()),
        Ok(ExchangeOutcome::Rejected {
            code,
            phase,
            detail,
        }) => Err(io::Error::other(format!(
            "protocol case returned code {code}, phase {phase}, detail {detail}"
        ))
        .into()),
        Ok(ExchangeOutcome::Complete(_)) => {
            Err(io::Error::other("invalid protocol case was accepted").into())
        }
        Ok(ExchangeOutcome::Crashed(point)) => {
            Err(io::Error::other(format!("protocol case crashed at {point:?}")).into())
        }
        Err(error) => Err(error),
    };
    finish_fixture(&fixture, result)
}

fn run_restriction_rejection(mode: ChildMode) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(true, false, false)?;
    let result = match exchange(&fixture, CaseMutation::None, mode) {
        Ok(ExchangeOutcome::Rejected {
            code,
            phase,
            detail: 0,
        }) if code == ERROR_RESTRICTION && phase == 3 => Ok(()),
        Ok(ExchangeOutcome::Rejected {
            code,
            phase,
            detail,
        }) => Err(io::Error::other(format!(
            "restriction injection returned code {code}, phase {phase}, detail {detail}"
        ))
        .into()),
        Ok(_) => Err(io::Error::other("restriction injection was not rejected").into()),
        Err(error) => Err(error),
    };
    finish_fixture(&fixture, result)
}

fn run_transport_rejection(
    mutation: CaseMutation,
    expected_detail: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    run_transport_rejection_with_mode(mutation, ChildMode::Normal, expected_detail)
}

fn run_transport_rejection_with_mode(
    mutation: CaseMutation,
    mode: ChildMode,
    expected_detail: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(false, false, false)?;
    let result = match exchange(&fixture, mutation, mode) {
        Ok(ExchangeOutcome::Rejected {
            code: ERROR_PROTOCOL,
            phase: 4,
            detail,
        }) if detail == expected_detail => Ok(()),
        Ok(_) => Err(io::Error::other("malformed process-boundary packet was accepted").into()),
        Err(error) => Err(error),
    };
    finish_fixture(&fixture, result)
}

fn run_crash_barrier(point: FaultPoint) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(true, false, false)?;
    let result = match exchange(&fixture, CaseMutation::None, ChildMode::ExitAt(point)) {
        Ok(ExchangeOutcome::Crashed(actual)) if actual == point => fixture
            .verify_authority_state(matches!(
                point,
                FaultPoint::StageCreate
                    | FaultPoint::CompletionSeal
                    | FaultPoint::Result
                    | FaultPoint::ExitAck
            ))
            .map_err(Into::into),
        Ok(ExchangeOutcome::Crashed(actual)) => {
            Err(io::Error::other(format!("worker exited at {actual:?}; expected {point:?}")).into())
        }
        Ok(_) => Err(io::Error::other(format!(
            "worker completed past injected crash barrier {point:?}"
        ))
        .into()),
        Err(error) => Err(error),
    };
    finish_fixture(&fixture, result)
}

fn run_plan_rejection(mutation: CaseMutation) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(false, false, false)?;
    let result = match exchange(&fixture, mutation, ChildMode::Normal) {
        Ok(ExchangeOutcome::Rejected {
            code: ERROR_PROTOCOL,
            phase: 7,
            detail: 0,
        }) => Ok(()),
        Ok(_) => Err(io::Error::other("invalid sealed plan was not rejected").into()),
        Err(error) => Err(error),
    };
    finish_fixture(&fixture, result)
}

fn run_stall_epoch(point: StallPoint) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(true, false, false)?;
    let expected_epoch = AuthorityEpoch::for_stall(point);
    let result = match exchange(&fixture, CaseMutation::None, ChildMode::StallAt(point)) {
        Err(error) => {
            let timeout = error.downcast_ref::<EpochTimeout>().ok_or_else(|| {
                io::Error::other(format!(
                    "worker stall at {point:?} did not produce an epoch timeout: {error}"
                ))
            })?;
            if timeout.epoch != expected_epoch || timeout.signal != libc::SIGKILL {
                Err(io::Error::other(format!(
                    "worker stall at {point:?} ended as {timeout}; expected {expected_epoch:?} through SIGKILL"
                ))
                .into())
            } else {
                fixture
                    .verify_authority_state(matches!(
                        point,
                        StallPoint::ProbeExecution
                            | StallPoint::ExitAckReceive
                            | StallPoint::ExitCompletion
                    ))
                    .map_err(Into::into)
            }
        }
        Ok(_) => Err(io::Error::other(format!(
            "worker completed past injected stall at {point:?}"
        ))
        .into()),
    };
    finish_fixture(&fixture, result)
}

fn run_repeated_stress() -> Result<(), Box<dyn std::error::Error>> {
    require_no_supervisor_children("before repeated stress")?;
    let expected_descriptors = supervisor_descriptor_count()?;
    for iteration in 0..STRESS_ITERATIONS {
        let case = iteration % STRESS_CASES;
        if let Err(error) = run_stress_case(case) {
            return Err(io::Error::other(format!(
                "worker stress iteration {iteration}, case {case} failed: {error}"
            ))
            .into());
        }
        require_no_supervisor_children(&format!("after stress iteration {iteration}"))?;
        let descriptors = supervisor_descriptor_count()?;
        if descriptors != expected_descriptors {
            return Err(io::Error::other(format!(
                "supervisor descriptor count changed from {expected_descriptors} to {descriptors} after stress iteration {iteration}"
            ))
            .into());
        }
    }
    Ok(())
}

fn run_stress_case(case: usize) -> Result<(), Box<dyn std::error::Error>> {
    const DESCRIPTOR_CASES: [(CaseMutation, u64); 7] = [
        (CaseMutation::WritableSource, 4),
        (CaseMutation::WrongSourceLength, 4),
        (CaseMutation::FileAsStage, 2),
        (CaseMutation::WrongStageIdentity, 2),
        (CaseMutation::MissingStageDescriptor, 2),
        (CaseMutation::ExtraInspectDescriptor, 2),
        (CaseMutation::DirectoryAsSource, 4),
    ];
    const PROTOCOL_CASES: [CaseMutation; 2] = [
        CaseMutation::ExtraSourceDescriptor,
        CaseMutation::WrongSourceOperation,
    ];
    const RESTRICTION_CASES: [ChildMode; 3] = [
        ChildMode::InsufficientLandlockAbi,
        ChildMode::RestrictionProbeFailure,
        ChildMode::SeccompInstallationFailure,
    ];
    const PLAN_CASES: [CaseMutation; 4] = [
        CaseMutation::UnsealedPlan,
        CaseMutation::WrongPlanLength,
        CaseMutation::WrongPlanBinding,
        CaseMutation::WrongPlanRole,
    ];

    match case {
        0 => run_success(false),
        1 => run_success(true),
        2..=8 => {
            let (mutation, phase) = DESCRIPTOR_CASES[case - 2];
            run_rejection(mutation, phase)
        }
        9..=10 => run_protocol_rejection(PROTOCOL_CASES[case - 9], 4),
        11..=13 => run_restriction_rejection(RESTRICTION_CASES[case - 11]),
        14 => run_transport_rejection(CaseMutation::ShortSource, DETAIL_SHORT_FRAME),
        15 => run_transport_rejection(CaseMutation::LongSource, DETAIL_DATA_TRUNCATED),
        16 => run_transport_rejection(
            CaseMutation::TruncatedSourceControl,
            DETAIL_CONTROL_TRUNCATED,
        ),
        17 => run_transport_rejection_with_mode(
            CaseMutation::None,
            ChildMode::UnknownAncillary,
            DETAIL_ANCILLARY_UNKNOWN,
        ),
        18..=21 => run_plan_rejection(PLAN_CASES[case - 18]),
        22..=43 => run_crash_barrier(FaultPoint::ALL[case - 22]),
        _ => Err(io::Error::other("worker stress case is outside its closed domain").into()),
    }
}

fn require_no_supervisor_children(context: &str) -> Result<(), Box<dyn std::error::Error>> {
    let children = fs::read_to_string(format!("/proc/self/task/{}/children", std::process::id()))?;
    if !children.trim().is_empty() {
        return Err(io::Error::other(format!(
            "supervisor has surviving child PIDs {children:?} {context}"
        ))
        .into());
    }
    Ok(())
}

fn supervisor_descriptor_count() -> io::Result<usize> {
    fs::read_dir("/proc/self/fd")?.try_fold(0_usize, |count, entry| {
        entry?;
        count
            .checked_add(1)
            .ok_or_else(|| io::Error::other("supervisor descriptor count overflowed"))
    })
}

fn finish_fixture<T>(
    fixture: &Fixture,
    result: Result<T, Box<dyn std::error::Error>>,
) -> Result<T, Box<dyn std::error::Error>> {
    let retained = fixture.verify_retained_authority_state();
    let result = match (result, retained) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(retained)) => Err(retained.into()),
        (Err(error), Err(retained)) => Err(io::Error::other(format!(
            "{error}; retained authority verification also failed: {retained}"
        ))
        .into()),
    };
    match (result, fixture.cleanup()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup)) => Err(cleanup.into()),
        (Err(error), Err(cleanup)) => Err(io::Error::other(format!(
            "{error}; checked fixture cleanup also failed: {cleanup}"
        ))
        .into()),
    }
}

fn run_timeout_reap() -> Result<(), Box<dyn std::error::Error>> {
    let (control, child_socket) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?;
    configure_timeout(&control)?;
    let mut child = ChildBoundary::bind_authenticated(
        spawn_child(child_socket, ChildMode::Normal)?,
        &control,
        ChildMode::Normal,
    )?;
    let error = child
        .wait_bounded()
        .expect_err("a worker awaiting bootstrap must exceed the supervisor deadline");
    let status = child
        .status()
        .ok_or("timed-out worker has no reaped status")?;
    if error.kind() != io::ErrorKind::TimedOut
        || !child.is_reaped()
        || status.signal() != Some(libc::SIGKILL)
    {
        return Err(io::Error::other(format!(
            "timed-out worker was not reaped through SIGKILL: {status}"
        ))
        .into());
    }
    Ok(())
}

fn configure_supervisor_control(control: &OwnedFd) -> Result<(), TransportError> {
    configure_timeout(control)?;
    let flags = rustix::fs::fcntl_getfl(control)?;
    rustix::fs::fcntl_setfl(control, flags | OFlags::NONBLOCK)?;
    Ok(())
}

fn exchange(
    fixture: &Fixture,
    mutation: CaseMutation,
    mode: ChildMode,
) -> Result<ExchangeOutcome, Box<dyn std::error::Error>> {
    let operation_id = random_operation_id()?;
    let (control, child_socket) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?;
    configure_supervisor_control(&control)?;

    let sentinel_flags = rustix::io::fcntl_getfd(&fixture.outside_sentinel)?;
    rustix::io::fcntl_setfd(&fixture.outside_sentinel, sentinel_flags - FdFlags::CLOEXEC)?;
    let spawn_result = spawn_child(child_socket, mode);
    if spawn_result.is_ok() {
        fixture.revoke_cleanup();
    }
    let restore_result = rustix::io::fcntl_setfd(&fixture.outside_sentinel, sentinel_flags);
    let child = match spawn_result {
        Ok(child) => child,
        Err(spawn) => {
            return match restore_result {
                Ok(()) => Err(spawn.into()),
                Err(restore) => Err(io::Error::other(format!(
                    "spawning worker failed: {spawn}; restoring inherited-sentinel flags also failed: {restore}"
                ))
                .into()),
            };
        }
    };
    let mut child = match ChildBoundary::bind_authenticated(child, &control, mode) {
        Ok(child) => child,
        Err(bind) => {
            if bind.reaped {
                fixture.authorize_cleanup();
            }
            return match restore_result {
                Ok(()) => Err(bind.into()),
                Err(restore) => Err(io::Error::other(format!(
                    "binding worker boundary failed: {bind}; restoring inherited-sentinel flags also failed: {restore}"
                ))
                .into()),
            };
        }
    };
    if let Err(error) = restore_result {
        let termination = child.terminate_and_reap_bounded();
        if child.is_reaped() {
            fixture.authorize_cleanup();
        }
        return match termination {
            Ok(_) => Err(error.into()),
            Err(termination) => Err(io::Error::other(format!(
                "restoring inherited-sentinel flags failed: {error}; worker termination also failed: {termination}"
            ))
            .into()),
        };
    }

    let result = exchange_active(fixture, mutation, mode, operation_id, &control, &mut child);
    let termination = if result.is_err() && !child.is_reaped() {
        child.terminate_and_reap_bounded().map(|_| ())
    } else {
        Ok(())
    };
    if child.is_reaped() {
        fixture.authorize_cleanup();
    }
    if let Err(termination) = termination {
        return match result {
            Ok(_) => Err(termination.into()),
            Err(error) => Err(io::Error::other(format!(
                "{error}; bounded worker termination also failed: {termination}"
            ))
            .into()),
        };
    }

    if let ChildMode::ExitAt(point) = mode {
        let expected = result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<ExpectedCrash>())
            .is_some_and(|expected| expected.0 == point);
        if !expected {
            return match result {
                Ok(_) => Err(io::Error::other(format!(
                    "exchange completed after injected worker exit at {point:?}"
                ))
                .into()),
                Err(error) => Err(error),
            };
        }
        let status = child
            .status()
            .ok_or("injected worker exit was not reaped")?;
        if status.code() != Some(point.exit_code()) {
            return Err(io::Error::other(format!(
                "injected worker exit at {point:?} produced {status}"
            ))
            .into());
        }
        return Ok(ExchangeOutcome::Crashed(point));
    }

    result
}

fn transport_until<T>(
    control: &OwnedFd,
    child: &mut ChildBoundary,
    deadline: EpochDeadline,
    events: libc::c_short,
    mut operation: impl FnMut() -> Result<T, TransportError>,
) -> Result<T, Box<dyn std::error::Error>> {
    loop {
        child.wait_for_control(control, deadline, events)?;
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if error.is_would_block() => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn exchange_active(
    fixture: &Fixture,
    mutation: CaseMutation,
    mode: ChildMode,
    operation_id: [u8; 16],
    control: &OwnedFd,
    child: &mut ChildBoundary,
) -> Result<ExchangeOutcome, Box<dyn std::error::Error>> {
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
    let restriction_deadline = EpochDeadline::start(AuthorityEpoch::BootstrapRestriction);
    expect_crash_transport(
        transport_until(control, child, restriction_deadline, libc::POLLOUT, || {
            send_packet(control, bootstrap, &stage_descriptors)
        }),
        mode,
        &[
            FaultPoint::ExecEntry,
            FaultPoint::PeerValidation,
            FaultPoint::InheritedClosure,
        ],
        child,
    )?;

    let (first_response, descriptors) = expect_crash_transport(
        transport_until(control, child, restriction_deadline, libc::POLLIN, || {
            receive_packet(control, Some(0))
        }),
        mode,
        &[
            FaultPoint::ExecEntry,
            FaultPoint::PeerValidation,
            FaultPoint::InheritedClosure,
            FaultPoint::BootstrapReceive,
            FaultPoint::StageValidation,
            FaultPoint::NoNewPrivs,
            FaultPoint::Landlock,
            FaultPoint::Seccomp,
        ],
        child,
    )?;
    if !descriptors.is_empty() {
        return Err(io::Error::other("worker returned authority in its response").into());
    }
    if first_response.kind == Kind::Error {
        return finish_rejection(child, first_response, operation_id);
    }
    validate_ready(&first_response, operation_id, fixture.stage.is_some())?;
    observe_restricted_child(
        child.pid(),
        &first_response,
        fixture.stage.as_ref(),
        &fixture.outside_sentinel,
    )?;
    if mode == ChildMode::ExitAt(FaultPoint::Ready) {
        return finish_observed_crash(control, child, operation_id, FaultPoint::Ready);
    }

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
    let source_deadline = EpochDeadline::start(AuthorityEpoch::SourceTransfer);
    match mutation {
        CaseMutation::ShortSource => {
            let encoded = source.encode();
            let written = transport_until(control, child, source_deadline, libc::POLLOUT, || {
                send_raw_conformance_packet(
                    control,
                    &encoded[..encoded.len() - 1],
                    &[source_descriptor.as_fd()],
                )
            })?;
            if written != encoded.len() - 1 {
                return Err(
                    io::Error::other("short source test packet was not sent atomically").into(),
                );
            }
        }
        CaseMutation::LongSource => {
            let mut encoded = source.encode().to_vec();
            encoded.push(0);
            let written = transport_until(control, child, source_deadline, libc::POLLOUT, || {
                send_raw_conformance_packet(control, &encoded, &[source_descriptor.as_fd()])
            })?;
            if written != encoded.len() {
                return Err(
                    io::Error::other("long source test packet was not sent atomically").into(),
                );
            }
        }
        CaseMutation::TruncatedSourceControl => {
            let encoded = source.encode();
            let descriptors = vec![fixture.outside_sentinel.as_fd(); 20];
            let written = transport_until(control, child, source_deadline, libc::POLLOUT, || {
                send_raw_conformance_packet(control, &encoded, &descriptors)
            })?;
            if written != encoded.len() {
                return Err(io::Error::other(
                    "control-truncation test packet was not sent atomically",
                )
                .into());
            }
        }
        _ => {
            expect_crash_transport(
                transport_until(control, child, source_deadline, libc::POLLOUT, || {
                    send_packet(control, source, &source_descriptors)
                }),
                mode,
                &[],
                child,
            )?;
        }
    }

    let (second_response, descriptors) = expect_crash_transport(
        transport_until(control, child, source_deadline, libc::POLLIN, || {
            receive_packet(control, Some(0))
        }),
        mode,
        &[FaultPoint::SourceReceive, FaultPoint::SourceValidation],
        child,
    )?;
    if !descriptors.is_empty() {
        return Err(io::Error::other("worker returned a source capability").into());
    }
    if second_response.kind == Kind::Error {
        return finish_rejection(child, second_response, operation_id);
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
    if mode == ChildMode::ExitAt(FaultPoint::Accepted) {
        return finish_observed_crash(control, child, operation_id, FaultPoint::Accepted);
    }

    let retention = crate::semantic_retention_request()
        .map_err(|error| io::Error::other(format!("building retention request: {error}")))?;
    let expected_planning_payload =
        sealr::__worker_lab::plan_inspect_retaining(source_bytes(), operation_id, &retention)
            .map_err(|error| {
                io::Error::other(format!("planning worker semantic record: {error}"))
            })?;
    let sent_planning_payload = if mutation == CaseMutation::WrongPlanBinding {
        sealr::__worker_lab::plan_inspect_retaining(
            source_bytes(),
            changed_operation_id(operation_id),
            &retention,
        )
        .map_err(|error| {
            io::Error::other(format!("planning mismatched semantic record: {error}"))
        })?
    } else {
        expected_planning_payload.clone()
    };
    let plan_role = if mutation == CaseMutation::WrongPlanRole {
        BlobRole::Completion
    } else {
        BlobRole::Planning
    };
    let plan_descriptor = if mutation == CaseMutation::UnsealedPlan {
        sealed::create_unsealed_for_conformance(plan_role, &sent_planning_payload)?
    } else {
        sealed::create(plan_role, &sent_planning_payload)?
    };
    let plan_total_len = sealed::total_len(sent_planning_payload.len())
        .ok_or("planning payload length is outside the sealed-blob bound")?;
    let invalid_plan = matches!(
        mutation,
        CaseMutation::UnsealedPlan
            | CaseMutation::WrongPlanLength
            | CaseMutation::WrongPlanBinding
            | CaseMutation::WrongPlanRole
    );
    let validated_plan = if invalid_plan {
        None
    } else {
        let validated = sealed::validate(&plan_descriptor, BlobRole::Planning, plan_total_len)?;
        Some(validated)
    };
    let mut plan_frame = Frame::new(Kind::Plan, operation_id);
    plan_frame.values[0] = if mutation == CaseMutation::WrongPlanLength {
        plan_total_len + 1
    } else {
        plan_total_len
    };
    expect_crash_transport(
        transport_until(control, child, source_deadline, libc::POLLOUT, || {
            send_packet(control, plan_frame, &[plan_descriptor.as_fd()])
        }),
        mode,
        &[],
        child,
    )?;
    let (plan_accepted, descriptors) = expect_crash_transport(
        transport_until(control, child, source_deadline, libc::POLLIN, || {
            receive_packet(control, Some(0))
        }),
        mode,
        &[FaultPoint::PlanReceive, FaultPoint::PlanValidation],
        child,
    )?;
    if !descriptors.is_empty() {
        return Err(io::Error::other("worker returned a plan capability").into());
    }
    if plan_accepted.kind == Kind::Error {
        return finish_rejection(child, plan_accepted, operation_id);
    }
    if plan_accepted.kind != Kind::PlanAccepted
        || plan_accepted.operation_id != operation_id
        || plan_accepted.flags != 0
        || plan_accepted.values[0] != plan_total_len
        || plan_accepted.values[1] > i32::MAX as u64
        || plan_accepted.values[2..] != [0; 2]
    {
        return Err(io::Error::other("worker plan acceptance is inconsistent").into());
    }
    observe_plan_accepted_child(
        child.pid(),
        &first_response,
        &second_response,
        &plan_accepted,
        fixture.stage.as_ref(),
        source_descriptor,
        &plan_descriptor,
        &fixture.outside_sentinel,
    )?;
    if mode == ChildMode::ExitAt(FaultPoint::PlanAccepted) {
        return finish_observed_crash(control, child, operation_id, FaultPoint::PlanAccepted);
    }

    let probe_deadline = EpochDeadline::start(AuthorityEpoch::ProbeExecution);
    let proceed = Frame::new(Kind::Proceed, operation_id);
    transport_until(control, child, probe_deadline, libc::POLLOUT, || {
        send_packet(control, proceed, &[])
    })?;
    let (mut result, mut descriptors) = expect_crash_transport(
        transport_until(control, child, probe_deadline, libc::POLLIN, || {
            receive_packet(control, Some(2))
        }),
        mode,
        &[
            FaultPoint::Proceed,
            FaultPoint::SourceProbe,
            FaultPoint::OutsideDenial,
            FaultPoint::StageCreate,
            FaultPoint::CompletionSeal,
        ],
        child,
    )?;
    if result.kind != Kind::Result
        || result.operation_id != operation_id
        || result.flags != bootstrap.flags
        || result.values[0] == 0
        || result.values[1] == 0
        || result.values[2] & 0xffff_ffff == 0
        || result.values[2] & 0xffff_ffff > i32::MAX as u64
        || result.values[2] >> 32 == 0
        || result.values[2] >> 32 > i32::MAX as u64
        || result.values[3] >> 40 != 0
    {
        return Err(io::Error::other("worker result is inconsistent").into());
    }
    let retained_descriptor = descriptors
        .pop()
        .expect("retained descriptor count was validated by the transport");
    let completion_descriptor = descriptors
        .pop()
        .expect("completion descriptor count was validated by the transport");
    let completion = sealed::validate(
        &completion_descriptor,
        BlobRole::Completion,
        result.values[0],
    )?;
    let retained = sealed::validate(
        &retained_descriptor,
        BlobRole::RetainedContent,
        result.values[1],
    )?;
    let source_byte = result.values[3] & 0xff;
    let outside_errno = (result.values[3] >> 8) & 0xffff_ffff;
    let completion_values = [
        source_byte,
        outside_errno,
        u64::from(fixture.stage.is_some()),
        SOURCE_RETAINED_BYTES,
    ];
    observe_completed_child(
        child.pid(),
        &first_response,
        &second_response,
        &plan_accepted,
        &result,
        fixture.stage.as_ref(),
        source_descriptor,
        &plan_descriptor,
        &completion_descriptor,
        &retained_descriptor,
        &fixture.outside_sentinel,
    )?;
    if mode == ChildMode::ExitAt(FaultPoint::Result) {
        return finish_observed_crash(control, child, operation_id, FaultPoint::Result);
    }

    let exit_deadline = EpochDeadline::start(AuthorityEpoch::WorkerExit);
    let ack = Frame::new(Kind::ExitAck, operation_id);
    transport_until(control, child, exit_deadline, libc::POLLOUT, || {
        send_packet(control, ack, &[])
    })?;
    let status = child.wait_for_exit(exit_deadline)?;
    if mode == ChildMode::ExitAt(FaultPoint::ExitAck) {
        return Err(ExpectedCrash(FaultPoint::ExitAck).into());
    }
    if !status.success() {
        return Err(io::Error::other(format!("worker exited unsuccessfully: {status}")).into());
    }
    let authorized = sealr::__worker_runtime::authorize_execution(
        source_descriptor.try_clone()?,
        source_values[0],
        operation_id,
        validated_plan
            .as_ref()
            .expect("accepted plan was validated by the supervisor")
            .bytes(),
        completion.bytes(),
        retained.bytes(),
        sealr::__worker_runtime::OperationKind::Inspect,
    )
    .map_err(|error| io::Error::other(format!("authorizing semantic execution: {error}")))?;
    let semantic_evidence = authorized.completion_evidence();
    let retention_evidence = authorized.retention_evidence();
    if !semantic_evidence.complete
        || semantic_evidence.member_count != SOURCE_MEMBER_COUNT
        || semantic_evidence.verified_members != SOURCE_MEMBER_COUNT
    {
        return Err(io::Error::other(format!(
            "semantic completion evidence is incomplete: {semantic_evidence:?}"
        ))
        .into());
    }
    if retention_evidence.requested_paths != 2
        || retention_evidence.retained_members != 2
        || retention_evidence.retained_bytes != SOURCE_RETAINED_BYTES
    {
        return Err(io::Error::other(format!(
            "retained-content evidence is incomplete: {retention_evidence:?}"
        ))
        .into());
    }
    result.values = completion_values;
    Ok(ExchangeOutcome::Complete(result))
}

fn expect_crash_transport<T>(
    result: Result<T, Box<dyn std::error::Error>>,
    mode: ChildMode,
    points: &[FaultPoint],
    child: &mut ChildBoundary,
) -> Result<T, Box<dyn std::error::Error>> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            let ChildMode::ExitAt(point) = mode else {
                return Err(error);
            };
            if !points.contains(&point) {
                return Err(error);
            }
            child.wait_bounded()?;
            Err(ExpectedCrash(point).into())
        }
    }
}

fn finish_observed_crash(
    control: &OwnedFd,
    child: &mut ChildBoundary,
    operation_id: [u8; 16],
    point: FaultPoint,
) -> Result<ExchangeOutcome, Box<dyn std::error::Error>> {
    let epoch = match point {
        FaultPoint::Ready => AuthorityEpoch::SourceTransfer,
        FaultPoint::Accepted => AuthorityEpoch::SourceTransfer,
        FaultPoint::PlanAccepted => AuthorityEpoch::ProbeExecution,
        FaultPoint::Result => AuthorityEpoch::WorkerExit,
        _ => {
            return Err(io::Error::other(
                "an observation checkpoint was requested for an unsupported crash point",
            )
            .into())
        }
    };
    let deadline = EpochDeadline::start(epoch);
    transport_until(control, child, deadline, libc::POLLOUT, || {
        send_packet(control, Frame::new(Kind::Checkpoint, operation_id), &[])
    })?;
    child.wait_bounded()?;
    Err(ExpectedCrash(point).into())
}

fn finish_rejection(
    child: &mut ChildBoundary,
    response: Frame,
    operation_id: [u8; 16],
) -> Result<ExchangeOutcome, Box<dyn std::error::Error>> {
    if response.operation_id != operation_id || response.flags != 0 || response.values[3] != 0 {
        return Err(io::Error::other("worker error frame is inconsistent").into());
    }
    let status = child.wait_for_exit(EpochDeadline::start(AuthorityEpoch::WorkerExit))?;
    if status.code() != Some(1) {
        return Err(io::Error::other(format!(
            "worker reported rejection but exited with {status} instead of code 1"
        ))
        .into());
    }
    Ok(ExchangeOutcome::Rejected {
        code: response.values[0],
        phase: response.values[1],
        detail: response.values[2],
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
    let seccomp_filters = status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp_filters:\t"))
        .map(str::parse::<u64>)
        .transpose()?;
    if !status.lines().any(|line| line == "NoNewPrivs:\t1")
        || !status.lines().any(|line| line == "Threads:\t1")
        || !status.lines().any(|line| line == "Seccomp:\t2")
        || seccomp_filters.is_none_or(|count| count == 0)
    {
        return Err(io::Error::other(
            "restricted worker status is not single-threaded NNP with an active seccomp filter",
        )
        .into());
    }
    let children = fs::read_to_string(proc_root.join(format!("task/{pid}/children")))?;
    if !children.trim().is_empty() {
        return Err(io::Error::other(format!(
            "restricted worker retained descendant PIDs {children:?}"
        ))
        .into());
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
    if stage.is_some() {
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

#[allow(clippy::too_many_arguments)]
fn observe_plan_accepted_child(
    pid: u32,
    ready: &Frame,
    source_accepted: &Frame,
    plan_accepted: &Frame,
    stage: Option<&File>,
    source: &File,
    plan: &OwnedFd,
    inherited_sentinel: &File,
) -> Result<(), Box<dyn std::error::Error>> {
    let proc_root = PathBuf::from(format!("/proc/{pid}"));
    let source_fd = i32::try_from(source_accepted.values[3])?;
    let plan_fd = i32::try_from(plan_accepted.values[1])?;
    let mut expected = vec![0, 1, 2, source_fd, plan_fd];
    if ready.values[3] != u64::MAX {
        expected.push(i32::try_from(ready.values[3])?);
    }
    expected.sort_unstable();
    let mut descriptors = proc_descriptors(&proc_root)?;
    descriptors.sort_unstable();
    if descriptors != expected {
        return Err(io::Error::other(format!(
            "plan-ready worker descriptor set is {descriptors:?}; expected {expected:?}"
        ))
        .into());
    }
    verify_sentinel_absent(&proc_root, &descriptors, inherited_sentinel)?;
    verify_same_object(&proc_root, source_fd, source)?;
    verify_same_object(&proc_root, plan_fd, plan)?;
    verify_access_mode(&proc_root, source_fd, source)?;
    verify_access_mode(&proc_root, plan_fd, plan)?;
    verify_cloexec(&proc_root, source_fd)?;
    verify_cloexec(&proc_root, plan_fd)?;
    if let (Some(stage), stage_fd) = (stage, ready.values[3]) {
        verify_same_object(&proc_root, i32::try_from(stage_fd)?, stage)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn observe_completed_child(
    pid: u32,
    ready: &Frame,
    source_accepted: &Frame,
    plan_accepted: &Frame,
    result: &Frame,
    stage: Option<&File>,
    source: &File,
    plan: &OwnedFd,
    completion: &OwnedFd,
    retained_content: &OwnedFd,
    inherited_sentinel: &File,
) -> Result<(), Box<dyn std::error::Error>> {
    let proc_root = PathBuf::from(format!("/proc/{pid}"));
    let source_fd = i32::try_from(source_accepted.values[3])?;
    let plan_fd = i32::try_from(plan_accepted.values[1])?;
    let completion_fd = i32::try_from(result.values[2] & 0xffff_ffff)?;
    let retained_fd = i32::try_from(result.values[2] >> 32)?;
    let mut expected = vec![0, 1, 2, source_fd, plan_fd, completion_fd, retained_fd];
    if stage.is_some() {
        expected.push(i32::try_from(ready.values[3])?);
    }
    expected.sort_unstable();
    let mut descriptors = proc_descriptors(&proc_root)?;
    descriptors.sort_unstable();
    if descriptors != expected {
        return Err(io::Error::other(format!(
            "completed worker descriptor set is {descriptors:?}; expected {expected:?}"
        ))
        .into());
    }
    verify_sentinel_absent(&proc_root, &descriptors, inherited_sentinel)?;
    for (descriptor, retained) in [
        (source_fd, source.as_fd()),
        (plan_fd, plan.as_fd()),
        (completion_fd, completion.as_fd()),
        (retained_fd, retained_content.as_fd()),
    ] {
        verify_same_object(&proc_root, descriptor, retained)?;
        verify_access_mode(&proc_root, descriptor, retained)?;
        verify_cloexec(&proc_root, descriptor)?;
    }
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
    retained: impl AsFd,
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
    retained: impl AsFd,
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

fn spawn_child(child_socket: OwnedFd, mode: ChildMode) -> io::Result<Child> {
    let programs = CHILD_PROGRAMS
        .get()
        .ok_or_else(|| io::Error::other("worker child programs are not initialized"))?;
    let production = mode == ChildMode::Normal;
    let mut command = if production {
        Command::new(programs.production.execution_path())
    } else {
        let mut command = Command::new(&programs.fault_lab);
        command
            .arg(CHILD_MARKER)
            .arg(std::process::id().to_string())
            .arg(mode.argument());
        command
    };
    command
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

fn source_identity(descriptor: &File) -> io::Result<[u64; 4]> {
    let stat = rustix::fs::fstat(descriptor)?;
    let length = u64::try_from(stat.st_size)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "source length is negative"))?;
    Ok([length, stat.st_dev, stat.st_ino, 0])
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
    ShortSource,
    LongSource,
    TruncatedSourceControl,
    UnsealedPlan,
    WrongPlanLength,
    WrongPlanBinding,
    WrongPlanRole,
}

enum ExchangeOutcome {
    Complete(Frame),
    Rejected { code: u64, phase: u64, detail: u64 },
    Crashed(FaultPoint),
}

#[derive(Debug, thiserror::Error)]
#[error("worker reached the observed crash barrier {0:?}")]
struct ExpectedCrash(FaultPoint);

struct Fixture {
    root: PathBuf,
    source: File,
    source_identity: [u64; 4],
    stage: Option<File>,
    stage_identity: Option<[u64; 4]>,
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
        source_writer.write_all(source_bytes())?;
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

        let source_identity = source_identity(&source)?;
        let stage_identity = stage.as_ref().map(descriptor_identity).transpose()?;

        Ok(Self {
            root,
            source,
            source_identity,
            stage,
            stage_identity,
            outside_sentinel,
            cleanup_authorized: Cell::new(true),
            cleanup_complete: Cell::new(false),
        })
    }

    fn authorize_cleanup(&self) {
        self.cleanup_authorized.set(true);
    }

    fn revoke_cleanup(&self) {
        self.cleanup_authorized.set(false);
    }

    fn cleanup(&self) -> io::Result<()> {
        if !self.cleanup_authorized.get() {
            return Err(io::Error::other(
                "fixture cleanup refused because worker reap is unproved",
            ));
        }
        fs::remove_dir_all(&self.root)?;
        if self.root.try_exists()? {
            return Err(io::Error::other(
                "fixture root still exists after checked cleanup",
            ));
        }
        self.cleanup_complete.set(true);
        Ok(())
    }

    fn verify_retained_authority_state(&self) -> io::Result<()> {
        if source_identity(&self.source)? != self.source_identity {
            return Err(io::Error::other(
                "source descriptor identity changed during worker execution",
            ));
        }
        let mut source = vec![0_u8; source_bytes().len()];
        let source_read = rustix::io::pread(&self.source, &mut source, 0)?;
        if source_read != source.len() || source != source_bytes() {
            return Err(io::Error::other("source changed during worker execution"));
        }

        let mut sentinel = [0_u8; 7];
        let sentinel_read = rustix::io::pread(&self.outside_sentinel, &mut sentinel, 0)?;
        if sentinel_read != sentinel.len() || &sentinel != b"outside" {
            return Err(io::Error::other(
                "outside sentinel changed during worker execution",
            ));
        }
        Ok(())
    }

    fn verify_authority_state(&self, expect_stage_probe: bool) -> io::Result<()> {
        self.verify_retained_authority_state()?;

        let stage = self
            .stage
            .as_ref()
            .ok_or_else(|| io::Error::other("crash barrier fixture has no stage"))?;
        if Some(descriptor_identity(stage)?) != self.stage_identity {
            return Err(io::Error::other(
                "stage identity, owner, type, or mode changed during injected worker failure",
            ));
        }

        let stage_path = self.root.join("stage");
        let probe = stage_path.join(".sealr-bootstrap-probe");
        if expect_stage_probe {
            if fs::read(&probe)? != b"ok" {
                return Err(io::Error::other(
                    "stage probe is invalid after its crash barrier",
                ));
            }
        } else if probe.try_exists()? {
            return Err(io::Error::other(
                "stage probe appeared before its lifecycle barrier",
            ));
        }

        let stage_entries = directory_entry_names(&stage_path)?;
        let expected_stage_entries = if expect_stage_probe {
            vec![".sealr-bootstrap-probe".to_owned()]
        } else {
            Vec::new()
        };
        if stage_entries != expected_stage_entries {
            return Err(io::Error::other(format!(
                "worker left unexpected stage entries: {stage_entries:?}"
            )));
        }

        let root_entries = directory_entry_names(&self.root)?;
        let expected = vec!["outside-sentinel".to_owned(), "stage".to_owned()];
        if root_entries != expected {
            return Err(io::Error::other(format!(
                "worker created unexpected fixture entries: {root_entries:?}"
            )));
        }
        Ok(())
    }
}

fn directory_entry_names(path: &Path) -> io::Result<Vec<String>> {
    let mut entries = fs::read_dir(path)?
        .map(|entry| {
            entry.and_then(|entry| {
                entry.file_name().into_string().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 fixture entry")
                })
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    entries.sort_unstable();
    Ok(entries)
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
    status: Option<ExitStatus>,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
struct BoundaryBindError {
    message: String,
    reaped: bool,
}

impl ChildBoundary {
    fn bind_authenticated(
        child: Child,
        control: &OwnedFd,
        mode: ChildMode,
    ) -> Result<Self, BoundaryBindError> {
        let mut boundary = Self::bind(child)?;
        if mode == ChildMode::Normal {
            if let Err(error) = boundary.authenticate_production(control) {
                return Err(boundary.reject_authentication(error));
            }
        }
        Ok(boundary)
    }

    fn bind(mut child: Child) -> Result<Self, BoundaryBindError> {
        let pid = rustix::process::Pid::from_child(&child);
        match rustix::process::pidfd_open(pid, PidfdFlags::empty()) {
            Ok(pidfd) => Ok(Self {
                child,
                pidfd,
                reaped: false,
                status: None,
            }),
            Err(error) => match terminate_unbound_child_bounded(&mut child) {
                Ok(status) => Err(BoundaryBindError {
                    message: format!(
                        "binding worker pidfd failed: {error}; bounded fallback reaped it as {status}"
                    ),
                    reaped: true,
                }),
                Err(termination) => Err(BoundaryBindError {
                    message: format!(
                        "binding worker pidfd failed: {error}; bounded fallback termination also failed: {termination}"
                    ),
                    reaped: false,
                }),
            },
        }
    }

    fn authenticate_production(
        &mut self,
        control: &OwnedFd,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let operation_id = random_operation_id()?;
        let mut challenge = Frame::new(Kind::HelperChallenge, operation_id);
        challenge.values = [HELPER_BOOTSTRAP_ABI, HELPER_FEATURE_ID, 0, 0];
        let deadline = EpochDeadline::start(AuthorityEpoch::HelperAuthentication);
        self.wait_for_control(control, deadline, libc::POLLOUT)?;
        send_packet(control, challenge, &[])?;

        self.wait_for_control(control, deadline, libc::POLLIN)?;
        let (hello, descriptors) = receive_packet(control, Some(0))?;
        if !descriptors.is_empty()
            || hello.kind != Kind::HelperHello
            || hello.flags != 0
            || hello.operation_id != operation_id
            || hello.values != [HELPER_BOOTSTRAP_ABI, HELPER_FEATURE_ID, 0, 0]
        {
            return Err(io::Error::other("worker authentication hello is invalid").into());
        }
        CHILD_PROGRAMS
            .get()
            .ok_or("worker child programs are not initialized")?
            .production
            .verify_process_executable(self.pid())?;
        Ok(())
    }

    fn reject_authentication(mut self, error: Box<dyn std::error::Error>) -> BoundaryBindError {
        if self.reaped {
            return BoundaryBindError {
                message: format!(
                    "authenticating worker failed: {error}; worker was already reaped as {}",
                    self.status
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "unknown status".to_owned())
                ),
                reaped: true,
            };
        }
        match self.terminate_and_reap_bounded() {
            Ok(status) => BoundaryBindError {
                message: format!(
                    "authenticating worker failed: {error}; bounded termination reaped it as {status}"
                ),
                reaped: true,
            },
            Err(termination) => BoundaryBindError {
                message: format!(
                    "authenticating worker failed: {error}; bounded termination also failed: {termination}"
                ),
                reaped: false,
            },
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn is_reaped(&self) -> bool {
        self.reaped
    }

    fn status(&self) -> Option<&ExitStatus> {
        self.status.as_ref()
    }

    fn record_status(&mut self, status: ExitStatus) -> ExitStatus {
        self.reaped = true;
        self.status = Some(status);
        status
    }

    fn expire_epoch<T>(
        &mut self,
        deadline: EpochDeadline,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let status = self.terminate_and_reap_bounded()?;
        Err(EpochTimeout {
            epoch: deadline.epoch,
            signal: status.signal().unwrap_or(0),
        }
        .into())
    }

    fn wait_for_control(
        &mut self,
        control: &OwnedFd,
        deadline: EpochDeadline,
        events: libc::c_short,
    ) -> Result<(), Box<dyn std::error::Error>> {
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
            // timeout is a finite recomputation from one absolute Instant.
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
                return Err(error.into());
            }
            if result == 0 {
                continue;
            }
            let control_events = descriptors[0].revents;
            if control_events & libc::POLLNVAL != 0 {
                return Err(io::Error::other("worker control descriptor became invalid").into());
            }
            if control_events & (events | libc::POLLERR | libc::POLLHUP) != 0 {
                return Ok(());
            }
            let pidfd_events = descriptors[1].revents;
            if pidfd_events & libc::POLLNVAL != 0 {
                return Err(io::Error::other("worker pidfd became invalid").into());
            }
            if pidfd_events & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
                let status = self.reap_until(deadline.expires_at)?;
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!(
                        "worker exited as {status} during authority epoch {:?}",
                        deadline.epoch
                    ),
                )
                .into());
            }
        }
    }

    fn wait_for_exit(
        &mut self,
        deadline: EpochDeadline,
    ) -> Result<ExitStatus, Box<dyn std::error::Error>> {
        loop {
            if let Some(status) = self.child.try_wait()? {
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
                return Err(error.into());
            }
            if result == 0 {
                continue;
            }
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::other("worker pidfd became invalid").into());
            }
            if descriptor.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
                return self.reap_until(deadline.expires_at).map_err(Into::into);
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

    fn wait_bounded(&mut self) -> io::Result<ExitStatus> {
        let deadline = Instant::now() + CHILD_EXIT_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(self.record_status(status));
            }
            if Instant::now() >= deadline {
                let status = self.terminate_and_reap_bounded()?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("worker exceeded deadline and was reaped as {status}"),
                ));
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

fn terminate_unbound_child_bounded(child: &mut Child) -> io::Result<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    child.kill()?;
    let deadline = Instant::now() + KILL_REAP_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "unbound worker reap could not be proved within the deadline",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_stall_maps_to_the_authority_epoch_that_must_expire() {
        let bootstrap = StallPoint::ALL
            .into_iter()
            .filter(|point| {
                AuthorityEpoch::for_stall(*point) == AuthorityEpoch::BootstrapRestriction
            })
            .count();
        let source = StallPoint::ALL
            .into_iter()
            .filter(|point| AuthorityEpoch::for_stall(*point) == AuthorityEpoch::SourceTransfer)
            .count();
        let probe = StallPoint::ALL
            .into_iter()
            .filter(|point| AuthorityEpoch::for_stall(*point) == AuthorityEpoch::ProbeExecution)
            .count();
        let exit = StallPoint::ALL
            .into_iter()
            .filter(|point| AuthorityEpoch::for_stall(*point) == AuthorityEpoch::WorkerExit)
            .count();
        assert_eq!([bootstrap, source, probe, exit], [3, 4, 2, 2]);
    }

    #[test]
    fn expired_deadline_never_becomes_a_relative_wait() {
        let deadline = EpochDeadline {
            epoch: AuthorityEpoch::SourceTransfer,
            expires_at: Instant::now() - Duration::from_millis(1),
        };
        assert_eq!(deadline.poll_timeout_ms(), None);

        let live = EpochDeadline::start(AuthorityEpoch::SourceTransfer)
            .poll_timeout_ms()
            .expect("new deadline remains live");
        assert!((1..=1_000).contains(&live));
    }

    #[test]
    fn stress_campaign_repeats_every_closed_case() {
        let mut counts = [0_usize; STRESS_CASES];
        for iteration in 0..STRESS_ITERATIONS {
            counts[iteration % STRESS_CASES] += 1;
        }

        assert_eq!(counts.iter().sum::<usize>(), STRESS_ITERATIONS);
        assert_eq!(counts.iter().copied().min(), Some(11));
        assert_eq!(counts.iter().copied().max(), Some(12));
    }
}
