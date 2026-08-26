use std::env;
use std::fs;
use std::io::{self, Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use sealr::{
    apply, AdmissionStatus, EffectStatus, FindingCode, InterpretationStatus, Policy, Request,
    Source, VerificationStatus,
};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const ITERATIONS: usize = 500;
const SEED: u64 = 0x6a09_e667_f3bc_c909;
const PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const STAGE_PREFIX: &str = ".sealr-stage-";

#[derive(Clone, Copy, Debug)]
enum LifecycleCase {
    Publish,
    SetupCollision,
    VerificationAbort,
    DestinationRace,
}

#[derive(Default)]
struct Counts {
    publish: usize,
    setup_collision: usize,
    verification_abort: usize,
    destination_race: usize,
}

struct RootGuard {
    path: PathBuf,
}

impl RootGuard {
    fn create() -> io::Result<Self> {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = env::temp_dir().join(format!("sealr-native-lifecycle-{suffix}"));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }
}

impl Drop for RootGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn main() -> ExitCode {
    if env::args_os().len() != 1 {
        eprintln!("sealr-materialization-lifecycle takes no arguments");
        return ExitCode::from(2);
    }
    match run() {
        Ok(counts) => {
            println!(
                "sealr.native-materialization-evidence.v1: seed {SEED:#018x}, {ITERATIONS} iterations, {} publications, {} setup collisions, {} verification aborts, {} destination races, exact lifecycle oracle agreement, and no leaked stages passed",
                counts.publish,
                counts.setup_collision,
                counts.verification_abort,
                counts.destination_race,
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("native materialization lifecycle failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<Counts, Box<dyn std::error::Error>> {
    let root = RootGuard::create()?;
    let valid = make_source(false)?;
    let invalid = make_source(true)?;
    let policy = Policy::default_v1();
    let mut state = SEED;
    let mut counts = Counts::default();

    for iteration in 0..ITERATIONS {
        let case = match iteration % 4 {
            0 => LifecycleCase::Publish,
            1 => LifecycleCase::SetupCollision,
            2 => LifecycleCase::VerificationAbort,
            3 => LifecycleCase::DestinationRace,
            _ => unreachable!("lifecycle modulus is closed"),
        };
        state = xorshift64(state);
        let case_root = root.path.join(format!("case-{iteration:03}"));
        fs::create_dir(&case_root)?;
        let destination = case_root.join("output");

        let result = match case {
            LifecycleCase::Publish => {
                counts.publish += 1;
                run_publish(&policy, &valid, &destination)
            }
            LifecycleCase::SetupCollision => {
                counts.setup_collision += 1;
                run_setup_collision(&policy, &valid, &destination)
            }
            LifecycleCase::VerificationAbort => {
                counts.verification_abort += 1;
                run_verification_abort(&policy, &invalid, &destination)
            }
            LifecycleCase::DestinationRace => {
                counts.destination_race += 1;
                run_destination_race(&policy, &valid, &case_root, &destination, state)
            }
        };
        result.map_err(|error| {
            io::Error::other(format!(
                "iteration {iteration} case {case:?} disagreed with the lifecycle oracle: {error}"
            ))
        })?;
        require_empty_directory(&case_root)?;
        fs::remove_dir(&case_root)?;
    }
    require_empty_directory(&root.path)?;
    Ok(counts)
}

fn run_publish(policy: &Policy, source: &[u8], destination: &Path) -> io::Result<()> {
    let outcome = apply(request(policy, source, destination));
    require_axes(
        &outcome,
        AdmissionStatus::Admitted,
        VerificationStatus::Complete,
        EffectStatus::Committed,
    )?;
    if !outcome.wrote()
        || outcome.receipt.materialization.outcome != "committed"
        || outcome.receipt.materialization.cleanup != "not-applicable-after-commit"
    {
        return Err(io::Error::other(
            "successful publication evidence is inconsistent",
        ));
    }
    require_published_tree(destination)?;
    let archive = outcome
        .into_verified_archive()
        .ok_or_else(|| io::Error::other("publication did not preserve verified authority"))?;
    if archive
        .read_member("stored.bin", PAYLOAD_BYTES as u64)
        .map_err(io::Error::other)?
        != payload(0x31)
        || archive
            .read_member("nested/deflated.bin", PAYLOAD_BYTES as u64)
            .map_err(io::Error::other)?
            != payload(0xa7)
    {
        return Err(io::Error::other(
            "published capability returned unexpected bytes",
        ));
    }
    fs::remove_dir_all(destination)
}

fn run_setup_collision(policy: &Policy, source: &[u8], destination: &Path) -> io::Result<()> {
    fs::create_dir(destination)?;
    fs::write(destination.join("sentinel"), b"existing")?;
    let outcome = apply(request(policy, source, destination));
    require_axes(
        &outcome,
        AdmissionStatus::Admitted,
        VerificationStatus::StructureOnly,
        EffectStatus::Failed,
    )?;
    require_finding(&outcome, FindingCode::MaterializeExists)?;
    if outcome.receipt.materialization.outcome != "setup-failed"
        || outcome.receipt.materialization.cleanup != "not-created"
        || outcome.verified_archive().is_some()
        || fs::read(destination.join("sentinel"))? != b"existing"
    {
        return Err(io::Error::other("setup-collision evidence is inconsistent"));
    }
    fs::remove_dir_all(destination)
}

fn run_verification_abort(policy: &Policy, source: &[u8], destination: &Path) -> io::Result<()> {
    let outcome = apply(request(policy, source, destination));
    require_axes(
        &outcome,
        AdmissionStatus::Denied,
        VerificationStatus::Partial {
            verified_members: 2,
            pending_members: 1,
        },
        EffectStatus::Failed,
    )?;
    require_finding(&outcome, FindingCode::CrcMismatch)?;
    if outcome.receipt.materialization.outcome != "aborted"
        || outcome.receipt.materialization.cleanup != "removed"
        || outcome.verified_archive().is_some()
        || destination.exists()
    {
        return Err(io::Error::other(
            "verification-abort evidence is inconsistent",
        ));
    }
    Ok(())
}

fn run_destination_race(
    policy: &Policy,
    source: &[u8],
    parent: &Path,
    destination: &Path,
    schedule: u64,
) -> io::Result<()> {
    let watcher_parent = parent.to_owned();
    let watcher_destination = destination.to_owned();
    let watcher = thread::spawn(move || -> io::Result<()> {
        let spin = usize::try_from(schedule & 0x3f).expect("six schedule bits fit usize");
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let mut stage_exists = false;
            for entry in fs::read_dir(&watcher_parent)? {
                if entry?
                    .file_name()
                    .to_string_lossy()
                    .starts_with(STAGE_PREFIX)
                {
                    stage_exists = true;
                    break;
                }
            }
            if stage_exists {
                for _ in 0..spin {
                    std::hint::spin_loop();
                }
                fs::create_dir(&watcher_destination)?;
                fs::write(watcher_destination.join("sentinel"), b"raced")?;
                return Ok(());
            }
            if watcher_destination.exists() {
                return Err(io::Error::other(
                    "publication completed before the watcher observed its stage",
                ));
            }
            thread::yield_now();
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "stage watcher exceeded its ten-second deadline",
        ))
    });

    let outcome = apply(request(policy, source, destination));
    watcher
        .join()
        .map_err(|_| io::Error::other("destination-race watcher panicked"))??;
    require_axes(
        &outcome,
        AdmissionStatus::Admitted,
        VerificationStatus::Complete,
        EffectStatus::Failed,
    )?;
    require_finding(&outcome, FindingCode::MaterializeExists)?;
    if outcome.receipt.materialization.outcome != "publication-failed"
        || outcome.receipt.materialization.cleanup != "removed"
        || outcome.verified_archive().is_none()
        || fs::read(destination.join("sentinel"))? != b"raced"
    {
        return Err(io::Error::other(
            "destination-race evidence is inconsistent",
        ));
    }
    fs::remove_dir_all(destination)
}

fn request<'a>(policy: &'a Policy, source: &'a [u8], destination: &'a Path) -> Request<'a> {
    Request {
        source: Source::Bytes {
            path: Some("native-lifecycle.zip"),
            data: source,
        },
        policy,
        dest: Some(destination),
    }
}

fn require_axes(
    outcome: &sealr::Outcome,
    admission: AdmissionStatus,
    verification: VerificationStatus,
    effect: EffectStatus,
) -> io::Result<()> {
    if outcome.interpretation != InterpretationStatus::Interpreted
        || outcome.admission != admission
        || outcome.verification != verification
        || outcome.effect != effect
    {
        return Err(io::Error::other(format!(
            "unexpected axes: interpretation={:?}, admission={:?}, verification={:?}, effect={:?}",
            outcome.interpretation, outcome.admission, outcome.verification, outcome.effect
        )));
    }
    Ok(())
}

fn require_finding(outcome: &sealr::Outcome, code: FindingCode) -> io::Result<()> {
    if outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == code)
    {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "expected finding {}, observed {:?}",
            code.as_str(),
            outcome.view.findings
        )))
    }
}

fn require_published_tree(destination: &Path) -> io::Result<()> {
    if fs::read(destination.join("stored.bin"))? != payload(0x31)
        || fs::read(destination.join("nested/deflated.bin"))? != payload(0xa7)
    {
        return Err(io::Error::other("published tree content is invalid"));
    }
    Ok(())
}

fn require_empty_directory(path: &Path) -> io::Result<()> {
    let entries = fs::read_dir(path)?.collect::<io::Result<Vec<_>>>()?;
    if entries.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "lifecycle left {} filesystem entries in {}",
            entries.len(),
            path.display()
        )))
    }
}

fn payload(fill: u8) -> Vec<u8> {
    let mut state = u64::from(fill) | 0x9e37_79b9_7f4a_7c00;
    let mut bytes = Vec::with_capacity(PAYLOAD_BYTES);
    for _ in 0..PAYLOAD_BYTES {
        state = xorshift64(state);
        bytes.push(state as u8);
    }
    bytes
}

fn make_source(corrupt_second_crc: bool) -> io::Result<Vec<u8>> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        let stored = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::default());
        writer
            .start_file("stored.bin", stored)
            .map_err(io::Error::other)?;
        writer.write_all(&payload(0x31))?;
        writer
            .add_directory("nested/", stored)
            .map_err(io::Error::other)?;
        let deflated = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .last_modified_time(zip::DateTime::default());
        writer
            .start_file("nested/deflated.bin", deflated)
            .map_err(io::Error::other)?;
        writer.write_all(&payload(0xa7))?;
        writer.finish().map_err(io::Error::other)?;
    }
    let mut bytes = cursor.into_inner();
    if corrupt_second_crc {
        corrupt_last_member_crc(&mut bytes)?;
    }
    Ok(bytes)
}

fn corrupt_last_member_crc(bytes: &mut [u8]) -> io::Result<()> {
    let local = signature_offsets(bytes, [0x50, 0x4b, 0x03, 0x04]);
    let central = signature_offsets(bytes, [0x50, 0x4b, 0x01, 0x02]);
    let local_offset = *local
        .last()
        .ok_or_else(|| io::Error::other("source has no local file header"))?;
    let central_offset = *central
        .last()
        .ok_or_else(|| io::Error::other("source has no central directory header"))?;
    let local_crc = local_offset + 14;
    let central_crc = central_offset + 16;
    let mut wrong = u32::from_le_bytes(
        bytes[central_crc..central_crc + 4]
            .try_into()
            .map_err(io::Error::other)?,
    );
    wrong ^= 1;
    bytes[local_crc..local_crc + 4].copy_from_slice(&wrong.to_le_bytes());
    bytes[central_crc..central_crc + 4].copy_from_slice(&wrong.to_le_bytes());
    Ok(())
}

fn signature_offsets(bytes: &[u8], signature: [u8; 4]) -> Vec<usize> {
    bytes
        .windows(signature.len())
        .enumerate()
        .filter_map(|(index, window)| (window == signature).then_some(index))
        .collect()
}

fn xorshift64(mut value: u64) -> u64 {
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    value
}
