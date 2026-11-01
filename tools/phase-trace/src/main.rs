//! Bounded diagnostic for unretained Linux member-read phases.
//!
//! This binary enables `__internal-phase-trace`. The released helper and the
//! default library build do not. It does not change admission, retention, or
//! evidence. A run that exceeds its budget is incomplete and exits 2.
//!
//! Two fixtures share one protocol. `small` is eight deflated members. `wide`
//! adds one unread stored pad so source hashing reads a larger file. The pad
//! is not a retained or requested member.

use std::env;
use std::process::ExitCode;

#[cfg(target_os = "linux")]
use std::fs::{self, File};
#[cfg(target_os = "linux")]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use sealr::{
    AdmissionStatus, ApplyOptions, LinuxWorker, Policy, Request, RetentionPlan, Source,
    VerificationStatus, apply_supervised, phase_trace,
};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use zip::write::SimpleFileOptions;
#[cfg(target_os = "linux")]
use zip::{CompressionMethod, ZipWriter};

const MEMBERS: usize = 8;
const MEMBER_LEN: usize = 45_000;
const PAD_LEN: usize = 8 * 1024 * 1024;
const PASSES: usize = 6;
const BUDGET: Duration = Duration::from_secs(120);
const CASES: &[(&str, usize)] = &[("small", 0), ("wide", PAD_LEN)];

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(flag) = args.next() else {
        eprintln!("usage: sealr-phase-trace --worker <helper>");
        return ExitCode::from(2);
    };
    if flag != "--worker" {
        eprintln!("usage: sealr-phase-trace --worker <helper>");
        return ExitCode::from(2);
    }
    let Some(worker_path) = args.next() else {
        eprintln!("missing helper path");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("usage: sealr-phase-trace --worker <helper>");
        return ExitCode::from(2);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = worker_path;
        eprintln!("phase trace requires Linux");
        return ExitCode::from(2);
    }

    #[cfg(target_os = "linux")]
    match run(Path::new(&worker_path)) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(target_os = "linux")]
struct Member {
    name: String,
    sha256: String,
}

#[cfg(target_os = "linux")]
struct ReadObs {
    strategy: &'static str,
    name: String,
    total_ns: u128,
    source_hash_ns: u128,
    plan_validation_ns: u128,
    worker_setup_ns: u128,
    payload_verification_ns: u128,
    source_hash_count: u32,
    plan_validation_count: u32,
    worker_setup_count: u32,
    payload_verification_count: u32,
}

#[cfg(target_os = "linux")]
struct CaseObs {
    name: &'static str,
    source_sha256: String,
    source_len: u64,
    pad_len: usize,
    members: Vec<Member>,
    reads: Vec<ReadObs>,
}

#[cfg(target_os = "linux")]
fn run(worker_path: &Path) -> Result<String, String> {
    let started = Instant::now();
    let worker_path = worker_path
        .canonicalize()
        .map_err(|error| format!("resolve helper path: {error}"))?;
    let worker_bytes = fs::read(&worker_path).map_err(|error| format!("read helper: {error}"))?;
    let worker = LinuxWorker::load(
        &worker_path,
        worker_bytes.len() as u64,
        &hex(&Sha256::digest(&worker_bytes)),
    )
    .map_err(|error| format!("authenticate helper: {error}"))?;

    let root = std::env::temp_dir().join(format!("sealr-phase-trace-{}", std::process::id()));
    fs::create_dir_all(&root).map_err(|error| format!("create diagnostic directory: {error}"))?;
    let mut cases = Vec::with_capacity(CASES.len());
    for (name, pad_len) in CASES {
        if started.elapsed() > BUDGET {
            let _ = fs::remove_dir_all(&root);
            return Err(format!(
                "diagnostic exceeded its budget before case {name}; observation is incomplete"
            ));
        }
        cases.push(measure_case(&root, &worker, &started, name, *pad_len)?);
    }
    phase_trace::end();
    let elapsed = started.elapsed();
    let _ = fs::remove_dir_all(&root);
    Ok(render(
        &worker_path.display().to_string(),
        &hex(&Sha256::digest(&worker_bytes)),
        worker_bytes.len(),
        &cases,
        elapsed,
    ))
}

#[cfg(target_os = "linux")]
fn measure_case(
    root: &Path,
    worker: &LinuxWorker,
    started: &Instant,
    name: &'static str,
    pad_len: usize,
) -> Result<CaseObs, String> {
    let archive_path = root.join(format!("{name}.zip"));
    let members = write_fixture(&archive_path, pad_len)?;
    let source_len = fs::metadata(&archive_path)
        .map_err(|error| format!("stat fixture: {error}"))?
        .len();
    let outcome = admit(&archive_path, worker, None)?;
    let retained_outcome = admit(&archive_path, worker, Some(&members))?;
    let archive = outcome
        .verified_archive()
        .ok_or_else(|| format!("{name} unretained admission did not return a verified archive"))?;
    let retained = retained_outcome
        .verified_archive()
        .ok_or_else(|| format!("{name} retained admission did not return a verified archive"))?;
    if archive.source_digest().sha256() != retained.source_digest().sha256() {
        return Err(format!(
            "{name} retained and unretained admissions disagree on the source digest"
        ));
    }
    let source_sha256 = archive
        .source_digest()
        .sha256()
        .unwrap_or("unavailable")
        .to_owned();

    phase_trace::begin();
    let warmup = read_pass(archive, &members, "warmup")?;
    let _ = warmup;
    phase_trace::take();
    if started.elapsed() > BUDGET {
        let _ = fs::remove_dir_all(root);
        return Err(format!(
            "diagnostic exceeded its budget during {name} warmup; observation is incomplete"
        ));
    }

    let mut reads = Vec::new();
    for pass in 0..PASSES {
        let first_retained = pass % 2 == 1;
        if first_retained {
            reads.extend(read_pass(retained, &members, "retained")?);
            reads.extend(read_pass(archive, &members, "unretained")?);
        } else {
            reads.extend(read_pass(archive, &members, "unretained")?);
            reads.extend(read_pass(retained, &members, "retained")?);
        }
        if started.elapsed() > BUDGET {
            let _ = fs::remove_dir_all(root);
            return Err(format!(
                "diagnostic exceeded its budget after {name} pass {pass}; observation is incomplete"
            ));
        }
    }
    // Drop samples from this case before the next fixture so its admission
    // does not inherit an open session from the measured reads.
    phase_trace::end();
    Ok(CaseObs {
        name,
        source_sha256,
        source_len,
        pad_len,
        members,
        reads,
    })
}

#[cfg(target_os = "linux")]
fn write_fixture(path: &Path, pad_len: usize) -> Result<Vec<Member>, String> {
    let file = File::create(path).map_err(|error| format!("create fixture: {error}"))?;
    let mut zip = ZipWriter::new(file);
    let deflated = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut members = Vec::with_capacity(MEMBERS);
    for index in 0..MEMBERS {
        let name = format!("m{index}.txt");
        let body: Vec<u8> = (0..MEMBER_LEN)
            .map(|offset| u8::try_from((index + offset) % 251).unwrap_or(0))
            .collect();
        zip.start_file(name.clone(), deflated)
            .map_err(|error| format!("start fixture member: {error}"))?;
        zip.write_all(&body)
            .map_err(|error| format!("write fixture member: {error}"))?;
        members.push(Member {
            name,
            sha256: hex(&Sha256::digest(&body)),
        });
    }
    if pad_len > 0 {
        let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        zip.start_file("pad.bin", stored)
            .map_err(|error| format!("start fixture pad: {error}"))?;
        let chunk = vec![0xA5_u8; 64 * 1024];
        let mut left = pad_len;
        while left > 0 {
            let n = left.min(chunk.len());
            zip.write_all(&chunk[..n])
                .map_err(|error| format!("write fixture pad: {error}"))?;
            left -= n;
        }
    }
    zip.finish()
        .map_err(|error| format!("finish fixture: {error}"))?;
    Ok(members)
}

#[cfg(target_os = "linux")]
fn admit(
    archive: &Path,
    worker: &LinuxWorker,
    members: Option<&[Member]>,
) -> Result<sealr::Outcome, String> {
    let policy = Policy::default_v8();
    let mut options = ApplyOptions::new();
    if let Some(members) = members {
        let mut plan = RetentionPlan::new(MEMBER_LEN as u64, (MEMBERS * MEMBER_LEN) as u64);
        for member in members {
            plan = plan
                .with_path(&member.name)
                .map_err(|error| format!("retention plan: {error}"))?;
        }
        options = options.with_retention(plan);
    }
    let outcome = apply_supervised(
        Request {
            source: Source::Path(archive),
            policy: &policy,
            dest: None,
        },
        &options,
        worker,
    )
    .map_err(|error| format!("supervised admission: {error}"))?;
    if outcome.admission != AdmissionStatus::Admitted
        || outcome.verification != VerificationStatus::Complete
    {
        return Err(format!(
            "admission {:?} verification {:?}",
            outcome.admission, outcome.verification
        ));
    }
    Ok(outcome)
}

#[cfg(target_os = "linux")]
fn read_pass(
    archive: &sealr::VerifiedArchive,
    members: &[Member],
    strategy: &'static str,
) -> Result<Vec<ReadObs>, String> {
    let mut reads = Vec::with_capacity(members.len());
    for member in members {
        phase_trace::take();
        let started = Instant::now();
        let bytes = archive
            .read_member(&member.name, MEMBER_LEN as u64)
            .map_err(|error| format!("read {} {strategy}: {error}", member.name))?;
        let total_ns = started.elapsed().as_nanos();
        let samples = phase_trace::take();
        if hex(&Sha256::digest(&bytes)) != member.sha256 {
            return Err(format!("member {} bytes changed", member.name));
        }
        let mut obs = ReadObs {
            strategy,
            name: member.name.clone(),
            total_ns,
            source_hash_ns: 0,
            plan_validation_ns: 0,
            worker_setup_ns: 0,
            payload_verification_ns: 0,
            source_hash_count: 0,
            plan_validation_count: 0,
            worker_setup_count: 0,
            payload_verification_count: 0,
        };
        for sample in samples {
            match sample.phase {
                phase_trace::Phase::SourceHash => {
                    obs.source_hash_ns += sample.nanos;
                    obs.source_hash_count += 1;
                }
                phase_trace::Phase::PlanValidation => {
                    obs.plan_validation_ns += sample.nanos;
                    obs.plan_validation_count += 1;
                }
                phase_trace::Phase::WorkerSetup => {
                    obs.worker_setup_ns += sample.nanos;
                    obs.worker_setup_count += 1;
                }
                phase_trace::Phase::PayloadVerification => {
                    obs.payload_verification_ns += sample.nanos;
                    obs.payload_verification_count += 1;
                }
            }
        }
        reads.push(obs);
    }
    Ok(reads)
}

#[cfg(target_os = "linux")]
fn render(
    worker_path: &str,
    worker_sha256: &str,
    worker_len: usize,
    cases: &[CaseObs],
    elapsed: Duration,
) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    push_str(&mut out, "protocol", "sealr.phase-trace.v1");
    push_str(
        &mut out,
        "helper_kind",
        "local diagnostic helper, not a released archive helper",
    );
    push_str(&mut out, "worker_path", worker_path);
    push_str(&mut out, "worker_sha256", worker_sha256);
    out.push_str(&format!("  \"worker_len\": {worker_len},\n"));
    out.push_str(&format!(
        "  \"members\": {MEMBERS},\n  \"member_len\": {MEMBER_LEN},\n  \"passes\": {PASSES},\n"
    ));
    out.push_str(&format!(
        "  \"elapsed_ns\": {},\n  \"complete\": true,\n",
        elapsed.as_nanos()
    ));
    out.push_str("  \"cases\": [\n");
    for (index, case) in cases.iter().enumerate() {
        let comma = if index + 1 == cases.len() { "" } else { "," };
        render_case(&mut out, case);
        out.push_str(comma);
        out.push('\n');
    }
    out.push_str("  ]\n}\n");
    out
}

#[cfg(target_os = "linux")]
fn render_case(out: &mut String, case: &CaseObs) {
    out.push_str("    {\n");
    out.push_str(&format!(
        "      \"name\": \"{}\",\n      \"pad_len\": {},\n      \"source_len\": {},\n",
        case.name, case.pad_len, case.source_len
    ));
    out.push_str(&format!(
        "      \"source_sha256\": \"{}\",\n",
        case.source_sha256
    ));
    out.push_str("      \"member_sha256\": {\n");
    for (index, member) in case.members.iter().enumerate() {
        let comma = if index + 1 == case.members.len() {
            ""
        } else {
            ","
        };
        out.push_str(&format!(
            "        \"{}\": \"{}\"{comma}\n",
            member.name, member.sha256
        ));
    }
    out.push_str("      },\n      \"reads\": [\n");
    for (index, read) in case.reads.iter().enumerate() {
        let comma = if index + 1 == case.reads.len() {
            ""
        } else {
            ","
        };
        out.push_str(&format!(
            "        {{\"strategy\":\"{}\",\"member\":\"{}\",\"total_ns\":{},\"source_hash_ns\":{},\"source_hash_count\":{},\"plan_validation_ns\":{},\"plan_validation_count\":{},\"worker_setup_ns\":{},\"worker_setup_count\":{},\"payload_verification_ns\":{},\"payload_verification_count\":{}}}{comma}\n",
            read.strategy,
            read.name,
            read.total_ns,
            read.source_hash_ns,
            read.source_hash_count,
            read.plan_validation_ns,
            read.plan_validation_count,
            read.worker_setup_ns,
            read.worker_setup_count,
            read.payload_verification_ns,
            read.payload_verification_count,
        ));
    }
    out.push_str("      ]\n    }");
}

#[cfg(target_os = "linux")]
fn push_str(out: &mut String, key: &str, value: &str) {
    out.push_str(&format!(
        "  \"{key}\": \"{}\",\n",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ));
}

#[cfg(target_os = "linux")]
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    out
}
