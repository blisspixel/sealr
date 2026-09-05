//! A narrow publisher decision over an admitted capability.
//!
//! The supplied wheel is preserved. A private copy is admitted, independently
//! checked, and deleted before wheel evaluation and the content gate run.
//! This example prepares an integration; it is not Deepr's production gate.

#[allow(dead_code)]
#[path = "../pypa_installer_handoff/stage.rs"]
mod stage;

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use sealr::wheel::{evaluate_wheel, WheelEvaluation, WheelLimits};
use sealr::{
    apply_supervised, ApplyOptions, LinuxWorker, MemberKind, Policy, Request, RetentionPlan,
    Source, VerifiedArchive, ZipInterpretationProfile,
};
use serde::Serialize;

const MAX_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
const REQUIRED_FILES: [&str; 5] = [
    "deepr/web/frontend/dist/index.html",
    "deepr/config/system_message.json",
    "deepr/skills/recon/skill.yaml",
    "deepr/skills/recon/prompt.md",
    "deepr/templates/documentation_research.md",
];
const ASSETS_PREFIX: &str = "deepr/web/frontend/dist/assets/";

#[derive(Debug, Eq, PartialEq, Serialize)]
struct ContentDecision {
    required_files: usize,
    javascript_files: usize,
    css_files: usize,
}

/// The business consumer receives neither a path nor source bytes. Admission
/// has already established path uniqueness, canonical names, and integrity.
fn check_deepr_content(archive: &VerifiedArchive) -> Result<ContentDecision, String> {
    let mut files = BTreeSet::new();
    let mut forbidden = BTreeSet::new();
    for member in archive.members() {
        let path = member.canonical_path.as_str();
        if path
            .split('/')
            .any(|part| matches!(part, "node_modules" | "__pycache__"))
            || path.rsplit('/').next() == Some("frontend-dist.zip")
            || path.ends_with(".pyc")
            || path.ends_with(".pyo")
        {
            forbidden.insert(path);
        }
        if member.kind == MemberKind::File {
            files.insert(path);
        }
    }
    if let Some(path) = forbidden.first() {
        return Err(format!("build-only member: {path}"));
    }
    for path in REQUIRED_FILES {
        if !files.contains(path) {
            return Err(format!("missing required file: {path}"));
        }
    }
    let javascript_files = files
        .iter()
        .filter(|path| path.starts_with(ASSETS_PREFIX) && path.ends_with(".js"))
        .count();
    let css_files = files
        .iter()
        .filter(|path| path.starts_with(ASSETS_PREFIX) && path.ends_with(".css"))
        .count();
    if javascript_files == 0 {
        return Err("no packaged frontend JavaScript assets".to_owned());
    }
    if css_files == 0 {
        return Err("no packaged frontend CSS assets".to_owned());
    }
    Ok(ContentDecision {
        required_files: REQUIRED_FILES.len(),
        javascript_files,
        css_files,
    })
}

struct Args {
    wheel: PathBuf,
    worker_manifest: PathBuf,
    verifier: PathBuf,
    retention: RetentionPlan,
}

impl Args {
    fn parse() -> Result<Self, Box<dyn std::error::Error>> {
        let mut values = std::env::args_os().skip(1);
        let mut wheel = None;
        let mut worker_manifest = None;
        let mut verifier = None;
        let mut retention = RetentionPlan::new(256 * 1024, 1024 * 1024);
        while let Some(flag) = values.next() {
            let value = values.next().ok_or("each flag requires a value")?;
            let slot = match flag.to_str() {
                Some("--wheel") => &mut wheel,
                Some("--worker-manifest") => &mut worker_manifest,
                Some("--verifier") => &mut verifier,
                Some("--retain-member") => {
                    retention.add_path(
                        value
                            .into_string()
                            .map_err(|_| "retention path must be UTF-8")?,
                    )?;
                    continue;
                }
                _ => return Err(format!("unknown argument: {}", flag.to_string_lossy()).into()),
            };
            if slot.is_some() {
                return Err(format!("duplicate argument: {}", flag.to_string_lossy()).into());
            }
            *slot = Some(PathBuf::from(value));
        }
        Ok(Self {
            wheel: wheel.ok_or("--wheel is required")?,
            worker_manifest: worker_manifest.ok_or("--worker-manifest is required")?,
            verifier: verifier.ok_or("--verifier is required")?,
            retention,
        })
    }
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    accepted: bool,
    private_source_deleted_before_evaluation: bool,
    installed_files: usize,
    source_sha256: String,
    archive_tree_sha256: String,
    artifact_sha256: String,
    install_plan_sha256: String,
    canonical_view_sha256: String,
    canonical_receipt_sha256: String,
    content: ContentDecision,
    retention: Vec<RetainedPath>,
    retained_bytes: u64,
    admission_seconds: f64,
    evidence_seconds: f64,
    evaluation_seconds: f64,
    content_gate_seconds: f64,
}

#[derive(Serialize)]
struct RetainedPath {
    path: String,
    status: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !cfg!(target_os = "linux") {
        return Err("this supervised content-gate example requires Linux".into());
    }
    let args = Args::parse()?;
    let filename = args
        .wheel
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("wheel filename must be UTF-8")?;
    let worker = LinuxWorker::load_from_manifest(&args.worker_manifest)?;
    let private = stage::PrivateRoot::create()?;
    let source = private.path().join(filename);
    copy_bounded(&args.wheel, &source)?;
    let policy = Policy::default_v1();
    let options = ApplyOptions::new()
        .with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1)
        .with_retention(args.retention.clone());
    let started = Instant::now();
    let outcome = apply_supervised(
        Request {
            source: Source::Path(&source),
            policy: &policy,
            dest: None,
        },
        &options,
        &worker,
    )?;
    let admission_seconds = started.elapsed().as_secs_f64();
    if outcome.rejected() {
        return Err(format!("archive admission failed: {:?}", outcome.view.findings).into());
    }
    let started = Instant::now();
    let evidence = outcome
        .canonical_evidence()
        .map_err(|finding| format!("canonical evidence failed: {}", finding.detail))?;
    let view = private.path().join("view.json");
    let receipt = private.path().join("receipt.json");
    write_new(&view, &evidence.view_bytes)?;
    write_new(&receipt, &evidence.receipt_bytes)?;
    let mut command = Command::new(&args.verifier);
    stage::configure_process_group(&mut command);
    let mut child = command
        .arg("evidence")
        .arg("--view")
        .arg(&view)
        .arg("--receipt")
        .arg(&receipt)
        .arg("--source")
        .arg(&source)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    if !stage::wait_for_child(&mut child, "independent evidence verifier")?.success() {
        return Err("independent evidence verification failed".into());
    }
    let evidence_seconds = started.elapsed().as_secs_f64();
    fs::remove_file(&source)?;
    if fs::symlink_metadata(&source).is_ok() {
        return Err("private source remained available after deletion".into());
    }
    let archive = outcome
        .into_verified_archive()
        .ok_or("verified capability unavailable")?;
    let started = Instant::now();
    let evaluation = evaluate_wheel(filename, &archive, WheelLimits::default());
    let WheelEvaluation::Admitted {
        artifact,
        identities,
        ..
    } = evaluation
    else {
        return Err(format!("wheel semantic evaluation failed: {evaluation:?}").into());
    };
    if artifact.filename.normalized_distribution != "deepr-research" {
        return Err("this content gate is scoped to the deepr-research distribution".into());
    }
    let evaluation_seconds = started.elapsed().as_secs_f64();
    let started = Instant::now();
    let content = check_deepr_content(&archive)?;
    let content_gate_seconds = started.elapsed().as_secs_f64();
    let report = Report {
        schema: "sealr.deepr-content-gate.v1",
        accepted: true,
        private_source_deleted_before_evaluation: true,
        installed_files: 0,
        source_sha256: identities.source_sha256,
        archive_tree_sha256: identities.archive_tree_sha256,
        artifact_sha256: identities.artifact_sha256,
        install_plan_sha256: identities.install_plan_sha256,
        canonical_view_sha256: evidence.view_digest,
        canonical_receipt_sha256: evidence.receipt_digest,
        content,
        retention: args
            .retention
            .paths()
            .map(|path| RetainedPath {
                path: path.to_owned(),
                status: format!("{:?}", archive.retention_status(path)),
            })
            .collect(),
        retained_bytes: archive.retained_bytes(),
        admission_seconds,
        evidence_seconds,
        evaluation_seconds,
        content_gate_seconds,
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn copy_bounded(source: &Path, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !fs::symlink_metadata(source)?.file_type().is_file() {
        return Err("wheel must be a regular file, not a link".into());
    }
    let input = File::open(source)?;
    if !input.metadata()?.is_file() {
        return Err("opened wheel must be a regular file".into());
    }
    let mut output = OpenOptions::new().write(true).create_new(true).open(dest)?;
    let bytes = std::io::copy(&mut input.take(MAX_SOURCE_BYTES + 1), &mut output)?;
    if bytes > MAX_SOURCE_BYTES {
        return Err("wheel exceeds the example's 128 MiB acquisition bound".into());
    }
    output.flush()?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests;
