mod stage;

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sealr::wheel::{evaluate_wheel, WheelEvaluation, WheelLimits};
use sealr::{
    apply_supervised, ApplyOptions, LinuxWorker, Policy, Request, Source, ZipInterpretationProfile,
};
use serde::Serialize;

use stage::{
    configure_process_group, prepare_wheel_source, wait_for_child, PrivateRoot, INSTALLER_POLICY,
    TARGET_MODEL,
};

#[derive(Debug)]
struct Args {
    wheel: PathBuf,
    worker_manifest: PathBuf,
    verifier: PathBuf,
    python: PathBuf,
    installer_root: PathBuf,
    output_root: PathBuf,
    materialize_raw: Option<PathBuf>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut values = std::env::args_os().skip(1);
        let mut wheel = None;
        let mut worker_manifest = None;
        let mut verifier = None;
        let mut python = None;
        let mut installer_root = None;
        let mut output_root = None;
        let mut materialize_raw = None;
        while let Some(flag) = values.next() {
            let slot = match flag.to_str() {
                Some("--consume-wheel") => &mut wheel,
                Some("--worker-manifest") => &mut worker_manifest,
                Some("--verifier") => &mut verifier,
                Some("--python") => &mut python,
                Some("--installer-root") => &mut installer_root,
                Some("--output-root") => &mut output_root,
                Some("--materialize-raw") => &mut materialize_raw,
                _ => return Err(format!("unknown argument: {}", flag.to_string_lossy())),
            };
            if slot.is_some() {
                return Err(format!("duplicate argument: {}", flag.to_string_lossy()));
            }
            *slot = Some(PathBuf::from(next_value(&mut values, &flag)?));
        }
        Ok(Self {
            wheel: wheel.ok_or("--consume-wheel is required")?,
            worker_manifest: worker_manifest.ok_or("--worker-manifest is required")?,
            verifier: verifier.ok_or("--verifier is required")?,
            python: python.ok_or("--python is required")?,
            installer_root: installer_root.ok_or("--installer-root is required")?,
            output_root: output_root.ok_or("--output-root is required")?,
            materialize_raw,
        })
    }
}

fn next_value(
    values: &mut impl Iterator<Item = OsString>,
    flag: &OsString,
) -> Result<OsString, String> {
    values
        .next()
        .ok_or_else(|| format!("missing value for {}", flag.to_string_lossy()))
}

#[derive(Serialize)]
struct SuccessReport {
    schema: &'static str,
    source_deleted_before_python: bool,
    target_model: &'static str,
    installer_policy: &'static str,
    canonical_view_sha256: String,
    canonical_receipt_sha256: String,
    source_sha256: String,
    archive_tree_sha256: String,
    artifact_sha256: String,
    install_plan_sha256: String,
    realization_sha256: String,
    installed_files: usize,
    raw_materialized: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !cfg!(target_os = "linux") {
        return Err("the first packaged WheelSource target requires Linux".into());
    }
    let args = Args::parse().map_err(|detail| {
        format!(
            "{detail}\n{}",
            concat!(
                "usage: pypa_installer_handoff \\\n",
                "  --consume-wheel FILE --worker-manifest ABSOLUTE_PATH --verifier FILE \\\n",
                "  --python /usr/bin/python3 --installer-root DIR --output-root NEW_DIR \\\n",
                "  [--materialize-raw NEW_DIR]"
            )
        )
    })?;
    require_regular_file(&args.wheel, "wheel")?;
    require_regular_file(&args.verifier, "identity verifier")?;
    require_real_directory(&args.installer_root, "installer root")?;
    require_absent(&args.output_root, "output root")?;
    if let Some(raw) = &args.materialize_raw {
        require_absent(raw, "raw materialization root")?;
        if raw == &args.output_root {
            return Err("raw materialization and installer output roots must differ".into());
        }
    }
    let filename = args
        .wheel
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("wheel filename must be UTF-8")?
        .to_owned();
    let worker = LinuxWorker::load_from_manifest(&args.worker_manifest)?;
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
    let outcome = apply_supervised(
        Request {
            source: Source::Path(&args.wheel),
            policy: &policy,
            dest: args.materialize_raw.as_deref(),
        },
        &options,
        &worker,
    )?;
    if outcome.rejected() {
        return Err(format!("wheel admission failed: {:?}", outcome.view.findings).into());
    }
    if args.materialize_raw.is_some() && !outcome.wrote() {
        return Err("raw materialization was requested but did not commit".into());
    }

    let canonical = outcome
        .canonical_evidence()
        .map_err(|finding| format!("canonical evidence failed: {}", finding.detail))?;
    let private = PrivateRoot::create()?;
    let view_path = private.path().join("view.json");
    let receipt_path = private.path().join("receipt.json");
    write_new(&view_path, &canonical.view_bytes)?;
    write_new(&receipt_path, &canonical.receipt_bytes)?;
    let mut verifier_command = Command::new(&args.verifier);
    configure_process_group(&mut verifier_command);
    let mut verifier = verifier_command
        .arg("evidence")
        .arg("--view")
        .arg(&view_path)
        .arg("--receipt")
        .arg(&receipt_path)
        .arg("--source")
        .arg(&args.wheel)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let status = wait_for_child(&mut verifier, "independent evidence verifier")?;
    if !status.success() {
        return Err(format!("independent evidence verification failed with {status}").into());
    }

    let evaluation = evaluate_wheel(
        &filename,
        outcome
            .verified_archive()
            .ok_or("admitted wheel did not expose verified authority")?,
        WheelLimits::default(),
    );
    let WheelEvaluation::Admitted {
        artifact,
        plan,
        identities,
        ..
    } = evaluation
    else {
        return Err(format!("wheel evaluation did not admit the artifact: {evaluation:?}").into());
    };
    let archive = outcome
        .into_verified_archive()
        .ok_or("verified wheel authority disappeared")?;
    let prepared = prepare_wheel_source(
        &private,
        &archive,
        &artifact,
        &plan,
        &identities,
        &canonical.receipt_digest,
    )?;
    drop(archive);

    fs::remove_file(&args.wheel)?;
    if args.wheel.exists() || fs::symlink_metadata(&args.wheel).is_ok() {
        return Err("consumed wheel remained accessible before Python started".into());
    }
    let installation = prepared.install(
        &args.python,
        &args.installer_root,
        &args.output_root,
        &plan,
        &artifact,
    )?;

    let report = SuccessReport {
        schema: "sealr.pypa-wheel-source-example.v1",
        source_deleted_before_python: true,
        target_model: TARGET_MODEL,
        installer_policy: INSTALLER_POLICY,
        canonical_view_sha256: canonical.view_digest,
        canonical_receipt_sha256: canonical.receipt_digest,
        source_sha256: identities.source_sha256,
        archive_tree_sha256: identities.archive_tree_sha256,
        artifact_sha256: identities.artifact_sha256,
        install_plan_sha256: identities.install_plan_sha256,
        realization_sha256: installation.realization_sha256,
        installed_files: installation.files.len(),
        raw_materialized: args.materialize_raw.is_some(),
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{label} must be a regular file, not a link: {}",
            path.display()
        )
        .into());
    }
    Ok(())
}

fn require_real_directory(path: &Path, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} must be a real directory: {}", path.display()).into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let effective_uid = unsafe { libc::geteuid() };
        let mode = metadata.permissions().mode();
        let trusted_owner = metadata.uid() == 0 || metadata.uid() == effective_uid;
        let writable_by_others = mode & 0o022 != 0;
        let trusted_sticky = metadata.uid() == 0 && mode & 0o1000 != 0;
        if !trusted_owner || writable_by_others && !trusted_sticky {
            return Err(format!(
                "{label} permits untrusted namespace mutation: {}",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

fn require_absent(path: &Path, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() || fs::symlink_metadata(path).is_ok() {
        return Err(format!("{label} must not already exist: {}", path.display()).into());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    require_real_directory(parent, &format!("{label} parent"))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut output = OpenOptions::new().create_new(true).write(true).open(path)?;
    output.write_all(bytes)?;
    output.flush()?;
    Ok(())
}
