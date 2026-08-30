use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sealr::wheel::{
    evaluate_wheel, realize_identity, ExecutableDisposition, InstallScheme, InstallTransform,
    RealizedOutput, RecordBinding, WheelArtifactIR, WheelEvaluation, WheelIdentities,
    WheelInstallPlan, WheelLimits,
};
use sealr::{
    apply_with_options, ApplyOptions, MemberKind, Policy, Request, Source, VerifiedArchive,
    ZipInterpretationProfile,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const BRIDGE_SCHEMA: &str = "sealr.pypa-adopter.v1";
const BRIDGE_ID: &str = "pypa-installer-1.0.1-wheel-source";
const REPORT_SCHEMA: &str = "sealr.pypa-adopter-report.v1";
const INSTALLER_VERSION: &str = "1.0.1";
const INSTALLER_WHEEL_SHA256: &str =
    "011d045df8b954ced7dde3a7e42ae4418da40ecda7990f2d11d5ed7c146fd98b";
const TARGET_MODEL: &str = "pypa-installer-1.0.1-linux-posix";
const INSTALLER_POLICY: &str = "separate-roots-no-bytecode-no-overwrite-v1";
const MAX_MEMBER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DESCRIPTOR_BYTES: usize = 16 * 1024 * 1024;
const PYTHON_INTERPRETER: &str = "/usr/bin/python3";
const CONTROLLED_IDENTITY_PINS: [&str; 5] = [
    "23619aae41ab794474aed01cb6e9877f0c1f68c21d135464b1c3f276168bc5be",
    "811ac7b1dd594500651918e41260274ed8b380fffd28736516c6f39c00091e34",
    "767126fa9683ee3b3a924b495e1380066695c171847f63cb3d761b3e0ca1eb06",
    "75c7b1e1906da096806aa984c4ef880181b24e5b9c1d635b7ffd33891a315087",
    "fee4c452e95ab3e2c27fcaa5acacd610c874af5490af7f7ab7364549f7bbc008",
];
const REAL_INSTALLER_IDENTITY_PINS: [&str; 5] = [
    INSTALLER_WHEEL_SHA256,
    "2502582bc7a6a4361755eaa4cce1f81446718dbe69363c51392882f7f4150c05",
    "225bee7abfb0beb5d7468904c246169919522a5f49a69d15fd365bcd5438e00b",
    "e44af3f5715c86d200b58b77183c182af2effd93956f8244a68439ef6aeb4f74",
    "df8de1bfe7f54ab5b61f2287008c362dc6c62d01369ae370ac919f44ebef8f95",
];

#[derive(Debug)]
struct Args {
    python: PathBuf,
    installer_root: PathBuf,
    verifier: PathBuf,
    real_wheel: PathBuf,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut values = std::env::args_os().skip(1);
        let mut python = None;
        let mut installer_root = None;
        let mut verifier = None;
        let mut real_wheel = None;
        while let Some(flag) = values.next() {
            let slot = match flag.to_str() {
                Some("--python") => &mut python,
                Some("--installer-root") => &mut installer_root,
                Some("--verifier") => &mut verifier,
                Some("--real-wheel") => &mut real_wheel,
                _ => return Err(format!("unknown argument: {}", flag.to_string_lossy())),
            };
            if slot.is_some() {
                return Err(format!("duplicate argument: {}", flag.to_string_lossy()));
            }
            *slot = Some(PathBuf::from(values.next().ok_or_else(|| {
                format!("missing value for {}", flag.to_string_lossy())
            })?));
        }
        Ok(Self {
            python: python.ok_or("--python is required")?,
            installer_root: installer_root.ok_or("--installer-root is required")?,
            verifier: verifier.ok_or("--verifier is required")?,
            real_wheel: real_wheel.ok_or("--real-wheel is required")?,
        })
    }
}

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "sealr-pypa-adopter-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Serialize)]
struct BridgeDescriptor<'a> {
    schema: &'static str,
    bridge: &'static str,
    installer_version: &'static str,
    installer_wheel_sha256: &'static str,
    interpreter: String,
    target_model: &'static str,
    installer_policy: &'static str,
    artifact: &'a WheelArtifactIR,
    plan: &'a WheelInstallPlan,
    identities: &'a WheelIdentities,
    members: Vec<BridgeMember>,
}

#[derive(Serialize)]
struct BridgeMember {
    member_index: usize,
    path: String,
    blob: String,
    sha256: String,
    size: u64,
    record_hash: String,
    record_size: String,
    executable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct InstalledFile {
    scheme: String,
    relative_path: String,
    sha256: String,
    size: u64,
    executable: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeReport {
    schema: String,
    installer_version: String,
    wheel_open_audit: String,
    repeatable_member_reads: usize,
    installed_files: Vec<InstalledFile>,
}

#[derive(Serialize)]
struct CaseReport {
    filename: String,
    source_sha256: String,
    archive_tree_sha256: String,
    artifact_sha256: String,
    install_plan_sha256: String,
    canonical_view_sha256: String,
    canonical_receipt_sha256: String,
    realization_sha256: String,
    installed_files: usize,
}

#[derive(Serialize)]
struct ConformanceReport {
    schema: &'static str,
    installer_version: &'static str,
    controlled: CaseReport,
    real_distribution: CaseReport,
    negative_gates: [&'static str; 5],
    claims: [&'static str; 3],
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !cfg!(target_os = "linux") {
        return Err("this first adopter target model is Linux POSIX only".into());
    }
    let args = Args::parse().map_err(|detail| {
        format!(
            "{detail}\nusage: sealr-pypa-installer-consumer --python PATH \\\n+             --installer-root DIR --verifier PATH --real-wheel FILE"
        )
    })?;
    for (label, path) in [
        ("Python interpreter", &args.python),
        ("installer import root", &args.installer_root),
        ("identity verifier", &args.verifier),
        ("real wheel", &args.real_wheel),
    ] {
        if !path.exists() {
            return Err(format!("{label} does not exist: {}", path.display()).into());
        }
    }
    if args.python != Path::new(PYTHON_INTERPRETER) {
        return Err(format!(
            "--python must select the pinned first target interpreter {PYTHON_INTERPRETER}"
        )
        .into());
    }
    if args.real_wheel.file_name().and_then(|name| name.to_str())
        != Some("installer-1.0.1-py3-none-any.whl")
    {
        return Err("--real-wheel must name installer-1.0.1-py3-none-any.whl".into());
    }
    let real_metadata = fs::symlink_metadata(&args.real_wheel)?;
    if real_metadata.file_type().is_symlink() || !real_metadata.is_file() {
        return Err("--real-wheel must be a regular file, not a link".into());
    }
    let real_bytes = fs::read(&args.real_wheel)?;
    if hex_sha256(&real_bytes) != INSTALLER_WHEEL_SHA256 {
        return Err("real installer wheel digest disagrees with the pinned distribution".into());
    }
    fs::remove_file(&args.real_wheel)?;
    if args.real_wheel.exists() {
        return Err("the pinned input wheel remained accessible after authentication".into());
    }

    prove_evaluator_denials()?;
    let fixture = controlled_wheel(false)?;
    let controlled = run_case(
        "controlled",
        "demo-1.0-py3-none-any.whl",
        &fixture,
        &args,
        true,
    )?;
    assert_case_pins("controlled", &controlled, CONTROLLED_IDENTITY_PINS, 10)?;
    let controlled_repeat = run_case(
        "controlled-repeat",
        "demo-1.0-py3-none-any.whl",
        &fixture,
        &args,
        false,
    )?;
    if semantic_case_identity(&controlled) != semantic_case_identity(&controlled_repeat) {
        return Err(
            "repeated controlled installation changed a wheel or realization identity".into(),
        );
    }
    let real_distribution = run_case(
        "real-installer",
        "installer-1.0.1-py3-none-any.whl",
        &real_bytes,
        &args,
        false,
    )?;
    assert_case_pins(
        "real installer",
        &real_distribution,
        REAL_INSTALLER_IDENTITY_PINS,
        23,
    )?;
    let report = ConformanceReport {
        schema: "sealr.pypa-adopter-conformance.v1",
        installer_version: INSTALLER_VERSION,
        controlled,
        real_distribution,
        negative_gates: [
            "lying-record-denied-before-bridge",
            "traversal-denied-before-capability",
            "member-tamper-denied-before-install",
            "descriptor-tamper-denied-before-install",
            "source-removed-before-python",
        ],
        claims: [
            "repository-conformance-kit",
            "linux-posix-target-model-only",
            "not-independent-external-adoption",
        ],
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn run_case(
    label: &str,
    filename: &str,
    bytes: &[u8],
    args: &Args,
    test_tamper: bool,
) -> Result<CaseReport, Box<dyn std::error::Error>> {
    let temp = TestDir::new()?;
    let source = temp.path().join(filename);
    fs::write(&source, bytes)?;
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
    let outcome = apply_with_options(
        Request {
            source: Source::Path(&source),
            policy: &policy,
            dest: None,
        },
        &options,
    );
    if outcome.rejected() {
        return Err(format!("{label} admission failed: {:?}", outcome.view.findings).into());
    }

    let canonical = outcome
        .canonical_evidence()
        .map_err(|finding| format!("{label} canonical evidence failed: {}", finding.detail))?;
    let evidence = temp.path().join("evidence");
    fs::create_dir(&evidence)?;
    let view = evidence.join("view.json");
    let receipt = evidence.join("receipt.json");
    fs::write(&view, &canonical.view_bytes)?;
    fs::write(&receipt, &canonical.receipt_bytes)?;
    let verification = Command::new(&args.verifier)
        .arg("evidence")
        .arg("--view")
        .arg(&view)
        .arg("--receipt")
        .arg(&receipt)
        .arg("--source")
        .arg(&source)
        .output()?;
    require_success("independent canonical evidence verification", &verification)?;

    let evaluation = evaluate_wheel(
        filename,
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
        return Err(format!("{label} public wheel evaluation failed: {evaluation:?}").into());
    };
    let archive = outcome
        .into_verified_archive()
        .ok_or("admitted wheel capability disappeared")?;
    fs::remove_file(&source)?;
    if source.exists() {
        return Err("source wheel remained available after removal".into());
    }

    if test_tamper {
        let tampered = temp.path().join("tampered-bridge");
        let descriptor = stage_bridge(
            &tampered,
            &args.python,
            &archive,
            &artifact,
            &plan,
            &identities,
        )?;
        let first_blob = first_blob_path(&descriptor)?;
        let mut data = fs::read(&first_blob)?;
        let first = data
            .first_mut()
            .ok_or("bridge blob was unexpectedly empty")?;
        *first ^= 1;
        fs::write(&first_blob, data)?;
        let output = invoke_bridge(args, &descriptor)?;
        if output.status.success() {
            return Err("tampered verified-member staging was accepted".into());
        }
        if contains_regular_file(&tampered.join("install"))? {
            return Err("tampered staging produced installation effects".into());
        }

        let descriptor_tampered = temp.path().join("tampered-descriptor-bridge");
        let descriptor = stage_bridge(
            &descriptor_tampered,
            &args.python,
            &archive,
            &artifact,
            &plan,
            &identities,
        )?;
        tamper_descriptor(&descriptor)?;
        let output = invoke_bridge(args, &descriptor)?;
        if output.status.success() {
            return Err("tampered handoff descriptor was accepted".into());
        }
        if contains_regular_file(&descriptor_tampered.join("install"))? {
            return Err("tampered descriptor produced installation effects".into());
        }
    }

    let bridge = temp.path().join("bridge");
    let descriptor = stage_bridge(
        &bridge,
        &args.python,
        &archive,
        &artifact,
        &plan,
        &identities,
    )?;
    let output = invoke_bridge(args, &descriptor)?;
    require_success("PyPA installer bridge", &output)?;
    if source.exists() {
        return Err("PyPA bridge recreated or retained the source wheel".into());
    }
    let report: BridgeReport = serde_json::from_slice(&output.stdout)?;
    if report.schema != REPORT_SCHEMA
        || report.installer_version != INSTALLER_VERSION
        || report.wheel_open_audit != "enforced"
        || report.repeatable_member_reads
            != archive
                .members()
                .iter()
                .filter(|member| matches!(member.kind, MemberKind::File))
                .count()
    {
        return Err(format!("bridge report contract disagreement: {report:?}").into());
    }

    let mut installed = enumerate_installation(&bridge.join("install"))?;
    let mut reported = report.installed_files;
    installed.sort();
    reported.sort();
    if installed != reported {
        return Err(format!(
            "independent installed-file enumeration disagrees\nexpected={reported:#?}\nactual={installed:#?}"
        )
        .into());
    }
    validate_installed_targets(&artifact, &plan, &installed)?;
    if label == "controlled" || label == "controlled-repeat" {
        validate_controlled_plan(&plan)?;
    }
    let outputs = installed
        .iter()
        .map(|file| {
            Ok(RealizedOutput::new(
                parse_scheme(&file.scheme)?,
                file.relative_path.clone(),
                file.sha256.clone(),
                file.size,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let realization = realize_identity(&plan, TARGET_MODEL, INSTALLER_POLICY, &outputs)?;
    if realization != realize_identity(&plan, TARGET_MODEL, INSTALLER_POLICY, &outputs)? {
        return Err("wheel realization identity was not repeatable".into());
    }
    let lineage = [
        &identities.source_sha256,
        &identities.archive_tree_sha256,
        &identities.artifact_sha256,
        &identities.install_plan_sha256,
        &realization,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if lineage.len() != 5 {
        return Err(
            "source, tree, artifact, plan, and realization identities are not distinct".into(),
        );
    }

    Ok(CaseReport {
        filename: filename.to_owned(),
        source_sha256: identities.source_sha256,
        archive_tree_sha256: identities.archive_tree_sha256,
        artifact_sha256: identities.artifact_sha256,
        install_plan_sha256: identities.install_plan_sha256,
        canonical_view_sha256: canonical.view_digest,
        canonical_receipt_sha256: canonical.receipt_digest,
        realization_sha256: realization,
        installed_files: installed.len(),
    })
}

fn stage_bridge(
    root: &Path,
    python: &Path,
    archive: &VerifiedArchive,
    artifact: &WheelArtifactIR,
    plan: &WheelInstallPlan,
    identities: &WheelIdentities,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if root.exists() {
        return Err("bridge staging root already exists".into());
    }
    let blobs = root.join("members");
    fs::create_dir_all(&blobs)?;
    let records = artifact
        .record
        .iter()
        .map(|record| (record.path.as_str(), record))
        .collect::<BTreeMap<_, _>>();
    let mut total = 0_u64;
    let mut members = Vec::new();
    for (member_index, member) in archive.members().iter().enumerate() {
        if matches!(member.kind, MemberKind::Directory) {
            continue;
        }
        let size = member
            .actual_uncomp_size
            .ok_or("verified bridge member lacks measured size")?;
        if size > MAX_MEMBER_BYTES {
            return Err(format!("{} exceeds the bridge member cap", member.canonical_path).into());
        }
        total = total
            .checked_add(size)
            .ok_or("bridge member byte total overflowed")?;
        if total > MAX_TOTAL_BYTES {
            return Err("bridge aggregate member cap exceeded".into());
        }
        let bytes = archive.read_member(&member.canonical_path, MAX_MEMBER_BYTES)?;
        if bytes.len() as u64 != size {
            return Err("verified member read disagrees with measured size".into());
        }
        let digest = member
            .content_sha256
            .as_deref()
            .ok_or("verified bridge member lacks SHA-256")?;
        if hex_sha256(&bytes) != digest {
            return Err("verified member bytes disagree with bound SHA-256".into());
        }
        let record = records
            .get(member.canonical_path.as_str())
            .ok_or("verified member is absent from bound RECORD")?;
        let executable = member
            .container_facts()
            .ok_or("wheel member lacks container facts")?
            .unix_regular_executable();
        let blob = format!("{member_index:06}.bin");
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(blobs.join(&blob))?;
        output.write_all(&bytes)?;
        output.flush()?;
        members.push(BridgeMember {
            member_index,
            path: member.canonical_path.clone(),
            blob,
            sha256: digest.to_owned(),
            size,
            record_hash: record_hash(record)?,
            record_size: record
                .size
                .map_or_else(String::new, |value| value.to_string()),
            executable,
        });
    }
    let descriptor = BridgeDescriptor {
        schema: BRIDGE_SCHEMA,
        bridge: BRIDGE_ID,
        installer_version: INSTALLER_VERSION,
        installer_wheel_sha256: INSTALLER_WHEEL_SHA256,
        interpreter: python.to_string_lossy().into_owned(),
        target_model: TARGET_MODEL,
        installer_policy: INSTALLER_POLICY,
        artifact,
        plan,
        identities,
        members,
    };
    let encoded = serde_json::to_vec_pretty(&descriptor)?;
    if encoded.len() > MAX_DESCRIPTOR_BYTES {
        return Err("bridge descriptor exceeds its byte cap".into());
    }
    let descriptor_path = root.join("descriptor.json");
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&descriptor_path)?;
    output.write_all(&encoded)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(descriptor_path)
}

fn invoke_bridge(args: &Args, descriptor: &Path) -> Result<Output, std::io::Error> {
    Command::new(&args.python)
        .arg("-I")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("bridge.py"))
        .arg(descriptor)
        .arg(&args.installer_root)
        .output()
}

fn require_success(label: &str, output: &Output) -> Result<(), Box<dyn std::error::Error>> {
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{label} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

fn first_blob_path(descriptor: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_slice(&fs::read(descriptor)?)?;
    let blob = value
        .get("members")
        .and_then(|members| members.as_array())
        .and_then(|members| members.first())
        .and_then(|member| member.get("blob"))
        .and_then(|blob| blob.as_str())
        .ok_or("descriptor did not contain a first member blob")?;
    Ok(descriptor.parent().unwrap().join("members").join(blob))
}

fn tamper_descriptor(descriptor: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(descriptor)?)?;
    let artifact_identity = value
        .get_mut("plan")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|plan| plan.get_mut("artifact_sha256"))
        .ok_or("descriptor plan artifact identity was unavailable")?;
    *artifact_identity = serde_json::Value::String("0".repeat(64));
    fs::write(descriptor, serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}

fn contains_regular_file(root: &Path) -> Result<bool, std::io::Error> {
    if !root.exists() {
        return Ok(false);
    }
    let mut pending = vec![root.to_owned()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_symlink() || kind.is_file() {
                return Ok(true);
            }
            if kind.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(false)
}

fn enumerate_installation(root: &Path) -> Result<Vec<InstalledFile>, Box<dyn std::error::Error>> {
    let mut outputs = Vec::new();
    for scheme in ["purelib", "platlib", "scripts", "headers", "data"] {
        let scheme_root = root.join(scheme);
        if !scheme_root.is_dir() {
            return Err(format!("installer did not create separate {scheme} root").into());
        }
        let mut pending = vec![scheme_root.clone()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                let metadata = fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink() {
                    return Err(format!(
                        "installation contains a link: {}",
                        entry.path().display()
                    )
                    .into());
                }
                if metadata.is_dir() {
                    pending.push(entry.path());
                    continue;
                }
                if !metadata.is_file() {
                    return Err(format!(
                        "installation contains a non-regular output: {}",
                        entry.path().display()
                    )
                    .into());
                }
                let relative_path = entry
                    .path()
                    .strip_prefix(&scheme_root)?
                    .to_string_lossy()
                    .replace('\\', "/");
                let bytes = fs::read(entry.path())?;
                #[cfg(unix)]
                let executable = {
                    use std::os::unix::fs::PermissionsExt;
                    metadata.permissions().mode() & 0o111 != 0
                };
                #[cfg(not(unix))]
                let executable = false;
                outputs.push(InstalledFile {
                    scheme: scheme.to_owned(),
                    relative_path,
                    sha256: hex_sha256(&bytes),
                    size: bytes.len() as u64,
                    executable,
                });
            }
        }
    }
    Ok(outputs)
}

fn parse_scheme(value: &str) -> Result<InstallScheme, String> {
    match value {
        "purelib" => Ok(InstallScheme::Purelib),
        "platlib" => Ok(InstallScheme::Platlib),
        "scripts" => Ok(InstallScheme::Scripts),
        "headers" => Ok(InstallScheme::Headers),
        "data" => Ok(InstallScheme::Data),
        _ => Err(format!("unknown install scheme: {value}")),
    }
}

fn scheme_name(value: &InstallScheme) -> &'static str {
    match value {
        InstallScheme::Purelib => "purelib",
        InstallScheme::Platlib => "platlib",
        InstallScheme::Scripts => "scripts",
        InstallScheme::Headers => "headers",
        InstallScheme::Data => "data",
        _ => "unsupported",
    }
}

fn validate_installed_targets(
    artifact: &WheelArtifactIR,
    plan: &WheelInstallPlan,
    installed: &[InstalledFile],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut expected = plan
        .entries()
        .iter()
        .map(|entry| {
            (
                scheme_name(&entry.scheme).to_owned(),
                entry.relative_path.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let record_scheme = if artifact.wheel.root_is_purelib {
        "purelib"
    } else {
        "platlib"
    };
    expected.insert((
        record_scheme.to_owned(),
        format!("{}/RECORD", artifact.dist_info_root),
    ));
    let actual = installed
        .iter()
        .map(|file| (file.scheme.clone(), file.relative_path.clone()))
        .collect::<BTreeSet<_>>();
    if actual != expected || installed.len() != expected.len() {
        return Err(format!(
            "installed paths disagree with the complete plan plus final RECORD\nexpected={expected:#?}\nactual={actual:#?}"
        )
        .into());
    }
    Ok(())
}

fn validate_controlled_plan(plan: &WheelInstallPlan) -> Result<(), Box<dyn std::error::Error>> {
    let entries = plan.entries();
    let has = |scheme: InstallScheme, path: &str, transform: InstallTransform| {
        entries.iter().any(|entry| {
            entry.scheme == scheme && entry.relative_path == path && entry.transform == transform
        })
    };
    if !has(InstallScheme::Purelib, "root.txt", InstallTransform::Copy)
        || !has(InstallScheme::Headers, "demo.h", InstallTransform::Copy)
        || !has(
            InstallScheme::Data,
            "share/demo.txt",
            InstallTransform::Copy,
        )
        || !has(
            InstallScheme::Scripts,
            "demo-script",
            InstallTransform::RewritePythonShebang,
        )
        || !has(
            InstallScheme::Scripts,
            "demo-cli",
            InstallTransform::GenerateConsoleWrapper,
        )
        || !entries.iter().any(|entry| {
            entry.relative_path == "demo-script"
                && matches!(entry.executable, ExecutableDisposition::SourceExecutable)
        })
    {
        return Err("controlled fixture did not cover the required install-plan semantics".into());
    }
    Ok(())
}

fn semantic_case_identity(case: &CaseReport) -> (&str, &str, &str, &str, &str, usize) {
    (
        &case.source_sha256,
        &case.archive_tree_sha256,
        &case.artifact_sha256,
        &case.install_plan_sha256,
        &case.realization_sha256,
        case.installed_files,
    )
}

fn assert_case_pins(
    label: &str,
    case: &CaseReport,
    pins: [&str; 5],
    installed_files: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = [
        case.source_sha256.as_str(),
        case.archive_tree_sha256.as_str(),
        case.artifact_sha256.as_str(),
        case.install_plan_sha256.as_str(),
        case.realization_sha256.as_str(),
    ];
    if actual != pins || case.installed_files != installed_files {
        return Err(format!(
            "{label} identity pins changed\nexpected={pins:#?}/{installed_files}\nactual={actual:#?}/{}",
            case.installed_files
        )
        .into());
    }
    Ok(())
}

fn prove_evaluator_denials() -> Result<(), Box<dyn std::error::Error>> {
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
    let lying = controlled_wheel(true)?;
    let lying_outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("demo-1.0-py3-none-any.whl"),
                data: &lying,
            },
            policy: &policy,
            dest: None,
        },
        &options,
    );
    let evaluation = evaluate_wheel(
        "demo-1.0-py3-none-any.whl",
        lying_outcome
            .verified_archive()
            .ok_or("lying RECORD fixture did not reach a verified container")?,
        WheelLimits::default(),
    );
    if !matches!(evaluation, WheelEvaluation::Denied { .. }) {
        return Err(format!("lying RECORD was not denied: {evaluation:?}").into());
    }

    let traversal = traversal_wheel()?;
    let traversal_outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("traversal.whl"),
                data: &traversal,
            },
            policy: &policy,
            dest: None,
        },
        &options,
    );
    if !traversal_outcome.rejected() || traversal_outcome.verified_archive().is_some() {
        return Err("traversal-bearing wheel yielded verified authority".into());
    }
    Ok(())
}

fn controlled_wheel(lying_record: bool) -> Result<Vec<u8>, zip::result::ZipError> {
    let mut files = BTreeMap::new();
    files.insert("demo/__init__.py", b"VALUE = 1\n".to_vec());
    files.insert("root.txt", b"root payload\n".to_vec());
    files.insert(
        "demo-1.0.data/scripts/demo-script",
        b"#!python\nprint('demo')\n".to_vec(),
    );
    files.insert("demo-1.0.data/headers/demo.h", b"#define DEMO 1\n".to_vec());
    files.insert(
        "demo-1.0.data/data/share/demo.txt",
        b"relocated data\n".to_vec(),
    );
    files.insert(
        "demo-1.0.dist-info/WHEEL",
        b"Wheel-Version: 1.0\nGenerator: packaged-adopter-conformance\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n".to_vec(),
    );
    files.insert(
        "demo-1.0.dist-info/METADATA",
        b"Metadata-Version: 2.4\nName: demo\nVersion: 1.0\n\n".to_vec(),
    );
    files.insert(
        "demo-1.0.dist-info/entry_points.txt",
        b"[console_scripts]\ndemo-cli = demo:main\n".to_vec(),
    );
    let mut record = String::new();
    for (path, bytes) in &files {
        record.push_str(path);
        record.push_str(",sha256=");
        if lying_record && *path == "root.txt" {
            record.push_str(&base64url(&[0_u8; 32]));
        } else {
            record.push_str(&base64url(&Sha256::digest(bytes)));
        }
        record.push(',');
        record.push_str(&bytes.len().to_string());
        record.push('\n');
    }
    record.push_str("demo-1.0.dist-info/RECORD,,\n");
    files.insert("demo-1.0.dist-info/RECORD", record.into_bytes());

    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        for (path, bytes) in files {
            let permissions = if path.ends_with("demo-script") {
                0o100755
            } else {
                0o100644
            };
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(permissions);
            writer.start_file(path, options)?;
            writer.write_all(&bytes)?;
        }
        writer.finish()?;
    }
    Ok(cursor.into_inner())
}

fn traversal_wheel() -> Result<Vec<u8>, zip::result::ZipError> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        writer.start_file(
            "../escape",
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
        )?;
        writer.write_all(b"escape")?;
        writer.finish()?;
    }
    Ok(cursor.into_inner())
}

fn record_hash(record: &RecordBinding) -> Result<String, Box<dyn std::error::Error>> {
    let Some(value) = record.sha256.as_deref() else {
        return Ok(String::new());
    };
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("RECORD SHA-256 is not 32-byte hexadecimal".into());
    }
    let mut digest = [0_u8; 32];
    for (index, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        digest[index] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(format!("sha256={}", base64url(&digest)))
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(ALPHABET[((value >> 18) & 63) as usize] as char);
        output.push(ALPHABET[((value >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[((value >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(value & 63) as usize] as char);
        }
    }
    output
}
