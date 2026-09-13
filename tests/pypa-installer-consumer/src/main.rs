use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use sealr::wheel::{
    evaluate_wheel, realize_identity, ExecutableDisposition, InstallScheme, InstallTransform,
    RealizedOutput, RecordBinding, WheelArtifactIR, WheelEvaluation, WheelIdentities,
    WheelInstallPlan, WheelLimits,
};
use sealr::{
    apply_with_options, ApplyOptions, MemberKind, MemberReadErrorKind, Policy, Request, Source,
    VerifiedArchive, ZipInterpretationProfile,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const BRIDGE_SCHEMA: &str = "sealr.pypa-wheel-source.v1";
const BRIDGE_ID: &str = "pypa-installer-1.0.1-wheel-source";
const REPORT_SCHEMA: &str = "sealr.pypa-wheel-source-report.v1";
const INSTALLER_VERSION: &str = "1.0.1";
const INSTALLER_WHEEL_SHA256: &str =
    "011d045df8b954ced7dde3a7e42ae4418da40ecda7990f2d11d5ed7c146fd98b";
const TARGET_MODEL: &str = "pypa-installer-1.0.1-linux-posix";
const INSTALLER_POLICY: &str = "separate-roots-no-bytecode-no-overwrite-v1";
const MAX_MEMBER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DESCRIPTOR_BYTES: usize = 16 * 1024 * 1024;
const PYTHON_INTERPRETER: &str = "/usr/bin/python3";
const BRIDGE_TIMEOUT: Duration = Duration::from_secs(120);
const CONTROLLED_IDENTITY_PINS: [&str; 5] = [
    "078364afdeda960f1e0df0959d9cafcdb067b2c3c8c2999c0cea7cd521c466ec",
    "7336763b06639d2cc5a1ee004adf6c42a0a15e6ace846e0457299f3010011f82",
    "986f82074b5ac802253ba317579bf1500a28947e022b0c27581180ea05004c55",
    "54b263d0c136a522fa08e0b5d582a5bdfb5203af970e5a84c786ef549a19dac8",
    "5978f3ebecb5a2ff85567240a2a659c01c4212e0a770ca8ba4d13b6bbe97f228",
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
    bridge: PathBuf,
    controlled_wheel_output: PathBuf,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut values = std::env::args_os().skip(1);
        let mut python = None;
        let mut installer_root = None;
        let mut verifier = None;
        let mut real_wheel = None;
        let mut bridge = None;
        let mut controlled_wheel_output = None;
        while let Some(flag) = values.next() {
            let slot = match flag.to_str() {
                Some("--python") => &mut python,
                Some("--installer-root") => &mut installer_root,
                Some("--verifier") => &mut verifier,
                Some("--real-wheel") => &mut real_wheel,
                Some("--bridge") => &mut bridge,
                Some("--controlled-wheel-output") => &mut controlled_wheel_output,
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
            bridge: bridge.ok_or("--bridge is required")?,
            controlled_wheel_output: controlled_wheel_output
                .ok_or("--controlled-wheel-output is required")?,
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
    adapter: &'static str,
    installer_version: &'static str,
    installer_wheel_sha256: &'static str,
    canonical_receipt_sha256: &'a str,
    artifact_sha256: &'a str,
    install_plan_sha256: &'a str,
    distribution: &'a str,
    version: &'a str,
    dist_info_dir: &'a str,
    data_dir: String,
    interpreter: &'static str,
    target_model: &'static str,
    installer_policy: &'static str,
    members: Vec<BridgeMember>,
}

#[derive(Serialize)]
struct BridgeMember {
    index: usize,
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
    adapter: String,
    installer_version: String,
    manifest_sha256: String,
    canonical_receipt_sha256: String,
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
    negative_gates: [&'static str; 8],
    claims: [&'static str; 3],
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !cfg!(target_os = "linux") {
        return Err("this first adopter target model is Linux POSIX only".into());
    }
    let args = Args::parse().map_err(|detail| {
        format!(
            "{detail}\nusage: sealr-pypa-installer-consumer --python PATH \\\n             --installer-root DIR --verifier PATH --real-wheel FILE \\\n             --bridge FILE --controlled-wheel-output NEW_FILE"
        )
    })?;
    for (label, path) in [
        ("Python interpreter", &args.python),
        ("installer import root", &args.installer_root),
        ("identity verifier", &args.verifier),
        ("real wheel", &args.real_wheel),
        ("packaged WheelSource bridge", &args.bridge),
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
    write_controlled_fixture(&args.controlled_wheel_output, &fixture)?;
    let controlled = run_case(
        "controlled",
        "demo-1.0-py3-none-any.whl",
        &fixture,
        &args,
        true,
    )?;
    assert_case_pins("controlled", &controlled, CONTROLLED_IDENTITY_PINS, 12)?;
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
            "raw-manifest-tamper-denied-before-install",
            "closed-schema-tamper-denied-before-install",
            "receipt-argument-tamper-denied-before-install",
            "unexpected-installer-directory-denied-before-install",
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

fn write_controlled_fixture(
    path: &Path,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if path.file_name().and_then(|name| name.to_str()) != Some("demo-1.0-py3-none-any.whl") {
        return Err("--controlled-wheel-output must end in demo-1.0-py3-none-any.whl".into());
    }
    let parent = path
        .parent()
        .ok_or("controlled wheel output requires a parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("controlled wheel output parent must be a real directory".into());
    }
    let mut output = OpenOptions::new().create_new(true).write(true).open(path)?;
    output.write_all(bytes)?;
    output.flush()?;
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
    if label == "controlled" || label == "controlled-repeat" {
        validate_controlled_reads(&archive)?;
    }
    fs::remove_file(&source)?;
    if source.exists() {
        return Err("source wheel remained available after removal".into());
    }

    if test_tamper {
        let tampered = temp.path().join("tampered-bridge");
        let descriptor = stage_bridge(
            &tampered,
            &archive,
            &artifact,
            &plan,
            &identities,
            &canonical.receipt_digest,
        )?;
        let first_blob = first_blob_path(&descriptor.manifest_path)?;
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
        require_no_install_effects(&descriptor)?;

        let descriptor_tampered = temp.path().join("tampered-descriptor-bridge");
        let descriptor = stage_bridge(
            &descriptor_tampered,
            &archive,
            &artifact,
            &plan,
            &identities,
            &canonical.receipt_digest,
        )?;
        tamper_descriptor(&descriptor.manifest_path)?;
        let output = invoke_bridge(args, &descriptor)?;
        if output.status.success() {
            return Err("tampered handoff descriptor was accepted".into());
        }
        require_no_install_effects(&descriptor)?;

        let schema_tampered = temp.path().join("schema-tampered-bridge");
        let mut descriptor = stage_bridge(
            &schema_tampered,
            &archive,
            &artifact,
            &plan,
            &identities,
            &canonical.receipt_digest,
        )?;
        add_unknown_manifest_key(&descriptor.manifest_path)?;
        descriptor.manifest_sha256 = hex_sha256(&fs::read(&descriptor.manifest_path)?);
        let output = invoke_bridge(args, &descriptor)?;
        if output.status.success() {
            return Err("unknown handoff manifest key was accepted".into());
        }
        require_no_install_effects(&descriptor)?;

        let receipt_tampered = temp.path().join("receipt-tampered-bridge");
        let mut descriptor = stage_bridge(
            &receipt_tampered,
            &archive,
            &artifact,
            &plan,
            &identities,
            &canonical.receipt_digest,
        )?;
        descriptor.receipt_sha256 = "0".repeat(64);
        let output = invoke_bridge(args, &descriptor)?;
        if output.status.success() {
            return Err("wrong out-of-band canonical receipt digest was accepted".into());
        }
        require_no_install_effects(&descriptor)?;

        let unexpected_tree = temp.path().join("unexpected-installer-tree-bridge");
        let descriptor = stage_bridge(
            &unexpected_tree,
            &archive,
            &artifact,
            &plan,
            &identities,
            &canonical.receipt_digest,
        )?;
        let unexpected_directory = args.installer_root.join("sealr-unexpected-empty-directory");
        fs::create_dir(&unexpected_directory)?;
        let output_result = invoke_bridge(args, &descriptor);
        fs::remove_dir(&unexpected_directory)?;
        let output = output_result?;
        if output.status.success() {
            return Err("unexpected empty installer directory was accepted".into());
        }
        require_no_install_effects(&descriptor)?;
    }

    let bridge = temp.path().join("bridge");
    let descriptor = stage_bridge(
        &bridge,
        &archive,
        &artifact,
        &plan,
        &identities,
        &canonical.receipt_digest,
    )?;
    let output = invoke_bridge(args, &descriptor)?;
    require_success("PyPA installer bridge", &output)?;
    if source.exists() {
        return Err("PyPA bridge recreated or retained the source wheel".into());
    }
    let report: BridgeReport = serde_json::from_slice(&fs::read(&descriptor.report_path)?)?;
    if report.schema != REPORT_SCHEMA
        || report.adapter != BRIDGE_ID
        || report.installer_version != INSTALLER_VERSION
        || report.manifest_sha256 != descriptor.manifest_sha256
        || report.canonical_receipt_sha256 != canonical.receipt_digest
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

    let mut installed = enumerate_installation(&descriptor.output_root)?;
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

struct PreparedBridge {
    manifest_path: PathBuf,
    manifest_sha256: String,
    receipt_sha256: String,
    output_root: PathBuf,
    report_path: PathBuf,
}

fn stage_bridge(
    root: &Path,
    archive: &VerifiedArchive,
    artifact: &WheelArtifactIR,
    plan: &WheelInstallPlan,
    identities: &WheelIdentities,
    receipt_sha256: &str,
) -> Result<PreparedBridge, Box<dyn std::error::Error>> {
    if root.exists() || fs::symlink_metadata(root).is_ok() {
        return Err("bridge staging root already exists".into());
    }
    fs::create_dir(root)?;
    let blobs = root.join("members");
    fs::create_dir(&blobs)?;
    let records = artifact
        .record
        .iter()
        .map(|record| (record.path.as_str(), record))
        .collect::<BTreeMap<_, _>>();
    let record_path = format!("{}/RECORD", artifact.dist_info_root);
    let signature_paths = [format!("{record_path}.jws"), format!("{record_path}.p7s")];
    let mut total = 0_u64;
    let mut preflight = Vec::new();
    for (index, member) in archive.members().iter().enumerate() {
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
        let record = records.get(member.canonical_path.as_str()).copied();
        if record.is_none()
            && !signature_paths
                .iter()
                .any(|path| path == &member.canonical_path)
        {
            return Err("verified member is absent from bound RECORD".into());
        }
        preflight.push((index, member, size, record));
    }

    let mut members = Vec::new();
    for (index, member, size, record) in preflight {
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
        let executable = member
            .container_facts()
            .ok_or("wheel member lacks container facts")?
            .unix_regular_executable();
        let blob = format!("{index:06}.bin");
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(blobs.join(&blob))?;
        output.write_all(&bytes)?;
        output.flush()?;
        let (record_hash, record_size) = match record {
            Some(record) => (
                record_hash(record)?,
                record
                    .size
                    .map_or_else(String::new, |value| value.to_string()),
            ),
            None => (String::new(), String::new()),
        };
        members.push(BridgeMember {
            index,
            path: member.canonical_path.clone(),
            blob,
            sha256: digest.to_owned(),
            size,
            record_hash,
            record_size,
            executable,
        });
    }
    let data_dir = artifact.data_root.clone().unwrap_or_else(|| {
        format!(
            "{}-{}.data",
            artifact.filename.normalized_distribution, artifact.filename.normalized_version
        )
    });
    let descriptor = BridgeDescriptor {
        schema: BRIDGE_SCHEMA,
        adapter: BRIDGE_ID,
        installer_version: INSTALLER_VERSION,
        installer_wheel_sha256: INSTALLER_WHEEL_SHA256,
        canonical_receipt_sha256: receipt_sha256,
        artifact_sha256: &identities.artifact_sha256,
        install_plan_sha256: &identities.install_plan_sha256,
        distribution: &artifact.filename.distribution,
        version: &artifact.filename.version,
        dist_info_dir: &artifact.dist_info_root,
        data_dir,
        interpreter: PYTHON_INTERPRETER,
        target_model: TARGET_MODEL,
        installer_policy: INSTALLER_POLICY,
        members,
    };
    if plan.artifact_sha256() != identities.artifact_sha256 {
        return Err("wheel plan and artifact identity disagree".into());
    }
    let mut encoded = serde_json::to_vec(&descriptor)?;
    encoded.push(b'\n');
    if encoded.len() > MAX_DESCRIPTOR_BYTES {
        return Err("bridge descriptor exceeds its byte cap".into());
    }
    let descriptor_path = root.join("manifest.json");
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&descriptor_path)?;
    output.write_all(&encoded)?;
    output.flush()?;
    Ok(PreparedBridge {
        manifest_path: descriptor_path,
        manifest_sha256: hex_sha256(&encoded),
        receipt_sha256: receipt_sha256.to_owned(),
        output_root: root.join("install"),
        report_path: root.join("report.json"),
    })
}

fn invoke_bridge(
    args: &Args,
    descriptor: &PreparedBridge,
) -> Result<Output, Box<dyn std::error::Error>> {
    let mut child = Command::new(&args.python)
        .arg("-I")
        .arg(&args.bridge)
        .arg(&descriptor.manifest_path)
        .arg(&descriptor.manifest_sha256)
        .arg(&descriptor.receipt_sha256)
        .arg(&args.installer_root)
        .arg(&descriptor.output_root)
        .arg(&descriptor.report_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + BRIDGE_TIMEOUT;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let output = child.wait_with_output()?;
            return Err(format!(
                "PyPA installer bridge exceeded its {}-second deadline; stderr:\n{}",
                BRIDGE_TIMEOUT.as_secs(),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
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
    *value
        .get_mut("artifact_sha256")
        .ok_or("descriptor artifact identity was unavailable")? =
        serde_json::Value::String("0".repeat(64));
    *value
        .get_mut("install_plan_sha256")
        .ok_or("descriptor plan identity was unavailable")? =
        serde_json::Value::String("1".repeat(64));
    fs::write(descriptor, serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}

fn add_unknown_manifest_key(descriptor: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(descriptor)?)?;
    value
        .as_object_mut()
        .ok_or("handoff manifest is not an object")?
        .insert("unknown".to_owned(), serde_json::Value::Bool(true));
    fs::write(descriptor, serde_json::to_vec(&value)?)?;
    Ok(())
}

fn require_no_install_effects(
    descriptor: &PreparedBridge,
) -> Result<(), Box<dyn std::error::Error>> {
    for (label, path) in [
        ("output root", &descriptor.output_root),
        ("report", &descriptor.report_path),
    ] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(format!(
                    "rejected handoff created its {label}: {}",
                    path.display()
                )
                .into())
            }
        }
    }
    Ok(())
}

fn enumerate_installation(root: &Path) -> Result<Vec<InstalledFile>, Box<dyn std::error::Error>> {
    let root_metadata = fs::symlink_metadata(root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err("installer output root is not a real directory".into());
    }
    validate_scheme_roots(root)?;
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
                require_single_link(&metadata, &entry.path())?;
                let entry_path = entry.path();
                let relative_path = entry_path
                    .strip_prefix(&scheme_root)?
                    .to_str()
                    .ok_or("installed output path is not UTF-8")?
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

#[cfg(unix)]
fn require_single_link(
    metadata: &fs::Metadata,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::MetadataExt;

    if metadata.nlink() != 1 {
        return Err(format!("installation contains a hard link: {}", path.display()).into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_single_link(
    _metadata: &fs::Metadata,
    _path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn validate_scheme_roots(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let expected = ["purelib", "platlib", "scripts", "headers", "data"]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "installer output root contains a non-directory entry: {}",
                path.display()
            )
            .into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "installer output root contains a non-UTF-8 scheme name")?;
        if !observed.insert(name) {
            return Err("installer output root contains duplicate scheme names".into());
        }
    }
    if observed != expected {
        return Err("installer output root disagrees with the five exact scheme roots".into());
    }
    Ok(())
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

fn scheme_name(value: &InstallScheme) -> Result<&'static str, Box<dyn std::error::Error>> {
    match value {
        InstallScheme::Purelib => Ok("purelib"),
        InstallScheme::Platlib => Ok("platlib"),
        InstallScheme::Scripts => Ok("scripts"),
        InstallScheme::Headers => Ok("headers"),
        InstallScheme::Data => Ok("data"),
        _ => Err("wheel plan contains an unsupported future install scheme".into()),
    }
}

fn validate_installed_targets(
    artifact: &WheelArtifactIR,
    plan: &WheelInstallPlan,
    installed: &[InstalledFile],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut expected = BTreeMap::new();
    for entry in plan.entries() {
        let key = (
            scheme_name(&entry.scheme)?.to_owned(),
            entry.relative_path.clone(),
        );
        if expected
            .insert(key, expected_executable(&entry.executable)?)
            .is_some()
        {
            return Err("wheel plan contains a duplicate output".into());
        }
    }
    let record_scheme = if artifact.wheel.root_is_purelib {
        "purelib"
    } else {
        "platlib"
    };
    expected.insert(
        (
            record_scheme.to_owned(),
            format!("{}/RECORD", artifact.dist_info_root),
        ),
        false,
    );
    let mut actual = BTreeSet::new();
    for file in installed {
        let key = (file.scheme.clone(), file.relative_path.clone());
        let Some(executable) = expected.get(&key) else {
            return Err(format!(
                "installation produced an unexpected output: {}/{}",
                file.scheme, file.relative_path
            )
            .into());
        };
        if file.executable != *executable {
            return Err(format!(
                "installed executable mode disagrees for {}/{}",
                file.scheme, file.relative_path
            )
            .into());
        }
        if !actual.insert(key) {
            return Err("installation report contains a duplicate output".into());
        }
    }
    if actual != expected.keys().cloned().collect::<BTreeSet<_>>() {
        return Err("installed paths disagree with the complete plan plus final RECORD".into());
    }
    Ok(())
}

fn expected_executable(
    disposition: &ExecutableDisposition,
) -> Result<bool, Box<dyn std::error::Error>> {
    match disposition {
        ExecutableDisposition::NotExecutable => Ok(false),
        ExecutableDisposition::SourceExecutable | ExecutableDisposition::GeneratedWrapper => {
            Ok(true)
        }
        _ => Err("wheel plan contains an unsupported future executable disposition".into()),
    }
}

fn validate_controlled_reads(
    archive: &VerifiedArchive,
) -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (
            "demo-1.0.data/scripts/demo-script",
            [b"#!python\nprint('deflated')\n".as_slice(), &[b'd'; 2048]].concat(),
            8_u16,
        ),
        (
            "demo-1.0.data/scripts/demo-stored",
            [b"#!python\nprint('stored')\n".as_slice(), &[b's'; 2048]].concat(),
            0_u16,
        ),
    ];
    let cloned = archive.clone();
    for (path, expected, method) in cases {
        let observed_method = archive
            .member(path)
            .and_then(|member| member.zip_evidence())
            .ok_or("controlled member lacks ZIP evidence")?
            .method;
        if observed_method != method {
            return Err(format!("controlled codec evidence changed for {path}").into());
        }
        let size = expected.len();
        for cap in [0, 9, 1024, size, size + 1] {
            let prefix = archive.read_member_prefix(path, cap)?;
            if prefix != expected[..size.min(cap)] {
                return Err(format!("verified prefix disagrees at cap {cap} for {path}").into());
            }
        }
        if archive.read_member(path, size as u64)? != expected {
            return Err(format!("verified full read disagrees for {path}").into());
        }
        let error = archive.read_member(path, (size - 1) as u64).unwrap_err();
        if error.kind() != MemberReadErrorKind::LimitExceeded {
            return Err(format!(
                "one-under full-read cap returned {:?} for {path}",
                error.kind()
            )
            .into());
        }
        if cloned.read_member_prefix(path, 1024)? != expected[..1024] {
            return Err(format!("cloned verified authority changed prefix bytes for {path}").into());
        }
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
            "demo-stored",
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
        [b"#!python\nprint('deflated')\n".as_slice(), &[b'd'; 2048]].concat(),
    );
    files.insert(
        "demo-1.0.data/scripts/demo-stored",
        [b"#!python\nprint('stored')\n".as_slice(), &[b's'; 2048]].concat(),
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
    files.insert(
        "demo-1.0.dist-info/RECORD.jws",
        b"repository-signature-fixture".to_vec(),
    );

    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        for (path, bytes) in files {
            let permissions = if path.ends_with("demo-script") || path.ends_with("demo-stored") {
                0o100755
            } else {
                0o100644
            };
            let options = SimpleFileOptions::default()
                .compression_method(if path.ends_with("demo-stored") {
                    CompressionMethod::Stored
                } else {
                    CompressionMethod::Deflated
                })
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
