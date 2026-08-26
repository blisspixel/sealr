use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use sealr::{apply_with_options, ApplyOptions, Policy, Request, Source, ZipInterpretationProfile};
use sealr_wheel_lab::{
    evaluate_wheel, realize_identity, stage_installer_bridge, InstallScheme, RealizedOutput,
    WheelEvaluation, WheelLimits,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "sealr-wheel-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("test directory");
        Self(path)
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

#[derive(Deserialize)]
struct BridgeReport {
    schema: String,
    installer_version: String,
    repeatable_member_reads: usize,
    actions: Vec<BridgeAction>,
    final_record: BridgeOutput,
    wheel_open_audit: String,
}

#[derive(Deserialize)]
struct BridgeAction {
    scheme: String,
    relative_path: String,
    sha256: String,
    size: u64,
}

#[derive(Deserialize)]
struct BridgeOutput {
    scheme: String,
    relative_path: String,
    sha256: String,
    size: u64,
}

#[test]
fn pypa_installer_consumes_only_verified_staged_members() {
    let Some(python) = std::env::var_os("SEALR_BRIDGE_PYTHON") else {
        eprintln!("skipped: SEALR_BRIDGE_PYTHON is not configured");
        return;
    };
    let Some(installer_pythonpath) = std::env::var_os("SEALR_INSTALLER_PYTHONPATH") else {
        eprintln!("skipped: SEALR_INSTALLER_PYTHONPATH is not configured");
        return;
    };

    let temp = TestDir::new("installer-bridge");
    let original = temp.path().join("demo-1.0-py3-none-any.whl");
    fs::write(&original, bridge_wheel()).expect("write source wheel");
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::WheelUtf8V1);
    let outcome = apply_with_options(
        Request {
            source: Source::Path(&original),
            policy: &policy,
            dest: None,
        },
        &options,
    );
    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
    let archive = outcome
        .verified_archive()
        .expect("verified wheel capability")
        .clone();
    fs::remove_file(&original).expect("make original wheel unavailable");
    assert!(!original.exists());

    let limits = WheelLimits::default();
    let evaluation = evaluate_wheel("demo-1.0-py3-none-any.whl", &archive, limits);
    let WheelEvaluation::Admitted {
        artifact,
        plan,
        identities,
        ..
    } = evaluation
    else {
        panic!("bridge fixture was not admitted: {evaluation:?}");
    };
    let stage = stage_installer_bridge(
        &temp.path().join("bridge"),
        &archive,
        &artifact,
        &plan,
        limits,
    )
    .expect("stage verified member bridge");
    assert!(!original.exists(), "staging must not recreate the wheel");

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("bridge/installer_bridge.py");
    let output = Command::new(python)
        .arg("-I")
        .arg(&script)
        .arg(stage.descriptor_path())
        .arg(installer_pythonpath)
        .output()
        .expect("run pinned PyPA installer bridge");
    assert!(
        output.status.success(),
        "bridge failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: BridgeReport = serde_json::from_slice(&output.stdout).expect("bridge report JSON");
    assert_eq!(report.schema, "sealr.installer-bridge-report.v1");
    assert_eq!(report.installer_version, "0.7.0");
    assert_eq!(report.repeatable_member_reads, archive.members().len());
    assert_eq!(report.wheel_open_audit, "enforced");
    assert!(
        !original.exists(),
        "external consumer must not recreate the wheel"
    );

    let mut outputs = report
        .actions
        .into_iter()
        .map(|action| RealizedOutput {
            scheme: parse_scheme(&action.scheme),
            relative_path: action.relative_path,
            sha256: action.sha256,
            size: action.size,
        })
        .collect::<Vec<_>>();
    outputs.push(RealizedOutput {
        scheme: parse_scheme(&report.final_record.scheme),
        relative_path: report.final_record.relative_path,
        sha256: report.final_record.sha256,
        size: report.final_record.size,
    });
    let realization = realize_identity(
        &plan,
        "pypa-installer-0.7.0-posix-research",
        "/sealr/python3-no-bytecode",
        &outputs,
    );
    assert_eq!(
        realization,
        realize_identity(
            &plan,
            "pypa-installer-0.7.0-posix-research",
            "/sealr/python3-no-bytecode",
            &outputs,
        )
    );
    assert!(
        [
            identities.source_sha256,
            identities.archive_tree_sha256,
            identities.artifact_sha256,
            identities.install_plan_sha256,
        ]
        .iter()
        .all(|identity| identity != &realization),
        "target realization identity remains a distinct domain"
    );
}

fn parse_scheme(value: &str) -> InstallScheme {
    match value {
        "purelib" => InstallScheme::Purelib,
        "platlib" => InstallScheme::Platlib,
        "scripts" => InstallScheme::Scripts,
        "headers" => InstallScheme::Headers,
        "data" => InstallScheme::Data,
        other => panic!("unknown bridge scheme {other}"),
    }
}

fn bridge_wheel() -> Vec<u8> {
    const WHEEL: &[u8] = b"Wheel-Version: 1.0\nGenerator: sealr-bridge-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n";
    const METADATA: &[u8] =
        b"Metadata-Version: 2.4\nName: demo\nVersion: 1.0\nSummary: bridge fixture\n";
    let mut files = BTreeMap::new();
    files.insert("demo/__init__.py", b"VALUE = 1\n".to_vec());
    files.insert("demo-1.0.dist-info/WHEEL", WHEEL.to_vec());
    files.insert("demo-1.0.dist-info/METADATA", METADATA.to_vec());
    files.insert(
        "demo-1.0.dist-info/entry_points.txt",
        b"[console_scripts]\ndemo-cli = demo:main\n".to_vec(),
    );
    files.insert(
        "demo-1.0.data/scripts/demo-script",
        b"#!python\nprint('demo')\n".to_vec(),
    );
    let mut record = String::new();
    for (path, bytes) in &files {
        record.push_str(path);
        record.push_str(",sha256=");
        record.push_str(&base64url(&Sha256::digest(bytes)));
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
                0o755
            } else {
                0o644
            };
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(permissions);
            writer.start_file(path, options).unwrap();
            writer.write_all(&bytes).unwrap();
        }
        writer.finish().unwrap();
    }
    cursor.into_inner()
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
