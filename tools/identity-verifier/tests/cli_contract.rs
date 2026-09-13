use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

const EVIDENCE_MANIFEST: &str =
    include_str!("../../../crates/sealr/tests/conformance/evidence-v1.json");
const MAX_EVIDENCE_BYTES: u64 = 16 * 1024 * 1024;
static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new() -> Self {
        let sequence = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sealr-identity-verifier-cli-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create verifier CLI test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove verifier CLI test directory");
    }
}

struct EvidenceFiles {
    _temporary: TemporaryDirectory,
    view: PathBuf,
    receipt: PathBuf,
    source: PathBuf,
}

impl EvidenceFiles {
    fn admitted_inspect() -> Self {
        let manifest: Value =
            serde_json::from_str(EVIDENCE_MANIFEST).expect("parse evidence fixture");
        let case = manifest["cases"]
            .as_array()
            .expect("evidence cases")
            .iter()
            .find(|case| case["id"] == "admitted-inspect")
            .expect("admitted inspect fixture");
        let temporary = TemporaryDirectory::new();
        let view = temporary.path().join("view.json");
        let receipt = temporary.path().join("receipt.json");
        let source = temporary.path().join("source.zip");
        fs::write(
            &view,
            decode_hex(case["view_bytes_hex"].as_str().expect("view hex")),
        )
        .expect("write view");
        fs::write(
            &receipt,
            decode_hex(case["receipt_bytes_hex"].as_str().expect("receipt hex")),
        )
        .expect("write receipt");
        fs::write(
            &source,
            decode_hex(case["source_bytes_hex"].as_str().expect("source hex")),
        )
        .expect("write source");
        Self {
            _temporary: temporary,
            view,
            receipt,
            source,
        }
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "hex input must contain byte pairs");
    pairs
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex is ASCII");
            u8::from_str_radix(text, 16).expect("valid hex byte")
        })
        .collect()
}

fn verifier(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sealr-identity-verifier"))
        .args(arguments)
        .output()
        .expect("run identity verifier")
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("test path is Unicode")
}

fn assert_exit(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn help_and_version_are_successful_command_surfaces() {
    for flag in ["--help", "-h"] {
        let output = verifier(&[flag]);
        assert_exit(&output, 0);
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("usage: sealr-identity-verifier"));
        assert!(output.stderr.is_empty());
    }

    for flag in ["--version", "-V"] {
        let output = verifier(&[flag]);
        assert_exit(&output, 0);
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("sealr-identity-verifier {}\n", env!("CARGO_PKG_VERSION"))
        );
        assert!(output.stderr.is_empty());
    }

    let output = verifier(&["evidence", "--help"]);
    assert_exit(&output, 0);
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("evidence --view <view.json>"));
    assert!(output.stderr.is_empty());
}

#[test]
fn malformed_invocations_are_usage_errors() {
    for arguments in [
        vec![],
        vec!["--unknown"],
        vec!["evidence"],
        vec!["evidence", "--unknown"],
        vec!["evidence", "--view", "only-view.json"],
        vec![
            "evidence",
            "--view",
            "a.json",
            "--view",
            "b.json",
            "--receipt",
            "r.json",
        ],
        vec!["evidence", "--help", "extra"],
    ] {
        let output = verifier(&arguments);
        assert_exit(&output, 2);
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("usage: "));
    }
}

#[test]
fn canonical_evidence_success_is_quiet_on_stderr_and_source_is_optional() {
    let files = EvidenceFiles::admitted_inspect();
    let base = [
        "evidence",
        "--view",
        path_text(&files.view),
        "--receipt",
        path_text(&files.receipt),
    ];
    let output = verifier(&base);
    assert_exit(&output, 0);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("content root independently verified, source not supplied"));
    assert!(stdout.ends_with("layout root remains a producer claim\n"));
    assert!(output.stderr.is_empty());

    let mut with_source = base.to_vec();
    with_source.extend(["--source", path_text(&files.source)]);
    let output = verifier(&with_source);
    assert_exit(&output, 0);
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("content root independently verified, source digest checked"));
    assert!(output.stderr.is_empty());
}

#[test]
fn view_receipt_and_source_mutations_fail_closed() {
    let files = EvidenceFiles::admitted_inspect();
    for path in [&files.view, &files.receipt, &files.source] {
        let original = fs::read(path).expect("read fixture");
        let mut mutated = original.clone();
        mutated.push(b'\n');
        fs::write(path, mutated).expect("mutate fixture");
        let output = verifier(&[
            "evidence",
            "--view",
            path_text(&files.view),
            "--receipt",
            path_text(&files.receipt),
            "--source",
            path_text(&files.source),
        ]);
        assert_exit(&output, 1);
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("canonical evidence rejected: "));
        fs::write(path, original).expect("restore fixture");
    }
}

#[test]
fn evidence_reads_enforce_the_limit_before_parsing() {
    let files = EvidenceFiles::admitted_inspect();
    let oversized = files._temporary.path().join("oversized.json");
    File::create(&oversized)
        .expect("create oversized evidence")
        .set_len(MAX_EVIDENCE_BYTES + 1)
        .expect("size oversized evidence");
    let output = verifier(&[
        "evidence",
        "--view",
        path_text(&oversized),
        "--receipt",
        path_text(&files.receipt),
    ]);
    assert_exit(&output, 1);
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "canonical evidence rejected: view exceeds the 16777216-byte verifier limit\n"
    );
}
