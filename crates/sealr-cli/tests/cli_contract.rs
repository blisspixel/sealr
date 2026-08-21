use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

#[path = "../../../scripts/walkthrough_fixtures.rs"]
mod walkthrough_fixtures;

const ALLOWED_SHA256: &str = "580606f3b53229ab60ff1d786bac90c91f75c054269c11142cd971f380d3fc25";
const REJECTED_SHA256: &str = "5039cccff40a5df0d0b61a2734b5dafeb8224f914603cae870f1638990f58140";

static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct RunDirectory {
    path: PathBuf,
}

impl RunDirectory {
    fn create(label: &str) -> Self {
        let target_tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(&target_tmp).expect("Cargo target temp directory should be creatable");
        let sequence = RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = target_tmp.join(format!(
            "sealr-cli-{label}-{}-{sequence}",
            std::process::id()
        ));
        assert!(!path.exists(), "unique test directory already exists");
        fs::create_dir(&path).expect("test directory should be creatable");
        Self { path }
    }
}

impl Drop for RunDirectory {
    fn drop(&mut self) {
        let target_tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        assert!(self.path.starts_with(&target_tmp));
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn sealr(arguments: &[&Path]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sealr"));
    for argument in arguments {
        command.arg(argument);
    }
    command.output().expect("sealr should start")
}

fn sealr_text(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sealr"))
        .args(arguments)
        .output()
        .expect("sealr should start")
}

fn json(bytes: &[u8], stream: &str) -> Value {
    serde_json::from_slice(bytes).unwrap_or_else(|error| {
        panic!(
            "{stream} should contain exactly one JSON document: {error}\n{}",
            String::from_utf8_lossy(bytes)
        )
    })
}

fn fixture_set(label: &str) -> (RunDirectory, walkthrough_fixtures::FixturePaths) {
    let run = RunDirectory::create(label);
    let fixtures = walkthrough_fixtures::generate(&run.path.join("fixtures"))
        .expect("walkthrough fixtures should generate");
    (run, fixtures)
}

fn assert_allowed_streams(output: &Output, wrote: bool) -> (Value, Value) {
    assert_eq!(output.status.code(), Some(0));
    let view = json(&output.stdout, "stdout");
    let receipt = json(&output.stderr, "stderr");

    assert_eq!(view["schema"], "sealr.view.v1");
    assert_eq!(receipt["schema"], "sealr.receipt.v2");
    assert_eq!(view["verdict"], "allowed");
    assert_eq!(view["wrote"], wrote);
    assert_eq!(receipt["verdict"], "allowed");
    assert_eq!(receipt["wrote"], wrote);
    assert_eq!(receipt["interpretation"]["status"], "interpreted");
    assert_eq!(receipt["admission"]["status"], "admitted");
    assert_eq!(receipt["verification"]["status"], "complete");
    assert_eq!(
        receipt["effect"]["status"],
        if wrote { "committed" } else { "not-requested" }
    );
    assert_eq!(receipt["view_completeness"]["status"], "complete");
    assert_eq!(receipt["source_snapshot"], "memory-owned");
    assert_eq!(receipt["signed"], false);
    assert_eq!(receipt["source"], view["source"]["digest"]);
    assert_eq!(receipt["policy"], view["policy"]);
    assert!(receipt["source"].get("status").is_none());
    (view, receipt)
}

#[test]
fn help_and_version_use_stdout_and_exit_zero() {
    let help = sealr_text(&["--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(help.stderr.is_empty());
    let help_text = String::from_utf8(help.stdout).expect("help should be UTF-8");
    assert!(help_text.contains("Usage: sealr"));
    assert!(help_text.contains("<ARCHIVE>"));
    assert!(help_text.contains("--dest <DEST>"));
    assert!(help_text.contains("--version"));

    let version = sealr_text(&["--version"]);
    assert_eq!(version.status.code(), Some(0));
    assert!(version.stderr.is_empty());
    assert_eq!(
        String::from_utf8(version.stdout).expect("version should be UTF-8"),
        format!("sealr {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn walkthrough_fixtures_are_byte_stable() {
    let (_run, fixtures) = fixture_set("fixtures");
    let allowed = fs::read(fixtures.allowed).expect("allowed fixture should be readable");
    let rejected = fs::read(fixtures.rejected).expect("rejected fixture should be readable");

    assert_eq!(sealr::hex_sha256(&allowed), ALLOWED_SHA256);
    assert_eq!(sealr::hex_sha256(&rejected), REJECTED_SHA256);
}

#[test]
fn inspect_allow_writes_view_to_stdout_and_receipt_to_stderr() {
    let (run, fixtures) = fixture_set("inspect");
    let output = sealr(&[&fixtures.allowed]);
    let (view, receipt) = assert_allowed_streams(&output, false);

    assert_eq!(view["findings"].as_array().map(Vec::len), Some(0));
    let members = view["members"]
        .as_array()
        .expect("members should be an array");
    assert_eq!(members.len(), 2);
    assert_eq!(members[0]["path"], walkthrough_fixtures::CONFIG_PATH);
    assert_eq!(members[0]["method"], "store");
    assert_eq!(members[0]["uncomp_bytes"], 14);
    assert_eq!(members[1]["path"], walkthrough_fixtures::HELLO_PATH);
    assert_eq!(members[1]["method"], "store");
    assert_eq!(members[1]["uncomp_bytes"], 17);
    assert_eq!(receipt["source"]["sha256"], ALLOWED_SHA256);

    assert!(!run.path.join("materialized").exists());
    assert!(!run.path.join("outside.txt").exists());
}

#[test]
fn rejected_parent_path_exits_two_and_never_writes() {
    let (run, fixtures) = fixture_set("reject");
    let destination = run.path.join("blocked");
    let output = sealr(&[&fixtures.rejected, Path::new("--dest"), &destination]);

    assert_eq!(output.status.code(), Some(2));
    let view = json(&output.stdout, "stdout");
    let receipt = json(&output.stderr, "stderr");
    assert_eq!(view["verdict"], "rejected");
    assert_eq!(view["wrote"], false);
    assert_eq!(view["members"].as_array().map(Vec::len), Some(0));
    assert_eq!(receipt["verdict"], "rejected");
    assert_eq!(receipt["wrote"], false);
    assert_eq!(receipt["source"]["sha256"], REJECTED_SHA256);
    assert_eq!(receipt["source"], view["source"]["digest"]);
    assert_eq!(receipt["schema"], "sealr.receipt.v2");
    assert_eq!(receipt["interpretation"]["status"], "interpreted");
    assert_eq!(receipt["admission"]["status"], "denied");
    assert_eq!(receipt["verification"]["status"], "structure-only");
    assert_eq!(receipt["effect"]["status"], "not-requested");

    let findings = view["findings"]
        .as_array()
        .expect("findings should be an array");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["code"], "path.dotdot");
    assert_eq!(findings[0]["severity"], "error");
    assert_eq!(findings[0]["member"], walkthrough_fixtures::REJECTED_PATH);
    assert_eq!(findings[0]["detail"], "parent component");
    assert_eq!(receipt["findings"], view["findings"]);

    assert!(!destination.exists());
    assert!(!run.path.join("outside.txt").exists());
}

#[test]
fn materialization_exits_zero_and_matches_the_inspected_members() {
    let (run, fixtures) = fixture_set("materialize");
    let inspect = sealr(&[&fixtures.allowed]);
    let (inspect_view, _) = assert_allowed_streams(&inspect, false);

    let destination = run.path.join("materialized");
    assert!(!destination.exists());
    let materialize = sealr(&[&fixtures.allowed, Path::new("--dest"), &destination]);
    let (materialized_view, receipt) = assert_allowed_streams(&materialize, true);

    assert_eq!(inspect_view["members"], materialized_view["members"]);
    assert_eq!(receipt["source"]["sha256"], ALLOWED_SHA256);
    assert_eq!(
        fs::read(destination.join(walkthrough_fixtures::CONFIG_PATH))
            .expect("config should materialize"),
        walkthrough_fixtures::CONFIG_BYTES
    );
    assert_eq!(
        fs::read(destination.join(walkthrough_fixtures::HELLO_PATH))
            .expect("hello should materialize"),
        walkthrough_fixtures::HELLO_BYTES
    );
    assert!(!run.path.join("outside.txt").exists());
}

#[test]
fn missing_destination_parent_rejects_without_creating_it() {
    let (run, fixtures) = fixture_set("missing-parent");
    let parent = run.path.join("missing");
    let destination = parent.join("materialized");

    let output = sealr(&[&fixtures.allowed, Path::new("--dest"), &destination]);

    assert_eq!(output.status.code(), Some(2));
    let view = json(&output.stdout, "stdout");
    let receipt = json(&output.stderr, "stderr");
    assert_eq!(view["verdict"], "rejected");
    assert_eq!(view["wrote"], false);
    assert_eq!(receipt["verdict"], "rejected");
    assert_eq!(receipt["wrote"], false);
    assert_eq!(receipt["materialization"]["outcome"], "setup-failed");
    assert_eq!(receipt["materialization"]["cleanup"], "not-created");
    assert_eq!(view["findings"][0]["code"], "materialize.io");
    assert_eq!(receipt["schema"], "sealr.receipt.v2");
    assert_eq!(receipt["interpretation"]["status"], "interpreted");
    assert_eq!(receipt["admission"]["status"], "admitted");
    assert_eq!(receipt["verification"]["status"], "structure-only");
    assert_eq!(receipt["effect"]["status"], "failed");
    assert!(!parent.exists());
    assert!(!destination.exists());
}

#[test]
fn missing_archive_exits_two_without_a_source_digest() {
    let run = RunDirectory::create("missing-archive");
    let missing = run.path.join("nope.zip");
    let output = sealr(&[&missing]);

    assert_eq!(output.status.code(), Some(2));
    let view = json(&output.stdout, "stdout");
    let receipt = json(&output.stderr, "stderr");
    assert_eq!(view["verdict"], "rejected");
    assert_eq!(receipt["schema"], "sealr.receipt.v2");
    assert_eq!(receipt["source"]["status"], "unavailable");
    assert!(receipt["source"].get("sha256").is_none());
    assert_eq!(view["source"]["digest"]["status"], "unavailable");
    assert_eq!(receipt["interpretation"]["status"], "indeterminate");
    assert_eq!(receipt["admission"]["status"], "not-evaluated");
    assert_eq!(receipt["effect"]["status"], "not-requested");
    assert_eq!(receipt["source_snapshot"], "unavailable");
}
