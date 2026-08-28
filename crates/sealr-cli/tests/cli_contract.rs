use std::fs;
#[cfg(unix)]
use std::net::Shutdown;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Stdio;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

#[path = "../../../scripts/walkthrough_fixtures.rs"]
mod walkthrough_fixtures;

const ALLOWED_SHA256: &str = "580606f3b53229ab60ff1d786bac90c91f75c054269c11142cd971f380d3fc25";
const REJECTED_SHA256: &str = "5039cccff40a5df0d0b61a2734b5dafeb8224f914603cae870f1638990f58140";
const PROFILE_DIGEST: &str = "da3a2145d48decf8f8995ea01f1ddd0adb587f7f3544d4642bb8bb07b8f039f5";
const ALLOWED_LAYOUT: &str = "9986381ec4a61fd34452fb759ccaf44b82ee58c8147ee032f077722c1ccac3a3";
const ALLOWED_CONTENT: &str = "ccae362a7daa3508aace90d589c4538c27f13ff517a82a049e47005724073f38";

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

#[cfg(unix)]
fn sealr_with_unwritable_stdout(arguments: &[&Path]) -> Output {
    let (_reader, writer) = UnixStream::pair().expect("stdout socket pair should be created");
    writer
        .shutdown(Shutdown::Write)
        .expect("stdout socket writes should be disabled");
    let mut command = Command::new(env!("CARGO_BIN_EXE_sealr"));
    for argument in arguments {
        command.arg(argument);
    }
    command
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::piped())
        .output()
        .expect("sealr should start with unwritable stdout")
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

fn write_octal(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let octal = format!("{value:o}");
    let digits = field.len() - 1;
    field[digits - octal.len()..digits].copy_from_slice(octal.as_bytes());
    field[digits] = 0;
}

fn write_tar_fixture(path: &Path) {
    let name = b"mission/status.txt";
    let body = b"nominal\n";
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name);
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], body.len() as u64);
    write_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    write_octal(&mut header[329..337], 0);
    write_octal(&mut header[337..345], 0);
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    let encoded = format!("{checksum:06o}");
    header[148..154].copy_from_slice(encoded.as_bytes());
    header[154] = 0;
    header[155] = b' ';

    let mut bytes = header.to_vec();
    bytes.extend_from_slice(body);
    bytes.resize(bytes.len().next_multiple_of(512), 0);
    bytes.resize(bytes.len() + 1024, 0);
    fs::write(path, bytes).expect("TAR fixture should be writable");
}

fn assert_allowed_streams(output: &Output, wrote: bool) -> (Value, Value) {
    assert_eq!(output.status.code(), Some(0));
    let view = json(&output.stdout, "stdout");
    let receipt = json(&output.stderr, "stderr");

    assert_eq!(view["schema"], "sealr.view.v1");
    assert_eq!(receipt["schema"], "sealr.receipt.v2");
    assert_eq!(view["verdict"], "allowed");
    assert_eq!(view["wrote"], wrote);
    assert_eq!(view["interpretation"]["status"], "interpreted");
    assert_eq!(view["admission"]["status"], "admitted");
    assert_eq!(view["verification"]["status"], "complete");
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
    assert_eq!(receipt["source_snapshot"], "private-file");
    assert_eq!(receipt["signed"], false);
    assert_eq!(receipt["source"], view["source"]["digest"]);
    assert_eq!(receipt["policy"], view["policy"]);
    assert!(receipt["source"].get("status").is_none());
    assert_eq!(
        receipt["identities"]["interpretation"]["id"],
        "sealr.profile.zip.strict-ascii.v1"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["digest"]["sha256"],
        PROFILE_DIGEST
    );
    assert_eq!(
        receipt["identities"]["layout"]["sealrTreeV1"],
        ALLOWED_LAYOUT
    );
    assert_eq!(
        receipt["identities"]["content"]["sealrTreeV1"],
        ALLOWED_CONTENT
    );
    assert_ne!(
        receipt["identities"]["layout"]["sealrTreeV1"],
        receipt["view_digest"]["sha256"]
    );
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
    assert!(help_text.contains("--format <FORMAT>"));
    assert!(help_text.contains("tar-ustar"));
    assert!(help_text.contains("--worker-manifest <ABSOLUTE_PATH>"));
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
fn explicit_tar_format_inspects_and_materializes() {
    let run = RunDirectory::create("tar");
    let archive = run.path.join("mission.tar");
    write_tar_fixture(&archive);

    let inspect = sealr(&[Path::new("--format"), Path::new("tar-ustar"), &archive]);
    assert_eq!(inspect.status.code(), Some(0));
    let view = json(&inspect.stdout, "TAR stdout");
    let receipt = json(&inspect.stderr, "TAR stderr");
    assert_eq!(view["source"]["magic"], "tar");
    assert_eq!(view["members"][0]["path"], "mission/status.txt");
    assert_eq!(
        receipt["identities"]["interpretation"]["id"],
        "sealr.profile.tar.ustar-portable.v1"
    );
    assert!(receipt["identities"]["layout"].get("sealrTreeV2").is_some());

    let destination = run.path.join("materialized");
    let materialize = sealr(&[
        Path::new("--format"),
        Path::new("tar-ustar"),
        &archive,
        Path::new("--dest"),
        &destination,
    ]);
    assert_eq!(materialize.status.code(), Some(0));
    assert_eq!(
        fs::read(destination.join("mission/status.txt")).unwrap(),
        b"nominal\n"
    );
}

#[test]
fn selected_supervision_failure_has_no_in_process_fallback() {
    let (run, fixtures) = fixture_set("supervision-failure");
    let missing_manifest = run.path.join("sealr-worker.manifest");
    let output = sealr(&[
        Path::new("--worker-manifest"),
        &missing_manifest,
        &fixtures.allowed,
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("diagnostic should be UTF-8");
    assert!(stderr.contains("sealr: supervised execution failed:"));
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
    let inspect_receipt = json(&inspect.stderr, "inspect stderr");
    assert_eq!(
        inspect_receipt["identities"]["layout"],
        receipt["identities"]["layout"]
    );
    assert_eq!(
        inspect_receipt["identities"]["content"],
        receipt["identities"]["content"]
    );
    assert_ne!(
        inspect_receipt["view_digest"], receipt["view_digest"],
        "view_digest covers the invocation, not the tree"
    );
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

#[cfg(unix)]
#[test]
fn unwritable_stdout_preserves_inspect_and_materialize_receipts() {
    let (run, fixtures) = fixture_set("unwritable-stdout");

    let inspect = sealr_with_unwritable_stdout(&[&fixtures.allowed]);
    assert_eq!(inspect.status.code(), Some(1));
    assert!(inspect.stdout.is_empty());
    let inspect_receipt = json(&inspect.stderr, "inspect stderr");
    assert_eq!(inspect_receipt["schema"], "sealr.receipt.v2");
    assert_eq!(inspect_receipt["verdict"], "allowed");
    assert_eq!(inspect_receipt["wrote"], false);
    assert_eq!(inspect_receipt["effect"]["status"], "not-requested");

    let destination = run.path.join("materialized");
    let materialize =
        sealr_with_unwritable_stdout(&[&fixtures.allowed, Path::new("--dest"), &destination]);
    assert_eq!(materialize.status.code(), Some(1));
    assert!(materialize.stdout.is_empty());
    let materialize_receipt = json(&materialize.stderr, "materialize stderr");
    assert_eq!(materialize_receipt["schema"], "sealr.receipt.v2");
    assert_eq!(materialize_receipt["verdict"], "allowed");
    assert_eq!(materialize_receipt["wrote"], true);
    assert_eq!(materialize_receipt["effect"]["status"], "committed");
    assert_eq!(
        fs::read(destination.join(walkthrough_fixtures::HELLO_PATH))
            .expect("materialization should complete even when stdout is unwritable"),
        walkthrough_fixtures::HELLO_BYTES
    );
}

#[test]
fn missing_destination_parent_rejects_without_creating_it() {
    let (run, fixtures) = fixture_set("missing-parent");
    let parent = run.path.join("missing");
    let destination = parent.join("materialized");

    let output = sealr(&[&fixtures.allowed, Path::new("--dest"), &destination]);

    assert_eq!(output.status.code(), Some(3));
    let view = json(&output.stdout, "stdout");
    let receipt = json(&output.stderr, "stderr");
    assert_eq!(view["verdict"], "rejected");
    assert_eq!(view["wrote"], false);
    assert_eq!(view["admission"]["status"], "admitted");
    assert_eq!(view["effect"]["status"], "failed");
    assert_eq!(receipt["verdict"], "rejected");
    assert_eq!(receipt["wrote"], false);
    assert_eq!(receipt["admission"]["status"], "admitted");
    assert_eq!(receipt["effect"]["status"], "failed");
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
