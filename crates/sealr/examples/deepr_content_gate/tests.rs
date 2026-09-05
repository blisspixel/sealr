//! Business-rule fixtures remain valid wheels so each refusal reaches its intended layer.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, ErrorKind, Write as _};
use std::path::PathBuf;

use sealr::wheel::{evaluate_wheel, WheelEvaluation, WheelIdentities, WheelLimits};
use sealr::{
    apply_with_options, ApplyOptions, Outcome, Policy, Request, RetentionPlan, RetentionStatus,
    Source, VerifiedArchive, ZipInterpretationProfile,
};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, System, ZipWriter};

const WHEEL_NAME: &str = "deepr_research-1.0-py3-none-any.whl";
const DIST_INFO: &str = "deepr_research-1.0.dist-info";
const REQUIRED: [&str; 5] = [
    "deepr/web/frontend/dist/index.html",
    "deepr/config/system_message.json",
    "deepr/skills/recon/skill.yaml",
    "deepr/skills/recon/prompt.md",
    "deepr/templates/documentation_research.md",
];
const JAVASCRIPT: &str = "deepr/web/frontend/dist/assets/app.js";
const CSS: &str = "deepr/web/frontend/dist/assets/app.css";
const UNRELATED: &str = "deepr/unrelated.py";

struct Fixture {
    files: BTreeMap<String, Vec<u8>>,
    directories: Vec<String>,
    lying_record: bool,
}

impl Fixture {
    fn valid() -> Self {
        let mut files = BTreeMap::new();
        for path in REQUIRED.into_iter().chain([JAVASCRIPT, CSS]) {
            files.insert(path.to_owned(), format!("fixture: {path}\n").into_bytes());
        }
        files.insert(UNRELATED.to_owned(), b"VALUE = 1\n".to_vec());
        files.insert(
            format!("{DIST_INFO}/WHEEL"),
            b"Wheel-Version: 1.0\nGenerator: sealr-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
                .to_vec(),
        );
        files.insert(
            format!("{DIST_INFO}/METADATA"),
            b"Metadata-Version: 2.6\nName: deepr-research\nVersion: 1.0\n\n".to_vec(),
        );
        Self {
            files,
            directories: Vec::new(),
            lying_record: false,
        }
    }

    fn bytes(&self, method: CompressionMethod) -> Vec<u8> {
        let mut files = self.files.clone();
        let mut record = String::new();
        for (path, bytes) in &files {
            let hashed = if self.lying_record && path == UNRELATED {
                b"different bytes\n".as_slice()
            } else {
                bytes.as_slice()
            };
            record.push_str(&format!(
                "{path},sha256={},{}\n",
                base64url(&Sha256::digest(hashed)),
                bytes.len()
            ));
        }
        let record_path = format!("{DIST_INFO}/RECORD");
        record.push_str(&format!("{record_path},,\n"));
        files.insert(record_path, record.into_bytes());

        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let options = SimpleFileOptions::default()
                .compression_method(method)
                .last_modified_time(DateTime::DEFAULT)
                .unix_permissions(0o644)
                .system(System::Unix);
            for (path, bytes) in files {
                writer.start_file(path, options).unwrap();
                writer.write_all(&bytes).unwrap();
            }
            for path in &self.directories {
                writer
                    .add_directory(
                        format!("{path}/"),
                        SimpleFileOptions::default()
                            .compression_method(CompressionMethod::Stored)
                            .last_modified_time(DateTime::DEFAULT)
                            .unix_permissions(0o755)
                            .system(System::Unix),
                    )
                    .unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }
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

fn options(retention: Option<RetentionPlan>) -> ApplyOptions {
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
    match retention {
        Some(plan) => options.with_retention(plan),
        None => options,
    }
}

fn admit(bytes: &[u8], retention: Option<RetentionPlan>) -> Outcome {
    apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some(WHEEL_NAME),
                data: bytes,
            },
            policy: &Policy::default_v1(),
            dest: None,
        },
        &options(retention),
    )
}

fn capability(outcome: &Outcome) -> &VerifiedArchive {
    outcome.verified_archive().unwrap_or_else(|| {
        panic!(
            "fixture must reach the consumer: {:?}",
            outcome.view.findings
        )
    })
}

fn evaluate(archive: &VerifiedArchive) -> WheelIdentities {
    match evaluate_wheel(WHEEL_NAME, archive, WheelLimits::default()) {
        WheelEvaluation::Admitted { identities, .. } => identities,
        other => panic!("business fixture must remain a valid wheel: {other:?}"),
    }
}

fn assert_gate_denial(fixture: &Fixture, expected: &str) {
    let outcome = admit(&fixture.bytes(CompressionMethod::Stored), None);
    let archive = capability(&outcome);
    evaluate(archive);
    match super::check_deepr_content(archive) {
        Err(message) => assert_eq!(message, expected),
        Ok(_) => panic!("business gate accepted fixture requiring {expected:?}"),
    }
}

fn assert_archive_denial(bytes: &[u8], expected_code: &str) {
    let outcome = admit(bytes, None);
    assert!(outcome.verified_archive().is_none());
    assert!(
        outcome
            .view
            .findings
            .iter()
            .any(|finding| finding.code.as_str() == expected_code),
        "expected {expected_code}, received {:?}",
        outcome.view.findings
    );
}

#[test]
fn valid_gate_decision_is_the_same_with_or_without_semantic_retention() {
    let bytes = Fixture::valid().bytes(CompressionMethod::Deflated);
    let mut retention = RetentionPlan::new(16 * 1024, 48 * 1024);
    let paths: Vec<String> = ["METADATA", "WHEEL", "RECORD"]
        .map(|name| format!("{DIST_INFO}/{name}"))
        .into_iter()
        .collect();
    for path in &paths {
        retention.add_path(path.clone()).unwrap();
    }
    let baseline = admit(&bytes, None);
    let retained = admit(&bytes, Some(retention));
    assert_eq!(
        serde_json::to_value(&baseline).unwrap(),
        serde_json::to_value(&retained).unwrap()
    );
    let baseline_archive = capability(&baseline);
    let retained_archive = capability(&retained);
    assert_eq!(evaluate(baseline_archive), evaluate(retained_archive));
    for path in &paths {
        assert_eq!(
            baseline_archive.retention_status(path),
            RetentionStatus::NotRequested
        );
        assert_eq!(
            retained_archive.retention_status(path),
            RetentionStatus::Retained
        );
    }
    for archive in [baseline_archive, retained_archive] {
        let decision = super::check_deepr_content(archive).unwrap();
        assert_eq!(decision.required_files, 5);
        assert_eq!(decision.javascript_files, 1);
        assert_eq!(decision.css_files, 1);
    }
}

#[test]
fn every_required_file_and_asset_family_is_required_after_wheel_evaluation() {
    for path in REQUIRED {
        let mut fixture = Fixture::valid();
        fixture.files.remove(path).unwrap();
        assert_gate_denial(&fixture, &format!("missing required file: {path}"));
    }
    for (path, expected) in [
        (JAVASCRIPT, "no packaged frontend JavaScript assets"),
        (CSS, "no packaged frontend CSS assets"),
    ] {
        let mut fixture = Fixture::valid();
        fixture.files.remove(path).unwrap();
        fixture
            .files
            .insert(format!("{path}.map"), b"source map\n".to_vec());
        fixture.files.insert(
            format!("deepr/elsewhere.{}", path.rsplit('.').next().unwrap()),
            b"outside the frontend asset directory\n".to_vec(),
        );
        assert_gate_denial(&fixture, expected);
    }
}

#[test]
fn directories_cannot_satisfy_required_files_or_asset_extensions() {
    for path in REQUIRED {
        let mut fixture = Fixture::valid();
        fixture.files.remove(path).unwrap();
        fixture.directories.push(path.to_owned());
        assert_gate_denial(&fixture, &format!("missing required file: {path}"));
    }
    for (path, expected) in [
        (JAVASCRIPT, "no packaged frontend JavaScript assets"),
        (CSS, "no packaged frontend CSS assets"),
    ] {
        let mut fixture = Fixture::valid();
        fixture.files.remove(path).unwrap();
        fixture.directories.push(path.to_owned());
        assert_gate_denial(&fixture, expected);
    }
}

#[test]
fn build_only_content_is_rejected_at_every_named_boundary() {
    for path in [
        "deepr/web/node_modules/dependency/index.js",
        "node_modules/dependency/index.js",
        "deepr/web/frontend/frontend-dist.zip",
        "frontend-dist.zip",
        "deepr/cached.pyc",
        "cached.pyo",
    ] {
        let mut fixture = Fixture::valid();
        fixture
            .files
            .insert(path.to_owned(), b"build-only\n".to_vec());
        assert_gate_denial(&fixture, &format!("build-only member: {path}"));
    }
}

#[test]
fn build_only_directories_are_also_rejected() {
    for path in ["node_modules", "deepr/frontend-dist.zip"] {
        let mut fixture = Fixture::valid();
        fixture.directories.push(path.to_owned());
        assert_gate_denial(&fixture, &format!("build-only member: {path}"));
    }
}

#[test]
fn pycache_is_denied_by_wheel_semantics_and_the_defensive_business_rule() {
    for (path, directory) in [
        ("deepr/__pycache__/cached.py", false),
        ("__pycache__/cached.py", false),
        ("deepr/__pycache__", true),
        ("__pycache__", true),
    ] {
        let mut fixture = Fixture::valid();
        if directory {
            fixture.directories.push(path.to_owned());
        } else {
            fixture.files.insert(path.to_owned(), b"cached\n".to_vec());
        }
        let outcome = admit(&fixture.bytes(CompressionMethod::Stored), None);
        let archive = capability(&outcome);
        match evaluate_wheel(WHEEL_NAME, archive, WheelLimits::default()) {
            WheelEvaluation::Denied { findings } => {
                assert!(findings
                    .iter()
                    .any(|finding| finding.code == "wheel.pycache-payload"));
            }
            other => panic!("pycache must be denied before the business gate: {other:?}"),
        }
        // The real caller stops above. Check the gate's own rule separately.
        match super::check_deepr_content(archive) {
            Err(message) => assert_eq!(message, format!("build-only member: {path}")),
            Ok(_) => panic!("business rule accepted {path}"),
        }
    }
}

#[test]
fn similar_names_do_not_trigger_build_only_rules() {
    let mut fixture = Fixture::valid();
    for path in [
        "deepr/node_modules_backup/module.js",
        "deepr/__pycache___notes/readme.txt",
        "deepr/frontend-dist.zip.sha256",
        "deepr/module.pyc.txt",
        "deepr/module.pyo.txt",
    ] {
        fixture
            .files
            .insert(path.to_owned(), b"ordinary\n".to_vec());
    }
    let outcome = admit(&fixture.bytes(CompressionMethod::Stored), None);
    let archive = capability(&outcome);
    evaluate(archive);
    assert!(super::check_deepr_content(archive).is_ok());
}

#[test]
fn unrelated_payload_corruption_cannot_reach_the_names_only_gate() {
    let mut bytes = Fixture::valid().bytes(CompressionMethod::Stored);
    let record = fixture_record(&bytes, UNRELATED);
    bytes[record.payload] ^= 1;
    assert_archive_denial(&bytes, "crc.mismatch");
}

#[test]
fn complete_plaintext_without_deflate_stream_end_cannot_reach_the_gate() {
    let fixture = Fixture::valid();
    let mut bytes = fixture.bytes(CompressionMethod::Deflated);
    let record = fixture_record(&bytes, UNRELATED);
    assert_eq!(
        bytes[record.payload] & 1,
        1,
        "fixture begins with a final block"
    );
    bytes[record.payload] &= !1;

    // Establish that this mutation preserves complete plaintext and compressed length.
    // The absent stream-end marker, rather than a business rule, must cause refusal.
    let mut decoder = flate2::Decompress::new(false);
    let mut decoded = Vec::with_capacity(fixture.files[UNRELATED].len() + 16);
    let status = decoder
        .decompress_vec(
            &bytes[record.payload..record.payload + record.compressed_size],
            &mut decoded,
            flate2::FlushDecompress::Finish,
        )
        .unwrap();
    assert_eq!(decoded, fixture.files[UNRELATED]);
    assert_eq!(decoder.total_in(), record.compressed_size as u64);
    assert_ne!(status, flate2::Status::StreamEnd);
    assert_archive_denial(&bytes, "codec.deflate.invalid_stream");
}

#[test]
fn duplicate_and_unsafe_names_never_become_a_capability() {
    for (path, expected) in [
        ("deepr/../escape.py", "path.dotdot"),
        ("deepr\\escape.py", "path.invalid_char"),
    ] {
        let mut fixture = Fixture::valid();
        fixture.files.insert(path.to_owned(), b"hostile\n".to_vec());
        assert_archive_denial(&fixture.bytes(CompressionMethod::Stored), expected);
    }

    let mut fixture = Fixture::valid();
    let first = "deepr/duplicate_1.py";
    let second = "deepr/duplicate_2.py";
    fixture.files.insert(first.to_owned(), b"first\n".to_vec());
    fixture
        .files
        .insert(second.to_owned(), b"second\n".to_vec());
    let mut bytes = fixture.bytes(CompressionMethod::Stored);
    let record = fixture_record(&bytes, second);
    bytes[record.local + 30..record.local + 30 + first.len()].copy_from_slice(first.as_bytes());
    bytes[record.central + 46..record.central + 46 + first.len()].copy_from_slice(first.as_bytes());
    assert_archive_denial(&bytes, "zip.diff.b1_dup");
}

#[test]
fn record_and_outer_filename_denials_precede_business_acceptance() {
    let mut fixture = Fixture::valid();
    fixture.lying_record = true;
    let lying = admit(&fixture.bytes(CompressionMethod::Stored), None);
    let ordinary = admit(&Fixture::valid().bytes(CompressionMethod::Stored), None);
    for (outcome, filename, expected) in [
        (&lying, WHEEL_NAME, "wheel.record-hash-mismatch"),
        (
            &ordinary,
            "other-1.0-py3-none-any.whl",
            "wheel.artifact-root-disagreement",
        ),
    ] {
        let archive = capability(outcome);
        match evaluate_wheel(filename, archive, WheelLimits::default()) {
            WheelEvaluation::Denied { findings } => {
                assert!(findings.iter().any(|finding| finding.code == expected));
            }
            other => panic!("expected {expected}, received {other:?}"),
        }
    }
}

#[test]
fn private_source_is_deleted_before_evaluation_and_business_acceptance() {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).unwrap();
    let root = std::env::temp_dir().join(format!("sealr-deepr-gate-{}", base64url(&random)));
    fs::create_dir(&root).unwrap();
    let temp = PrivateSource(root);
    let path = temp.0.join(WHEEL_NAME);
    fs::write(&path, Fixture::valid().bytes(CompressionMethod::Deflated)).unwrap();
    let outcome = apply_with_options(
        Request {
            source: Source::Path(&path),
            policy: &Policy::default_v1(),
            dest: None,
        },
        &options(None),
    );
    let archive = capability(&outcome);
    fs::remove_file(&path).unwrap();
    assert_eq!(
        fs::File::open(&path).unwrap_err().kind(),
        ErrorKind::NotFound
    );
    evaluate(archive);
    let decision = super::check_deepr_content(archive).unwrap();
    assert_eq!(decision.required_files, 5);
    assert_eq!(archive.read_member(UNRELATED, 64).unwrap(), b"VALUE = 1\n");
}

struct PrivateSource(PathBuf);

impl Drop for PrivateSource {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join(WHEEL_NAME));
        let _ = fs::remove_dir(&self.0);
    }
}

struct FixtureRecord {
    local: usize,
    central: usize,
    payload: usize,
    compressed_size: usize,
}

fn u16_at(bytes: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap()))
}

fn u32_at(bytes: &[u8], at: usize) -> usize {
    usize::try_from(u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())).unwrap()
}

/// Locate records only in the deterministic ZIP32 test producer's output.
fn fixture_record(bytes: &[u8], path: &str) -> FixtureRecord {
    let eocd = bytes.len() - 22;
    assert_eq!(&bytes[eocd..eocd + 4], b"PK\x05\x06");
    let mut central = u32_at(bytes, eocd + 16);
    for _ in 0..u16_at(bytes, eocd + 10) {
        assert_eq!(&bytes[central..central + 4], b"PK\x01\x02");
        let name_len = u16_at(bytes, central + 28);
        if &bytes[central + 46..central + 46 + name_len] == path.as_bytes() {
            let local = u32_at(bytes, central + 42);
            assert_eq!(&bytes[local..local + 4], b"PK\x03\x04");
            return FixtureRecord {
                local,
                central,
                payload: local + 30 + u16_at(bytes, local + 26) + u16_at(bytes, local + 28),
                compressed_size: u32_at(bytes, central + 20),
            };
        }
        central += 46 + name_len + u16_at(bytes, central + 30) + u16_at(bytes, central + 32);
    }
    panic!("test producer omitted {path}");
}
