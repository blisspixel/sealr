use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;

use sealr::wheel::{
    evaluate_wheel as evaluate_supported_wheel, WheelEvaluation as SupportedWheelEvaluation,
    WheelLimits as SupportedWheelLimits,
};
use sealr::{apply_with_options, ApplyOptions, Policy, Request, Source, ZipInterpretationProfile};
use sealr_wheel_lab::{evaluate_wheel, WheelEvaluation, WheelLimits};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, System, ZipWriter};

const CORPUS: &str = "../../tests/corpus/wheels/hostile";

#[derive(Serialize, Deserialize)]
struct Manifest {
    schema: String,
    cases: Vec<ManifestCase>,
}

#[derive(Serialize, Deserialize)]
struct ManifestCase {
    id: String,
    filename: String,
    outer_filename: String,
    mutation: String,
    sha256: String,
    bytes: u64,
    status: String,
    finding: Option<String>,
}

struct Fixture {
    id: &'static str,
    mutation: &'static str,
    outer_filename: &'static str,
    expected_status: &'static str,
    expected_finding: Option<&'static str>,
    files: Vec<(&'static str, &'static [u8])>,
    record: RecordMutation,
}

#[derive(Clone, Copy)]
enum RecordMutation {
    None,
    WrongHash,
    WrongSize,
    MissingMember,
    Phantom,
    Duplicate,
}

#[test]
fn hostile_wheel_fixtures_are_minimized_deterministic_regressions() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS);
    let generated = fixtures()
        .into_iter()
        .map(|fixture| {
            let bytes = build_wheel(&fixture);
            let (status, finding) = evaluate(&fixture, &bytes);
            assert_eq!(status, fixture.expected_status, "{} status", fixture.id);
            assert_eq!(
                finding.as_deref(),
                fixture.expected_finding,
                "{} finding",
                fixture.id
            );
            let supported = evaluate_supported(&fixture, &bytes);
            assert_eq!(supported.0, status, "{} supported status", fixture.id);
            assert_eq!(supported.1, finding, "{} supported finding", fixture.id);
            let filename = format!("{}.whl", fixture.id);
            (
                ManifestCase {
                    id: fixture.id.into(),
                    filename: filename.clone(),
                    outer_filename: fixture.outer_filename.into(),
                    mutation: fixture.mutation.into(),
                    sha256: hex_sha256(&bytes),
                    bytes: bytes.len() as u64,
                    status,
                    finding,
                },
                filename,
                bytes,
            )
        })
        .collect::<Vec<_>>();

    if std::env::var_os("SEALR_UPDATE_WHEEL_FIXTURES").is_some() {
        fs::create_dir_all(&root).expect("create hostile corpus directory");
        for (_, filename, bytes) in &generated {
            fs::write(root.join(filename), bytes).expect("write hostile wheel fixture");
        }
        let manifest = Manifest {
            schema: "sealr.hostile-wheel-corpus.v1".into(),
            cases: generated
                .iter()
                .map(|(case, _, _)| ManifestCase {
                    id: case.id.clone(),
                    filename: case.filename.clone(),
                    outer_filename: case.outer_filename.clone(),
                    mutation: case.mutation.clone(),
                    sha256: case.sha256.clone(),
                    bytes: case.bytes,
                    status: case.status.clone(),
                    finding: case.finding.clone(),
                })
                .collect(),
        };
        let mut json = serde_json::to_vec_pretty(&manifest).expect("encode hostile manifest");
        json.push(b'\n');
        fs::write(root.join("manifest.json"), json).expect("write hostile manifest");
    }

    let committed: Manifest = serde_json::from_slice(
        &fs::read(root.join("manifest.json")).expect("read hostile manifest"),
    )
    .expect("parse hostile manifest");
    assert_eq!(committed.schema, "sealr.hostile-wheel-corpus.v1");
    assert_eq!(committed.cases.len(), generated.len());
    for ((expected, filename, bytes), actual) in generated.iter().zip(&committed.cases) {
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.filename, expected.filename);
        assert_eq!(actual.outer_filename, expected.outer_filename);
        assert_eq!(actual.mutation, expected.mutation);
        assert_eq!(actual.sha256, expected.sha256);
        assert_eq!(actual.bytes, expected.bytes);
        assert_eq!(actual.status, expected.status);
        assert_eq!(actual.finding, expected.finding);
        assert_eq!(
            fs::read(root.join(filename)).expect("read hostile fixture"),
            *bytes,
            "{} fixture bytes changed",
            expected.id
        );
    }
}

fn fixtures() -> Vec<Fixture> {
    vec![
        fixture("valid-control", "unmodified control", "admitted", None),
        fixture(
            "record-wrong-hash",
            "replace one canonical RECORD digest",
            "denied",
            Some("wheel.record-hash-mismatch"),
        )
        .with_record(RecordMutation::WrongHash),
        fixture(
            "record-wrong-size",
            "increase one RECORD size",
            "denied",
            Some("wheel.record-size-mismatch"),
        )
        .with_record(RecordMutation::WrongSize),
        fixture(
            "record-missing-member",
            "remove one member row",
            "denied",
            Some("wheel.record-member-missing"),
        )
        .with_record(RecordMutation::MissingMember),
        fixture(
            "record-phantom",
            "append a row for an absent member",
            "denied",
            Some("wheel.record-phantom"),
        )
        .with_record(RecordMutation::Phantom),
        fixture(
            "record-duplicate",
            "append a duplicate row",
            "denied",
            Some("wheel.record-duplicate"),
        )
        .with_record(RecordMutation::Duplicate),
        fixture(
            "relocation-collision",
            "map root and .data members to one target",
            "denied",
            Some("wheel.relocation-collision"),
        )
        .with_files(vec![
            ("shared.txt", b"root"),
            ("demo-1.0.data/purelib/shared.txt", b"relocated"),
        ]),
        fixture(
            "generated-target",
            "unsafe reserved console-script target",
            "denied",
            Some("wheel.generated-target-name"),
        )
        .with_files(vec![(
            "demo-1.0.dist-info/entry_points.txt",
            b"[console_scripts]\nCON = demo:main\n",
        )]),
        fixture(
            "metadata-disagreement",
            "METADATA Name disagrees with the filename",
            "denied",
            Some("wheel.filename-metadata-disagreement"),
        )
        .with_files(vec![(
            "demo-1.0.dist-info/METADATA",
            b"Metadata-Version: 2.4\nName: other\nVersion: 1.0\n",
        )]),
        fixture(
            "multiple-dist-info",
            "add a second top-level dist-info root",
            "denied",
            Some("wheel.dist-info-count"),
        )
        .with_files(vec![("other-1.0.dist-info/WHEEL", b"other")]),
        fixture(
            "non-nfc-path",
            "add a decomposed Unicode member path",
            "denied",
            Some("path.unicode"),
        )
        .with_files(vec![("demo/cafe\u{301}.txt", b"decomposed")]),
        fixture(
            "unknown-data-scheme",
            "add an unknown .data scheme key",
            "denied",
            Some("wheel.data-scheme"),
        )
        .with_files(vec![("demo-1.0.data/unknown/file.txt", b"unknown")]),
        fixture(
            "script-rewrite-control",
            "executable #!python script relocation",
            "admitted",
            None,
        )
        .with_files(vec![(
            "demo-1.0.data/scripts/demo-script",
            b"#!python\nprint('demo')\n",
        )]),
    ]
}

fn fixture(
    id: &'static str,
    mutation: &'static str,
    expected_status: &'static str,
    expected_finding: Option<&'static str>,
) -> Fixture {
    Fixture {
        id,
        mutation,
        outer_filename: "demo-1.0-py3-none-any.whl",
        expected_status,
        expected_finding,
        files: Vec::new(),
        record: RecordMutation::None,
    }
}

impl Fixture {
    fn with_files(mut self, files: Vec<(&'static str, &'static [u8])>) -> Self {
        self.files = files;
        self
    }

    fn with_record(mut self, record: RecordMutation) -> Self {
        self.record = record;
        self
    }
}

fn build_wheel(fixture: &Fixture) -> Vec<u8> {
    let mut files = BTreeMap::new();
    files.insert("demo/__init__.py", b"VALUE = 1\n".to_vec());
    files.insert(
        "demo-1.0.dist-info/WHEEL",
        b"Wheel-Version: 1.0\nGenerator: sealr-hostile-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n".to_vec(),
    );
    files.insert(
        "demo-1.0.dist-info/METADATA",
        b"Metadata-Version: 2.4\nName: demo\nVersion: 1.0\n".to_vec(),
    );
    for (path, bytes) in &fixture.files {
        files.insert(*path, bytes.to_vec());
    }
    let mut rows = files
        .iter()
        .map(|(path, bytes)| {
            format!(
                "{path},sha256={},{}",
                base64url(&Sha256::digest(bytes)),
                bytes.len()
            )
        })
        .collect::<Vec<_>>();
    match fixture.record {
        RecordMutation::None => {}
        RecordMutation::WrongHash => {
            let fields = rows[0].split(',').collect::<Vec<_>>();
            rows[0] = format!(
                "{},sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,{}",
                fields[0], fields[2]
            );
        }
        RecordMutation::WrongSize => {
            let fields = rows[0].split(',').collect::<Vec<_>>();
            rows[0] = format!(
                "{},{},{}",
                fields[0],
                fields[1],
                fields[2].parse::<u64>().unwrap() + 1
            );
        }
        RecordMutation::MissingMember => {
            rows.retain(|row| !row.starts_with("demo/__init__.py,"));
        }
        RecordMutation::Phantom => {
            rows.push("ghost.py,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,0".into())
        }
        RecordMutation::Duplicate => rows.push(rows[0].clone()),
    }
    rows.push("demo-1.0.dist-info/RECORD,,".into());
    files.insert(
        "demo-1.0.dist-info/RECORD",
        (rows.join("\n") + "\n").into_bytes(),
    );
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
                .compression_method(CompressionMethod::Stored)
                .last_modified_time(DateTime::DEFAULT)
                .system(System::Unix)
                .unix_permissions(permissions);
            writer.start_file(path, options).unwrap();
            writer.write_all(&bytes).unwrap();
        }
        writer.finish().unwrap();
    }
    cursor.into_inner()
}

fn evaluate(fixture: &Fixture, bytes: &[u8]) -> (String, Option<String>) {
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::WheelUtf8V1);
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some(fixture.outer_filename),
                data: bytes,
            },
            policy: &policy,
            dest: None,
        },
        &options,
    );
    if outcome.rejected() {
        return (
            "denied".into(),
            outcome
                .view
                .findings
                .first()
                .map(|finding| finding.code.as_str().to_owned()),
        );
    }
    let archive = outcome
        .verified_archive()
        .expect("verified hostile fixture");
    match evaluate_wheel(fixture.outer_filename, archive, WheelLimits::default()) {
        WheelEvaluation::Admitted { .. } => ("admitted".into(), None),
        WheelEvaluation::Denied { findings } => ("denied".into(), Some(findings[0].code.clone())),
        WheelEvaluation::Unsupported { findings } => {
            ("unsupported".into(), Some(findings[0].code.clone()))
        }
        WheelEvaluation::InfrastructureFailure { detail } => {
            panic!("fixture evaluation infrastructure failure: {detail}")
        }
    }
}

fn evaluate_supported(fixture: &Fixture, bytes: &[u8]) -> (String, Option<String>) {
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some(fixture.outer_filename),
                data: bytes,
            },
            policy: &policy,
            dest: None,
        },
        &options,
    );
    if outcome.rejected() {
        return (
            "denied".into(),
            outcome
                .view
                .findings
                .first()
                .map(|finding| finding.code.as_str().to_owned()),
        );
    }
    let archive = outcome
        .verified_archive()
        .expect("verified hostile fixture");
    match evaluate_supported_wheel(
        fixture.outer_filename,
        archive,
        SupportedWheelLimits::default(),
    ) {
        SupportedWheelEvaluation::Admitted { .. } => ("admitted".into(), None),
        SupportedWheelEvaluation::Denied { findings } => {
            ("denied".into(), Some(findings[0].code.clone()))
        }
        SupportedWheelEvaluation::Unsupported { findings } => {
            ("unsupported".into(), Some(findings[0].code.clone()))
        }
        SupportedWheelEvaluation::InfrastructureFailure { detail, .. } => {
            panic!("fixture evaluation infrastructure failure: {detail}")
        }
        _ => panic!("fixture evaluation returned an unknown outcome"),
    }
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
