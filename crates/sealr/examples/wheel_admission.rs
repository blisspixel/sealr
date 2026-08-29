//! End-to-end downstream consumer demonstration: one parse, one verified
//! capability, and a wheel installation planned and realized without the
//! source archive ever being reopened.
//!
//! ```text
//! cargo run --locked -p sealr --example wheel_admission
//! ```
//!
//! The demonstration runs three scenarios:
//!
//! 1. A valid wheel is admitted once. The original file is then DELETED, and
//!    the consumer evaluates, plans, materializes, and computes the
//!    realization identity purely from the retained verified capability.
//! 2. A hostile container with a `..` member path never becomes a capability
//!    at all: admission itself fails closed.
//! 3. An admitted container whose `RECORD` lies about a member hash is denied
//!    by the wheel consumer with an exact finding, and nothing is installed.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Write as _};
use std::path::{Path, PathBuf};

use sealr::wheel::{evaluate_wheel, RealizedOutput, WheelEvaluation, WheelLimits};
use sealr::{
    apply_with_options, ApplyOptions, Policy, Request, Source, VerifiedArchive,
    ZipInterpretationProfile,
};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, System, ZipWriter};

const WHEEL_NAME: &str = "demo-1.0-py3-none-any.whl";
const MAX_DEMO_MEMBER_BYTES: u64 = 1 << 20;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

fn zip_bytes(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .compression_level(Some(6))
            .last_modified_time(DateTime::DEFAULT)
            .unix_permissions(0o644)
            .system(System::Unix);
        for (path, bytes) in files {
            writer.start_file(path, options).expect("start zip member");
            writer.write_all(bytes).expect("write zip member");
        }
        writer.finish().expect("finish zip");
    }
    cursor.into_inner()
}

/// Build a small valid wheel. When `lying_record` is set, the recorded hash
/// of the module file is replaced with the hash of different bytes.
fn wheel_bytes(lying_record: bool) -> Vec<u8> {
    let mut files = BTreeMap::new();
    files.insert(
        "demo/greet.py".to_owned(),
        b"def greet():\n    return \"sealed\"\n".to_vec(),
    );
    files.insert(
        "demo-1.0.dist-info/WHEEL".to_owned(),
        b"Wheel-Version: 1.0\nGenerator: sealr-demo\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
            .to_vec(),
    );
    files.insert(
        "demo-1.0.dist-info/METADATA".to_owned(),
        b"Metadata-Version: 2.6\nName: demo\nVersion: 1.0\n\n".to_vec(),
    );

    let mut record = String::new();
    for (path, bytes) in &files {
        let hashed: &[u8] = if lying_record && path == "demo/greet.py" {
            b"different bytes entirely\n"
        } else {
            bytes
        };
        record.push_str(path);
        record.push_str(",sha256=");
        record.push_str(&base64url(&Sha256::digest(hashed)));
        record.push(',');
        record.push_str(&bytes.len().to_string());
        record.push('\n');
    }
    record.push_str("demo-1.0.dist-info/RECORD,,\n");
    files.insert("demo-1.0.dist-info/RECORD".to_owned(), record.into_bytes());
    zip_bytes(&files)
}

fn admit(path: &Path) -> Result<VerifiedArchive, Vec<String>> {
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
    let outcome = apply_with_options(
        Request {
            source: Source::Path(path),
            policy: &policy,
            dest: None,
        },
        &options,
    );
    match outcome.verified_archive() {
        Some(archive) => Ok(archive.clone()),
        None => Err(outcome
            .view
            .findings
            .iter()
            .map(|finding| format!("{} ({})", finding.code.as_str(), finding.detail))
            .collect()),
    }
}

fn demo_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "sealr-wheel-admission-demo-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    fs::create_dir(&path).expect("create demo directory");
    path
}

fn main() {
    let root = demo_dir();

    // Scenario 1: admit once, delete the source, consume the capability.
    println!("== 1. Valid wheel: admit once, delete the source, install ==");
    let source = root.join(WHEEL_NAME);
    fs::write(&source, wheel_bytes(false)).expect("write demo wheel");
    let archive = admit(&source).expect("valid demo wheel should be admitted");
    fs::remove_file(&source).expect("delete original wheel");
    println!("   admitted, source deleted: {}", !source.exists());
    println!(
        "   verified source sha256:    {}",
        archive.source_digest().sha256().unwrap_or("?")
    );

    let evaluation = evaluate_wheel(WHEEL_NAME, &archive, WheelLimits::default());
    let WheelEvaluation::Admitted {
        plan, identities, ..
    } = evaluation
    else {
        panic!("valid wheel was not admitted: {evaluation:?}");
    };
    println!("   artifact identity:         {}", identities.artifact_sha256);
    println!(
        "   install plan identity:     {}",
        identities.install_plan_sha256
    );

    let site = root.join("site");
    let mut outputs = Vec::new();
    for entry in plan.entries() {
        let Some(source_path) = entry.source_path.as_deref() else {
            println!("   (skipping generated target {})", entry.relative_path);
            continue;
        };
        let bytes = archive
            .read_member(source_path, MAX_DEMO_MEMBER_BYTES)
            .expect("planned member should be readable from the capability");
        let target = site
            .join(format!("{:?}", entry.scheme).to_lowercase())
            .join(&entry.relative_path);
        fs::create_dir_all(target.parent().expect("target parent"))
            .expect("create target directory");
        fs::write(&target, &bytes).expect("write installed file");
        outputs.push(RealizedOutput::new(
            entry.scheme.clone(),
            entry.relative_path.clone(),
            hex(&Sha256::digest(&bytes)),
            bytes.len() as u64,
        ));
        println!("   installed {}", target.display());
    }
    let realization = sealr::wheel::realize_identity(
        &plan,
        "sealr-demo-target-v1",
        "sealr-demo-policy-v1",
        &outputs,
    )
    .expect("realization identity");
    println!("   realization identity:      {realization}");

    // Scenario 2: a hostile container never becomes a capability.
    println!("== 2. Hostile container: `..` member path ==");
    let hostile = root.join("hostile-1.0-py3-none-any.whl");
    let mut files = BTreeMap::new();
    files.insert("../escape.py".to_owned(), b"import os\n".to_vec());
    fs::write(&hostile, zip_bytes(&files)).expect("write hostile zip");
    match admit(&hostile) {
        Ok(_) => panic!("hostile container must not be admitted"),
        Err(findings) => {
            for finding in findings {
                println!("   rejected at admission: {finding}");
            }
        }
    }

    // Scenario 3: an admitted container whose RECORD lies is denied.
    println!("== 3. Lying RECORD: admitted container, denied wheel ==");
    let lying = root.join(WHEEL_NAME);
    fs::write(&lying, wheel_bytes(true)).expect("write lying wheel");
    let archive = admit(&lying).expect("container itself is well-formed");
    fs::remove_file(&lying).expect("delete lying wheel");
    match evaluate_wheel(WHEEL_NAME, &archive, WheelLimits::default()) {
        WheelEvaluation::Denied { findings } => {
            for finding in findings {
                println!(
                    "   denied: {} ({}){}",
                    finding.code,
                    finding.detail,
                    finding
                        .path
                        .map(|path| format!(" at {path}"))
                        .unwrap_or_default()
                );
            }
        }
        other => panic!("lying RECORD must deny the wheel: {other:?}"),
    }

    fs::remove_dir_all(&root).expect("remove demo directory");
    println!("== Done. One parse, one meaning, one verified tree. ==");
}
