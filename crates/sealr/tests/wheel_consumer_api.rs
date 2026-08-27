//! Downstream contract tests for the supported wheel consumer.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use sealr::wheel::{evaluate_wheel, WheelEvaluation, WheelLimits, CONSUMER_PROFILE_ID};
use sealr::{
    apply_with_options, ApplyOptions, Policy, Request, Source, ZipInterpretationProfile,
    ZIP_PORTABLE_UTF8_V1,
};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const WHEEL: &[u8] =
    b"Wheel-Version: 1.0\nGenerator: sealr-api-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n";
const METADATA: &[u8] = b"Metadata-Version: 2.4\nName: demo\nVersion: 1.0\n\n";

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "sealr-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        fs::create_dir(&path).expect("create test directory");
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

fn wheel_bytes() -> Vec<u8> {
    let mut files = BTreeMap::new();
    files.insert("demo/caf\u{e9}.py".to_owned(), b"VALUE = 1\n".to_vec());
    files.insert("demo-1.0.dist-info/WHEEL".to_owned(), WHEEL.to_vec());
    files.insert("demo-1.0.dist-info/METADATA".to_owned(), METADATA.to_vec());

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
    files.insert("demo-1.0.dist-info/RECORD".to_owned(), record.into_bytes());

    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (path, bytes) in files {
            writer
                .start_file(path, options)
                .expect("start wheel member");
            writer.write_all(&bytes).expect("write wheel member");
        }
        writer.finish().expect("finish wheel");
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

#[test]
fn supported_consumer_uses_only_the_verified_capability_after_source_deletion() {
    let temp = TestDir::new("wheel-consumer-api");
    let source = temp.path().join("demo-1.0-py3-none-any.whl");
    fs::write(&source, wheel_bytes()).expect("write wheel fixture");

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
    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
    let archive = outcome
        .verified_archive()
        .expect("verified wheel capability")
        .clone();
    fs::remove_file(&source).expect("remove original wheel");

    let first = evaluate_wheel(
        "demo-1.0-py3-none-any.whl",
        &archive,
        WheelLimits::default(),
    );
    let second = evaluate_wheel(
        "demo-1.0-py3-none-any.whl",
        &archive,
        WheelLimits::default(),
    );
    assert_eq!(first, second);
    assert!(
        !source.exists(),
        "consumer must not recreate or reopen the source"
    );

    let WheelEvaluation::Admitted {
        artifact,
        plan,
        identities,
        ..
    } = first
    else {
        panic!("valid wheel was not admitted");
    };
    assert_eq!(artifact.consumer_profile, CONSUMER_PROFILE_ID);
    assert_eq!(
        artifact.consumer_profile_digest,
        "d10b535baea72217bf12703468b200bdd2557a4a747f57fc211480216d1c7263"
    );
    assert_eq!(artifact.interpretation_profile, ZIP_PORTABLE_UTF8_V1);
    assert!(artifact
        .record
        .iter()
        .any(|binding| binding.path == "demo/caf\u{e9}.py"));
    assert_eq!(plan.artifact_sha256(), identities.artifact_sha256);
    assert_eq!(
        identities.source_sha256,
        "6f7e1b33fcd0ea3bcee2ad9bb3cbd946a4d3ad8a29c70632fcb8b27752292082"
    );
    assert_eq!(
        identities.archive_tree_sha256,
        "600896f7db6d95a0a66aadf436d8dce68752ed7406b4fea739d3e9cf88d4b612"
    );
    assert_eq!(
        identities.artifact_sha256,
        "122788049c0b2487bd349a338927e3332d11bb82ef2b36e5d4a83d35b9b765aa"
    );
    assert_eq!(
        identities.install_plan_sha256,
        "0341aca87f33afea6e8cc4d0e755156aaafc1248df0a26d2923552446976aa24"
    );
    assert_eq!(
        [
            identities.source_sha256.as_str(),
            identities.archive_tree_sha256.as_str(),
            identities.artifact_sha256.as_str(),
            identities.install_plan_sha256.as_str(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .len(),
        4
    );
}

#[test]
fn wrong_container_profile_is_unsupported_not_denied() {
    let bytes = wheel_bytes();
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::WheelUtf8V1);
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("demo-1.0-py3-none-any.whl"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        },
        &options,
    );
    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);

    let evaluation = evaluate_wheel(
        "demo-1.0-py3-none-any.whl",
        outcome.verified_archive().expect("verified archive"),
        WheelLimits::default(),
    );
    let WheelEvaluation::Unsupported { findings } = evaluation else {
        panic!("wrong profile must be unsupported");
    };
    assert_eq!(findings[0].code, "wheel.container-profile");
}
