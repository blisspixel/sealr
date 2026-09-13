//! Shared public-API measurement used by the corpus tool and packaged tests.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use sealr::wheel::{evaluate_wheel, WheelEvaluation, WheelLimits};
use sealr::{apply_with_options, ApplyOptions, Policy, Request, Source, ZipInterpretationProfile};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vectors {
    pub schema: String,
    pub producer: Value,
    pub selection: String,
    pub fixtures: Vec<Fixture>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub id: String,
    pub filename: String,
    pub derivation: String,
    pub expected_outcome: String,
    pub source_sha256: String,
    pub source_bytes: usize,
    pub source_hex: String,
    pub members: Vec<Member>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub path: String,
    pub content_hex: String,
}

pub fn decode_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn load(bytes: &[u8]) -> Vectors {
    let vectors: Vectors = serde_json::from_slice(bytes).expect("closed producer vector schema");
    assert_eq!(vectors.schema, "sealr.wheel-producer-vectors.v1");
    assert_eq!(vectors.producer["implementation"], "CPython");
    assert_eq!(vectors.producer["python"], "3.12.10");
    assert!(vectors.selection.contains("not external adoption"));
    assert_eq!(vectors.fixtures.len(), 24);
    let ids: BTreeSet<_> = vectors.fixtures.iter().map(|f| &f.id).collect();
    assert_eq!(ids.len(), vectors.fixtures.len());
    vectors
}

/// A supplied source path is consumed, then deleted before wheel evaluation.
/// A destination requests actual native no-replace materialization.
pub fn measure(fixture: &Fixture, source_path: Option<&Path>, dest: Option<&Path>) -> Value {
    let bytes = decode_hex(&fixture.source_hex);
    assert_eq!(bytes.len(), fixture.source_bytes, "{}", fixture.id);
    assert_eq!(digest(&bytes), fixture.source_sha256, "{}", fixture.id);
    assert!(!fixture.derivation.is_empty());
    if let Some(path) = source_path {
        fs::write(path, &bytes).unwrap();
    }
    let source = match source_path {
        Some(path) => Source::Path(path),
        None => Source::Bytes {
            path: Some(&fixture.filename),
            data: &bytes,
        },
    };
    let outcome = apply_with_options(
        Request {
            source,
            policy: &Policy::default_v1(),
            dest,
        },
        &ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1),
    );
    if let Some(path) = source_path {
        fs::remove_file(path).unwrap();
        assert!(!path.exists());
    }
    let archive_findings: Vec<_> = outcome
        .view
        .findings
        .iter()
        .map(|f| f.code.as_str())
        .collect();
    let mut report = json!({
        "id": fixture.id,
        "source_sha256": fixture.source_sha256,
        "archive_findings": archive_findings,
    });
    let Some(archive) = outcome.verified_archive() else {
        assert!(outcome.rejected());
        if let Some(dest) = dest {
            assert!(!dest.exists(), "rejection published a destination");
        }
        report["outcome"] = json!("archive-rejected");
        assert_eq!(
            fixture.expected_outcome, "archive-rejected",
            "{}: {report}",
            fixture.id
        );
        return report;
    };
    assert!(!outcome.rejected());
    assert_eq!(archive.members().len(), fixture.members.len());
    let mut methods = BTreeSet::new();
    let mut descriptor_members = 0;
    let mut unicode_members = 0;
    for expected in &fixture.members {
        let member = archive
            .member(&expected.path)
            .expect("producer path preserved exactly");
        let content = decode_hex(&expected.content_hex);
        assert_eq!(
            archive
                .read_member(&expected.path, content.len() as u64)
                .unwrap(),
            content
        );
        if !content.is_empty() {
            assert!(archive
                .read_member(&expected.path, content.len() as u64 - 1)
                .is_err());
            let prefix = archive.read_member_prefix(&expected.path, 3).unwrap();
            assert_eq!(prefix, &content[..content.len().min(3)]);
        }
        assert_eq!(
            member.content_sha256.as_deref(),
            Some(digest(&content).as_str())
        );
        let zip = member.zip_evidence().unwrap();
        methods.insert(zip.method);
        descriptor_members += usize::from(zip.flags & 8 != 0);
        if !expected.path.is_ascii() {
            unicode_members += 1;
            assert_ne!(zip.flags & 0x800, 0);
        }
        if let Some(dest) = dest {
            assert_eq!(fs::read(dest.join(&expected.path)).unwrap(), content);
        }
    }
    report["methods"] = json!(methods);
    report["descriptor_members"] = json!(descriptor_members);
    report["unicode_members"] = json!(unicode_members);
    report["member_count"] = json!(archive.members().len());
    match evaluate_wheel(&fixture.filename, archive, WheelLimits::default()) {
        WheelEvaluation::Admitted {
            artifact,
            plan,
            identities,
            ..
        } => {
            report["outcome"] = json!("admitted");
            report["identities"] = serde_json::to_value(identities).unwrap();
            report["consumer_profile_digest"] = json!(artifact.consumer_profile_digest);
            report["plan"] = serde_json::to_value(plan.entries()).unwrap();
        }
        WheelEvaluation::Denied { findings, .. } => {
            report["outcome"] = json!("wheel-denied");
            report["wheel_findings"] =
                json!(findings.iter().map(|f| f.code.as_str()).collect::<Vec<_>>());
        }
        other => panic!("unexpected wheel result for {}: {other:?}", fixture.id),
    }
    assert_eq!(
        report["outcome"], fixture.expected_outcome,
        "{}: {report}",
        fixture.id
    );
    report
}
