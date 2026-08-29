//! Guard tests for the declaration-order canonical encoding contract.
//!
//! [`docs/evidence-encoding.md`] states the normative encoding behind the
//! policy v1-v11 digests and the receipt's `view_digest`. These tests hold the
//! machine-checkable half of that statement: the emitted JSON stays inside the
//! integer-only, ASCII-key, float-free domain an external verifier can
//! reproduce, and the digests cover exactly the compact bytes the contract
//! names.

use std::io::{Cursor, Write};

use sealr::{apply, Policy, Request, Source};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

/// Largest integer exactly representable as an IEEE-754 double, the ceiling a
/// future RFC 8785 lineage must observe. The declaration-order contract keeps
/// every emitted integer inside it so the same values survive both lineages.
const MAX_DOUBLE_SAFE_INTEGER: u64 = (1 << 53) - 1;

fn assert_canonical_domain(value: &Value, path: &str) {
    match value {
        Value::Null | Value::Bool(_) => {}
        Value::Number(number) => {
            assert!(
                !number.is_f64(),
                "{path} carries a float; the evidence domain is integer-only"
            );
            let magnitude = number
                .as_u64()
                .or_else(|| number.as_i64().map(i64::unsigned_abs))
                .unwrap_or_else(|| panic!("{path} carries a non-integer number"));
            assert!(
                magnitude <= MAX_DOUBLE_SAFE_INTEGER,
                "{path} carries {magnitude}, above the 2^53-1 double-safe ceiling"
            );
        }
        Value::String(_) => {}
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                assert_canonical_domain(item, &format!("{path}[{index}]"));
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                assert!(
                    key.is_ascii(),
                    "{path}.{key} uses a non-ASCII object key; keys are fixed ASCII names"
                );
                assert_canonical_domain(item, &format!("{path}.{key}"));
            }
        }
    }
}

fn default_policies() -> Vec<Policy> {
    vec![
        Policy::default_v1(),
        Policy::default_v2(),
        Policy::default_v3(),
        Policy::default_v4(),
        Policy::default_v5(),
        Policy::default_v6(),
        Policy::default_v7(),
        Policy::default_v8(),
        Policy::default_v9(),
        Policy::default_v10(),
        Policy::default_v11(),
    ]
}

#[test]
fn every_default_policy_stays_inside_the_canonical_integer_domain() {
    for policy in default_policies() {
        let value = serde_json::to_value(&policy).expect("policy serializes");
        assert_canonical_domain(&value, &policy.id);
    }
}

#[test]
fn the_conditional_derived_bytes_field_is_present_exactly_when_set() {
    for policy in default_policies() {
        let value = serde_json::to_value(&policy).expect("policy serializes");
        let serialized_field = value
            .as_object()
            .expect("policy is an object")
            .contains_key("max_derived_archive_bytes");
        assert_eq!(
            serialized_field,
            policy.max_derived_archive_bytes.is_some(),
            "{}: max_derived_archive_bytes must serialize exactly when it is set",
            policy.id
        );
    }
}

fn fixture_zip() -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer.start_file("hello.txt", options).expect("member");
        writer.write_all(b"sealed evidence").expect("payload");
        writer.finish().expect("finish");
    }
    cursor.into_inner()
}

#[test]
fn views_and_receipts_stay_inside_the_canonical_integer_domain() {
    let bytes = fixture_zip();
    let policy = Policy::default_v1();
    let outcome = apply(Request {
        source: Source::Bytes {
            path: Some("evidence.zip"),
            data: &bytes,
        },
        policy: &policy,
        dest: None,
    });
    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);

    let view = serde_json::to_value(&outcome.view).expect("view serializes");
    let receipt = serde_json::to_value(&outcome.receipt).expect("receipt serializes");
    assert_canonical_domain(&view, "view");
    assert_canonical_domain(&receipt, "receipt");
}

#[test]
fn the_view_digest_covers_exactly_the_compact_declaration_order_bytes() {
    let bytes = fixture_zip();
    let policy = Policy::default_v1();
    let outcome = apply(Request {
        source: Source::Bytes {
            path: Some("evidence.zip"),
            data: &bytes,
        },
        policy: &policy,
        dest: None,
    });
    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);

    let compact = serde_json::to_vec(&outcome.view).expect("compact view bytes");
    let digest: String = Sha256::digest(&compact)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        outcome.receipt.view_digest.sha256, digest,
        "view_digest must cover the compact declaration-order view bytes"
    );

    let pretty = serde_json::to_vec_pretty(&outcome.view).expect("pretty view bytes");
    assert_ne!(
        compact, pretty,
        "the pretty presentation is distinct from the digested compact bytes; \
         the contract documents this split explicitly"
    );
}

#[test]
fn the_policy_digest_covers_exactly_the_compact_declaration_order_bytes() {
    for policy in default_policies() {
        let compact = serde_json::to_vec(&policy).expect("compact policy bytes");
        let digest: String = Sha256::digest(&compact)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            policy.digest_hex(),
            digest,
            "{}: policy digest must cover the compact declaration-order bytes",
            policy.id
        );
    }
}

fn rejected_fixture_zip() -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer.start_file("../escape.txt", options).expect("member");
        writer.write_all(b"outside").expect("payload");
        writer.finish().expect("finish");
    }
    cursor.into_inner()
}

fn apply_fixture(bytes: &[u8]) -> sealr::Outcome {
    let policy = Policy::default_v1();
    apply(Request {
        source: Source::Bytes {
            path: Some("evidence.zip"),
            data: bytes,
        },
        policy: &policy,
        dest: None,
    })
}

#[test]
fn canonical_evidence_bytes_are_exactly_the_digested_bytes() {
    let outcome = apply_fixture(&fixture_zip());
    assert!(!outcome.rejected());
    let evidence = outcome
        .canonical_evidence()
        .expect("canonicalization is total");

    let view_digest: String = Sha256::digest(&evidence.view_bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(evidence.view_digest, view_digest);
    let receipt_digest: String = Sha256::digest(&evidence.receipt_bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(evidence.receipt_digest, receipt_digest);

    let receipt: Value = serde_json::from_slice(&evidence.receipt_bytes).expect("one document");
    assert_eq!(receipt["schema"], "sealr.receipt.v3");
    assert_eq!(receipt["canonicalization"], "rfc8785");
    assert_eq!(receipt["view_schema"], "sealr.view.v2");
    assert_eq!(receipt["view_digest"]["sha256"], view_digest);

    let view: Value = serde_json::from_slice(&evidence.view_bytes).expect("one document");
    assert_eq!(view["schema"], "sealr.view.v2");

    assert_eq!(*evidence.view_bytes.last().unwrap(), b'}');
    assert_eq!(*evidence.receipt_bytes.last().unwrap(), b'}');
}

#[test]
fn the_canonical_lineage_carries_identical_semantic_content() {
    let outcome = apply_fixture(&fixture_zip());
    let evidence = outcome
        .canonical_evidence()
        .expect("canonicalization is total");

    let mut v1_view = serde_json::to_value(&outcome.view).expect("v1 view");
    let mut v2_view: Value = serde_json::from_slice(&evidence.view_bytes).expect("v2 view");
    assert_eq!(v1_view["schema"], "sealr.view.v1");
    assert_eq!(v2_view["schema"], "sealr.view.v2");
    v1_view.as_object_mut().unwrap().remove("schema");
    v2_view.as_object_mut().unwrap().remove("schema");
    assert_eq!(v1_view, v2_view, "views must differ only in schema");

    let mut v2_receipt = serde_json::to_value(&outcome.receipt).expect("v2 receipt");
    let mut v3_receipt: Value =
        serde_json::from_slice(&evidence.receipt_bytes).expect("v3 receipt");
    for key in ["schema", "canonicalization", "view_schema", "view_digest"] {
        v2_receipt.as_object_mut().unwrap().remove(key);
        v3_receipt.as_object_mut().unwrap().remove(key);
    }
    assert_eq!(
        v2_receipt, v3_receipt,
        "receipts must differ only in the four enumerated fields"
    );
}

#[test]
fn the_shipped_receipt_lineage_never_carries_the_canonicalization_fields() {
    let outcome = apply_fixture(&fixture_zip());
    let receipt = serde_json::to_value(&outcome.receipt).expect("receipt");
    let object = receipt.as_object().expect("object");
    assert_eq!(receipt["schema"], "sealr.receipt.v2");
    assert!(!object.contains_key("canonicalization"));
    assert!(!object.contains_key("view_schema"));
}

#[test]
fn canonicalization_is_total_on_rejection_paths_and_deterministic() {
    let outcome = apply_fixture(&rejected_fixture_zip());
    assert!(outcome.rejected());
    let first = outcome
        .canonical_evidence()
        .expect("rejected outcomes canonicalize");
    let second = outcome
        .canonical_evidence()
        .expect("rejected outcomes canonicalize");
    assert_eq!(first.view_bytes, second.view_bytes);
    assert_eq!(first.receipt_bytes, second.receipt_bytes);

    let view: Value = serde_json::from_slice(&first.view_bytes).expect("one document");
    assert_eq!(view["verdict"], "rejected");
    assert_canonical_domain(&view, "rejected canonical view");
    let receipt: Value = serde_json::from_slice(&first.receipt_bytes).expect("one document");
    assert_canonical_domain(&receipt, "rejected canonical receipt");
}
