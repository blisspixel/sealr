//! Wrap a Sealr receipt file into an unsigned in-toto Statement v1.
//!
//! This tool performs JSON assembly and contains no cryptography. Canonical
//! receipt v3 input is accepted only after the independent verifier checks its
//! matching view and source archive. The receipt JSON token is embedded
//! verbatim as the predicate for an external DSSE signer.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::process::ExitCode;

use sealr_identity_verifier::{
    reject_duplicate_json_properties, verify_canonical_evidence, MAX_EVIDENCE_BYTES,
};
use serde::Serialize;
use serde_json::value::RawValue;
use serde_json::Value;
use sha2::{Digest, Sha256};

const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
const PREDICATE_TYPE_V2: &str = "https://github.com/blisspixel/sealr/receipt/v2";
const PREDICATE_TYPE_V3: &str = "https://github.com/blisspixel/sealr/receipt/v3";
const DEFAULT_SUBJECT_NAME: &str = "archive";
const MAX_RECEIPT_BYTES: u64 = MAX_EVIDENCE_BYTES as u64;

fn usage() -> String {
    "usage: sealr-attest statement --receipt <FILE> --out <NEW_FILE> \
     [--view <VIEW>] [--source <ARCHIVE>] [--subject-name <NAME>] \
     [--predicate-type <URI>]"
        .to_owned()
}

struct Arguments {
    view: Option<String>,
    receipt: String,
    source: Option<String>,
    out: String,
    subject_name: String,
    predicate_type: Option<String>,
}

fn parse_arguments(mut args: impl Iterator<Item = String>) -> Result<Arguments, String> {
    if args.next().as_deref() != Some("statement") {
        return Err(usage());
    }
    let mut view = None;
    let mut receipt = None;
    let mut source = None;
    let mut out = None;
    let mut subject_name = None;
    let mut predicate_type = None;
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "--view" => &mut view,
            "--receipt" => &mut receipt,
            "--source" => &mut source,
            "--out" => &mut out,
            "--subject-name" => &mut subject_name,
            "--predicate-type" => &mut predicate_type,
            other => return Err(format!("unknown argument {other:?}\n{}", usage())),
        };
        if slot.is_some() {
            return Err(format!("{flag} was given twice\n{}", usage()));
        }
        *slot = Some(
            args.next()
                .ok_or_else(|| format!("{flag} requires a value\n{}", usage()))?,
        );
    }
    Ok(Arguments {
        view,
        receipt: receipt.ok_or_else(usage)?,
        source,
        out: out.ok_or_else(usage)?,
        subject_name: subject_name.unwrap_or_else(|| DEFAULT_SUBJECT_NAME.to_owned()),
        predicate_type,
    })
}

#[derive(Serialize)]
struct Statement<'a> {
    #[serde(rename = "_type")]
    statement_type: &'static str,
    subject: [Subject<'a>; 1],
    #[serde(rename = "predicateType")]
    predicate_type: &'a str,
    predicate: &'a RawValue,
}

#[derive(Serialize)]
struct Subject<'a> {
    name: &'a str,
    digest: SubjectDigest<'a>,
}

#[derive(Serialize)]
struct SubjectDigest<'a> {
    sha256: &'a str,
}

fn build_statement(
    receipt_bytes: &[u8],
    view_bytes: Option<&[u8]>,
    observed_source_sha256: Option<&str>,
    arguments: &Arguments,
) -> Result<Vec<u8>, String> {
    reject_duplicate_json_properties(receipt_bytes)
        .map_err(|error| format!("receipt file was rejected: {error}"))?;
    let receipt: Value = serde_json::from_slice(receipt_bytes)
        .map_err(|error| format!("receipt file is not one JSON document: {error}"))?;
    let predicate: &RawValue = serde_json::from_slice(receipt_bytes)
        .map_err(|error| format!("receipt predicate could not be preserved: {error}"))?;
    let schema = receipt
        .get("schema")
        .and_then(Value::as_str)
        .ok_or("receipt carries no schema field")?;
    let default_predicate_type = match schema {
        "sealr.receipt.v2" => PREDICATE_TYPE_V2,
        "sealr.receipt.v3" => {
            let view = view_bytes.ok_or(
                "sealr.receipt.v3 requires --view so its canonical evidence can be verified",
            )?;
            let observed_source_sha256 = observed_source_sha256.ok_or(
                "sealr.receipt.v3 requires --source so its subject is checked against archive bytes",
            )?;
            verify_canonical_evidence(view, receipt_bytes, Some(observed_source_sha256))
                .map_err(|error| format!("canonical evidence was rejected: {error}"))?;
            PREDICATE_TYPE_V3
        }
        other => {
            return Err(format!(
                "receipt schema {other:?} is not supported; expected sealr.receipt.v2 or sealr.receipt.v3"
            ));
        }
    };
    if schema == "sealr.receipt.v2" && view_bytes.is_some() {
        return Err("--view is only valid with sealr.receipt.v3".to_owned());
    }

    let source_sha256 = receipt
        .get("source")
        .and_then(|source| source.get("sha256"))
        .and_then(Value::as_str)
        .ok_or(
            "receipt source digest is unavailable; an attestation must bind the exact \
             evaluated bytes, so a receipt without a source digest is refused",
        )?;
    verify_sha256(source_sha256, "receipt source digest")?;
    if let Some(observed) = observed_source_sha256 {
        verify_sha256(observed, "observed source digest")?;
        if observed != source_sha256 {
            return Err("receipt source digest does not match --source archive bytes".to_owned());
        }
    }

    let predicate_type = arguments
        .predicate_type
        .as_deref()
        .unwrap_or(default_predicate_type);
    let statement = Statement {
        statement_type: STATEMENT_TYPE,
        subject: [Subject {
            name: &arguments.subject_name,
            digest: SubjectDigest {
                sha256: source_sha256,
            },
        }],
        predicate_type,
        predicate,
    };
    let mut output = serde_json::to_vec_pretty(&statement)
        .map_err(|error| format!("statement was not encoded: {error}"))?;
    output.push(b'\n');
    Ok(output)
}

fn verify_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{label} is not lowercase hex SHA-256"))
    }
}

fn read_bounded(path: &str, label: &str) -> Result<Vec<u8>, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("{label} file was not readable: {error}"))?;
    if metadata.len() > MAX_RECEIPT_BYTES {
        return Err(format!(
            "{label} file of {} bytes exceeds the {MAX_RECEIPT_BYTES}-byte bound",
            metadata.len()
        ));
    }
    fs::read(path).map_err(|error| format!("{label} file was not readable: {error}"))
}

fn hash_source(path: &str) -> Result<String, String> {
    let mut source =
        File::open(path).map_err(|error| format!("source archive was not readable: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|error| format!("source archive was not readable: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(lower_hex(&digest.finalize()))
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}

fn run(arguments: &Arguments) -> Result<(), String> {
    let receipt_bytes = read_bounded(&arguments.receipt, "receipt")?;
    let view_bytes = arguments
        .view
        .as_deref()
        .map(|path| read_bounded(path, "view"))
        .transpose()?;
    let source_sha256 = arguments.source.as_deref().map(hash_source).transpose()?;
    let statement = build_statement(
        &receipt_bytes,
        view_bytes.as_deref(),
        source_sha256.as_deref(),
        arguments,
    )?;
    let mut out = File::create_new(&arguments.out)
        .map_err(|error| format!("output file {} was not created: {error}", arguments.out))?;
    out.write_all(&statement)
        .map_err(|error| format!("statement was not written: {error}"))?;
    Ok(())
}

fn main() -> ExitCode {
    let arguments = match parse_arguments(std::env::args().skip(1)) {
        Ok(arguments) => arguments,
        Err(message) => {
            eprintln!("sealr-attest: {message}");
            return ExitCode::from(2);
        }
    };
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("sealr-attest: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMITTED_EVIDENCE: &[u8] =
        include_bytes!("../../../../crates/sealr/tests/conformance/evidence-v1.json");

    fn arguments() -> Arguments {
        Arguments {
            view: None,
            receipt: String::new(),
            source: None,
            out: String::new(),
            subject_name: DEFAULT_SUBJECT_NAME.to_owned(),
            predicate_type: None,
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty(), "fixture hex has odd length");
        pairs
            .iter()
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid fixture hex"),
                };
                digit(pair[0]) << 4 | digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn legacy_receipt_becomes_a_statement_and_preserves_its_json_token() {
        let bytes = br#"{ "schema": "sealr.receipt.v2", "source": { "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }, "verdict": "allowed" }"#;
        let output = build_statement(bytes, None, None, &arguments()).unwrap();
        let statement: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(statement["_type"], STATEMENT_TYPE);
        assert_eq!(statement["predicateType"], PREDICATE_TYPE_V2);
        assert_eq!(statement["subject"][0]["name"], DEFAULT_SUBJECT_NAME);
        assert_eq!(statement["subject"][0]["digest"]["sha256"], "a".repeat(64));
        assert!(output.windows(bytes.len()).any(|window| window == bytes));
    }

    #[test]
    fn canonical_receipt_requires_and_verifies_view_and_source() {
        let manifest: Value = serde_json::from_slice(COMMITTED_EVIDENCE).unwrap();
        let case = &manifest["cases"][0];
        let view = decode_hex(case["view_bytes_hex"].as_str().unwrap());
        let receipt = decode_hex(case["receipt_bytes_hex"].as_str().unwrap());
        let source = decode_hex(case["source_bytes_hex"].as_str().unwrap());
        let source_digest = lower_hex(&Sha256::digest(&source));

        let output =
            build_statement(&receipt, Some(&view), Some(&source_digest), &arguments()).unwrap();
        let statement: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(statement["predicateType"], PREDICATE_TYPE_V3);
        assert_eq!(statement["subject"][0]["digest"]["sha256"], source_digest);
        assert!(output
            .windows(receipt.len())
            .any(|window| window == receipt));

        assert!(build_statement(&receipt, None, Some(&source_digest), &arguments()).is_err());
        assert!(build_statement(&receipt, Some(&view), None, &arguments()).is_err());
        assert!(
            build_statement(&receipt, Some(&view), Some(&"0".repeat(64)), &arguments()).is_err()
        );
    }

    #[test]
    fn unavailable_source_unknown_schema_and_malformed_digest_are_refused() {
        for receipt in [
            serde_json::json!({
                "schema": "sealr.receipt.v2",
                "source": { "status": "unavailable" },
            }),
            serde_json::json!({
                "schema": "sealr.receipt.v99",
                "source": { "sha256": "a".repeat(64) },
            }),
            serde_json::json!({
                "schema": "sealr.receipt.v2",
                "source": { "sha256": "A".repeat(64) },
            }),
        ] {
            let bytes = serde_json::to_vec(&receipt).unwrap();
            assert!(build_statement(&bytes, None, None, &arguments()).is_err());
        }
    }

    #[test]
    fn duplicate_legacy_receipt_properties_are_refused() {
        let receipt = br#"{"schema":"sealr.receipt.v2","schema":"sealr.receipt.v3","source":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#;
        assert!(build_statement(receipt, None, None, &arguments()).is_err());
    }
}
