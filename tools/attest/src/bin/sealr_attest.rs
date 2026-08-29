//! Wrap a sealr receipt file into an unsigned in-toto Statement v1.
//!
//! This tool performs pure JSON assembly and contains no cryptography: the
//! statement it writes is the payload an external DSSE signer such as cosign
//! signs and logs. The receipt stays byte-for-byte verbatim as the predicate,
//! and the statement subject is the receipt's own verified source digest, so
//! the attestation is about the exact archive that was evaluated.
//!
//! ```text
//! sealr-attest statement --receipt receipt.json --out statement.json
//! ```

use std::fs::{self, File};
use std::io::Write;
use std::process::ExitCode;

use serde_json::{json, Value};

const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
const DEFAULT_PREDICATE_TYPE: &str = "https://github.com/blisspixel/sealr/receipt/v2";
const DEFAULT_SUBJECT_NAME: &str = "archive";
const MAX_RECEIPT_BYTES: u64 = 16 * 1024 * 1024;

fn usage() -> String {
    "usage: sealr-attest statement --receipt <FILE> --out <NEW_FILE> \
     [--subject-name <NAME>] [--predicate-type <URI>]"
        .to_owned()
}

struct Arguments {
    receipt: String,
    out: String,
    subject_name: String,
    predicate_type: String,
}

fn parse_arguments(mut args: impl Iterator<Item = String>) -> Result<Arguments, String> {
    if args.next().as_deref() != Some("statement") {
        return Err(usage());
    }
    let mut receipt = None;
    let mut out = None;
    let mut subject_name = None;
    let mut predicate_type = None;
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "--receipt" => &mut receipt,
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
        receipt: receipt.ok_or_else(usage)?,
        out: out.ok_or_else(usage)?,
        subject_name: subject_name.unwrap_or_else(|| DEFAULT_SUBJECT_NAME.to_owned()),
        predicate_type: predicate_type.unwrap_or_else(|| DEFAULT_PREDICATE_TYPE.to_owned()),
    })
}

fn build_statement(receipt_bytes: &[u8], arguments: &Arguments) -> Result<Value, String> {
    let receipt: Value = serde_json::from_slice(receipt_bytes)
        .map_err(|error| format!("receipt file is not one JSON document: {error}"))?;
    let schema = receipt
        .get("schema")
        .and_then(Value::as_str)
        .ok_or("receipt carries no schema field")?;
    if schema != "sealr.receipt.v2" {
        return Err(format!(
            "receipt schema {schema:?} is not the supported sealr.receipt.v2"
        ));
    }
    let source_sha256 = receipt
        .get("source")
        .and_then(|source| source.get("sha256"))
        .and_then(Value::as_str)
        .ok_or(
            "receipt source digest is unavailable; an attestation must bind the exact \
             evaluated bytes, so a receipt without a source digest is refused",
        )?;
    if source_sha256.len() != 64
        || !source_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("receipt source digest is not lowercase hex SHA-256".to_owned());
    }
    Ok(json!({
        "_type": STATEMENT_TYPE,
        "subject": [{
            "name": arguments.subject_name,
            "digest": { "sha256": source_sha256 },
        }],
        "predicateType": arguments.predicate_type,
        "predicate": receipt,
    }))
}

fn run(arguments: &Arguments) -> Result<(), String> {
    let metadata = fs::metadata(&arguments.receipt)
        .map_err(|error| format!("receipt file was not readable: {error}"))?;
    if metadata.len() > MAX_RECEIPT_BYTES {
        return Err(format!(
            "receipt file of {} bytes exceeds the {MAX_RECEIPT_BYTES}-byte bound",
            metadata.len()
        ));
    }
    let receipt_bytes = fs::read(&arguments.receipt)
        .map_err(|error| format!("receipt file was not readable: {error}"))?;
    let statement = build_statement(&receipt_bytes, arguments)?;
    let mut out = File::create_new(&arguments.out)
        .map_err(|error| format!("output file {} was not created: {error}", arguments.out))?;
    serde_json::to_writer_pretty(&mut out, &statement)
        .and_then(|()| out.write_all(b"\n").map_err(serde_json::Error::io))
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

    fn arguments() -> Arguments {
        Arguments {
            receipt: String::new(),
            out: String::new(),
            subject_name: DEFAULT_SUBJECT_NAME.to_owned(),
            predicate_type: DEFAULT_PREDICATE_TYPE.to_owned(),
        }
    }

    #[test]
    fn a_verified_receipt_becomes_a_statement_with_the_source_digest_subject() {
        let receipt = serde_json::json!({
            "schema": "sealr.receipt.v2",
            "source": { "sha256": "a".repeat(64) },
            "verdict": "allowed",
        });
        let bytes = serde_json::to_vec(&receipt).unwrap();
        let statement = build_statement(&bytes, &arguments()).unwrap();
        assert_eq!(statement["_type"], STATEMENT_TYPE);
        assert_eq!(statement["predicateType"], DEFAULT_PREDICATE_TYPE);
        assert_eq!(statement["subject"][0]["name"], DEFAULT_SUBJECT_NAME);
        assert_eq!(statement["subject"][0]["digest"]["sha256"], "a".repeat(64));
        assert_eq!(statement["predicate"], receipt);
    }

    #[test]
    fn an_unavailable_source_digest_is_refused() {
        let receipt = serde_json::json!({
            "schema": "sealr.receipt.v2",
            "source": { "status": "unavailable" },
        });
        let bytes = serde_json::to_vec(&receipt).unwrap();
        let error = build_statement(&bytes, &arguments()).unwrap_err();
        assert!(error.contains("source digest is unavailable"), "{error}");
    }

    #[test]
    fn an_unknown_schema_is_refused() {
        let receipt = serde_json::json!({
            "schema": "sealr.receipt.v99",
            "source": { "sha256": "a".repeat(64) },
        });
        let bytes = serde_json::to_vec(&receipt).unwrap();
        let error = build_statement(&bytes, &arguments()).unwrap_err();
        assert!(error.contains("not the supported"), "{error}");
    }

    #[test]
    fn a_malformed_digest_is_refused() {
        for hostile in [
            "A".repeat(64),
            "a".repeat(63),
            format!("{}g", "a".repeat(63)),
        ] {
            let receipt = serde_json::json!({
                "schema": "sealr.receipt.v2",
                "source": { "sha256": hostile },
            });
            let bytes = serde_json::to_vec(&receipt).unwrap();
            assert!(build_statement(&bytes, &arguments()).is_err());
        }
    }
}
