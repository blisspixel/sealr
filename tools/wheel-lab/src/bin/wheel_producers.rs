//! Reproduce exact current public-API observations for the controlled producer matrix.

#[path = "../../../../crates/sealr/tests/support/wheel_producers.rs"]
mod support;

use serde_json::json;
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() != 3 || !matches!(args[0].as_str(), "record" | "verify") {
        return Err("usage: wheel_producers <record|verify> <vectors.json> <report.json>".into());
    }
    let input = fs::read(&args[1])?;
    let vectors = support::load(&input);
    let reports: Vec<_> = vectors
        .fixtures
        .iter()
        .map(|f| support::measure(f, None, None))
        .collect();
    let report = json!({
        "schema": "sealr.wheel-producer-report.v1",
        "vectors_sha256": support::digest(&input),
        "interpretation_profile": "sealr.profile.zip.portable-utf8.v1",
        "policy": "sealr:policy/default/v1",
        "fixtures": reports,
    });
    let encoded = serde_json::to_string_pretty(&report)? + "\n";
    if args[0] == "record" {
        fs::write(&args[2], encoded)?;
    } else if fs::read(&args[2])? != encoded.as_bytes() {
        return Err("producer observations differ from the committed report".into());
    }
    println!("Verified {} producer observations", vectors.fixtures.len());
    Ok(())
}
