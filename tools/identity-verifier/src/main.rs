use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use sealr_identity_verifier::{verify_manifest_json, MAX_MANIFEST_BYTES};

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .and_then(|value| Path::new(&value).file_name().map(|name| name.to_owned()))
        .unwrap_or_else(|| "sealr-identity-verifier".into());
    let Some(path) = arguments.next() else {
        eprintln!(
            "usage: {} <identity-conformance.json>",
            Path::new(&program).display()
        );
        return ExitCode::from(2);
    };
    if arguments.next().is_some() {
        eprintln!(
            "usage: {} <identity-conformance.json>",
            Path::new(&program).display()
        );
        return ExitCode::from(2);
    }

    let path = Path::new(&path);
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("identity manifest metadata: {error}");
            return ExitCode::FAILURE;
        }
    };
    if metadata.len() > MAX_MANIFEST_BYTES as u64 {
        eprintln!("identity manifest exceeds the {MAX_MANIFEST_BYTES}-byte verifier limit");
        return ExitCode::FAILURE;
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("identity manifest read: {error}");
            return ExitCode::FAILURE;
        }
    };

    match verify_manifest_json(&bytes) {
        Ok(summary) => {
            println!(
                "verified {} profile vector(s), {} case(s), {} layout root(s), and {} content root(s)",
                summary.profiles,
                summary.cases,
                summary.layout_roots,
                summary.content_roots
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("identity manifest rejected: {error}");
            ExitCode::FAILURE
        }
    }
}
