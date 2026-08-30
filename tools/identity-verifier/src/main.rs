use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use sealr_identity_verifier::{
    verify_canonical_evidence, verify_manifest_json, MAX_EVIDENCE_BYTES, MAX_MANIFEST_BYTES,
};
use sha2::{Digest, Sha256};

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .and_then(|value| Path::new(&value).file_name().map(|name| name.to_owned()))
        .unwrap_or_else(|| "sealr-identity-verifier".into());
    let arguments: Vec<_> = arguments.collect();
    if arguments.first().is_some_and(|value| value == "evidence") {
        return run_evidence(&program, &arguments[1..]);
    }
    run_manifest(&program, &arguments)
}

fn usage(program: &OsStr) -> String {
    format!(
        "usage: {} <identity-conformance.json>\n       {} evidence --view <view.json> --receipt <receipt.json> [--source <archive>]",
        Path::new(program).display(),
        Path::new(program).display()
    )
}

fn run_manifest(program: &OsStr, arguments: &[OsString]) -> ExitCode {
    let [path] = arguments else {
        eprintln!("{}", usage(program));
        return ExitCode::from(2);
    };

    let path = Path::new(path);
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

fn run_evidence(program: &OsStr, arguments: &[OsString]) -> ExitCode {
    let mut view = None;
    let mut receipt = None;
    let mut source = None;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        let slot = match flag.to_str() {
            Some("--view") => &mut view,
            Some("--receipt") => &mut receipt,
            Some("--source") => &mut source,
            _ => {
                eprintln!("{}", usage(program));
                return ExitCode::from(2);
            }
        };
        if slot.is_some() || index + 1 >= arguments.len() {
            eprintln!("{}", usage(program));
            return ExitCode::from(2);
        }
        *slot = Some(arguments[index + 1].clone());
        index += 2;
    }
    let (Some(view), Some(receipt)) = (view, receipt) else {
        eprintln!("{}", usage(program));
        return ExitCode::from(2);
    };

    let view = match read_bounded(Path::new(&view), "view") {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("canonical evidence rejected: {error}");
            return ExitCode::FAILURE;
        }
    };
    let receipt = match read_bounded(Path::new(&receipt), "receipt") {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("canonical evidence rejected: {error}");
            return ExitCode::FAILURE;
        }
    };
    let source_digest = match source {
        Some(path) => match hash_source(Path::new(&path)) {
            Ok(digest) => Some(digest),
            Err(error) => {
                eprintln!("canonical evidence rejected: {error}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    match verify_canonical_evidence(&view, &receipt, source_digest.as_deref()) {
        Ok(summary) => {
            let content = if summary.content_root_verified {
                "content root independently verified"
            } else {
                "content root unavailable"
            };
            let source = if summary.source_checked {
                "source digest checked"
            } else {
                "source not supplied"
            };
            println!(
                "verified canonical evidence: view sha256 {}, receipt sha256 {}, {} member(s), {content}, {source}; layout root remains a producer claim",
                summary.view_digest, summary.receipt_digest, summary.members
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("canonical evidence rejected: {error}");
            ExitCode::FAILURE
        }
    }
}

fn read_bounded(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("{label} metadata: {error}"))?;
    if metadata.len() > MAX_EVIDENCE_BYTES as u64 {
        return Err(format!(
            "{label} exceeds the {MAX_EVIDENCE_BYTES}-byte verifier limit"
        ));
    }
    fs::read(path).map_err(|error| format!("{label} read: {error}"))
}

fn hash_source(path: &Path) -> Result<String, String> {
    let mut source = File::open(path).map_err(|error| format!("source open: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|error| format!("source read: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let mut output = String::with_capacity(64);
    for byte in digest.finalize() {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    Ok(output)
}
