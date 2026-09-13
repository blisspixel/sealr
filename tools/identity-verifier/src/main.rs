use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::File;
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
    if matches!(arguments.as_slice(), [argument] if argument == "--help" || argument == "-h") {
        println!("{}", usage(&program));
        return ExitCode::SUCCESS;
    }
    if matches!(arguments.as_slice(), [argument] if argument == "--version" || argument == "-V") {
        println!("sealr-identity-verifier {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if arguments.first().is_some_and(|value| value == "evidence") {
        if matches!(&arguments[1..], [argument] if argument == "--help" || argument == "-h") {
            println!("{}", evidence_usage(&program));
            return ExitCode::SUCCESS;
        }
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

fn evidence_usage(program: &OsStr) -> String {
    format!(
        "usage: {} evidence --view <view.json> --receipt <receipt.json> [--source <archive>]",
        Path::new(program).display()
    )
}

fn run_manifest(program: &OsStr, arguments: &[OsString]) -> ExitCode {
    let [path] = arguments else {
        eprintln!("{}", usage(program));
        return ExitCode::from(2);
    };
    if path.to_string_lossy().starts_with('-') {
        eprintln!("{}", usage(program));
        return ExitCode::from(2);
    }

    let path = Path::new(path);
    let bytes = match read_limited(path, "identity manifest", MAX_MANIFEST_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("{error}");
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
    read_limited(path, label, MAX_EVIDENCE_BYTES)
}

fn read_limited(path: &Path, label: &str, limit: usize) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| format!("{label} open: {error}"))?;
    let initial_length = file
        .metadata()
        .map_err(|error| format!("{label} metadata: {error}"))?
        .len();
    if initial_length > limit as u64 {
        return Err(format!("{label} exceeds the {limit}-byte verifier limit"));
    }

    let initial_capacity = usize::try_from(initial_length).unwrap_or(limit).min(limit);
    let mut bytes = Vec::with_capacity(initial_capacity);
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{label} read: {error}"))?;
    if bytes.len() > limit {
        return Err(format!("{label} exceeds the {limit}-byte verifier limit"));
    }
    Ok(bytes)
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
