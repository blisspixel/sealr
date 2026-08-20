use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sealr::{apply, Policy, Request, Source};
use sha2::{Digest, Sha256};

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(root) = args.next().map(PathBuf::from) else {
        usage();
        return ExitCode::from(2);
    };
    let mut list_allowed = false;
    let mut expectation_path = None;
    while let Some(argument) = args.next() {
        if argument == "--list-allowed" {
            list_allowed = true;
        } else if argument == "--expect" {
            let Some(path) = args.next() else {
                eprintln!("--expect requires a manifest path");
                return ExitCode::from(2);
            };
            expectation_path = Some(PathBuf::from(path));
        } else {
            eprintln!("unknown argument: {}", argument.to_string_lossy());
            usage();
            return ExitCode::from(2);
        }
    }
    let expectations = match expectation_path.as_deref().map(read_expectations) {
        Some(Ok(expectations)) => Some(expectations),
        Some(Err(error)) => {
            eprintln!("expectation manifest: {error}");
            return ExitCode::from(2);
        }
        None => None,
    };

    let files = match zip_files(&root) {
        Ok(files) => files,
        Err(error) => {
            eprintln!("{}: {error}", root.display());
            return ExitCode::from(2);
        }
    };
    let total_files = files.len();
    let policy = Policy::default_v1();
    let mut groups: BTreeMap<(String, String), (usize, PathBuf)> = BTreeMap::new();
    let mut allowed = BTreeSet::new();
    let mut corpus_hasher = Sha256::new();

    for path in files {
        let relative = relative_key(&root, &path);
        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(error) => {
                eprintln!("{}: {error}", path.display());
                return ExitCode::from(2);
            }
        };
        hash_fixture(&mut corpus_hasher, &relative, &data);
        let class = path
            .parent()
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".to_owned());
        let outcome = apply(Request {
            source: Source::Bytes {
                path: Some(&relative),
                data: &data,
            },
            policy: &policy,
            dest: None,
        });
        let result = if outcome.rejected() {
            outcome
                .view
                .findings
                .iter()
                .map(|finding| finding.code.as_str())
                .collect::<Vec<_>>()
                .join("+")
        } else {
            allowed.insert(relative.clone());
            if list_allowed {
                eprintln!("ALLOWED\t{relative}");
            }
            "ALLOWED".to_owned()
        };
        let entry = groups
            .entry((class, result))
            .or_insert_with(|| (0, path.clone()));
        entry.0 += 1;
    }

    let corpus_digest = hex(corpus_hasher.finalize());
    println!("class\tresult\tcount\tfirst");
    for ((class, result), (count, first)) in &groups {
        println!("{class}\t{result}\t{count}\t{}", first.display());
    }
    println!("corpus\tsha256\t{corpus_digest}");
    if let Some(expectations) = expectations {
        return verify(
            &expectations,
            total_files,
            &corpus_digest,
            &allowed,
            &groups,
        );
    }
    ExitCode::SUCCESS
}

#[derive(Debug)]
struct Expectations {
    total: usize,
    digests: BTreeMap<String, String>,
    groups: BTreeMap<(String, String), usize>,
    allowed: BTreeSet<String>,
}

fn read_expectations(path: &Path) -> Result<Expectations, String> {
    let contents =
        fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut total = None;
    let mut digests = BTreeMap::new();
    let mut groups = BTreeMap::new();
    let mut allowed = BTreeSet::new();
    for (index, raw_line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["total", value] => {
                let value = value
                    .parse::<usize>()
                    .map_err(|error| format!("line {line_number}: invalid total: {error}"))?;
                if total.replace(value).is_some() {
                    return Err(format!("line {line_number}: duplicate total"));
                }
            }
            ["digest", "sha256", platform, value] => {
                if platform.is_empty()
                    || !platform
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
                {
                    return Err(format!("line {line_number}: invalid platform"));
                }
                if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(format!("line {line_number}: invalid SHA-256 digest"));
                }
                if digests
                    .insert((*platform).to_owned(), value.to_ascii_lowercase())
                    .is_some()
                {
                    return Err(format!(
                        "line {line_number}: duplicate digest for {platform}"
                    ));
                }
            }
            ["count", class, result, value] => {
                let value = value
                    .parse::<usize>()
                    .map_err(|error| format!("line {line_number}: invalid count: {error}"))?;
                let key = ((*class).to_owned(), (*result).to_owned());
                if groups.insert(key, value).is_some() {
                    return Err(format!("line {line_number}: duplicate count"));
                }
            }
            ["allow", relative] => {
                if !allowed.insert((*relative).to_owned()) {
                    return Err(format!("line {line_number}: duplicate allow entry"));
                }
            }
            _ => return Err(format!("line {line_number}: invalid directive")),
        }
    }
    let total = total.ok_or_else(|| "missing total directive".to_owned())?;
    if digests.is_empty() {
        return Err("missing digest directive".to_owned());
    }
    let grouped_total: usize = groups.values().sum();
    if grouped_total != total {
        return Err(format!(
            "count directives sum to {grouped_total}, but total is {total}"
        ));
    }
    let allowed_total: usize = groups
        .iter()
        .filter_map(|((_, result), count)| (result == "ALLOWED").then_some(*count))
        .sum();
    if allowed.len() != allowed_total {
        return Err(format!(
            "{} allow entries do not match the {allowed_total} ALLOWED count",
            allowed.len()
        ));
    }
    Ok(Expectations {
        total,
        digests,
        groups,
        allowed,
    })
}

fn verify(
    expectations: &Expectations,
    total_files: usize,
    corpus_digest: &str,
    allowed: &BTreeSet<String>,
    groups: &BTreeMap<(String, String), (usize, PathBuf)>,
) -> ExitCode {
    let mut failures = Vec::new();
    if total_files != expectations.total {
        failures.push(format!(
            "fixture total: expected {}, got {total_files}",
            expectations.total
        ));
    }
    let platform = env::consts::OS;
    match expectations.digests.get(platform) {
        Some(expected) if corpus_digest != expected => failures.push(format!(
            "corpus digest on {platform}: expected {expected}, got {corpus_digest}"
        )),
        Some(_) => {}
        None => failures.push(format!(
            "corpus digest: manifest has no expectation for platform {platform}"
        )),
    }
    for (key, expected) in &expectations.groups {
        let actual = groups.get(key).map_or(0, |entry| entry.0);
        if actual != *expected {
            failures.push(format!(
                "count {}/{}: expected {expected}, got {actual}",
                key.0, key.1
            ));
        }
    }
    for (key, (actual, _)) in groups {
        if !expectations.groups.contains_key(key) {
            failures.push(format!("unexpected count {}/{}: {actual}", key.0, key.1));
        }
    }
    for relative in expectations.allowed.difference(allowed) {
        failures.push(format!("expected control was rejected: {relative}"));
    }
    for relative in allowed.difference(&expectations.allowed) {
        failures.push(format!("unexpected archive was allowed: {relative}"));
    }
    if failures.is_empty() {
        eprintln!(
            "verified {} ZipDiff constructions on {platform}; {} documented controls allowed",
            expectations.total,
            expectations.allowed.len()
        );
        ExitCode::SUCCESS
    } else {
        for failure in failures {
            eprintln!("verification failed: {failure}");
        }
        ExitCode::from(1)
    }
}

fn relative_key(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn hash_fixture(hasher: &mut Sha256, relative: &str, data: &[u8]) {
    let fixture_digest = Sha256::digest(data);
    hasher.update((relative.len() as u64).to_le_bytes());
    hasher.update(relative.as_bytes());
    hasher.update((data.len() as u64).to_le_bytes());
    hasher.update(fixture_digest);
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn usage() {
    eprintln!(
        "usage: classify_zipdiff <construction-directory> [--list-allowed] [--expect <manifest>]"
    );
}

fn zip_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
            {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    Ok(files)
}
