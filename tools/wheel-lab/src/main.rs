//! Deterministic, non-shipping compatibility inventory over Sealr outcomes.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sealr::{
    apply, zip_strict_ascii_v1_digest, AdmissionStatus, ExtraDisposition, ExtraSite, MemberKind,
    NormalizationAction, Policy, Request, Severity, Source, ZIP_STRICT_ASCII_V1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MANIFEST_SCHEMA: &str = "sealr.wheel-corpus.v1";
const REPORT_SCHEMA: &str = "sealr.wheel-compatibility-report.v1";
const ANALYZER_REVISION: &str = "sealr-wheel-lab.v1";
const MAX_ARTIFACTS: usize = 128;
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CORPUS_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_REPORT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_INVENTORIED_MEMBERS: u64 = 65_536;
const MAX_FINDING_OCCURRENCES: u64 = 65_536;

type AnyError = Box<dyn Error>;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    query_date: String,
    selection_method: String,
    entries: Vec<ManifestEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    project: String,
    version: String,
    cohort: String,
    filename: String,
    url: String,
    sha256: String,
    size: u64,
    upload_time: String,
    provenance_url: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema: String,
    manifest_sha256: String,
    query_date: String,
    selection_method: String,
    analyzer_revision: String,
    interpretation_profile: String,
    interpretation_profile_sha256: String,
    policy: String,
    policy_sha256: String,
    artifact_count: usize,
    source_bytes: u64,
    summary: Summary,
    artifacts: Vec<ArtifactReport>,
}

#[derive(Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct Summary {
    admission: BTreeMap<String, u64>,
    cohorts: BTreeMap<String, u64>,
    admitted_by_cohort: BTreeMap<String, u64>,
    finding_artifacts: BTreeMap<String, u64>,
    finding_occurrences: BTreeMap<String, u64>,
    methods: BTreeMap<String, u64>,
    flags: BTreeMap<String, u64>,
    extra_fields: BTreeMap<String, u64>,
    normalization_actions: BTreeMap<String, u64>,
    top_level_dist_info_path_counts: BTreeMap<String, u64>,
    candidate_metadata_members: BTreeMap<String, u64>,
    top_level_metadata_members: BTreeMap<String, u64>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactReport {
    project: String,
    version: String,
    cohort: String,
    filename: String,
    sha256: String,
    size: u64,
    upload_time: String,
    admission: String,
    findings: Vec<FindingObservation>,
    archive_ir_available: bool,
    member_count: u64,
    file_count: u64,
    directory_count: u64,
    declared_compressed_bytes: u64,
    declared_uncompressed_bytes: u64,
    max_path_bytes: u64,
    max_path_depth: u64,
    methods: BTreeMap<String, u64>,
    flags: BTreeMap<String, u64>,
    extra_fields: BTreeMap<String, u64>,
    normalization_actions: BTreeMap<String, u64>,
    dist_info_paths: Vec<String>,
    top_level_dist_info_paths: Vec<String>,
    candidate_metadata_name_counts: BTreeMap<String, u64>,
    top_level_metadata_name_counts: BTreeMap<String, u64>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(deny_unknown_fields)]
struct FindingObservation {
    code: String,
    severity: String,
    member: Option<String>,
    detail: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("wheel lab: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), AnyError> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(usage_error)?;
    match command.as_str() {
        "validate-manifest" => {
            let manifest_path = required_path(&mut args, "manifest")?;
            reject_extra_args(args)?;
            let raw = read_bounded(&manifest_path, MAX_MANIFEST_BYTES, "manifest")?;
            let manifest = parse_manifest(&raw)?;
            println!(
                "validated {} artifact(s), {} bytes, manifest sha256 {}",
                manifest.entries.len(),
                manifest_size(&manifest)?,
                sha256_hex(&raw)
            );
        }
        "analyze" | "check" => {
            let manifest_path = required_path(&mut args, "manifest")?;
            let cache_dir = required_path(&mut args, "cache directory")?;
            let json_path = required_path(&mut args, "JSON report")?;
            let markdown_path = required_path(&mut args, "Markdown report")?;
            reject_extra_args(args)?;
            let (json, markdown) = analyze(&manifest_path, &cache_dir)?;
            if command == "analyze" {
                fs::write(&json_path, json)?;
                fs::write(&markdown_path, markdown)?;
                println!(
                    "wrote {} and {}",
                    json_path.display(),
                    markdown_path.display()
                );
            } else {
                check_exact(&json_path, &json)?;
                check_exact(&markdown_path, &markdown)?;
                println!("wheel compatibility reports are current");
            }
        }
        "verify-report" => {
            let manifest_path = required_path(&mut args, "manifest")?;
            let json_path = required_path(&mut args, "JSON report")?;
            let markdown_path = required_path(&mut args, "Markdown report")?;
            reject_extra_args(args)?;
            verify_committed_report(&manifest_path, &json_path, &markdown_path)?;
            println!("wheel compatibility report is internally consistent and current");
        }
        _ => return Err(usage_error()),
    }
    Ok(())
}

fn usage_error() -> AnyError {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: sealr-wheel-lab validate-manifest <manifest> | (analyze|check) <manifest> <cache-dir> <report.json> <report.md> | verify-report <manifest> <report.json> <report.md>",
    )
    .into()
}

fn required_path(
    args: &mut impl Iterator<Item = String>,
    label: &str,
) -> Result<PathBuf, AnyError> {
    args.next().map(PathBuf::from).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("missing {label} path")).into()
    })
}

fn reject_extra_args(mut args: impl Iterator<Item = String>) -> Result<(), AnyError> {
    if let Some(extra) = args.next() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unexpected argument {extra}"),
        )
        .into());
    }
    Ok(())
}

fn parse_manifest(raw: &[u8]) -> Result<Manifest, AnyError> {
    let manifest: Manifest = serde_json::from_slice(raw)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &Manifest) -> Result<(), AnyError> {
    if manifest.schema != MANIFEST_SCHEMA {
        return invalid(format!("unsupported manifest schema {}", manifest.schema));
    }
    if !is_iso_date(&manifest.query_date) {
        return invalid("query_date must use YYYY-MM-DD");
    }
    if manifest.selection_method.trim().is_empty()
        || manifest.selection_method.len() > 4_096
        || !manifest.selection_method.is_ascii()
        || manifest.selection_method.chars().any(char::is_control)
    {
        return invalid(
            "selection_method must be a non-empty single ASCII line of at most 4096 bytes",
        );
    }
    if manifest.entries.is_empty() || manifest.entries.len() > MAX_ARTIFACTS {
        return invalid(format!(
            "manifest must contain 1 through {MAX_ARTIFACTS} artifacts"
        ));
    }

    let mut filenames = BTreeSet::new();
    let mut digests = BTreeSet::new();
    let mut prior_filename: Option<&str> = None;
    let mut total = 0_u64;
    for entry in &manifest.entries {
        for (label, value) in [
            ("project", entry.project.as_str()),
            ("version", entry.version.as_str()),
            ("cohort", entry.cohort.as_str()),
        ] {
            if value.is_empty()
                || value.len() > 256
                || !value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-' | b'!')
                })
            {
                return invalid(format!("{} has invalid {label}", entry.filename));
            }
        }
        if !is_utc_timestamp(&entry.upload_time) {
            return invalid(format!("{} has invalid upload_time", entry.filename));
        }
        if entry.filename.len() > 1_024 || !is_safe_wheel_filename(&entry.filename) {
            return invalid(format!("invalid wheel filename {}", entry.filename));
        }
        if let Some(prior) = prior_filename {
            if prior >= entry.filename.as_str() {
                return invalid("manifest entries must be strictly sorted by filename");
            }
        }
        prior_filename = Some(&entry.filename);
        if !filenames.insert(entry.filename.as_str()) {
            return invalid(format!("duplicate filename {}", entry.filename));
        }
        if !is_lower_sha256(&entry.sha256) || !digests.insert(entry.sha256.as_str()) {
            return invalid(format!(
                "invalid or duplicate sha256 for {}",
                entry.filename
            ));
        }
        if entry.size == 0 || entry.size > MAX_ARTIFACT_BYTES {
            return invalid(format!("invalid size for {}", entry.filename));
        }
        total = total
            .checked_add(entry.size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "corpus size overflow"))?;
        if total > MAX_CORPUS_BYTES {
            return invalid(format!("corpus exceeds {MAX_CORPUS_BYTES} bytes"));
        }
        let expected_suffix = format!("/{}", entry.filename);
        if entry.url.len() > 4_096
            || !entry
                .url
                .starts_with("https://files.pythonhosted.org/packages/")
            || !entry.url.ends_with(&expected_suffix)
            || entry.url.contains(['?', '#'])
        {
            return invalid(format!("invalid artifact URL for {}", entry.filename));
        }
        let expected_provenance = format!(
            "https://pypi.org/project/{}/{}/#files",
            entry.project, entry.version
        );
        if entry.provenance_url.len() > 4_096 || entry.provenance_url != expected_provenance {
            return invalid(format!("invalid provenance URL for {}", entry.filename));
        }
    }
    Ok(())
}

fn manifest_size(manifest: &Manifest) -> Result<u64, AnyError> {
    manifest.entries.iter().try_fold(0_u64, |total, entry| {
        total.checked_add(entry.size).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "corpus size overflow").into()
        })
    })
}

fn is_safe_wheel_filename(filename: &str) -> bool {
    filename.is_ascii()
        && filename.ends_with(".whl")
        && filename != ".whl"
        && filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return false;
    }
    let year = decimal(&bytes[0..4]);
    let month = decimal(&bytes[5..7]);
    let day = decimal(&bytes[8..10]);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => return false,
    };
    (1..=max_day).contains(&day)
}

fn is_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || !value.is_ascii()
        || !is_iso_date(&value[..10])
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || *bytes.last().unwrap_or(&0) != b'Z'
        || !bytes[11..13].iter().all(u8::is_ascii_digit)
        || !bytes[14..16].iter().all(u8::is_ascii_digit)
        || !bytes[17..19].iter().all(u8::is_ascii_digit)
    {
        return false;
    }
    let hour = decimal(&bytes[11..13]);
    let minute = decimal(&bytes[14..16]);
    let second = decimal(&bytes[17..19]);
    let fraction_valid = match bytes.len() {
        20 => true,
        22..=30 => bytes[19] == b'.' && bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit),
        _ => false,
    };
    hour <= 23 && minute <= 59 && second <= 59 && fraction_valid
}

fn decimal(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0_u32, |value, byte| value * 10 + u32::from(byte - b'0'))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid<T>(message: impl Into<String>) -> Result<T, AnyError> {
    Err(io::Error::new(io::ErrorKind::InvalidData, message.into()).into())
}

fn read_bounded(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>, AnyError> {
    let file = fs::File::open(path)?;
    let mut limited = file.take(max_bytes.saturating_add(1));
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return invalid(format!(
            "{} exceeds the {max_bytes}-byte {label} limit",
            path.display()
        ));
    }
    Ok(bytes)
}

fn read_bounded_string(path: &Path, max_bytes: u64, label: &str) -> Result<String, AnyError> {
    Ok(String::from_utf8(read_bounded(path, max_bytes, label)?)?)
}

fn analyze(manifest_path: &Path, cache_dir: &Path) -> Result<(String, String), AnyError> {
    let manifest_raw = read_bounded(manifest_path, MAX_MANIFEST_BYTES, "manifest")?;
    let manifest = parse_manifest(&manifest_raw)?;
    let policy = Policy::default_v1();
    let mut artifacts = Vec::with_capacity(manifest.entries.len());
    let mut inventoried_members = 0_u64;
    let mut finding_occurrences = 0_u64;
    for entry in &manifest.entries {
        let artifact = analyze_artifact(entry, cache_dir, &policy)?;
        inventoried_members = inventoried_members
            .checked_add(artifact.member_count)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "member count overflow"))?;
        finding_occurrences = finding_occurrences
            .checked_add(artifact.findings.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "finding count overflow"))?;
        if inventoried_members > MAX_INVENTORIED_MEMBERS {
            return invalid(format!(
                "corpus exceeds the {MAX_INVENTORIED_MEMBERS}-member inventory limit"
            ));
        }
        if finding_occurrences > MAX_FINDING_OCCURRENCES {
            return invalid(format!(
                "corpus exceeds the {MAX_FINDING_OCCURRENCES}-finding report limit"
            ));
        }
        artifacts.push(artifact);
    }
    let summary = summarize(&artifacts);
    let source_bytes = manifest_size(&manifest)?;
    let report = Report {
        schema: REPORT_SCHEMA.to_string(),
        manifest_sha256: sha256_hex(&manifest_raw),
        query_date: manifest.query_date,
        selection_method: manifest.selection_method,
        analyzer_revision: ANALYZER_REVISION.to_string(),
        interpretation_profile: ZIP_STRICT_ASCII_V1.to_string(),
        interpretation_profile_sha256: zip_strict_ascii_v1_digest(),
        policy: policy.id.clone(),
        policy_sha256: policy.digest_hex(),
        artifact_count: artifacts.len(),
        source_bytes,
        summary,
        artifacts,
    };
    let mut json = serde_json::to_string_pretty(&report)?;
    json.push('\n');
    let markdown = render_markdown(&report);
    if json.len() as u64 > MAX_REPORT_BYTES || markdown.len() as u64 > MAX_REPORT_BYTES {
        return invalid(format!(
            "generated report exceeds the {MAX_REPORT_BYTES}-byte output limit"
        ));
    }
    Ok((json, markdown))
}

fn analyze_artifact(
    entry: &ManifestEntry,
    cache_dir: &Path,
    policy: &Policy,
) -> Result<ArtifactReport, AnyError> {
    let path = cache_dir.join(format!("{}.whl", entry.sha256));
    let metadata = fs::metadata(&path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("{}: {error}; run the acquisition script", path.display()),
        )
    })?;
    if metadata.len() != entry.size {
        return invalid(format!(
            "{} has {} bytes, expected {}",
            path.display(),
            metadata.len(),
            entry.size
        ));
    }
    let bytes = read_bounded(&path, entry.size, "cached artifact")?;
    if bytes.len() as u64 != entry.size {
        return invalid(format!(
            "{} yielded {} bytes, expected {}",
            path.display(),
            bytes.len(),
            entry.size
        ));
    }
    let actual_digest = sha256_hex(&bytes);
    if actual_digest != entry.sha256 {
        return invalid(format!(
            "{} digest is {actual_digest}, expected {}",
            path.display(),
            entry.sha256
        ));
    }

    let outcome = apply(Request {
        source: Source::Bytes {
            path: Some(&entry.filename),
            data: &bytes,
        },
        policy,
        dest: None,
    });
    let admission = match outcome.admission {
        AdmissionStatus::Admitted => "admitted",
        AdmissionStatus::Denied => "denied",
        AdmissionStatus::NotEvaluated => "not-evaluated",
        _ => return invalid("wheel lab does not support this admission status"),
    }
    .to_string();
    let mut findings: Vec<FindingObservation> = outcome
        .view
        .findings
        .iter()
        .map(|finding| FindingObservation {
            code: finding.code.as_str().to_string(),
            severity: severity_name(finding.severity).to_string(),
            member: finding.member.clone(),
            detail: finding.detail.clone(),
        })
        .collect();
    findings.sort();

    let mut artifact = ArtifactReport {
        project: entry.project.clone(),
        version: entry.version.clone(),
        cohort: entry.cohort.clone(),
        filename: entry.filename.clone(),
        sha256: entry.sha256.clone(),
        size: entry.size,
        upload_time: entry.upload_time.clone(),
        admission,
        findings,
        archive_ir_available: false,
        member_count: 0,
        file_count: 0,
        directory_count: 0,
        declared_compressed_bytes: 0,
        declared_uncompressed_bytes: 0,
        max_path_bytes: 0,
        max_path_depth: 0,
        methods: BTreeMap::new(),
        flags: BTreeMap::new(),
        extra_fields: BTreeMap::new(),
        normalization_actions: BTreeMap::new(),
        dist_info_paths: Vec::new(),
        top_level_dist_info_paths: Vec::new(),
        candidate_metadata_name_counts: BTreeMap::new(),
        top_level_metadata_name_counts: BTreeMap::new(),
    };

    let Some(ir) = outcome.archive_ir() else {
        return Ok(artifact);
    };
    artifact.archive_ir_available = true;
    artifact.member_count = ir.members().len() as u64;
    let mut dist_info = BTreeSet::new();
    let mut top_level_dist_info = BTreeSet::new();
    for member in ir.members() {
        match member.kind {
            MemberKind::File => artifact.file_count += 1,
            MemberKind::Directory => artifact.directory_count += 1,
            _ => {}
        }
        artifact.declared_compressed_bytes = artifact
            .declared_compressed_bytes
            .checked_add(member.declared_comp_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "compressed sum overflow"))?;
        artifact.declared_uncompressed_bytes = artifact
            .declared_uncompressed_bytes
            .checked_add(member.declared_uncomp_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expanded sum overflow"))?;
        artifact.max_path_bytes = artifact
            .max_path_bytes
            .max(member.canonical_path.len() as u64);
        artifact.max_path_depth = artifact.max_path_depth.max(member.components.len() as u64);
        increment(&mut artifact.methods, method_key(member.method));
        increment(&mut artifact.flags, format!("0x{:04x}", member.flags));
        for extra in &member.extra_fields {
            increment(
                &mut artifact.extra_fields,
                extra_key(extra.site, extra.id, extra.disposition),
            );
        }
        for action in &member.normalization_actions {
            increment(
                &mut artifact.normalization_actions,
                normalization_key(action),
            );
        }
        for (index, component) in member.components.iter().enumerate() {
            if component.ends_with(".dist-info") {
                dist_info.insert(member.components[..=index].join("/"));
                if index == 0 {
                    top_level_dist_info.insert(component.clone());
                }
            }
        }
        if let Some(name) = member.components.last() {
            let is_candidate = matches!(
                name.as_str(),
                "WHEEL" | "METADATA" | "RECORD" | "entry_points.txt"
            );
            let under_dist_info = member.components[..member.components.len().saturating_sub(1)]
                .iter()
                .any(|component| component.ends_with(".dist-info"));
            if is_candidate && under_dist_info {
                increment(&mut artifact.candidate_metadata_name_counts, name.clone());
                if member
                    .components
                    .first()
                    .is_some_and(|component| component.ends_with(".dist-info"))
                {
                    increment(&mut artifact.top_level_metadata_name_counts, name.clone());
                }
            }
        }
    }
    artifact.dist_info_paths = dist_info.into_iter().collect();
    artifact.top_level_dist_info_paths = top_level_dist_info.into_iter().collect();
    Ok(artifact)
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Deny => "deny",
        Severity::Warn => "warn",
        Severity::Info => "info",
        _ => "unknown",
    }
}

fn method_key(method: u16) -> String {
    match method {
        0 => "0:store".to_string(),
        8 => "8:deflate".to_string(),
        other => format!("{other}:other"),
    }
}

fn extra_key(site: ExtraSite, id: u16, disposition: ExtraDisposition) -> String {
    let site = match site {
        ExtraSite::Local => "local",
        ExtraSite::Central => "central",
        _ => "unknown",
    };
    let disposition = match disposition {
        ExtraDisposition::Semantic => "semantic",
        ExtraDisposition::Ignored => "ignored",
        ExtraDisposition::Denied => "denied",
        _ => "unknown",
    };
    format!("{site}:0x{id:04x}:{disposition}")
}

fn normalization_key(action: &NormalizationAction) -> String {
    match action {
        NormalizationAction::StripDirectoryTrailingSlash => {
            "strip-directory-trailing-slash".to_string()
        }
        NormalizationAction::DropDotComponent { .. } => "drop-dot-component".to_string(),
        _ => "unknown".to_string(),
    }
}

fn summarize(artifacts: &[ArtifactReport]) -> Summary {
    let mut summary = Summary::default();
    for artifact in artifacts {
        increment(&mut summary.admission, artifact.admission.clone());
        increment(&mut summary.cohorts, artifact.cohort.clone());
        if artifact.admission == "admitted" {
            increment(&mut summary.admitted_by_cohort, artifact.cohort.clone());
        }
        let mut artifact_codes = BTreeSet::new();
        for finding in &artifact.findings {
            increment(&mut summary.finding_occurrences, finding.code.clone());
            artifact_codes.insert(finding.code.clone());
        }
        for code in artifact_codes {
            increment(&mut summary.finding_artifacts, code);
        }
        merge_counts(&mut summary.methods, &artifact.methods);
        merge_counts(&mut summary.flags, &artifact.flags);
        merge_counts(&mut summary.extra_fields, &artifact.extra_fields);
        merge_counts(
            &mut summary.normalization_actions,
            &artifact.normalization_actions,
        );
        if artifact.archive_ir_available {
            increment(
                &mut summary.top_level_dist_info_path_counts,
                artifact.top_level_dist_info_paths.len().to_string(),
            );
            merge_counts(
                &mut summary.candidate_metadata_members,
                &artifact.candidate_metadata_name_counts,
            );
            merge_counts(
                &mut summary.top_level_metadata_members,
                &artifact.top_level_metadata_name_counts,
            );
        }
    }
    summary
}

fn increment(counts: &mut BTreeMap<String, u64>, key: String) {
    *counts.entry(key).or_default() += 1;
}

fn merge_counts(target: &mut BTreeMap<String, u64>, source: &BTreeMap<String, u64>) {
    for (key, count) in source {
        *target.entry(key.clone()).or_default() += count;
    }
}

fn render_markdown(report: &Report) -> String {
    let mut output = String::new();
    let admitted = report
        .summary
        .admission
        .get("admitted")
        .copied()
        .unwrap_or(0);
    writeln!(output, "# Wheel compatibility pilot").unwrap();
    writeln!(output).unwrap();
    writeln!(output, "> Status: non-shipping compatibility evidence. This is a deliberately small, stratified pilot, not a claim about PyPI-wide acceptance or wheel support.").unwrap();
    writeln!(output).unwrap();
    writeln!(output, "- Query date: `{}`", report.query_date).unwrap();
    writeln!(output, "- Artifacts: `{}`", report.artifact_count).unwrap();
    writeln!(output, "- Source bytes: `{}`", report.source_bytes).unwrap();
    writeln!(
        output,
        "- Analyzer revision: `{}`",
        report.analyzer_revision
    )
    .unwrap();
    writeln!(
        output,
        "- Interpretation profile: `{}`",
        report.interpretation_profile
    )
    .unwrap();
    writeln!(
        output,
        "- Interpretation profile SHA-256: `{}`",
        report.interpretation_profile_sha256
    )
    .unwrap();
    writeln!(output, "- Policy: `{}`", report.policy).unwrap();
    writeln!(output, "- Policy SHA-256: `{}`", report.policy_sha256).unwrap();
    writeln!(
        output,
        "- Admitted by current strict ASCII ZIP profile: `{admitted}/{}`",
        report.artifact_count
    )
    .unwrap();
    writeln!(output, "- Manifest SHA-256: `{}`", report.manifest_sha256).unwrap();
    writeln!(
        output,
        "- Selection: {}",
        markdown_cell(&report.selection_method)
    )
    .unwrap();
    writeln!(output).unwrap();
    writeln!(output, "The [corpus manifest and reproduction instructions](../tests/corpus/wheels/README.md) define acquisition, full re-analysis, and offline report verification.").unwrap();
    writeln!(output).unwrap();

    render_count_table(
        &mut output,
        "Admission",
        "Result",
        &report.summary.admission,
    );
    render_cohort_table(&mut output, report);
    render_count_table(
        &mut output,
        "Artifacts by finding code",
        "Finding",
        &report.summary.finding_artifacts,
    );
    render_count_table(
        &mut output,
        "Finding occurrences",
        "Finding",
        &report.summary.finding_occurrences,
    );
    render_count_table(&mut output, "Methods", "Method", &report.summary.methods);
    render_count_table(
        &mut output,
        "General-purpose flags",
        "Flags",
        &report.summary.flags,
    );
    render_count_table(
        &mut output,
        "Extra fields",
        "Site, ID, disposition",
        &report.summary.extra_fields,
    );
    render_count_table(
        &mut output,
        "Normalization actions",
        "Action",
        &report.summary.normalization_actions,
    );
    render_count_table(
        &mut output,
        "Top-level .dist-info paths per interpreted artifact",
        "Path count",
        &report.summary.top_level_dist_info_path_counts,
    );
    render_count_table(
        &mut output,
        "Candidate metadata members under any .dist-info path",
        "Basename",
        &report.summary.candidate_metadata_members,
    );
    render_count_table(
        &mut output,
        "Candidate metadata members under top-level .dist-info paths",
        "Basename",
        &report.summary.top_level_metadata_members,
    );

    writeln!(output, "## Artifacts").unwrap();
    writeln!(output).unwrap();
    writeln!(
        output,
        "| Project | Cohort | Result | Members | .dist-info top/all | Findings | Filename |"
    )
    .unwrap();
    writeln!(output, "|---|---|---:|---:|---:|---|---|").unwrap();
    for artifact in &report.artifacts {
        let members = if artifact.archive_ir_available {
            artifact.member_count.to_string()
        } else {
            "unavailable".to_string()
        };
        let dist_info = if artifact.archive_ir_available {
            format!(
                "{}/{}",
                artifact.top_level_dist_info_paths.len(),
                artifact.dist_info_paths.len()
            )
        } else {
            "unavailable".to_string()
        };
        let findings = if artifact.findings.is_empty() {
            "none".to_string()
        } else {
            finding_counts(&artifact.findings)
                .into_iter()
                .map(|(code, count)| {
                    if count == 1 {
                        code
                    } else {
                        format!("{code} ({count})")
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        writeln!(
            output,
            "| {} {} | {} | {} | {} | {} | {} | `{}` |",
            markdown_cell(&artifact.project),
            markdown_cell(&artifact.version),
            markdown_cell(&artifact.cohort),
            artifact.admission,
            members,
            dist_info,
            markdown_cell(&findings),
            markdown_cell(&artifact.filename)
        )
        .unwrap();
    }
    writeln!(output).unwrap();
    render_denial_evidence(&mut output, report);
    writeln!(output, "## Interpretation").unwrap();
    writeln!(output).unwrap();
    writeln!(output, "The report is produced only through Sealr's public `apply` outcome and read-only `ArchiveIR`. It does not invoke Python `zipfile`, another ZIP parser, or an external extractor. Counts describe the exact byte-addressed artifacts in the manifest. Rejected artifacts can lack an IR, so their container features are not inferred by a fallback parser.").unwrap();
    writeln!(output).unwrap();
    writeln!(output, "The `.dist-info` and metadata-name counts are structural candidates only. They do not parse metadata or decide which directory matches the outer wheel filename. Distinguishing one top-level artifact directory from nested vendored `.dist-info` trees is a required consumer step.").unwrap();
    writeln!(output).unwrap();
    writeln!(output, "This pilot does not justify relaxing the default `100:1` per-member expansion-ratio limit. A ratio denial is a bounded-resource policy decision, not a parser incompatibility, and any future change needs a larger corpus plus explicit memory, time, and adversarial-cost analysis.").unwrap();
    writeln!(output).unwrap();
    writeln!(output, "The pilot can identify candidate flag and extra-field rules for the next profile, but it cannot establish ecosystem prevalence, semantic safety of ignored payloads, wheel metadata correctness, `RECORD` agreement, target compatibility, or install-plan identity. Those remain separate gates.").unwrap();
    output
}

fn finding_counts(findings: &[FindingObservation]) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        increment(&mut counts, finding.code.clone());
    }
    counts
}

fn render_denial_evidence(output: &mut String, report: &Report) {
    writeln!(output, "## Denial evidence").unwrap();
    writeln!(output).unwrap();
    let denied: Vec<_> = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.admission != "admitted")
        .flat_map(|artifact| {
            artifact
                .findings
                .iter()
                .map(move |finding| (artifact, finding))
        })
        .collect();
    if denied.is_empty() {
        writeln!(output, "No denial findings.").unwrap();
        writeln!(output).unwrap();
        return;
    }
    writeln!(output, "| Artifact | Finding | Member | Detail |").unwrap();
    writeln!(output, "|---|---|---|---|").unwrap();
    for (artifact, finding) in denied {
        writeln!(
            output,
            "| `{}` | `{}` | {} | {} |",
            markdown_cell(&artifact.filename),
            markdown_cell(&finding.code),
            markdown_cell(finding.member.as_deref().unwrap_or("archive")),
            markdown_cell(&finding.detail)
        )
        .unwrap();
    }
    writeln!(output).unwrap();
}

fn render_count_table(
    output: &mut String,
    heading: &str,
    key_heading: &str,
    counts: &BTreeMap<String, u64>,
) {
    writeln!(output, "## {heading}").unwrap();
    writeln!(output).unwrap();
    if counts.is_empty() {
        writeln!(output, "No observations.").unwrap();
        writeln!(output).unwrap();
        return;
    }
    writeln!(output, "| {key_heading} | Count |").unwrap();
    writeln!(output, "|---|---:|").unwrap();
    for (key, count) in counts {
        writeln!(output, "| `{}` | {count} |", markdown_cell(key)).unwrap();
    }
    writeln!(output).unwrap();
}

fn render_cohort_table(output: &mut String, report: &Report) {
    writeln!(output, "## Cohorts").unwrap();
    writeln!(output).unwrap();
    writeln!(output, "| Cohort | Artifacts | Admitted |").unwrap();
    writeln!(output, "|---|---:|---:|").unwrap();
    for (cohort, count) in &report.summary.cohorts {
        let admitted = report
            .summary
            .admitted_by_cohort
            .get(cohort)
            .copied()
            .unwrap_or(0);
        writeln!(
            output,
            "| `{}` | {count} | {admitted} |",
            markdown_cell(cohort)
        )
        .unwrap();
    }
    writeln!(output).unwrap();
}

fn markdown_cell(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('`', "&#96;")
        .replace('|', "\\|")
        .replace("\r\n", "<br>")
        .replace(['\r', '\n'], "<br>")
}

fn verify_committed_report(
    manifest_path: &Path,
    json_path: &Path,
    markdown_path: &Path,
) -> Result<(), AnyError> {
    let manifest_raw = read_bounded(manifest_path, MAX_MANIFEST_BYTES, "manifest")?;
    let manifest = parse_manifest(&manifest_raw)?;
    let json = read_bounded_string(json_path, MAX_REPORT_BYTES, "JSON report")?;
    let report: Report = serde_json::from_str(&json)?;
    validate_report(&report, &manifest, &manifest_raw)?;

    let mut canonical_json = serde_json::to_string_pretty(&report)?;
    canonical_json.push('\n');
    if json != canonical_json {
        return invalid(format!(
            "{} is not canonical report JSON",
            json_path.display()
        ));
    }
    check_exact(markdown_path, &render_markdown(&report))?;
    Ok(())
}

fn validate_report(
    report: &Report,
    manifest: &Manifest,
    manifest_raw: &[u8],
) -> Result<(), AnyError> {
    if report.schema != REPORT_SCHEMA {
        return invalid(format!("unsupported report schema {}", report.schema));
    }
    if report.manifest_sha256 != sha256_hex(manifest_raw) {
        return invalid("report manifest digest does not match the manifest bytes");
    }
    if report.query_date != manifest.query_date
        || report.selection_method != manifest.selection_method
    {
        return invalid("report corpus description does not match the manifest");
    }
    if report.analyzer_revision != ANALYZER_REVISION {
        return invalid("report analyzer revision does not match this wheel lab");
    }
    if report.interpretation_profile != ZIP_STRICT_ASCII_V1
        || report.interpretation_profile_sha256 != zip_strict_ascii_v1_digest()
    {
        return invalid("report interpretation profile does not match this Sealr build");
    }
    let policy = Policy::default_v1();
    if report.policy != policy.id || report.policy_sha256 != policy.digest_hex() {
        return invalid("report policy does not match the default policy in this Sealr build");
    }
    if report.artifact_count != manifest.entries.len()
        || report.artifacts.len() != manifest.entries.len()
        || report.source_bytes != manifest_size(manifest)?
    {
        return invalid("report corpus totals do not match the manifest");
    }

    let mut inventoried_members = 0_u64;
    let mut finding_occurrences = 0_u64;
    for (artifact, entry) in report.artifacts.iter().zip(&manifest.entries) {
        if artifact.project != entry.project
            || artifact.version != entry.version
            || artifact.cohort != entry.cohort
            || artifact.filename != entry.filename
            || artifact.sha256 != entry.sha256
            || artifact.size != entry.size
            || artifact.upload_time != entry.upload_time
        {
            return invalid(format!(
                "report metadata does not match manifest entry {}",
                entry.filename
            ));
        }
        validate_artifact_report(artifact)?;
        inventoried_members = inventoried_members
            .checked_add(artifact.member_count)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "member count overflow"))?;
        finding_occurrences = finding_occurrences
            .checked_add(artifact.findings.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "finding count overflow"))?;
        if inventoried_members > MAX_INVENTORIED_MEMBERS
            || finding_occurrences > MAX_FINDING_OCCURRENCES
        {
            return invalid("report exceeds its corpus-wide inventory limits");
        }
    }
    if report.summary != summarize(&report.artifacts) {
        return invalid("report summary does not match its artifact records");
    }
    validate_positive_counts(&report.summary.admission, "admission")?;
    validate_positive_counts(&report.summary.cohorts, "cohort")?;
    validate_positive_counts(&report.summary.admitted_by_cohort, "admitted cohort")?;
    validate_positive_counts(&report.summary.finding_artifacts, "finding artifact")?;
    validate_positive_counts(&report.summary.finding_occurrences, "finding occurrence")?;
    validate_positive_counts(
        &report.summary.top_level_dist_info_path_counts,
        "top-level dist-info path",
    )?;
    validate_positive_counts(
        &report.summary.candidate_metadata_members,
        "candidate metadata member",
    )?;
    validate_positive_counts(
        &report.summary.top_level_metadata_members,
        "top-level metadata member",
    )?;
    Ok(())
}

fn validate_artifact_report(artifact: &ArtifactReport) -> Result<(), AnyError> {
    if !matches!(
        artifact.admission.as_str(),
        "admitted" | "denied" | "not-evaluated"
    ) {
        return invalid(format!(
            "unsupported admission value for {}",
            artifact.filename
        ));
    }
    if !artifact.findings.windows(2).all(|pair| pair[0] <= pair[1]) {
        return invalid(format!("unsorted findings for {}", artifact.filename));
    }
    for finding in &artifact.findings {
        if finding.code.is_empty()
            || finding.detail.is_empty()
            || !matches!(
                finding.severity.as_str(),
                "error" | "deny" | "warn" | "info"
            )
        {
            return invalid(format!("invalid finding for {}", artifact.filename));
        }
    }
    if (artifact.admission == "admitted" && !artifact.archive_ir_available)
        || (artifact.admission != "admitted" && artifact.findings.is_empty())
    {
        return invalid(format!(
            "admission and evidence availability are inconsistent for {}",
            artifact.filename
        ));
    }
    for (counts, label) in [
        (&artifact.methods, "method"),
        (&artifact.flags, "flags"),
        (&artifact.extra_fields, "extra field"),
        (&artifact.normalization_actions, "normalization action"),
        (
            &artifact.candidate_metadata_name_counts,
            "candidate metadata member",
        ),
        (
            &artifact.top_level_metadata_name_counts,
            "top-level metadata member",
        ),
    ] {
        validate_positive_counts(counts, label)?;
    }

    if artifact.archive_ir_available {
        let files_and_directories = artifact
            .file_count
            .checked_add(artifact.directory_count)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "member count overflow"))?;
        if files_and_directories != artifact.member_count
            || count_total(&artifact.methods)? != artifact.member_count
            || count_total(&artifact.flags)? != artifact.member_count
        {
            return invalid(format!(
                "IR counts are inconsistent for {}",
                artifact.filename
            ));
        }
    } else if artifact.member_count != 0
        || artifact.file_count != 0
        || artifact.directory_count != 0
        || artifact.declared_compressed_bytes != 0
        || artifact.declared_uncompressed_bytes != 0
        || artifact.max_path_bytes != 0
        || artifact.max_path_depth != 0
        || !artifact.methods.is_empty()
        || !artifact.flags.is_empty()
        || !artifact.extra_fields.is_empty()
        || !artifact.normalization_actions.is_empty()
        || !artifact.dist_info_paths.is_empty()
        || !artifact.top_level_dist_info_paths.is_empty()
        || !artifact.candidate_metadata_name_counts.is_empty()
        || !artifact.top_level_metadata_name_counts.is_empty()
    {
        return invalid(format!(
            "IR-derived fields exist without an IR for {}",
            artifact.filename
        ));
    }
    if !artifact
        .dist_info_paths
        .windows(2)
        .all(|pair| pair[0] < pair[1])
        || !artifact
            .top_level_dist_info_paths
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return invalid(format!(
            "dist-info paths are not strictly sorted for {}",
            artifact.filename
        ));
    }
    let all_dist_info: BTreeSet<_> = artifact.dist_info_paths.iter().collect();
    if artifact.top_level_dist_info_paths.iter().any(|path| {
        path.contains('/') || !path.ends_with(".dist-info") || !all_dist_info.contains(path)
    }) {
        return invalid(format!(
            "top-level dist-info paths are inconsistent for {}",
            artifact.filename
        ));
    }
    for (name, count) in &artifact.top_level_metadata_name_counts {
        if !matches!(
            name.as_str(),
            "WHEEL" | "METADATA" | "RECORD" | "entry_points.txt"
        ) {
            return invalid(format!(
                "unknown metadata candidate for {}",
                artifact.filename
            ));
        }
        if artifact
            .candidate_metadata_name_counts
            .get(name)
            .is_none_or(|all_count| count > all_count)
        {
            return invalid(format!(
                "top-level metadata count is inconsistent for {}",
                artifact.filename
            ));
        }
    }
    if artifact.candidate_metadata_name_counts.keys().any(|name| {
        !matches!(
            name.as_str(),
            "WHEEL" | "METADATA" | "RECORD" | "entry_points.txt"
        )
    }) {
        return invalid(format!(
            "unknown metadata candidate for {}",
            artifact.filename
        ));
    }
    Ok(())
}

fn validate_positive_counts(counts: &BTreeMap<String, u64>, label: &str) -> Result<(), AnyError> {
    if counts
        .iter()
        .any(|(key, count)| key.is_empty() || *count == 0)
    {
        return invalid(format!("invalid {label} count map"));
    }
    Ok(())
}

fn count_total(counts: &BTreeMap<String, u64>) -> Result<u64, AnyError> {
    counts.values().try_fold(0_u64, |total, count| {
        total
            .checked_add(*count)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "count overflow").into())
    })
}

fn check_exact(path: &Path, expected: &str) -> Result<(), AnyError> {
    let actual = read_bounded_string(path, MAX_REPORT_BYTES, "report")?;
    if actual != expected {
        return invalid(format!("{} is stale; rerun analyze", path.display()));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(filename: &str, digest: &str) -> ManifestEntry {
        ManifestEntry {
            project: "example".to_string(),
            version: "1.0".to_string(),
            cohort: "universal".to_string(),
            filename: filename.to_string(),
            url: format!("https://files.pythonhosted.org/packages/aa/bb/{filename}"),
            sha256: digest.to_string(),
            size: 1,
            upload_time: "2026-08-22T00:00:00Z".to_string(),
            provenance_url: "https://pypi.org/project/example/1.0/#files".to_string(),
        }
    }

    fn manifest(entries: Vec<ManifestEntry>) -> Manifest {
        Manifest {
            schema: MANIFEST_SCHEMA.to_string(),
            query_date: "2026-08-22".to_string(),
            selection_method: "test".to_string(),
            entries,
        }
    }

    fn artifact(name: &str, finding_codes: &[&str]) -> ArtifactReport {
        ArtifactReport {
            project: "example".to_string(),
            version: "1.0".to_string(),
            cohort: "universal".to_string(),
            filename: name.to_string(),
            sha256: "0".repeat(64),
            size: 1,
            upload_time: "2026-08-22T00:00:00Z".to_string(),
            admission: if finding_codes.is_empty() {
                "admitted".to_string()
            } else {
                "denied".to_string()
            },
            findings: finding_codes
                .iter()
                .map(|code| FindingObservation {
                    code: (*code).to_string(),
                    severity: "error".to_string(),
                    member: None,
                    detail: "test".to_string(),
                })
                .collect(),
            archive_ir_available: false,
            member_count: 0,
            file_count: 0,
            directory_count: 0,
            declared_compressed_bytes: 0,
            declared_uncompressed_bytes: 0,
            max_path_bytes: 0,
            max_path_depth: 0,
            methods: BTreeMap::new(),
            flags: BTreeMap::new(),
            extra_fields: BTreeMap::new(),
            normalization_actions: BTreeMap::new(),
            dist_info_paths: Vec::new(),
            top_level_dist_info_paths: Vec::new(),
            candidate_metadata_name_counts: BTreeMap::new(),
            top_level_metadata_name_counts: BTreeMap::new(),
        }
    }

    fn report_for(manifest: &Manifest, raw: &[u8], artifacts: Vec<ArtifactReport>) -> Report {
        let policy = Policy::default_v1();
        Report {
            schema: REPORT_SCHEMA.to_string(),
            manifest_sha256: sha256_hex(raw),
            query_date: manifest.query_date.clone(),
            selection_method: manifest.selection_method.clone(),
            analyzer_revision: ANALYZER_REVISION.to_string(),
            interpretation_profile: ZIP_STRICT_ASCII_V1.to_string(),
            interpretation_profile_sha256: zip_strict_ascii_v1_digest(),
            policy: policy.id.clone(),
            policy_sha256: policy.digest_hex(),
            artifact_count: artifacts.len(),
            source_bytes: manifest_size(manifest).unwrap(),
            summary: summarize(&artifacts),
            artifacts,
        }
    }

    #[test]
    fn validates_a_bounded_sorted_manifest() {
        let first = "0".repeat(64);
        let second = "1".repeat(64);
        validate_manifest(&manifest(vec![
            entry("a-1-py3-none-any.whl", &first),
            entry("b-1-py3-none-any.whl", &second),
        ]))
        .unwrap();
    }

    #[test]
    fn rejects_duplicate_or_unsorted_artifacts() {
        let digest = "0".repeat(64);
        assert!(validate_manifest(&manifest(vec![
            entry("b-1-py3-none-any.whl", &digest),
            entry("a-1-py3-none-any.whl", &"1".repeat(64)),
        ]))
        .is_err());
        assert!(validate_manifest(&manifest(vec![
            entry("a-1-py3-none-any.whl", &digest),
            entry("b-1-py3-none-any.whl", &digest),
        ]))
        .is_err());
    }

    #[test]
    fn rejects_non_pypi_or_unbounded_entries() {
        let mut invalid_entry = entry("a-1-py3-none-any.whl", &"0".repeat(64));
        invalid_entry.url = "https://example.com/a-1-py3-none-any.whl".to_string();
        assert!(validate_manifest(&manifest(vec![invalid_entry])).is_err());

        let mut huge_entry = entry("a-1-py3-none-any.whl", &"0".repeat(64));
        huge_entry.size = MAX_ARTIFACT_BYTES + 1;
        assert!(validate_manifest(&manifest(vec![huge_entry])).is_err());
    }

    #[test]
    fn rejects_malformed_dates_and_filenames() {
        let mut bad_date = manifest(vec![entry("a-1-py3-none-any.whl", &"0".repeat(64))]);
        bad_date.query_date = "2026-aa-22".to_string();
        assert!(validate_manifest(&bad_date).is_err());

        bad_date.query_date = "2026-02-29".to_string();
        assert!(validate_manifest(&bad_date).is_err());

        let bad_name = entry("a-1-py3-none-any?.whl", &"0".repeat(64));
        assert!(validate_manifest(&manifest(vec![bad_name])).is_err());

        let mut bad_upload = entry("a-1-py3-none-any.whl", &"0".repeat(64));
        bad_upload.upload_time = "2026-08-22T25:00:00Z".to_string();
        assert!(validate_manifest(&manifest(vec![bad_upload])).is_err());
    }

    #[test]
    fn distinguishes_affected_artifacts_from_finding_occurrences() {
        let summary = summarize(&[
            artifact("a.whl", &["quota.ratio", "quota.ratio"]),
            artifact("b.whl", &["quota.ratio"]),
        ]);
        assert_eq!(summary.finding_artifacts.get("quota.ratio"), Some(&2));
        assert_eq!(summary.finding_occurrences.get("quota.ratio"), Some(&3));
    }

    #[test]
    fn report_validation_rejects_tampered_rollups_and_impossible_evidence() {
        let manifest = manifest(vec![entry("a-1-py3-none-any.whl", &"0".repeat(64))]);
        let raw = serde_json::to_vec(&manifest).unwrap();
        let mut report = report_for(
            &manifest,
            &raw,
            vec![artifact("a-1-py3-none-any.whl", &["quota.ratio"])],
        );
        validate_report(&report, &manifest, &raw).unwrap();

        report.summary.admission.insert("denied".to_string(), 2);
        assert!(validate_report(&report, &manifest, &raw).is_err());

        let mut impossible = artifact("a-1-py3-none-any.whl", &[]);
        assert!(validate_artifact_report(&impossible).is_err());
        impossible.admission = "denied".to_string();
        impossible.member_count = 1;
        assert!(validate_artifact_report(&impossible).is_err());
    }

    #[test]
    fn markdown_cells_neutralize_table_and_markup_controls() {
        assert_eq!(markdown_cell("a|b\n<c>`"), "a\\|b<br>&lt;c&gt;&#96;");
    }

    #[test]
    fn sha256_encoding_is_pinned() {
        assert_eq!(
            sha256_hex(b"sealr wheel lab"),
            "32e5d1166e26e65692ea71cc1ebc0d42d9ae724f0564c19fecd39e27d3806030"
        );
    }
}
