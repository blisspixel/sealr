//! Predecessor-bound inventory for the shipped Alpha.8 wheel evaluator.
//!
//! This binary remains separate from `wheel_inventory_v2` so the Alpha.7
//! analyzer and report stay executable under their exact historical profile.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use sealr::wheel::{evaluate_wheel, EvaluationStage, InstallScheme, WheelEvaluation, WheelLimits};
use sealr::{
    apply_with_options, ApplyOptions, Policy, Request, Source, ZipInterpretationProfile,
    ZIP_PORTABLE_UTF8_V1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REPORT_SCHEMA: &str = "sealr.wheel-compatibility-report.v3";
const ANALYZER: &str = "sealr-wheel-inventory.v3";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_REPORT_BYTES: u64 = 32 * 1024 * 1024;

type AnyError = Box<dyn Error>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    query_date: String,
    selection_method: String,
    entries: Vec<ManifestEntry>,
}

#[derive(Deserialize)]
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema: String,
    predecessor_report_sha256: String,
    manifest_sha256: String,
    query_date: String,
    selection_method: String,
    analyzer: String,
    interpretation_profile: String,
    interpretation_profile_sha256: String,
    artifact_count: usize,
    source_bytes: u64,
    summary: Summary,
    artifacts: Vec<Artifact>,
}

#[derive(Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Summary {
    outcomes: BTreeMap<String, u64>,
    metadata_versions: BTreeMap<String, u64>,
    generators: BTreeMap<String, u64>,
    data_schemes: BTreeMap<String, u64>,
    filename_tags: BTreeMap<String, u64>,
    finding_artifacts: BTreeMap<String, u64>,
    finding_occurrences: BTreeMap<String, u64>,
    creator_systems: BTreeMap<String, u64>,
    artifacts_with_unicode_paths: u64,
    executable_members: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    project: String,
    version: String,
    cohort: String,
    filename: String,
    sha256: String,
    size: u64,
    outcome: String,
    findings: Vec<Finding>,
    metadata_version: Option<String>,
    generator: Option<String>,
    data_schemes: Vec<String>,
    filename_tags: Vec<String>,
    unicode_paths: u64,
    creator_systems: BTreeMap<String, u64>,
    executable_members: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Finding {
    stage: String,
    code: String,
    detail: String,
    path: Option<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("wheel inventory v3: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), AnyError> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("analyze") => {
            let manifest = required_path(&mut args, "manifest")?;
            let cache = required_path(&mut args, "cache")?;
            let report = required_path(&mut args, "report")?;
            let markdown = required_path(&mut args, "markdown")?;
            reject_extra(args)?;
            let (json, document) = analyze(&manifest, &cache)?;
            fs::write(report, json)?;
            fs::write(markdown, document)?;
        }
        Some("verify") => {
            let manifest = required_path(&mut args, "manifest")?;
            let report = required_path(&mut args, "report")?;
            let markdown = required_path(&mut args, "markdown")?;
            reject_extra(args)?;
            verify(&manifest, &report, &markdown)?;
            println!("wheel compatibility inventory v3 is internally consistent");
        }
        _ => return Err(usage()),
    }
    Ok(())
}

fn analyze(manifest_path: &Path, cache: &Path) -> Result<(Vec<u8>, Vec<u8>), AnyError> {
    let raw_manifest = read_bounded(manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: Manifest = serde_json::from_slice(&raw_manifest)?;
    if manifest.schema != "sealr.wheel-corpus.v1" || manifest.entries.len() > 128 {
        return invalid("manifest schema or artifact count is unsupported");
    }
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
    let limits = WheelLimits::default();
    let mut artifacts = Vec::new();
    let mut summary = Summary::default();
    let mut source_bytes = 0_u64;
    for entry in &manifest.entries {
        if !entry.url.starts_with("https://files.pythonhosted.org/")
            || entry.upload_time.is_empty()
            || !entry.provenance_url.starts_with("https://pypi.org/")
        {
            return invalid(format!(
                "manifest provenance fields are invalid for {}",
                entry.filename
            ));
        }
        source_bytes = source_bytes
            .checked_add(entry.size)
            .ok_or("source byte total overflowed")?;
        let path = cache.join(format!("{}.whl", entry.sha256));
        let bytes = read_bounded(&path, MAX_ARTIFACT_BYTES)?;
        if bytes.len() as u64 != entry.size || hex_sha256(&bytes) != entry.sha256 {
            return invalid(format!("cached bytes disagree for {}", entry.filename));
        }
        let outcome = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some(&entry.filename),
                    data: &bytes,
                },
                policy: &policy,
                dest: None,
            },
            &options,
        );
        let mut artifact = Artifact {
            project: entry.project.clone(),
            version: entry.version.clone(),
            cohort: entry.cohort.clone(),
            filename: entry.filename.clone(),
            sha256: entry.sha256.clone(),
            size: entry.size,
            outcome: "denied".into(),
            findings: Vec::new(),
            metadata_version: None,
            generator: None,
            data_schemes: Vec::new(),
            filename_tags: Vec::new(),
            unicode_paths: 0,
            creator_systems: BTreeMap::new(),
            executable_members: 0,
        };
        if outcome.rejected() {
            artifact.findings = outcome
                .view
                .findings
                .iter()
                .map(|finding| Finding {
                    stage: "container".into(),
                    code: finding.code.as_str().into(),
                    detail: finding.detail.clone(),
                    path: finding.member.clone(),
                })
                .collect();
        } else {
            let archive = outcome
                .verified_archive()
                .ok_or("admitted outcome lacks capability")?;
            artifact.unicode_paths = archive
                .members()
                .iter()
                .filter(|member| !member.canonical_path.is_ascii())
                .count() as u64;
            match evaluate_wheel(&entry.filename, archive, limits) {
                WheelEvaluation::Admitted {
                    artifact: wheel,
                    plan,
                    ..
                } => {
                    artifact.outcome = "admitted".into();
                    artifact.metadata_version = Some(wheel.metadata.metadata_version);
                    artifact.generator = wheel.wheel.generator;
                    artifact.filename_tags = wheel.filename.expanded_tags;
                    artifact.data_schemes = plan
                        .entries()
                        .iter()
                        .filter(|plan_entry| {
                            wheel.data_root.as_ref().is_some_and(|root| {
                                plan_entry
                                    .source_path
                                    .as_ref()
                                    .is_some_and(|path| path.starts_with(&format!("{root}/")))
                            })
                        })
                        .map(|entry| scheme(&entry.scheme).to_owned())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                    for facts in wheel.member_facts {
                        *artifact
                            .creator_systems
                            .entry(facts.creator_system.to_string())
                            .or_default() += 1;
                        artifact.executable_members += u64::from(facts.source_executable);
                    }
                }
                WheelEvaluation::Denied { findings } => {
                    artifact.findings = findings
                        .into_iter()
                        .map(|finding| Finding {
                            stage: stage(finding.stage),
                            code: finding.code,
                            detail: finding.detail,
                            path: finding.path,
                        })
                        .collect();
                }
                WheelEvaluation::Unsupported { findings } => {
                    artifact.outcome = "unsupported".into();
                    artifact.findings = findings
                        .into_iter()
                        .map(|finding| Finding {
                            stage: stage(finding.stage),
                            code: finding.code,
                            detail: finding.detail,
                            path: finding.path,
                        })
                        .collect();
                }
                WheelEvaluation::InfrastructureFailure { detail, .. } => {
                    return invalid(format!("{}: {detail}", entry.filename));
                }
                _ => return invalid("wheel evaluator returned an unknown outcome variant"),
            }
        }
        rollup(&mut summary, &artifact);
        artifacts.push(artifact);
    }
    let report = Report {
        schema: REPORT_SCHEMA.into(),
        predecessor_report_sha256: hex_sha256(&fs::read("tests/corpus/wheels/report-v2.json")?),
        manifest_sha256: hex_sha256(&raw_manifest),
        query_date: manifest.query_date,
        selection_method: manifest.selection_method,
        analyzer: ANALYZER.into(),
        interpretation_profile: ZIP_PORTABLE_UTF8_V1.into(),
        interpretation_profile_sha256: sealr::zip_portable_utf8_v1_digest(),
        artifact_count: artifacts.len(),
        source_bytes,
        summary,
        artifacts,
    };
    encode(&report)
}

fn rollup(summary: &mut Summary, artifact: &Artifact) {
    *summary
        .outcomes
        .entry(artifact.outcome.clone())
        .or_default() += 1;
    if let Some(version) = &artifact.metadata_version {
        *summary
            .metadata_versions
            .entry(version.clone())
            .or_default() += 1;
    }
    if let Some(generator) = &artifact.generator {
        *summary.generators.entry(generator.clone()).or_default() += 1;
    }
    for value in &artifact.data_schemes {
        *summary.data_schemes.entry(value.clone()).or_default() += 1;
    }
    for value in &artifact.filename_tags {
        *summary.filename_tags.entry(value.clone()).or_default() += 1;
    }
    for (system, count) in &artifact.creator_systems {
        *summary.creator_systems.entry(system.clone()).or_default() += count;
    }
    summary.artifacts_with_unicode_paths += u64::from(artifact.unicode_paths > 0);
    summary.executable_members += artifact.executable_members;
    let mut artifact_codes = BTreeSet::new();
    for finding in &artifact.findings {
        *summary
            .finding_occurrences
            .entry(finding.code.clone())
            .or_default() += 1;
        artifact_codes.insert(finding.code.clone());
    }
    for code in artifact_codes {
        *summary.finding_artifacts.entry(code).or_default() += 1;
    }
}

fn encode(report: &Report) -> Result<(Vec<u8>, Vec<u8>), AnyError> {
    let mut json = serde_json::to_vec_pretty(report)?;
    json.push(b'\n');
    let markdown = render(report).into_bytes();
    if json.len() as u64 > MAX_REPORT_BYTES || markdown.len() as u64 > MAX_REPORT_BYTES {
        return invalid("generated inventory exceeds its report cap");
    }
    Ok((json, markdown))
}

fn render(report: &Report) -> String {
    let mut out = String::new();
    writeln!(out, "# Wheel compatibility inventory v3\n").unwrap();
    writeln!(out, "> Status: Alpha.8 supported-preview baseline over the pinned 20-wheel pilot. This is not a PyPI prevalence estimate or a claim of general wheel compatibility.\n").unwrap();
    writeln!(out, "- Analyzer: `{}`", report.analyzer).unwrap();
    writeln!(out, "- Profile: `{}`", report.interpretation_profile).unwrap();
    writeln!(
        out,
        "- Profile SHA-256: `{}`",
        report.interpretation_profile_sha256
    )
    .unwrap();
    writeln!(out, "- Artifacts: `{}`", report.artifact_count).unwrap();
    writeln!(out, "- Source bytes: `{}`\n", report.source_bytes).unwrap();
    table(&mut out, "Outcomes", &report.summary.outcomes);
    table(
        &mut out,
        "Metadata versions",
        &report.summary.metadata_versions,
    );
    table(&mut out, "Generators", &report.summary.generators);
    table(&mut out, ".data schemes", &report.summary.data_schemes);
    table(
        &mut out,
        "Expanded filename tags",
        &report.summary.filename_tags,
    );
    table(
        &mut out,
        "ZIP creator systems",
        &report.summary.creator_systems,
    );
    table(
        &mut out,
        "Finding clusters",
        &report.summary.finding_artifacts,
    );
    writeln!(out, "## Rejection-cluster investigation\n").unwrap();
    writeln!(out, "- `wheel.header-duplicate`: the cffi artifact contains two `Generator` fields. The supported model denies this because it has not defined ordered or merged generator semantics; this is a consumer-compatibility gap, not a container disagreement.").unwrap();
    writeln!(out, "- `wheel.metadata-version-unsupported`: Hatchling and wheel declare Core Metadata 2.5. The pinned supported snapshot implements 2.1 through 2.4, so both are unsupported rather than denied.").unwrap();
    writeln!(out, "- `quota.ratio`: SciPy reaches the existing default 100:1 expansion ceiling on three test-data members before wheel evaluation. The portable profile does not weaken the adversarial resource policy to improve corpus acceptance.\n").unwrap();
    writeln!(out, "## Predecessor delta\n").unwrap();
    writeln!(out, "The supported evaluator preserves the v2 cohort outcome of 16 admitted, two denied, and two unsupported artifacts. Every artifact in this cohort uses a zero general-purpose flag word, so admitting data descriptors in the portable profile does not change these results.").unwrap();
    writeln!(out, "\nThe supported model reports 60 source-executable members instead of 61. The removed case is an orjson member created under ZIP creator system 0 whose external attributes happen to resemble a Unix executable mode. Alpha.8 requires creator system 3 before treating Unix mode bits as executable authority; the immutable v2 report retains the exact PyPA installer 0.7.0 observation.\n").unwrap();
    writeln!(out, "## Additional observations\n").unwrap();
    writeln!(
        out,
        "- Artifacts with Unicode paths: `{}`",
        report.summary.artifacts_with_unicode_paths
    )
    .unwrap();
    writeln!(
        out,
        "- Unix-creator executable regular-file members: `{}`\n",
        report.summary.executable_members
    )
    .unwrap();
    writeln!(out, "## Artifacts\n").unwrap();
    writeln!(
        out,
        "| Project | Cohort | Outcome | Metadata | Generator | .data | Findings | Filename |"
    )
    .unwrap();
    writeln!(out, "|---|---|---|---|---|---|---|---|").unwrap();
    for artifact in &report.artifacts {
        let findings = artifact
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            out,
            "| {} {} | {} | {} | {} | {} | {} | {} | `{}` |",
            artifact.project,
            artifact.version,
            artifact.cohort,
            artifact.outcome,
            artifact
                .metadata_version
                .as_deref()
                .unwrap_or("unavailable"),
            artifact
                .generator
                .as_deref()
                .unwrap_or("unavailable")
                .replace('|', "\\|"),
            if artifact.data_schemes.is_empty() {
                "none".into()
            } else {
                artifact.data_schemes.join(", ")
            },
            if findings.is_empty() {
                "none"
            } else {
                &findings
            },
            artifact.filename
        )
        .unwrap();
    }
    out
}

fn table(out: &mut String, heading: &str, values: &BTreeMap<String, u64>) {
    writeln!(out, "## {heading}\n").unwrap();
    writeln!(out, "| Value | Count |\n|---|---:|").unwrap();
    if values.is_empty() {
        writeln!(out, "| none | 0 |").unwrap();
    } else {
        for (value, count) in values {
            writeln!(out, "| `{}` | {} |", value.replace('|', "\\|"), count).unwrap();
        }
    }
    writeln!(out).unwrap();
}

fn verify(manifest: &Path, report_path: &Path, markdown_path: &Path) -> Result<(), AnyError> {
    let raw_manifest = read_bounded(manifest, MAX_MANIFEST_BYTES)?;
    let manifest: Manifest = serde_json::from_slice(&raw_manifest)?;
    let raw_report = read_bounded(report_path, MAX_REPORT_BYTES)?;
    let report: Report = serde_json::from_slice(&raw_report)?;
    if report.schema != REPORT_SCHEMA
        || report.analyzer != ANALYZER
        || report.manifest_sha256 != hex_sha256(&raw_manifest)
        || report.interpretation_profile != ZIP_PORTABLE_UTF8_V1
        || report.interpretation_profile_sha256 != sealr::zip_portable_utf8_v1_digest()
        || report.predecessor_report_sha256
            != hex_sha256(&fs::read("tests/corpus/wheels/report-v2.json")?)
    {
        return invalid("inventory bindings are stale");
    }
    validate_report_semantics(&manifest, &report)?;
    let (canonical, markdown) = encode(&report)?;
    if canonical != raw_report || markdown != read_bounded(markdown_path, MAX_REPORT_BYTES)? {
        return invalid("inventory JSON or Markdown is not canonical");
    }
    Ok(())
}

fn validate_report_semantics(manifest: &Manifest, report: &Report) -> Result<(), AnyError> {
    if manifest.schema != "sealr.wheel-corpus.v1"
        || manifest.entries.len() > 128
        || report.query_date != manifest.query_date
        || report.selection_method != manifest.selection_method
        || report.artifact_count != report.artifacts.len()
        || report.artifact_count != manifest.entries.len()
    {
        return invalid("inventory manifest correspondence is invalid");
    }
    let source_bytes = manifest.entries.iter().try_fold(0_u64, |total, entry| {
        total
            .checked_add(entry.size)
            .ok_or("source byte total overflowed")
    })?;
    if report.source_bytes != source_bytes {
        return invalid("inventory source byte total is invalid");
    }

    let mut recomputed = Summary::default();
    for (entry, artifact) in manifest.entries.iter().zip(&report.artifacts) {
        if entry
            .url
            .strip_prefix("https://files.pythonhosted.org/")
            .is_none()
            || entry.upload_time.is_empty()
            || entry
                .provenance_url
                .strip_prefix("https://pypi.org/")
                .is_none()
            || artifact.project != entry.project
            || artifact.version != entry.version
            || artifact.cohort != entry.cohort
            || artifact.filename != entry.filename
            || artifact.sha256 != entry.sha256
            || artifact.size != entry.size
        {
            return invalid(format!(
                "inventory artifact disagrees with manifest entry {}",
                entry.filename
            ));
        }
        match artifact.outcome.as_str() {
            "admitted"
                if artifact.findings.is_empty()
                    && artifact.metadata_version.is_some()
                    && !artifact.creator_systems.is_empty() => {}
            "denied" | "unsupported"
                if !artifact.findings.is_empty()
                    && artifact.metadata_version.is_none()
                    && artifact.generator.is_none()
                    && artifact.data_schemes.is_empty()
                    && artifact.filename_tags.is_empty()
                    && artifact.unicode_paths == 0
                    && artifact.creator_systems.is_empty()
                    && artifact.executable_members == 0 => {}
            _ => {
                return invalid(format!(
                    "inventory outcome fields are incoherent for {}",
                    artifact.filename
                ));
            }
        }
        if artifact.findings.iter().any(|finding| {
            finding.stage.is_empty()
                || finding.code.is_empty()
                || finding.detail.is_empty()
                || finding.path.as_deref().is_some_and(|path| path.is_empty())
        }) {
            return invalid(format!(
                "inventory finding is incomplete for {}",
                artifact.filename
            ));
        }
        rollup(&mut recomputed, artifact);
    }
    if report.summary != recomputed {
        return invalid("inventory summary does not match artifact rollups");
    }
    Ok(())
}

fn scheme(value: &InstallScheme) -> &'static str {
    match value {
        InstallScheme::Purelib => "purelib",
        InstallScheme::Platlib => "platlib",
        InstallScheme::Scripts => "scripts",
        InstallScheme::Headers => "headers",
        InstallScheme::Data => "data",
        _ => "unknown",
    }
}

fn stage(value: EvaluationStage) -> String {
    serde_json::to_value(value)
        .expect("stage serializes")
        .as_str()
        .expect("stage is a string")
        .to_owned()
}

fn required_path(
    args: &mut impl Iterator<Item = String>,
    label: &str,
) -> Result<PathBuf, AnyError> {
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {label}").into())
}

fn reject_extra(mut args: impl Iterator<Item = String>) -> Result<(), AnyError> {
    if args.next().is_some() {
        return Err(usage());
    }
    Ok(())
}

fn usage() -> AnyError {
    "usage: sealr-wheel-inventory-v3 analyze <manifest> <cache> <report> <markdown> | verify <manifest> <report> <markdown>".into()
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, AnyError> {
    let size = fs::metadata(path)?.len();
    if size > limit {
        return invalid(format!("{} exceeds {limit} bytes", path.display()));
    }
    let bytes = fs::read(path)?;
    if bytes.len() as u64 != size {
        return invalid(format!("{} changed while reading", path.display()));
    }
    Ok(bytes)
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn invalid<T>(detail: impl Into<String>) -> Result<T, AnyError> {
    Err(std::io::Error::new(std::io::ErrorKind::InvalidData, detail.into()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Manifest, Report) {
        let manifest = Manifest {
            schema: "sealr.wheel-corpus.v1".into(),
            query_date: "2026-08-26".into(),
            selection_method: "fixture".into(),
            entries: vec![ManifestEntry {
                project: "demo".into(),
                version: "1.0".into(),
                cohort: "test".into(),
                filename: "demo-1.0-py3-none-any.whl".into(),
                url: "https://files.pythonhosted.org/packages/demo.whl".into(),
                sha256: "00".repeat(32),
                size: 7,
                upload_time: "2026-08-26T00:00:00Z".into(),
                provenance_url: "https://pypi.org/project/demo/1.0/".into(),
            }],
        };
        let artifact = Artifact {
            project: "demo".into(),
            version: "1.0".into(),
            cohort: "test".into(),
            filename: "demo-1.0-py3-none-any.whl".into(),
            sha256: "00".repeat(32),
            size: 7,
            outcome: "denied".into(),
            findings: vec![Finding {
                stage: "container".into(),
                code: "fixture.denied".into(),
                detail: "fixture denial".into(),
                path: None,
            }],
            metadata_version: None,
            generator: None,
            data_schemes: Vec::new(),
            filename_tags: Vec::new(),
            unicode_paths: 0,
            creator_systems: BTreeMap::new(),
            executable_members: 0,
        };
        let mut summary = Summary::default();
        rollup(&mut summary, &artifact);
        let report = Report {
            schema: REPORT_SCHEMA.into(),
            predecessor_report_sha256: "11".repeat(32),
            manifest_sha256: "22".repeat(32),
            query_date: manifest.query_date.clone(),
            selection_method: manifest.selection_method.clone(),
            analyzer: ANALYZER.into(),
            interpretation_profile: ZIP_PORTABLE_UTF8_V1.into(),
            interpretation_profile_sha256: "33".repeat(32),
            artifact_count: 1,
            source_bytes: 7,
            summary,
            artifacts: vec![artifact],
        };
        (manifest, report)
    }

    #[test]
    fn report_semantics_bind_manifest_outcomes_and_rollups() {
        let (manifest, mut report) = fixture();
        validate_report_semantics(&manifest, &report).unwrap();

        report.summary.outcomes.insert("admitted".into(), 1);
        assert!(validate_report_semantics(&manifest, &report).is_err());
        report.summary.outcomes.remove("admitted");
        report.artifacts[0].size += 1;
        assert!(validate_report_semantics(&manifest, &report).is_err());
    }
}
