//! Successor-bound inventory for the script-prefix-classification revision.
//!
//! This binary remains separate from the frozen `wheel-lab` analyzers and the
//! immutable v4 analyzer so every historical report stays executable under its
//! exact profile. It measures the supported `sealr::wheel` evaluator under the
//! `script-prefix-classification.v1` consumer rule and binds the immutable v4
//! report so every outcome delta is attributable.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use sealr::wheel::{
    evaluate_wheel, EvaluationStage, InstallScheme, WheelEvaluation, WheelLimits, SPEC_SNAPSHOT_ID,
};
use sealr::{
    apply_with_options, ApplyOptions, Policy, Request, Source, ZipInterpretationProfile,
    ZIP_PORTABLE_UTF8_V1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REPORT_SCHEMA: &str = "sealr.wheel-compatibility-report.v5";
const ANALYZER: &str = "sealr-wheel-inventory.v5";
const PREDECESSOR_REPORT: &str = "tests/corpus/wheels/report-v4.json";
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

/// The subset of the immutable v4 report needed to attribute outcome deltas.
#[derive(Deserialize)]
struct PredecessorReport {
    schema: String,
    artifacts: Vec<PredecessorArtifact>,
}

#[derive(Deserialize)]
struct PredecessorArtifact {
    sha256: String,
    outcome: String,
    findings: Vec<PredecessorFinding>,
}

#[derive(Deserialize)]
struct PredecessorFinding {
    code: String,
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
    spec_snapshot: String,
    consumer_profile_digest: String,
    artifact_count: usize,
    source_bytes: u64,
    summary: Summary,
    predecessor_delta: Vec<OutcomeFlip>,
    artifacts: Vec<Artifact>,
}

/// One artifact shared with the v4 corpus whose outcome or finding codes
/// changed under the script-prefix-classification revision.
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OutcomeFlip {
    filename: String,
    sha256: String,
    predecessor_outcome: String,
    outcome: String,
    predecessor_finding_codes: Vec<String>,
    finding_codes: Vec<String>,
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
        eprintln!("wheel inventory v5: {error}");
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
            println!("wheel compatibility inventory v5 is internally consistent");
        }
        _ => return Err(usage()),
    }
    Ok(())
}

fn load_predecessor() -> Result<(String, BTreeMap<String, PredecessorArtifact>), AnyError> {
    let raw = fs::read(PREDECESSOR_REPORT)?;
    let digest = hex_sha256(&raw);
    let report: PredecessorReport = serde_json::from_slice(&raw)?;
    if report.schema != "sealr.wheel-compatibility-report.v4" {
        return invalid("predecessor report schema is not v4");
    }
    let mut by_digest = BTreeMap::new();
    for artifact in report.artifacts {
        if by_digest
            .insert(artifact.sha256.clone(), artifact)
            .is_some()
        {
            return invalid("predecessor report repeats an artifact digest");
        }
    }
    Ok((digest, by_digest))
}

fn predecessor_delta(
    predecessor: &BTreeMap<String, PredecessorArtifact>,
    artifacts: &[Artifact],
) -> Vec<OutcomeFlip> {
    let mut flips = Vec::new();
    for artifact in artifacts {
        let Some(prior) = predecessor.get(&artifact.sha256) else {
            continue;
        };
        let prior_codes: Vec<String> = prior
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect();
        let codes: Vec<String> = artifact
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect();
        if prior.outcome != artifact.outcome || prior_codes != codes {
            flips.push(OutcomeFlip {
                filename: artifact.filename.clone(),
                sha256: artifact.sha256.clone(),
                predecessor_outcome: prior.outcome.clone(),
                outcome: artifact.outcome.clone(),
                predecessor_finding_codes: prior_codes,
                finding_codes: codes,
            });
        }
    }
    flips
}

fn analyze(manifest_path: &Path, cache: &Path) -> Result<(Vec<u8>, Vec<u8>), AnyError> {
    let raw_manifest = read_bounded(manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: Manifest = serde_json::from_slice(&raw_manifest)?;
    if manifest.schema != "sealr.wheel-corpus.v1" || manifest.entries.len() > 512 {
        return invalid("manifest schema or artifact count is unsupported");
    }
    let (predecessor_digest, predecessor) = load_predecessor()?;
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
    let limits = WheelLimits::default();
    let mut artifacts = Vec::new();
    let mut summary = Summary::default();
    let mut source_bytes = 0_u64;
    let mut consumer_profile_digest: Option<String> = None;
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
                    match &consumer_profile_digest {
                        Some(digest) if *digest != wheel.consumer_profile_digest => {
                            return invalid("consumer profile digest varied across artifacts");
                        }
                        Some(_) => {}
                        None => {
                            consumer_profile_digest = Some(wheel.consumer_profile_digest.clone());
                        }
                    }
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
    let delta = predecessor_delta(&predecessor, &artifacts);
    let report = Report {
        schema: REPORT_SCHEMA.into(),
        predecessor_report_sha256: predecessor_digest,
        manifest_sha256: hex_sha256(&raw_manifest),
        query_date: manifest.query_date,
        selection_method: manifest.selection_method,
        analyzer: ANALYZER.into(),
        interpretation_profile: ZIP_PORTABLE_UTF8_V1.into(),
        interpretation_profile_sha256: sealr::zip_portable_utf8_v1_digest(),
        spec_snapshot: SPEC_SNAPSHOT_ID.into(),
        consumer_profile_digest: consumer_profile_digest
            .ok_or("corpus produced no admitted artifact to bind the consumer digest")?,
        artifact_count: artifacts.len(),
        source_bytes,
        summary,
        predecessor_delta: delta,
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
    writeln!(out, "# Wheel compatibility inventory v5\n").unwrap();
    writeln!(out, "> Status: supported-preview measurement of the `script-prefix-classification.v1` consumer revision over a stratified corpus roughly five times the v4 pilot. This is not a PyPI prevalence estimate or a claim of general wheel compatibility.\n").unwrap();
    writeln!(out, "- Analyzer: `{}`", report.analyzer).unwrap();
    writeln!(out, "- Profile: `{}`", report.interpretation_profile).unwrap();
    writeln!(
        out,
        "- Profile SHA-256: `{}`",
        report.interpretation_profile_sha256
    )
    .unwrap();
    writeln!(out, "- Specification snapshot: `{}`", report.spec_snapshot).unwrap();
    writeln!(
        out,
        "- Consumer profile digest: `{}`",
        report.consumer_profile_digest
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
    writeln!(out, "- `wheel.header-duplicate`: fourteen artifacts carry a duplicated `Generator` field - the cffi and matplotlib pair the v4 pilot investigated, joined at population scale by cbor2, ddtrace, duckdb, h5py, mmh3, pymssql, pyroaring, simplejson, statsmodels, thrift, xgboost, and zopfli, almost all cp310 macOS artifacts whose build pipelines emit a second generator line. The supported model still denies duplicated headers because it has not defined ordered or merged generator semantics; this is a consumer-compatibility gap, not a container disagreement, and it is now the dominant denial cluster.").unwrap();
    writeln!(out, "- `quota.ratio`: SciPy reaches the existing default 100:1 expansion ceiling on three NIST ANOVA test-data members before wheel evaluation, exactly as in v3 and v4. The portable profile does not weaken the adversarial resource policy to improve corpus acceptance.").unwrap();
    writeln!(out, "- `wheel.tag-disagreement`: playwright publishes the filename tag `py3-none-win_amd64` while its `WHEEL` Tag fields expand to a different set, and the mysql-connector-python aarch64 artifact disagrees the same way. Two declared tag sets that disagree are denied rather than one being silently preferred.").unwrap();
    writeln!(out, "- `wheel.artifact-root-disagreement`: jaraco.classes keeps its legacy dotted distribution name as the `.dist-info` root, which is not the canonical normalized root bound to the outer filename. The consumer requires exact root agreement instead of re-normalizing on its behalf.
- `wheel.record-path`: the pendulum Windows artifact writes one `RECORD` row with a backslash separator. `RECORD` paths must be canonical forward-slash archive-relative paths, so producer-side path bugs deny instead of being repaired.
- `zip.extra`: the protobuf Windows artifact carries extra field `0x0001` (ZIP64 extended information) in a local header, which `sealr.profile.zip.portable-utf8.v1` denies. This remains the only container-stage denial in the corpus and would require the strict ZIP64 profile lineage to interpret.\n").unwrap();
    writeln!(out, "## Predecessor delta\n").unwrap();
    writeln!(out, "Exactly the two artifacts the immutable v4 report denied with `wheel.script-aggregate-limit` flip to admitted under the `script-prefix-classification.v1` rule: uv 0.12.7 and ruff 0.16.5, each shipping one multi-megabyte native executable under `.data/scripts` that the revised consumer now plans as a verbatim copy whose hash and size come from admission evidence, because a non-launcher prefix classifies as `Copy` by rule. No other artifact shared with the v4 corpus changed outcome or finding codes, so the prefix revision is the only observable behavior change over the retained corpus. The interpretation profile and the `pypa-wheel-core-metadata-2026-08-28` specification snapshot are unchanged from v4; only the consumer profile digest moved, to the value this report binds.").unwrap();
    if report.predecessor_delta.is_empty() {
        writeln!(
            out,
            "\nNo shared artifact changed outcome or finding codes.\n"
        )
        .unwrap();
    } else {
        writeln!(
            out,
            "\n| Filename | v4 outcome | v5 outcome | v4 findings | v5 findings |"
        )
        .unwrap();
        writeln!(out, "|---|---|---|---|---|").unwrap();
        for flip in &report.predecessor_delta {
            writeln!(
                out,
                "| `{}` | {} | {} | {} | {} |",
                flip.filename,
                flip.predecessor_outcome,
                flip.outcome,
                codes(&flip.predecessor_finding_codes),
                codes(&flip.finding_codes),
            )
            .unwrap();
        }
        writeln!(out).unwrap();
    }
    writeln!(out, "## Additional observations\n").unwrap();
    writeln!(
        out,
        "- Artifacts with Unicode paths: `{}`",
        report.summary.artifacts_with_unicode_paths
    )
    .unwrap();
    writeln!(
        out,
        "- Unix-creator executable regular-file members: `{}`",
        report.summary.executable_members
    )
    .unwrap();
    writeln!(out, "- The `scripts` scheme is measured on twelve admitted artifacts - awscli, dill, dulwich, jmespath, maturin, ninja, numba, patchelf, pywin32, ruff, ty, and uv - so the native-CLI shape the revision unblocked is proven at population scale, not only on the two flipped artifacts.
- The `headers` scheme is measured for the first time: greenlet relocates `.data/headers`. fonttools, jupyterlab, and notebook relocate the `data` scheme.").unwrap();
    writeln!(out, "- No measured artifact declares Core Metadata 2.6, and none surfaced across the PEP 658 metadata prospecting of several hundred candidate projects; that half of the snapshot widening is still exercised only by unit fixtures. Core Metadata 2.3 is measured for the first time on two artifacts.").unwrap();
    writeln!(out, "- No measured artifact contains Unicode member paths, so those rule consequences continue to rely on hostile fixtures.\n").unwrap();
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

fn codes(values: &[String]) -> String {
    if values.is_empty() {
        "none".into()
    } else {
        values
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ")
    }
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
    let (predecessor_digest, predecessor) = load_predecessor()?;
    if report.schema != REPORT_SCHEMA
        || report.analyzer != ANALYZER
        || report.manifest_sha256 != hex_sha256(&raw_manifest)
        || report.interpretation_profile != ZIP_PORTABLE_UTF8_V1
        || report.interpretation_profile_sha256 != sealr::zip_portable_utf8_v1_digest()
        || report.spec_snapshot != SPEC_SNAPSHOT_ID
        || report.consumer_profile_digest.len() != 64
        || report.predecessor_report_sha256 != predecessor_digest
    {
        return invalid("inventory bindings are stale");
    }
    validate_report_semantics(&manifest, &report)?;
    if report.predecessor_delta != predecessor_delta(&predecessor, &report.artifacts) {
        return invalid("inventory predecessor delta does not match the bound v4 report");
    }
    let (canonical, markdown) = encode(&report)?;
    if canonical != raw_report || markdown != read_bounded(markdown_path, MAX_REPORT_BYTES)? {
        return invalid("inventory JSON or Markdown is not canonical");
    }
    Ok(())
}

fn validate_report_semantics(manifest: &Manifest, report: &Report) -> Result<(), AnyError> {
    if manifest.schema != "sealr.wheel-corpus.v1"
        || manifest.entries.len() > 512
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
    "usage: wheel_inventory_v5 analyze <manifest> <cache> <report> <markdown> | verify <manifest> <report> <markdown>".into()
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
            query_date: "2026-08-28".into(),
            selection_method: "fixture".into(),
            entries: vec![ManifestEntry {
                project: "demo".into(),
                version: "1.0".into(),
                cohort: "test".into(),
                filename: "demo-1.0-py3-none-any.whl".into(),
                url: "https://files.pythonhosted.org/packages/demo.whl".into(),
                sha256: "00".repeat(32),
                size: 7,
                upload_time: "2026-08-28T00:00:00Z".into(),
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
            spec_snapshot: SPEC_SNAPSHOT_ID.into(),
            consumer_profile_digest: "44".repeat(32),
            artifact_count: 1,
            source_bytes: 7,
            summary,
            predecessor_delta: Vec::new(),
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

    #[test]
    fn the_predecessor_delta_reports_only_shared_artifacts_that_changed() {
        let (_, report) = fixture();
        let shared = &report.artifacts[0];
        let mut predecessor = BTreeMap::new();
        predecessor.insert(
            shared.sha256.clone(),
            PredecessorArtifact {
                sha256: shared.sha256.clone(),
                outcome: "unsupported".into(),
                findings: vec![PredecessorFinding {
                    code: "wheel.metadata-version-unsupported".into(),
                }],
            },
        );

        let flips = predecessor_delta(&predecessor, &report.artifacts);
        assert_eq!(flips.len(), 1);
        assert_eq!(flips[0].predecessor_outcome, "unsupported");
        assert_eq!(flips[0].outcome, "denied");
        assert_eq!(
            flips[0].predecessor_finding_codes,
            vec!["wheel.metadata-version-unsupported".to_owned()]
        );
        assert_eq!(flips[0].finding_codes, vec!["fixture.denied".to_owned()]);

        let unchanged = PredecessorArtifact {
            sha256: shared.sha256.clone(),
            outcome: shared.outcome.clone(),
            findings: vec![PredecessorFinding {
                code: "fixture.denied".into(),
            }],
        };
        predecessor.insert(shared.sha256.clone(), unchanged);
        assert!(predecessor_delta(&predecessor, &report.artifacts).is_empty());

        predecessor.clear();
        predecessor.insert(
            "55".repeat(32),
            PredecessorArtifact {
                sha256: "55".repeat(32),
                outcome: "admitted".into(),
                findings: Vec::new(),
            },
        );
        assert!(
            predecessor_delta(&predecessor, &report.artifacts).is_empty(),
            "artifacts absent from the corpus never flip"
        );
    }
}
