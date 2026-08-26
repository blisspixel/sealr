use std::collections::{BTreeMap, BTreeSet};

use sealr::{content_root, MemberKind, VerifiedArchive, ZIP_WHEEL_UTF8_V1};
use unicode_normalization::UnicodeNormalization;

use crate::identity::{
    artifact_identity, consumer_profile_digest, plan_identity, realization_identity,
};
use crate::model::{
    EntryPoint, EvaluationStage, ExecutableDisposition, InstallEntry, InstallScheme,
    InstallTransform, RealizedOutput, RecordBinding, WheelArtifactIR, WheelEvaluation,
    WheelFinding, WheelIdentities, WheelInstallPlan, WheelLimits, WheelMemberFacts,
    ARTIFACT_ENCODING_ID, CONSUMER_PROFILE_ID, PLAN_ENCODING_ID, SPEC_SNAPSHOT_ID,
};
use crate::parse::{
    decode_sha256_record, normalize_distribution, normalize_version, parse_core_metadata,
    parse_entry_points, parse_record_rows, parse_wheel_filename, parse_wheel_headers,
};

pub fn evaluate_wheel(
    outer_filename: &str,
    archive: &VerifiedArchive,
    limits: WheelLimits,
) -> WheelEvaluation {
    match evaluate(outer_filename, archive, limits) {
        Ok(result) => result,
        Err(EvaluationFailure::Denied(finding)) => WheelEvaluation::Denied {
            findings: vec![finding],
        },
        Err(EvaluationFailure::Unsupported(finding)) => WheelEvaluation::Unsupported {
            findings: vec![finding],
        },
        Err(EvaluationFailure::Infrastructure(detail)) => {
            WheelEvaluation::InfrastructureFailure { detail }
        }
    }
}

fn evaluate(
    outer_filename: &str,
    archive: &VerifiedArchive,
    limits: WheelLimits,
) -> Result<WheelEvaluation, EvaluationFailure> {
    if archive.archive_ir().profile() != ZIP_WHEEL_UTF8_V1 {
        return unsupported(WheelFinding::new(
            EvaluationStage::Container,
            "wheel.container-profile",
            format!(
                "wheel evaluation requires {ZIP_WHEEL_UTF8_V1}, not {}",
                archive.archive_ir().profile()
            ),
        ));
    }
    let source_sha256 = archive.source_digest().sha256().ok_or_else(|| {
        EvaluationFailure::Infrastructure("verified archive source identity is unavailable".into())
    })?;
    let archive_tree = content_root(archive.archive_ir());
    let archive_tree_sha256 = archive_tree.hex().ok_or_else(|| {
        EvaluationFailure::Infrastructure("verified archive tree identity is unavailable".into())
    })?;
    let filename = parse_wheel_filename(outer_filename, limits).map_err(classify_parse)?;
    let roots = select_roots(archive, &filename)?;
    let wheel_path = format!("{}/WHEEL", roots.dist_info);
    let metadata_path = format!("{}/METADATA", roots.dist_info);
    let record_path = format!("{}/RECORD", roots.dist_info);
    for path in [&wheel_path, &metadata_path, &record_path] {
        require_regular(archive, path)?;
    }
    let entry_points_path = format!("{}/entry_points.txt", roots.dist_info);
    let has_entry_points = archive.member(&entry_points_path).is_some();
    if has_entry_points {
        require_regular(archive, &entry_points_path)?;
    }
    preflight_semantic_bytes(
        archive,
        [
            (&wheel_path, limits.max_wheel_bytes),
            (&metadata_path, limits.max_metadata_bytes),
            (&record_path, limits.max_record_bytes),
        ]
        .into_iter()
        .chain(has_entry_points.then_some((&entry_points_path, limits.max_entry_points_bytes))),
        limits.max_semantic_bytes,
    )?;
    let wheel_bytes = read_semantic(archive, &wheel_path, limits.max_wheel_bytes)?;
    let metadata_bytes = read_semantic(archive, &metadata_path, limits.max_metadata_bytes)?;
    let record_bytes = read_semantic(archive, &record_path, limits.max_record_bytes)?;
    let wheel = parse_wheel_headers(&wheel_bytes, limits).map_err(classify_parse)?;
    let metadata = parse_core_metadata(&metadata_bytes, limits).map_err(classify_parse)?;

    let filename_tags: BTreeSet<&str> = filename.expanded_tags.iter().map(String::as_str).collect();
    let metadata_tags: BTreeSet<&str> = wheel.tags.iter().map(String::as_str).collect();
    if filename_tags != metadata_tags {
        return denied(WheelFinding::new(
            EvaluationStage::WheelMetadata,
            "wheel.tag-disagreement",
            "outer filename tags and expanded WHEEL Tag fields disagree",
        ));
    }
    if filename.build != wheel.build {
        return denied(WheelFinding::new(
            EvaluationStage::WheelMetadata,
            "wheel.build-disagreement",
            "outer filename build tag and WHEEL Build field disagree",
        ));
    }
    if filename.normalized_distribution != metadata.normalized_name
        || filename.normalized_version != metadata.normalized_version
    {
        return denied(WheelFinding::new(
            EvaluationStage::CoreMetadata,
            "wheel.filename-metadata-disagreement",
            "outer filename distribution or version disagrees with METADATA",
        ));
    }

    let rows = parse_record_rows(&record_bytes, limits).map_err(classify_parse)?;
    let record = bind_record(archive, &record_path, rows)?;
    let entry_points = if has_entry_points {
        let bytes = read_semantic(archive, &entry_points_path, limits.max_entry_points_bytes)?;
        parse_entry_points(&bytes, limits).map_err(classify_parse)?
    } else {
        Vec::new()
    };

    let mut artifact = WheelArtifactIR {
        schema: ARTIFACT_ENCODING_ID.into(),
        consumer_profile: CONSUMER_PROFILE_ID.into(),
        consumer_profile_digest: consumer_profile_digest(limits),
        spec_snapshot: SPEC_SNAPSHOT_ID.into(),
        source_sha256: source_sha256.to_owned(),
        archive_tree_sha256: archive_tree_sha256.to_owned(),
        interpretation_profile: archive.archive_ir().profile().into(),
        interpretation_profile_sha256: archive.archive_ir().profile_digest().into(),
        filename,
        dist_info_root: roots.dist_info,
        data_root: roots.data,
        wheel,
        metadata,
        record,
        entry_points,
        member_facts: archive
            .members()
            .iter()
            .enumerate()
            .map(|(member_index, member)| {
                let facts = member.container_facts();
                WheelMemberFacts {
                    member_index,
                    path: member.canonical_path.clone(),
                    creator_system: facts.creator_system,
                    external_attributes: facts.external_attributes,
                    pypa_installer_0_7_executable: facts.pypa_installer_0_7_executable(),
                }
            })
            .collect(),
    };
    artifact
        .record
        .sort_by(|left, right| left.path.cmp(&right.path));
    let artifact_sha256 = artifact_identity(&artifact);
    let plan = build_plan(archive, &artifact, &artifact_sha256, limits)?;
    let install_plan_sha256 = plan_identity(&plan);
    if [
        artifact.source_sha256.as_str(),
        artifact.archive_tree_sha256.as_str(),
        artifact_sha256.as_str(),
        install_plan_sha256.as_str(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>()
    .len()
        != 4
    {
        return infrastructure("domain-separated wheel identities unexpectedly collide");
    }
    let identities = WheelIdentities {
        source_sha256: artifact.source_sha256.clone(),
        archive_tree_sha256: artifact.archive_tree_sha256.clone(),
        artifact_sha256,
        install_plan_sha256,
        realization_sha256: None,
    };
    Ok(WheelEvaluation::Admitted {
        artifact: Box::new(artifact),
        plan: Box::new(plan),
        identities,
        findings: Vec::new(),
    })
}

struct Roots {
    dist_info: String,
    data: Option<String>,
}

fn select_roots(
    archive: &VerifiedArchive,
    filename: &crate::model::WheelFilename,
) -> Result<Roots, EvaluationFailure> {
    let mut dist_info = BTreeSet::new();
    let mut data = BTreeSet::new();
    for member in archive.members() {
        let Some(root) = member.components.first() else {
            continue;
        };
        if root.ends_with(".dist-info") {
            dist_info.insert(root.clone());
        }
        if root.ends_with(".data") {
            data.insert(root.clone());
        }
    }
    if dist_info.len() != 1 {
        return denied(WheelFinding::new(
            EvaluationStage::Selection,
            "wheel.dist-info-count",
            format!(
                "wheel must contain exactly one top-level .dist-info root; observed {}",
                dist_info.len()
            ),
        ));
    }
    let selected = dist_info.into_iter().next().unwrap();
    validate_named_root(&selected, ".dist-info", filename)?;
    if data.len() > 1 {
        return denied(WheelFinding::new(
            EvaluationStage::Selection,
            "wheel.data-count",
            "wheel contains more than one top-level .data root",
        ));
    }
    let data = data.into_iter().next();
    if let Some(data) = &data {
        validate_named_root(data, ".data", filename)?;
    }
    Ok(Roots {
        dist_info: selected,
        data,
    })
}

fn validate_named_root(
    root: &str,
    suffix: &str,
    filename: &crate::model::WheelFilename,
) -> Result<(), EvaluationFailure> {
    let stem = root.strip_suffix(suffix).unwrap();
    let (distribution, version) = stem.rsplit_once('-').ok_or_else(|| {
        EvaluationFailure::Denied(WheelFinding::new(
            EvaluationStage::Selection,
            "wheel.artifact-root-name",
            format!("{root} does not contain a distribution-version stem"),
        ))
    })?;
    let normalized_version = normalize_version(version).map_err(classify_parse)?;
    if normalize_distribution(distribution) != filename.normalized_distribution
        || normalized_version != filename.normalized_version
    {
        return denied(WheelFinding::new(
            EvaluationStage::Selection,
            "wheel.artifact-root-disagreement",
            format!("{root} disagrees with the outer filename"),
        ));
    }
    Ok(())
}

fn require_regular(archive: &VerifiedArchive, path: &str) -> Result<(), EvaluationFailure> {
    match archive.member(path) {
        Some(member) if matches!(member.kind, MemberKind::File) => Ok(()),
        Some(_) => denied(
            WheelFinding::new(
                EvaluationStage::Selection,
                "wheel.semantic-member-kind",
                "required semantic member is not a regular file",
            )
            .on(path),
        ),
        None => denied(
            WheelFinding::new(
                EvaluationStage::Selection,
                "wheel.semantic-member-missing",
                "required semantic member is missing",
            )
            .on(path),
        ),
    }
}

fn preflight_semantic_bytes<'a>(
    archive: &VerifiedArchive,
    paths: impl Iterator<Item = (&'a String, u64)>,
    aggregate_cap: u64,
) -> Result<(), EvaluationFailure> {
    let mut total = 0_u64;
    for (path, cap) in paths {
        let member = archive.member(path).ok_or_else(|| {
            EvaluationFailure::Infrastructure("preflight member disappeared".into())
        })?;
        let size = member.actual_uncomp_size.ok_or_else(|| {
            EvaluationFailure::Infrastructure("verified member lacks measured size".into())
        })?;
        if size > cap {
            return denied(
                WheelFinding::new(
                    EvaluationStage::Selection,
                    "wheel.semantic-member-limit",
                    format!("verified member size {size} exceeds its cap {cap}"),
                )
                .on(path),
            );
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| EvaluationFailure::Denied(limit_overflow()))?;
        if total > aggregate_cap {
            return denied(WheelFinding::new(
                EvaluationStage::Selection,
                "wheel.semantic-aggregate-limit",
                format!("semantic member total exceeds {aggregate_cap}"),
            ));
        }
    }
    Ok(())
}

fn read_semantic(
    archive: &VerifiedArchive,
    path: &str,
    cap: u64,
) -> Result<Vec<u8>, EvaluationFailure> {
    archive.read_member(path, cap).map_err(|error| {
        EvaluationFailure::Infrastructure(format!("verified read of {path:?} failed: {error}"))
    })
}

fn bind_record(
    archive: &VerifiedArchive,
    record_path: &str,
    rows: Vec<[String; 3]>,
) -> Result<Vec<RecordBinding>, EvaluationFailure> {
    let members: BTreeMap<&str, usize> = archive
        .members()
        .iter()
        .enumerate()
        .filter(|(_, member)| matches!(member.kind, MemberKind::File))
        .map(|(index, member)| (member.canonical_path.as_str(), index))
        .collect();
    let mut seen = BTreeSet::new();
    let mut bindings = Vec::new();
    for [path, hash, size] in rows {
        validate_record_path(&path)?;
        if !seen.insert(path.clone()) {
            return denied(
                WheelFinding::new(
                    EvaluationStage::Record,
                    "wheel.record-duplicate",
                    "RECORD contains a duplicate path",
                )
                .on(path),
            );
        }
        let index = *members.get(path.as_str()).ok_or_else(|| {
            EvaluationFailure::Denied(
                WheelFinding::new(
                    EvaluationStage::Record,
                    "wheel.record-phantom",
                    "RECORD path has no verified regular member",
                )
                .on(&path),
            )
        })?;
        let member = &archive.members()[index];
        let is_record = path == record_path;
        if is_record {
            if !hash.is_empty() || !size.is_empty() {
                return denied(
                    WheelFinding::new(
                        EvaluationStage::Record,
                        "wheel.record-self-fields",
                        "RECORD self row must have empty hash and size",
                    )
                    .on(path),
                );
            }
            bindings.push(RecordBinding {
                path,
                member_index: index,
                sha256: None,
                size: None,
                is_record: true,
            });
            continue;
        }
        if path.ends_with("/RECORD.jws") || path.ends_with("/RECORD.p7s") {
            return denied(
                WheelFinding::new(
                    EvaluationStage::Record,
                    "wheel.record-signature-listed",
                    "legacy RECORD signature files must remain outside RECORD",
                )
                .on(path),
            );
        }
        if hash.starts_with("sha384=") || hash.starts_with("sha512=") {
            return unsupported(
                WheelFinding::new(
                    EvaluationStage::Record,
                    "wheel.record-hash-evidence-unavailable",
                    "verified archive exposes SHA-256 evidence only",
                )
                .on(path),
            );
        }
        if hash.starts_with("md5=") || hash.starts_with("sha1=") {
            return denied(
                WheelFinding::new(
                    EvaluationStage::Record,
                    "wheel.record-hash-insecure",
                    "RECORD uses an insecure hash algorithm",
                )
                .on(path),
            );
        }
        let digest = decode_sha256_record(&hash).map_err(classify_parse)?;
        let expected_digest = member.content_sha256.as_deref().ok_or_else(|| {
            EvaluationFailure::Infrastructure("verified member lacks SHA-256 evidence".into())
        })?;
        if digest != expected_digest {
            return denied(
                WheelFinding::new(
                    EvaluationStage::Record,
                    "wheel.record-hash-mismatch",
                    "RECORD hash disagrees with verified member evidence",
                )
                .on(path),
            );
        }
        let declared_size = parse_record_size(&size)?;
        let expected_size = member.actual_uncomp_size.ok_or_else(|| {
            EvaluationFailure::Infrastructure("verified member lacks size evidence".into())
        })?;
        if declared_size != expected_size {
            return denied(
                WheelFinding::new(
                    EvaluationStage::Record,
                    "wheel.record-size-mismatch",
                    "RECORD size disagrees with verified member evidence",
                )
                .on(path),
            );
        }
        bindings.push(RecordBinding {
            path,
            member_index: index,
            sha256: Some(digest),
            size: Some(declared_size),
            is_record: false,
        });
    }
    for path in members.keys() {
        if *path == record_path || path.ends_with("/RECORD.jws") || path.ends_with("/RECORD.p7s") {
            if *path == record_path && !seen.contains(*path) {
                return denied(WheelFinding::new(
                    EvaluationStage::Record,
                    "wheel.record-self-missing",
                    "RECORD does not list itself",
                ));
            }
            continue;
        }
        if !seen.contains(*path) {
            return denied(
                WheelFinding::new(
                    EvaluationStage::Record,
                    "wheel.record-member-missing",
                    "verified regular member is absent from RECORD",
                )
                .on(*path),
            );
        }
    }
    Ok(bindings)
}

fn validate_record_path(path: &str) -> Result<(), EvaluationFailure> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains(['\\', '\0'])
        || path
            .split('/')
            .any(|component| matches!(component, "" | "." | ".."))
    {
        return denied(
            WheelFinding::new(
                EvaluationStage::Record,
                "wheel.record-path",
                "RECORD path is not a canonical archive-relative path",
            )
            .on(path),
        );
    }
    Ok(())
}

fn parse_record_size(value: &str) -> Result<u64, EvaluationFailure> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return denied(WheelFinding::new(
            EvaluationStage::Record,
            "wheel.record-size",
            "RECORD size is not a canonical unsigned decimal integer",
        ));
    }
    value.parse().map_err(|_| {
        EvaluationFailure::Denied(WheelFinding::new(
            EvaluationStage::Record,
            "wheel.record-size-overflow",
            "RECORD size exceeds u64",
        ))
    })
}

fn build_plan(
    archive: &VerifiedArchive,
    artifact: &WheelArtifactIR,
    artifact_sha256: &str,
    limits: WheelLimits,
) -> Result<WheelInstallPlan, EvaluationFailure> {
    let root_scheme = if artifact.wheel.root_is_purelib {
        InstallScheme::Purelib
    } else {
        InstallScheme::Platlib
    };
    let mut entries = Vec::new();
    let mut inspected_script_bytes = 0_u64;
    let record_path = format!("{}/RECORD", artifact.dist_info_root);
    for (index, member) in archive.members().iter().enumerate() {
        if member
            .components
            .iter()
            .any(|component| component == "__pycache__")
        {
            return denied(
                WheelFinding::new(
                    EvaluationStage::Plan,
                    "wheel.pycache-payload",
                    "wheel payload contains __pycache__, which the bridge would skip",
                )
                .on(&member.canonical_path),
            );
        }
        if matches!(member.kind, MemberKind::Directory) {
            validate_data_shape(member, artifact.data_root.as_deref())?;
            continue;
        }
        if member.canonical_path == record_path {
            // PyPA installer writes a target-specific RECORD during finalization.
            // The source RECORD remains artifact evidence, not a copy action.
            continue;
        }
        let (scheme, relative_path) = relocate_member(member, artifact, &root_scheme)?;
        let facts = member.container_facts();
        let executable = if facts.pypa_installer_0_7_executable() {
            ExecutableDisposition::SourceExecutable
        } else {
            ExecutableDisposition::NotExecutable
        };
        let transform = if matches!(scheme, InstallScheme::Scripts) {
            let size = member.actual_uncomp_size.ok_or_else(|| {
                EvaluationFailure::Infrastructure("verified script lacks size evidence".into())
            })?;
            inspected_script_bytes = inspected_script_bytes
                .checked_add(size)
                .ok_or_else(|| EvaluationFailure::Denied(limit_overflow()))?;
            if inspected_script_bytes > limits.max_plan_inspection_bytes {
                return denied(
                    WheelFinding::new(
                        EvaluationStage::Plan,
                        "wheel.script-aggregate-limit",
                        "source scripts exceed the plan-inspection aggregate cap",
                    )
                    .on(&member.canonical_path),
                );
            }
            let bytes = read_semantic(archive, &member.canonical_path, limits.max_script_bytes)?;
            if has_python_shebang(&bytes) {
                InstallTransform::RewritePythonShebang
            } else {
                InstallTransform::Copy
            }
        } else {
            InstallTransform::Copy
        };
        entries.push(InstallEntry {
            source_member_index: Some(index),
            source_path: Some(member.canonical_path.clone()),
            scheme,
            relative_path,
            sha256: member.content_sha256.clone(),
            size: member.actual_uncomp_size,
            executable,
            transform,
            entry_point: None,
        });
    }
    for point in &artifact.entry_points {
        entries.push(generated_entry(point.clone()));
    }
    entries.sort_by(|left, right| {
        (
            scheme_order(&left.scheme),
            portable_fold(&left.relative_path),
            &left.relative_path,
            left.source_member_index,
        )
            .cmp(&(
                scheme_order(&right.scheme),
                portable_fold(&right.relative_path),
                &right.relative_path,
                right.source_member_index,
            ))
    });
    validate_plan_collisions(&entries)?;
    Ok(WheelInstallPlan {
        schema: PLAN_ENCODING_ID.into(),
        model: "scheme-relative-v1".into(),
        artifact_sha256: artifact_sha256.into(),
        entries,
    })
}

fn validate_data_shape(
    member: &sealr::IrMember,
    data_root: Option<&str>,
) -> Result<(), EvaluationFailure> {
    let Some(data_root) = data_root else {
        return Ok(());
    };
    if member.components.first().map(String::as_str) != Some(data_root) {
        return Ok(());
    }
    if member.components.len() == 1 {
        return Ok(());
    }
    if !matches!(
        member.components[1].as_str(),
        "purelib" | "platlib" | "scripts" | "headers" | "data"
    ) {
        return denied(
            WheelFinding::new(
                EvaluationStage::Plan,
                "wheel.data-scheme",
                "wheel .data tree contains an unknown scheme key",
            )
            .on(&member.canonical_path),
        );
    }
    Ok(())
}

fn relocate_member(
    member: &sealr::IrMember,
    artifact: &WheelArtifactIR,
    root_scheme: &InstallScheme,
) -> Result<(InstallScheme, String), EvaluationFailure> {
    let Some(data_root) = artifact.data_root.as_deref() else {
        return Ok((root_scheme.clone(), member.canonical_path.clone()));
    };
    if member.components.first().map(String::as_str) != Some(data_root) {
        return Ok((root_scheme.clone(), member.canonical_path.clone()));
    }
    if member.components.len() < 3 {
        return denied(
            WheelFinding::new(
                EvaluationStage::Plan,
                "wheel.data-shape",
                ".data file must be beneath a supported scheme and relative path",
            )
            .on(&member.canonical_path),
        );
    }
    let scheme = match member.components[1].as_str() {
        "purelib" => InstallScheme::Purelib,
        "platlib" => InstallScheme::Platlib,
        "scripts" => InstallScheme::Scripts,
        "headers" => InstallScheme::Headers,
        "data" => InstallScheme::Data,
        _ => {
            return denied(
                WheelFinding::new(
                    EvaluationStage::Plan,
                    "wheel.data-scheme",
                    "wheel .data tree contains an unknown scheme key",
                )
                .on(&member.canonical_path),
            );
        }
    };
    Ok((scheme, member.components[2..].join("/")))
}

fn generated_entry(point: EntryPoint) -> InstallEntry {
    let transform = if point.group == "console_scripts" {
        InstallTransform::GenerateConsoleWrapper
    } else {
        InstallTransform::GenerateGuiWrapper
    };
    InstallEntry {
        source_member_index: None,
        source_path: None,
        scheme: InstallScheme::Scripts,
        relative_path: point.name.clone(),
        sha256: None,
        size: None,
        executable: ExecutableDisposition::GeneratedWrapper,
        transform,
        entry_point: Some(point),
    }
}

fn has_python_shebang(bytes: &[u8]) -> bool {
    bytes.starts_with(b"#!python\n")
        || bytes.starts_with(b"#!python\r\n")
        || bytes.starts_with(b"#!pythonw\n")
        || bytes.starts_with(b"#!pythonw\r\n")
}

fn validate_plan_collisions(entries: &[InstallEntry]) -> Result<(), EvaluationFailure> {
    let mut exact = BTreeMap::new();
    let mut folded = BTreeMap::new();
    for entry in entries {
        let scheme = scheme_order(&entry.scheme);
        let exact_key = (scheme, entry.relative_path.clone());
        if exact.insert(exact_key, ()).is_some() {
            return denied(
                WheelFinding::new(
                    EvaluationStage::Plan,
                    "wheel.relocation-collision",
                    "two plan entries target the same scheme-relative path",
                )
                .on(&entry.relative_path),
            );
        }
        let folded_key = (scheme, portable_fold(&entry.relative_path));
        if folded.insert(folded_key, ()).is_some() {
            return denied(
                WheelFinding::new(
                    EvaluationStage::Plan,
                    "wheel.target-case-collision",
                    "two plan entries collide under the portable target model",
                )
                .on(&entry.relative_path),
            );
        }
    }
    Ok(())
}

fn portable_fold(value: &str) -> String {
    value.chars().flat_map(char::to_lowercase).nfc().collect()
}

fn scheme_order(scheme: &InstallScheme) -> u8 {
    match scheme {
        InstallScheme::Purelib => 0,
        InstallScheme::Platlib => 1,
        InstallScheme::Scripts => 2,
        InstallScheme::Headers => 3,
        InstallScheme::Data => 4,
    }
}

pub fn realize_identity(
    plan: &WheelInstallPlan,
    target_model: &str,
    installer_policy: &str,
    outputs: &[RealizedOutput],
) -> String {
    realization_identity(plan, target_model, installer_policy, outputs)
}

fn classify_parse(finding: WheelFinding) -> EvaluationFailure {
    if finding.code.ends_with("-unsupported")
        || finding.code == "wheel.record-hash-evidence-unavailable"
    {
        EvaluationFailure::Unsupported(finding)
    } else {
        EvaluationFailure::Denied(finding)
    }
}

fn limit_overflow() -> WheelFinding {
    WheelFinding::new(
        EvaluationStage::Selection,
        "wheel.semantic-aggregate-overflow",
        "semantic member total overflowed u64",
    )
}

enum EvaluationFailure {
    Denied(WheelFinding),
    Unsupported(WheelFinding),
    Infrastructure(String),
}

fn denied<T>(finding: WheelFinding) -> Result<T, EvaluationFailure> {
    Err(EvaluationFailure::Denied(finding))
}

fn unsupported<T>(finding: WheelFinding) -> Result<T, EvaluationFailure> {
    Err(EvaluationFailure::Unsupported(finding))
}

fn infrastructure<T>(detail: impl Into<String>) -> Result<T, EvaluationFailure> {
    Err(EvaluationFailure::Infrastructure(detail.into()))
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use sealr::{
        apply_with_options, ApplyOptions, Policy, Request, Source, ZipInterpretationProfile,
    };
    use sha2::{Digest, Sha256};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;

    const WHEEL: &[u8] = b"Wheel-Version: 1.0\nGenerator: sealr-wheel-lab-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n";
    const METADATA: &[u8] = b"Metadata-Version: 2.4\nName: demo\nVersion: 1.0\n\n";

    fn build_wheel(
        extra: Vec<(String, Vec<u8>)>,
        mutate_record: impl FnOnce(String) -> String,
    ) -> Vec<u8> {
        let mut files = BTreeMap::new();
        files.insert("demo/__init__.py".to_owned(), b"VALUE = 1\n".to_vec());
        files.insert("demo-1.0.dist-info/WHEEL".to_owned(), WHEEL.to_vec());
        files.insert("demo-1.0.dist-info/METADATA".to_owned(), METADATA.to_vec());
        for (path, bytes) in extra {
            assert!(files.insert(path, bytes).is_none());
        }
        let mut record = String::new();
        for (path, bytes) in &files {
            record.push_str(path);
            record.push_str(",sha256=");
            record.push_str(&base64url(&Sha256::digest(bytes)));
            record.push(',');
            record.push_str(&bytes.len().to_string());
            record.push('\n');
        }
        record.push_str("demo-1.0.dist-info/RECORD,,\n");
        files.insert(
            "demo-1.0.dist-info/RECORD".into(),
            mutate_record(record).into_bytes(),
        );
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            for (path, bytes) in files {
                writer.start_file(path, options).unwrap();
                writer.write_all(&bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn base64url(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut output = String::new();
        for chunk in bytes.chunks(3) {
            let value = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            output.push(ALPHABET[((value >> 18) & 63) as usize] as char);
            output.push(ALPHABET[((value >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                output.push(ALPHABET[((value >> 6) & 63) as usize] as char);
            }
            if chunk.len() > 2 {
                output.push(ALPHABET[(value & 63) as usize] as char);
            }
        }
        output
    }

    fn verified(bytes: &[u8]) -> VerifiedArchive {
        let policy = Policy::default_v1();
        let options =
            ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::WheelUtf8V1);
        let outcome = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("fixture.whl"),
                    data: bytes,
                },
                policy: &policy,
                dest: None,
            },
            &options,
        );
        assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
        outcome
            .verified_archive()
            .expect("admitted verified archive")
            .clone()
    }

    fn finding_code(evaluation: &WheelEvaluation) -> &str {
        match evaluation {
            WheelEvaluation::Denied { findings } | WheelEvaluation::Unsupported { findings } => {
                &findings[0].code
            }
            other => panic!("expected finding, got {other:?}"),
        }
    }

    #[test]
    fn valid_wheel_produces_repeatable_distinct_identities_and_plan() {
        let bytes = build_wheel(Vec::new(), |record| record);
        let archive = verified(&bytes);
        let first = evaluate_wheel(
            "demo-1.0-py3-none-any.whl",
            &archive,
            WheelLimits::default(),
        );
        let second = evaluate_wheel(
            "demo-1.0-py3-none-any.whl",
            &archive,
            WheelLimits::default(),
        );
        assert_eq!(first, second);
        let WheelEvaluation::Admitted {
            artifact,
            plan,
            identities,
            ..
        } = first
        else {
            panic!("valid fixture was not admitted");
        };
        assert_eq!(artifact.record.len(), 4);
        assert_eq!(plan.entries.len(), 3);
        assert_eq!(
            [
                identities.source_sha256.as_str(),
                identities.archive_tree_sha256.as_str(),
                identities.artifact_sha256.as_str(),
                identities.install_plan_sha256.as_str(),
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len(),
            4
        );
        let renamed = evaluate_wheel(
            "Demo-1.0-py3-none-any.whl",
            &archive,
            WheelLimits::default(),
        );
        let WheelEvaluation::Admitted {
            identities: renamed,
            ..
        } = renamed
        else {
            panic!("normalization-equivalent rename should remain evaluable");
        };
        assert_eq!(renamed.source_sha256, identities.source_sha256);
        assert_eq!(renamed.archive_tree_sha256, identities.archive_tree_sha256);
        assert_ne!(renamed.artifact_sha256, identities.artifact_sha256);
        assert_ne!(renamed.install_plan_sha256, identities.install_plan_sha256);
    }

    #[test]
    fn record_hash_size_missing_duplicate_and_phantom_cases_fail_closed() {
        let wrong_hash = build_wheel(Vec::new(), |record| {
            let mut lines = record.lines().map(str::to_owned).collect::<Vec<_>>();
            let fields = lines[0].split(',').collect::<Vec<_>>();
            lines[0] = format!(
                "{},sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,{}",
                fields[0], fields[2]
            );
            lines.join("\n") + "\n"
        });
        assert_eq!(
            finding_code(&evaluate_wheel(
                "demo-1.0-py3-none-any.whl",
                &verified(&wrong_hash),
                WheelLimits::default()
            )),
            "wheel.record-hash-mismatch"
        );

        let missing = build_wheel(Vec::new(), |record| {
            record
                .lines()
                .filter(|line| !line.starts_with("demo/__init__.py,"))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        });
        assert_eq!(
            finding_code(&evaluate_wheel(
                "demo-1.0-py3-none-any.whl",
                &verified(&missing),
                WheelLimits::default()
            )),
            "wheel.record-member-missing"
        );

        let duplicate = build_wheel(Vec::new(), |record| {
            let first = record.lines().next().unwrap();
            format!("{record}{first}\n")
        });
        assert_eq!(
            finding_code(&evaluate_wheel(
                "demo-1.0-py3-none-any.whl",
                &verified(&duplicate),
                WheelLimits::default()
            )),
            "wheel.record-duplicate"
        );

        let phantom = build_wheel(Vec::new(), |record| {
            format!("{record}ghost.py,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,0\n")
        });
        assert_eq!(
            finding_code(&evaluate_wheel(
                "demo-1.0-py3-none-any.whl",
                &verified(&phantom),
                WheelLimits::default()
            )),
            "wheel.record-phantom"
        );
    }

    #[test]
    fn relocation_generated_target_and_executable_mode_cases_are_explicit() {
        let collision = build_wheel(
            vec![
                ("shared.txt".into(), b"root".to_vec()),
                (
                    "demo-1.0.data/purelib/shared.txt".into(),
                    b"relocated".to_vec(),
                ),
            ],
            |record| record,
        );
        assert_eq!(
            finding_code(&evaluate_wheel(
                "demo-1.0-py3-none-any.whl",
                &verified(&collision),
                WheelLimits::default()
            )),
            "wheel.relocation-collision"
        );

        let unsafe_target = build_wheel(
            vec![(
                "demo-1.0.dist-info/entry_points.txt".into(),
                b"[console_scripts]\nCON = demo:main\n".to_vec(),
            )],
            |record| record,
        );
        assert_eq!(
            finding_code(&evaluate_wheel(
                "demo-1.0-py3-none-any.whl",
                &verified(&unsafe_target),
                WheelLimits::default()
            )),
            "wheel.generated-target-name"
        );

        let script = build_wheel(
            vec![(
                "demo-1.0.data/scripts/run-demo".into(),
                b"#!python\nprint('demo')\n".to_vec(),
            )],
            |record| record,
        );
        let evaluation = evaluate_wheel(
            "demo-1.0-py3-none-any.whl",
            &verified(&script),
            WheelLimits::default(),
        );
        let WheelEvaluation::Admitted { plan, .. } = evaluation else {
            panic!("mode-bound source script should be admitted");
        };
        let script = plan
            .entries
            .iter()
            .find(|entry| entry.relative_path == "run-demo")
            .unwrap();
        assert_eq!(script.transform, InstallTransform::RewritePythonShebang);
    }

    #[test]
    fn semantic_preflight_accepts_cap_and_denies_cap_minus_one() {
        let bytes = build_wheel(Vec::new(), |record| record);
        let archive = verified(&bytes);
        let wheel_size = archive
            .member("demo-1.0.dist-info/WHEEL")
            .unwrap()
            .actual_uncomp_size
            .unwrap();
        let mut limits = WheelLimits {
            max_wheel_bytes: wheel_size,
            ..WheelLimits::default()
        };
        assert!(matches!(
            evaluate_wheel("demo-1.0-py3-none-any.whl", &archive, limits),
            WheelEvaluation::Admitted { .. }
        ));
        limits.max_wheel_bytes -= 1;
        assert_eq!(
            finding_code(&evaluate_wheel(
                "demo-1.0-py3-none-any.whl",
                &archive,
                limits
            )),
            "wheel.semantic-member-limit"
        );
    }
}
