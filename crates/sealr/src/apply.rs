use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use crate::covering::audit_covering;
use crate::findings::{Finding, FindingCode, Severity};
use crate::identity::OutcomeIdentities;
use crate::ir::{ArchiveIR, IrMember, MemberKind, NormalizationAction};
use crate::jail::jail_name;
use crate::materialize::{CapabilityMaterializer, MaterializationMeta};
use crate::outcome::{
    AdmissionStatus, DigestHex, EffectStatus, InterpretationStatus, SemanticAxes, SourceDigest,
    VerificationStatus, ViewCompleteness,
};
use crate::policy::{hex_sha256, ratio_exceeds, Policy, ResourceBudget};
use crate::snapshot::{SnapshotKind, SourceSnapshot};
use crate::verified::VerifiedArchive;
use crate::zip::{self, ZipMember};
use cap_std::fs::File as CapFile;
use crc32fast::Hasher as Crc;
use flate2::bufread::DeflateDecoder;
use serde::Serialize;
use sha2::{Digest, Sha256};

// PKWARE APPNOTE 4.4.4: traditional encryption, strong encryption, and
// central-directory encryption with masked local-header values.
const ZIP_ENCRYPTION_FLAGS: u16 = (1 << 0) | (1 << 6) | (1 << 13);

#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Source<'a> {
    Path(&'a Path),
    Bytes {
        path: Option<&'a str>,
        data: &'a [u8],
    },
}

#[derive(Clone, Debug)]
pub struct Request<'a> {
    pub source: Source<'a>,
    pub policy: &'a Policy,
    pub dest: Option<&'a Path>,
}

#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub enum Verdict {
    Allowed { wrote: bool },
    Rejected,
}

#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct MemberView {
    pub path: String,
    pub kind: &'static str,
    pub comp_bytes: u64,
    pub uncomp_bytes: u64,
    pub method: &'static str,
    pub crc32: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct View {
    pub schema: &'static str,
    pub source: SourceMeta,
    pub policy: PolicyMeta,
    pub interpretation: InterpretationStatus,
    pub admission: AdmissionStatus,
    pub verification: VerificationStatus,
    pub effect: EffectStatus,
    pub view_completeness: ViewCompleteness,
    pub verdict: &'static str,
    pub wrote: bool,
    pub findings: Vec<Finding>,
    pub members: Vec<MemberView>,
}

#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct SourceMeta {
    pub path: Option<String>,
    pub digest: SourceDigest,
    pub magic: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct PolicyMeta {
    pub id: String,
    pub digest: DigestHex,
}

#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct Receipt {
    pub schema: &'static str,
    pub verdict: &'static str,
    pub wrote: bool,
    pub interpretation: InterpretationStatus,
    pub admission: AdmissionStatus,
    pub verification: VerificationStatus,
    pub effect: EffectStatus,
    pub view_completeness: ViewCompleteness,
    pub source: SourceDigest,
    pub source_snapshot: SnapshotKind,
    pub policy: PolicyMeta,
    pub identities: OutcomeIdentities,
    pub view_digest: DigestHex,
    pub tool: ToolMeta,
    pub environment: EnvMeta,
    pub materialization: MaterializationMeta,
    pub signed: bool,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct ToolMeta {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct EnvMeta {
    pub os: &'static str,
    pub arch: &'static str,
    pub kernel_jail: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[must_use = "archive outcomes contain the admission decision and evidence"]
#[non_exhaustive]
pub struct Outcome {
    pub interpretation: InterpretationStatus,
    pub admission: AdmissionStatus,
    pub verification: VerificationStatus,
    pub effect: EffectStatus,
    pub view_completeness: ViewCompleteness,
    pub verdict: Verdict,
    pub receipt: Receipt,
    pub view: View,
    /// Effect-independent ZIP interpretation when planning produced a member list.
    /// Absent when ingest or structure failed before a tree existed.
    #[serde(skip)]
    archive_ir: Option<ArchiveIR>,
    /// Opaque authority for bounded member reads after complete verification.
    #[serde(skip)]
    verified_archive: Option<VerifiedArchive>,
}

impl Outcome {
    pub fn rejected(&self) -> bool {
        matches!(self.verdict, Verdict::Rejected)
    }

    pub fn wrote(&self) -> bool {
        matches!(self.verdict, Verdict::Allowed { wrote: true })
    }

    /// Read-only interpreted archive evidence, when structure planning completed.
    ///
    /// This evidence view is available after planning. Only
    /// [`Self::verified_archive`] grants authority to read verified member bytes.
    pub fn archive_ir(&self) -> Option<&ArchiveIR> {
        self.verified_archive
            .as_ref()
            .map(VerifiedArchive::archive_ir)
            .or(self.archive_ir.as_ref())
    }

    /// Opaque verified capability, available only after every member passes.
    pub fn verified_archive(&self) -> Option<&VerifiedArchive> {
        self.verified_archive.as_ref()
    }

    /// Consume the outcome and retain only its verified archive capability.
    pub fn into_verified_archive(self) -> Option<VerifiedArchive> {
        self.verified_archive
    }

    /// Process exit class: 0 admitted without effect failure, 2 not admitted, 3 admitted but effect failed.
    pub fn cli_exit_code(&self) -> u8 {
        if self.admission == AdmissionStatus::Admitted {
            match self.effect {
                EffectStatus::Failed => 3,
                EffectStatus::Committed | EffectStatus::NotRequested => 0,
            }
        } else {
            2
        }
    }
}

pub fn apply(req: Request<'_>) -> Outcome {
    let compiled = match req.policy.compile() {
        Ok(compiled) => compiled,
        Err(finding) => {
            return reject_only(
                (None, SourceDigest::unavailable(), req.policy.clone()),
                vec![finding.clone()],
                None,
                MaterializationMeta::not_started(req.dest.is_some(), req.policy.atomic),
                SemanticAxes::policy_compile_failed(&finding),
                SnapshotKind::Unavailable,
                OutcomeIdentities::without_source(),
            );
        }
    };
    match apply_inner(&req, compiled.budget) {
        Ok(o) => o,
        Err(failure) => {
            let admission = if failure.finding.code == FindingCode::QuotaArchive {
                AdmissionStatus::Denied
            } else {
                AdmissionStatus::NotEvaluated
            };
            let digest = failure.digest.clone();
            reject_only(
                (failure.path, failure.digest, req.policy.clone()),
                vec![failure.finding.clone()],
                None,
                MaterializationMeta::not_started(req.dest.is_some(), req.policy.atomic),
                SemanticAxes::source_failure(&failure.finding, admission),
                failure.snapshot_kind,
                OutcomeIdentities::unavailable(digest),
            )
        }
    }
}

struct SourceFailure {
    path: Option<String>,
    digest: SourceDigest,
    finding: Finding,
    snapshot_kind: SnapshotKind,
}

fn read_source<'a>(
    src: &'a Source<'a>,
    budget: ResourceBudget,
) -> Result<SourceSnapshot<'a>, SourceFailure> {
    match src {
        Source::Path(p) => {
            let path = Some(p.display().to_string());
            let unavailable = |finding: Finding| SourceFailure {
                path: path.clone(),
                digest: SourceDigest::unavailable(),
                finding,
                snapshot_kind: SnapshotKind::Unavailable,
            };
            let len = fs::metadata(p)
                .map_err(|e| {
                    unavailable(Finding::error(
                        FindingCode::SourceIo,
                        format!("metadata: {e}"),
                    ))
                })?
                .len();
            if len > budget.max_archive_bytes {
                return Err(unavailable(Finding::error(
                    FindingCode::QuotaArchive,
                    format!(
                        "archive is {len} bytes; cap is {}",
                        budget.max_archive_bytes
                    ),
                )));
            }
            let mut file = File::open(p).map_err(|e| {
                unavailable(Finding::error(FindingCode::SourceIo, format!("open: {e}")))
            })?;
            let initial_capacity = usize::try_from(len)
                .unwrap_or(usize::MAX)
                .min(8 * 1024 * 1024);
            let mut bytes = Vec::with_capacity(initial_capacity);
            let take_limit = budget.max_archive_bytes.saturating_add(1);
            (&mut file)
                .take(take_limit)
                .read_to_end(&mut bytes)
                .map_err(|e| {
                    unavailable(Finding::error(FindingCode::SourceIo, format!("read: {e}")))
                })?;
            if bytes.len() as u64 > budget.max_archive_bytes {
                return Err(SourceFailure {
                    path,
                    digest: SourceDigest::unavailable(),
                    finding: Finding::error(
                        FindingCode::QuotaArchive,
                        "archive grew beyond the input cap while being read",
                    ),
                    snapshot_kind: SnapshotKind::Unavailable,
                });
            }
            Ok(SourceSnapshot::owned(path, bytes))
        }
        Source::Bytes { path, data } => {
            let path = path.map(|s| s.to_string());
            if data.len() as u64 > budget.max_archive_bytes {
                return Err(SourceFailure {
                    path,
                    digest: SourceDigest::available(hex_sha256(data)),
                    finding: Finding::error(
                        FindingCode::QuotaArchive,
                        format!(
                            "archive is {} bytes; cap is {}",
                            data.len(),
                            budget.max_archive_bytes
                        ),
                    ),
                    snapshot_kind: SnapshotKind::MemoryBorrowed,
                });
            }
            Ok(SourceSnapshot::borrowed(path, data))
        }
    }
}

fn apply_inner(req: &Request<'_>, budget: ResourceBudget) -> Result<Outcome, SourceFailure> {
    let policy = req.policy;
    let initial_materialization =
        MaterializationMeta::not_started(req.dest.is_some(), policy.atomic);
    let snapshot = read_source(&req.source, budget)?;
    let identities_base = OutcomeIdentities::unavailable(snapshot.digest().clone());
    let source_digest = snapshot.digest().clone();
    let source_meta = (snapshot.path_owned(), source_digest.clone(), policy.clone());
    let magic = detect_magic(snapshot.as_bytes());
    if magic != "zip" {
        let f = Finding::error(FindingCode::FormatUnsupported, format!("magic {magic}"));
        return Ok(reject_only(
            source_meta,
            vec![f.clone()],
            Some(magic),
            initial_materialization,
            SemanticAxes::structure_stop(
                InterpretationStatus::Unsupported,
                AdmissionStatus::NotEvaluated,
                &f,
            ),
            snapshot.kind(),
            identities_base.clone(),
        ));
    }
    if !policy.allows_format("zip") {
        let f = Finding::error(FindingCode::FormatUnsupported, "zip not in policy.formats");
        return Ok(reject_only(
            source_meta,
            vec![f.clone()],
            Some("zip"),
            initial_materialization,
            SemanticAxes::structure_stop(
                InterpretationStatus::Unsupported,
                AdmissionStatus::Denied,
                &f,
            ),
            snapshot.kind(),
            identities_base.clone(),
        ));
    }

    let parsed = match zip::parse_zip(
        snapshot.as_bytes(),
        budget.max_files,
        budget.max_metadata_bytes,
    ) {
        Ok(z) => z,
        Err(f) => {
            return Ok(reject_only(
                source_meta,
                vec![f.clone()],
                Some("zip"),
                initial_materialization,
                parse_failure_axes(&f),
                snapshot.kind(),
                identities_base.clone(),
            ));
        }
    };

    if parsed.members.len() as u64 > budget.max_files {
        let f = Finding::error(
            FindingCode::QuotaFiles,
            format!("{} entries", parsed.members.len()),
        );
        return Ok(reject_only(
            source_meta,
            vec![f.clone()],
            Some("zip"),
            initial_materialization,
            SemanticAxes::structure_stop(
                InterpretationStatus::Interpreted,
                AdmissionStatus::Denied,
                &f,
            ),
            snapshot.kind(),
            identities_base.clone(),
        ));
    }
    if parsed.metadata_bytes > budget.max_metadata_bytes {
        let f = Finding::error(
            FindingCode::QuotaMetadata,
            format!(
                "ZIP metadata is {} bytes; cap is {}",
                parsed.metadata_bytes, budget.max_metadata_bytes
            ),
        );
        return Ok(reject_only(
            source_meta,
            vec![f.clone()],
            Some("zip"),
            initial_materialization,
            SemanticAxes::structure_stop(
                InterpretationStatus::Interpreted,
                AdmissionStatus::Denied,
                &f,
            ),
            snapshot.kind(),
            identities_base.clone(),
        ));
    }

    let covering = parsed.covering();
    let mut findings = Vec::new();
    let mut planned: Vec<(ZipMember, Vec<String>, Vec<NormalizationAction>)> = Vec::new();
    let mut dest_seen: BTreeMap<String, bool> = BTreeMap::new();
    let mut fold_seen: BTreeMap<String, bool> = BTreeMap::new();
    let mut declared_total: u64 = 0;

    for m in parsed.members {
        if (m.flags & ZIP_ENCRYPTION_FLAGS) != 0 {
            findings.push(
                Finding::error(
                    FindingCode::ZipEncrypted,
                    format!("encryption-related general-purpose flags 0x{:04x}", m.flags),
                )
                .on(&m.name),
            );
            continue;
        }
        if m.method != 0 && m.method != 8 {
            findings.push(
                Finding::error(
                    FindingCode::MethodUnsupported,
                    format!("method {}", m.method),
                )
                .on(&m.name),
            );
            continue;
        }
        if m.uncomp_size > budget.max_member_bytes {
            findings.push(
                Finding::error(FindingCode::QuotaMember, "declared member too large").on(&m.name),
            );
            continue;
        }
        if let Some(max_r) = budget.max_ratio {
            if ratio_exceeds(m.uncomp_size, m.comp_size, max_r) {
                findings.push(
                    Finding::error(
                        FindingCode::QuotaRatio,
                        format!(
                            "declared {}:{} exceeds {max_r}:1",
                            m.uncomp_size, m.comp_size
                        ),
                    )
                    .on(&m.name),
                );
                continue;
            }
        }
        declared_total = match declared_total.checked_add(m.uncomp_size) {
            Some(total) => total,
            None => {
                findings.push(Finding::error(
                    FindingCode::QuotaOverflow,
                    "declared uncompressed total overflowed u64",
                ));
                break;
            }
        };
        if declared_total > budget.max_total_bytes {
            findings.push(Finding::error(
                FindingCode::QuotaTotal,
                "declared total too large",
            ));
            break;
        }

        let mut actions = Vec::new();
        let jailed_name = if m.is_dir {
            actions.push(NormalizationAction::StripDirectoryTrailingSlash);
            m.name.strip_suffix('/').unwrap_or(&m.name)
        } else {
            &m.name
        };
        match jail_name(jailed_name, budget.max_path_depth) {
            Ok(jailed) => {
                let mut actions = actions;
                actions.extend(jailed.actions);
                let parts = jailed.components;
                let joined = parts.join("/");
                let fold = joined.to_ascii_lowercase();
                if dest_seen.contains_key(&joined) {
                    findings.push(
                        Finding::error(FindingCode::ZipDiffB1Dup, "duplicate dest path")
                            .on(&m.name),
                    );
                    continue;
                }
                if fold_seen.contains_key(&fold) {
                    findings.push(
                        Finding::error(FindingCode::PathCaseFold, "case-fold collision")
                            .on(&m.name),
                    );
                    continue;
                }
                if let Some(conflict) = path_conflict(&dest_seen, &joined, m.is_dir) {
                    findings.push(
                        Finding::error(
                            FindingCode::PathConflict,
                            format!("file/directory conflict with {conflict}"),
                        )
                        .on(&m.name),
                    );
                    continue;
                }
                if let Some(conflict) = path_conflict(&fold_seen, &fold, m.is_dir) {
                    findings.push(
                        Finding::error(
                            FindingCode::PathCaseFold,
                            format!("case-fold topology conflict with {conflict}"),
                        )
                        .on(&m.name),
                    );
                    continue;
                }
                dest_seen.insert(joined, m.is_dir);
                fold_seen.insert(fold, m.is_dir);
                planned.push((m, parts, actions));
            }
            Err(f) => findings.push(f),
        }
    }

    let fatal = findings.iter().any(|f| f.severity == Severity::Error);
    if fatal {
        let cause = first_error(&findings);
        return Ok(finish(
            (snapshot.path_owned(), source_digest, snapshot.kind()),
            "zip",
            policy,
            findings,
            Vec::new(),
            initial_materialization,
            SemanticAxes::denied_at_admission(&cause),
            identities_base.clone(),
        ));
    }

    let mut ir = ArchiveIR::with_covering(
        source_digest.clone(),
        covering,
        planned
            .into_iter()
            .map(|(zip, components, actions)| IrMember::from_planned(zip, components, actions))
            .collect(),
    );
    if let Err(finding) = audit_covering(&snapshot, &ir) {
        findings.push(finding);
        let cause = first_error(&findings);
        return Ok(with_ir(
            finish(
                (snapshot.path_owned(), source_digest, snapshot.kind()),
                "zip",
                policy,
                findings,
                Vec::new(),
                initial_materialization,
                SemanticAxes::structure_stop(
                    InterpretationStatus::Malformed,
                    AdmissionStatus::Denied,
                    &cause,
                ),
                identities_base.clone(),
            ),
            ir,
        ));
    }
    let planned_count = ir.members.len() as u64;
    let mut members_view = Vec::new();
    let mut actual_total: u64 = 0;
    let mut materialization = initial_materialization;
    let mut stage = match req.dest {
        None => None,
        Some(dest) => match CapabilityMaterializer::create(dest, policy.atomic) {
            Ok(stage) => {
                materialization = stage.report();
                Some(stage)
            }
            Err(setup_error) => {
                let (setup_findings, cleanup, windows) = setup_error.into_parts();
                findings.extend(setup_findings);
                materialization =
                    MaterializationMeta::setup_failed(policy.atomic, cleanup, windows);
                let cause = first_error(&findings);
                return Ok(with_ir(
                    finish(
                        (snapshot.path_owned(), source_digest, snapshot.kind()),
                        "zip",
                        policy,
                        findings,
                        members_view,
                        materialization,
                        SemanticAxes::admitted_setup_failed(&cause),
                        identities_base.clone(),
                    ),
                    ir,
                ));
            }
        },
    };
    let write = stage.is_some();

    for index in 0..ir.members.len() {
        if matches!(ir.members[index].kind, MemberKind::Directory) {
            if let Some(materializer) = stage.as_ref() {
                if let Err(finding) = materializer.create_directory(
                    &ir.members[index].components,
                    &ir.members[index].decoded_name,
                ) {
                    ir.members[index].mark_failed(finding.code.as_str());
                    findings.push(finding);
                    materialization = abort_and_report(&mut stage, &mut findings, materialization);
                    let cause = first_error(&findings);
                    let verified = members_view.len() as u64;
                    return Ok(with_ir(
                        finish(
                            (snapshot.path_owned(), source_digest, snapshot.kind()),
                            "zip",
                            policy,
                            findings,
                            members_view,
                            materialization,
                            SemanticAxes::admitted_verification_stop(
                                verified,
                                planned_count.saturating_sub(verified),
                                &cause,
                                write,
                            ),
                            identities_base.clone(),
                        ),
                        ir,
                    ));
                }
            }
            ir.members[index].mark_directory_verified();
            members_view.push(member_view(&ir.members[index]));
            continue;
        }

        let zip_member = ir.members[index].as_zip_member();
        let payload = match zip::payload(&snapshot, &zip_member) {
            Ok(payload) => payload,
            Err(finding) => {
                ir.members[index].mark_failed(finding.code.as_str());
                findings.push(finding);
                materialization = abort_and_report(&mut stage, &mut findings, materialization);
                let cause = first_error(&findings);
                let verified = members_view.len() as u64;
                return Ok(with_ir(
                    finish(
                        (snapshot.path_owned(), source_digest, snapshot.kind()),
                        "zip",
                        policy,
                        findings,
                        members_view,
                        materialization,
                        SemanticAxes::admitted_verification_stop(
                            verified,
                            planned_count.saturating_sub(verified),
                            &cause,
                            write,
                        ),
                        identities_base.clone(),
                    ),
                    ir,
                ));
            }
        };
        let remaining = match budget.max_total_bytes.checked_sub(actual_total) {
            Some(remaining) => remaining,
            None => {
                let finding =
                    Finding::error(FindingCode::QuotaOverflow, "remaining total underflowed");
                ir.members[index].mark_failed(finding.code.as_str());
                findings.push(finding);
                materialization = abort_and_report(&mut stage, &mut findings, materialization);
                let cause = first_error(&findings);
                let verified = members_view.len() as u64;
                return Ok(with_ir(
                    finish(
                        (snapshot.path_owned(), source_digest, snapshot.kind()),
                        "zip",
                        policy,
                        findings,
                        members_view,
                        materialization,
                        SemanticAxes::admitted_verification_stop(
                            verified,
                            planned_count.saturating_sub(verified),
                            &cause,
                            write,
                        ),
                        identities_base.clone(),
                    ),
                    ir,
                ));
            }
        };
        let processed = if let Some(stage) = stage.as_ref() {
            stage
                .create_file(&ir.members[index].components)
                .and_then(|file| {
                    process_member_to_file(
                        payload,
                        &zip_member,
                        budget,
                        remaining,
                        policy.atomic,
                        file,
                    )
                })
        } else {
            let mut sink = io::sink();
            process_member(payload, &zip_member, budget, remaining, &mut sink)
        };
        let (actual, crc, sha) = match processed {
            Ok(result) => result,
            Err(finding) => {
                let finding = finding.on(&ir.members[index].decoded_name);
                ir.members[index].mark_failed(finding.code.as_str());
                findings.push(finding);
                materialization = abort_and_report(&mut stage, &mut findings, materialization);
                let cause = first_error(&findings);
                let verified = members_view.len() as u64;
                return Ok(with_ir(
                    finish(
                        (snapshot.path_owned(), source_digest, snapshot.kind()),
                        "zip",
                        policy,
                        findings,
                        members_view,
                        materialization,
                        SemanticAxes::admitted_verification_stop(
                            verified,
                            planned_count.saturating_sub(verified),
                            &cause,
                            write,
                        ),
                        identities_base.clone(),
                    ),
                    ir,
                ));
            }
        };
        if crc != ir.members[index].declared_crc {
            let finding = Finding::error(
                FindingCode::CrcMismatch,
                format!("got {crc:08x} want {:08x}", ir.members[index].declared_crc),
            )
            .on(&ir.members[index].decoded_name);
            ir.members[index].mark_failed(finding.code.as_str());
            findings.push(finding);
            materialization = abort_and_report(&mut stage, &mut findings, materialization);
            let cause = first_error(&findings);
            let verified = members_view.len() as u64;
            return Ok(with_ir(
                finish(
                    (snapshot.path_owned(), source_digest, snapshot.kind()),
                    "zip",
                    policy,
                    findings,
                    members_view,
                    materialization,
                    SemanticAxes::admitted_verification_stop(
                        verified,
                        planned_count.saturating_sub(verified),
                        &cause,
                        write,
                    ),
                    identities_base.clone(),
                ),
                ir,
            ));
        }
        actual_total = match actual_total.checked_add(actual) {
            Some(total) => total,
            None => {
                let finding = Finding::error(
                    FindingCode::QuotaOverflow,
                    "actual uncompressed total overflowed u64",
                )
                .on(&ir.members[index].decoded_name);
                ir.members[index].mark_failed(finding.code.as_str());
                findings.push(finding);
                materialization = abort_and_report(&mut stage, &mut findings, materialization);
                let cause = first_error(&findings);
                let verified = members_view.len() as u64;
                return Ok(with_ir(
                    finish(
                        (snapshot.path_owned(), source_digest, snapshot.kind()),
                        "zip",
                        policy,
                        findings,
                        members_view,
                        materialization,
                        SemanticAxes::admitted_verification_stop(
                            verified,
                            planned_count.saturating_sub(verified),
                            &cause,
                            write,
                        ),
                        identities_base.clone(),
                    ),
                    ir,
                ));
            }
        };
        ir.members[index].mark_file_verified(actual, crc, sha);
        members_view.push(member_view(&ir.members[index]));
    }

    members_view.sort_by(|a, b| a.path.cmp(&b.path));
    if let Some(materializer) = stage.as_mut() {
        if let Err(finding) = materializer.audit_against(&ir) {
            findings.push(finding);
            materialization = abort_and_report(&mut stage, &mut findings, materialization);
            let cause = first_error(&findings);
            let source_meta = (snapshot.path_owned(), source_digest, snapshot.kind());
            let archive = VerifiedArchive::new(snapshot, ir, budget);
            return Ok(with_verified_archive(
                finish(
                    source_meta,
                    "zip",
                    policy,
                    findings,
                    members_view,
                    materialization,
                    SemanticAxes::admitted_publication_failed(&cause),
                    identities_base.clone(),
                ),
                archive,
            ));
        }
        if let Err(finding) = materializer.commit() {
            findings.push(finding);
            materialization = abort_and_report(&mut stage, &mut findings, materialization);
            let cause = first_error(&findings);
            let source_meta = (snapshot.path_owned(), source_digest, snapshot.kind());
            let archive = VerifiedArchive::new(snapshot, ir, budget);
            return Ok(with_verified_archive(
                finish(
                    source_meta,
                    "zip",
                    policy,
                    findings,
                    members_view,
                    materialization,
                    SemanticAxes::admitted_publication_failed(&cause),
                    identities_base.clone(),
                ),
                archive,
            ));
        }
        materialization = materializer.report();
    }
    let source_meta = (snapshot.path_owned(), source_digest, snapshot.kind());
    let archive = VerifiedArchive::new(snapshot, ir, budget);
    Ok(with_verified_archive(
        finish(
            source_meta,
            "zip",
            policy,
            findings,
            members_view,
            materialization,
            if write {
                SemanticAxes::materialize_committed()
            } else {
                SemanticAxes::inspect_complete()
            },
            identities_base.clone(),
        ),
        archive,
    ))
}

fn abort_and_report(
    stage: &mut Option<CapabilityMaterializer>,
    findings: &mut Vec<Finding>,
    fallback: MaterializationMeta,
) -> MaterializationMeta {
    let Some(stage) = stage.as_mut() else {
        return fallback;
    };
    if let Err(first_cleanup) = stage.abort() {
        findings.push(first_cleanup);
        if let Err(final_cleanup) = stage.abort() {
            findings.push(final_cleanup);
        }
    }
    stage.report()
}

fn path_conflict(seen: &BTreeMap<String, bool>, path: &str, is_dir: bool) -> Option<String> {
    for (index, _) in path.match_indices('/') {
        let ancestor = &path[..index];
        if matches!(seen.get(ancestor), Some(false)) {
            return Some(ancestor.to_owned());
        }
    }
    if !is_dir {
        let prefix = format!("{path}/");
        if let Some((candidate, _)) = seen.range(prefix.clone()..).next() {
            if candidate.starts_with(&prefix) {
                return Some(candidate.clone());
            }
        }
    }
    None
}

fn process_member_to_file(
    payload: &[u8],
    member: &ZipMember,
    budget: ResourceBudget,
    remaining_total: u64,
    member_sync: bool,
    mut file: CapFile,
) -> Result<(u64, u32, String), Finding> {
    let result = process_member(payload, member, budget, remaining_total, &mut file)?;
    file.flush().map_err(|error| {
        Finding::error(FindingCode::MaterializeIo, format!("flush member: {error}"))
    })?;
    if member_sync {
        file.sync_all().map_err(|error| {
            Finding::error(FindingCode::MaterializeIo, format!("sync member: {error}"))
        })?;
    }
    Ok(result)
}

pub(crate) fn process_member(
    payload: &[u8],
    member: &ZipMember,
    budget: ResourceBudget,
    remaining_total: u64,
    writer: &mut impl Write,
) -> Result<(u64, u32, String), Finding> {
    let mut actual = 0_u64;
    let mut crc = Crc::new();
    let mut sha = Sha256::new();
    let mut consume = |chunk: &[u8]| -> Result<(), Finding> {
        actual = actual.checked_add(chunk.len() as u64).ok_or_else(|| {
            Finding::error(
                FindingCode::QuotaOverflow,
                "actual member size overflowed u64",
            )
        })?;
        if actual > member.uncomp_size {
            return Err(Finding::error(
                FindingCode::QuotaDeclaredLie,
                "actual bytes exceeded the declared uncompressed size",
            ));
        }
        if actual > budget.max_member_bytes {
            return Err(Finding::error(
                FindingCode::QuotaMember,
                "actual bytes exceeded the member cap",
            ));
        }
        if actual > remaining_total {
            return Err(Finding::error(
                FindingCode::QuotaTotal,
                "actual bytes exceeded the remaining archive cap",
            ));
        }
        if let Some(max_ratio) = budget.max_ratio {
            if ratio_exceeds(actual, member.comp_size, max_ratio) {
                return Err(Finding::error(
                    FindingCode::QuotaRatio,
                    format!(
                        "actual {}:{} exceeded {max_ratio}:1",
                        actual, member.comp_size
                    ),
                ));
            }
        }
        writer.write_all(chunk).map_err(|error| {
            Finding::error(FindingCode::MaterializeIo, format!("write member: {error}"))
        })?;
        crc.update(chunk);
        sha.update(chunk);
        Ok(())
    };

    match member.method {
        0 => {
            for chunk in payload.chunks(64 * 1024) {
                consume(chunk)?;
            }
        }
        8 => {
            let mut decoder = DeflateDecoder::new(payload);
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = decoder.read(&mut buffer).map_err(|error| {
                    Finding::error(
                        FindingCode::CodecDeflateInvalidStream,
                        format!("deflate: {error}"),
                    )
                })?;
                if read == 0 {
                    break;
                }
                consume(&buffer[..read])?;
            }
            let consumed = decoder.total_in();
            if consumed != payload.len() as u64 {
                return Err(Finding::error(
                    FindingCode::CodecDeflateTrailingInput,
                    format!(
                        "deflate consumed {consumed} of {} declared compressed bytes",
                        payload.len()
                    ),
                ));
            }
            if decoder.total_out() != actual {
                return Err(Finding::error(
                    FindingCode::CodecDeflateInvalidStream,
                    "deflate output accounting disagreed with the verified byte count",
                ));
            }
        }
        _ => {
            return Err(Finding::error(
                FindingCode::MethodUnsupported,
                format!("method {}", member.method),
            ));
        }
    }
    if actual != member.uncomp_size {
        return Err(Finding::error(
            FindingCode::QuotaDeclaredLie,
            format!(
                "actual size {actual} != declared size {}",
                member.uncomp_size
            ),
        ));
    }
    let digest = sha.finalize();
    let sha256 = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok((actual, crc.finalize(), sha256))
}

fn detect_magic(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 4
        && bytes[0] == 0x50
        && bytes[1] == 0x4b
        && (bytes[2] == 0x03 || bytes[2] == 0x05)
    {
        "zip"
    } else if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        "gz"
    } else {
        "unknown"
    }
}

#[allow(clippy::too_many_arguments)]
fn finish(
    (path, source_digest, source_snapshot): (Option<String>, SourceDigest, SnapshotKind),
    magic: &'static str,
    policy: &Policy,
    findings: Vec<Finding>,
    members: Vec<MemberView>,
    materialization: MaterializationMeta,
    axes: SemanticAxes,
    identities: OutcomeIdentities,
) -> Outcome {
    let verdict = compat_verdict(&axes);
    let (verdict_s, wrote) = match &verdict {
        Verdict::Allowed { wrote } => ("allowed", *wrote),
        Verdict::Rejected => ("rejected", false),
    };
    let view = View {
        schema: "sealr.view.v1",
        source: SourceMeta {
            path,
            digest: source_digest.clone(),
            magic,
        },
        policy: PolicyMeta {
            id: policy.id.clone(),
            digest: DigestHex {
                sha256: policy.digest_hex(),
            },
        },
        interpretation: axes.interpretation.clone(),
        admission: axes.admission.clone(),
        verification: axes.verification.clone(),
        effect: axes.effect.clone(),
        view_completeness: axes.view_completeness.clone(),
        verdict: verdict_s,
        wrote,
        findings: findings.clone(),
        members,
    };
    let view_json = serde_json::to_vec(&view).expect("view json");
    let receipt = Receipt {
        schema: "sealr.receipt.v2",
        verdict: verdict_s,
        wrote,
        interpretation: axes.interpretation.clone(),
        admission: axes.admission.clone(),
        verification: axes.verification.clone(),
        effect: axes.effect.clone(),
        view_completeness: axes.view_completeness.clone(),
        source: source_digest,
        source_snapshot,
        policy: view.policy.clone(),
        identities,
        view_digest: DigestHex {
            sha256: hex_sha256(&view_json),
        },
        tool: ToolMeta {
            name: "sealr",
            version: env!("CARGO_PKG_VERSION"),
        },
        environment: EnvMeta {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            kernel_jail: "unavailable",
        },
        materialization,
        signed: false,
        findings,
    };
    Outcome {
        interpretation: axes.interpretation,
        admission: axes.admission,
        verification: axes.verification,
        effect: axes.effect,
        view_completeness: axes.view_completeness,
        verdict,
        receipt,
        view,
        archive_ir: None,
        verified_archive: None,
    }
}

fn with_ir(mut outcome: Outcome, ir: ArchiveIR) -> Outcome {
    outcome.receipt.identities =
        OutcomeIdentities::from_ir(outcome.receipt.source.clone(), &ir, &outcome.verification);
    outcome.archive_ir = Some(ir);
    outcome
}

fn with_verified_archive(mut outcome: Outcome, archive: VerifiedArchive) -> Outcome {
    outcome.receipt.identities = OutcomeIdentities::from_ir(
        outcome.receipt.source.clone(),
        archive.archive_ir(),
        &outcome.verification,
    );
    outcome.verified_archive = Some(archive);
    outcome
}

fn member_view(member: &IrMember) -> MemberView {
    let method = if member.method == 0 {
        "store"
    } else {
        "deflate"
    };
    MemberView {
        path: member.canonical_path.clone(),
        kind: match member.kind {
            MemberKind::Directory => "dir",
            MemberKind::File => "file",
        },
        comp_bytes: if matches!(member.kind, MemberKind::Directory) {
            0
        } else {
            member.declared_comp_size
        },
        uncomp_bytes: member.actual_uncomp_size.unwrap_or(0),
        method: if matches!(member.kind, MemberKind::Directory) {
            "store"
        } else {
            method
        },
        crc32: format!("{:08x}", member.actual_crc.unwrap_or(member.declared_crc)),
        sha256: member.content_sha256.clone().unwrap_or_default(),
    }
}

fn reject_only(
    (path, digest, policy): (Option<String>, SourceDigest, Policy),
    findings: Vec<Finding>,
    magic: Option<&'static str>,
    materialization: MaterializationMeta,
    axes: SemanticAxes,
    source_snapshot: SnapshotKind,
    identities: OutcomeIdentities,
) -> Outcome {
    finish(
        (path, digest, source_snapshot),
        magic.unwrap_or("unknown"),
        &policy,
        findings,
        Vec::new(),
        materialization,
        axes,
        identities,
    )
}

fn compat_verdict(axes: &SemanticAxes) -> Verdict {
    match (&axes.admission, &axes.effect) {
        (AdmissionStatus::Admitted, EffectStatus::Committed) => Verdict::Allowed { wrote: true },
        (AdmissionStatus::Admitted, EffectStatus::NotRequested) => {
            Verdict::Allowed { wrote: false }
        }
        _ => Verdict::Rejected,
    }
}

fn first_error(findings: &[Finding]) -> Finding {
    findings
        .iter()
        .find(|finding| finding.severity == Severity::Error)
        .cloned()
        .expect("error path records an error finding")
}

fn parse_failure_axes(finding: &Finding) -> SemanticAxes {
    let interpretation = match finding.code {
        FindingCode::FormatUnsupported
        | FindingCode::FormatMagic
        | FindingCode::ZipDiffC5Zip64
        | FindingCode::ZipEncoding
        | FindingCode::ZipEncrypted
        | FindingCode::MethodUnsupported => InterpretationStatus::Unsupported,
        FindingCode::QuotaFiles | FindingCode::QuotaMetadata | FindingCode::QuotaOverflow => {
            InterpretationStatus::Interpreted
        }
        _ => InterpretationStatus::Malformed,
    };
    let admission = match finding.code {
        FindingCode::QuotaFiles | FindingCode::QuotaMetadata | FindingCode::QuotaOverflow => {
            AdmissionStatus::Denied
        }
        _ => AdmissionStatus::NotEvaluated,
    };
    SemanticAxes::structure_stop(interpretation, admission, finding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::zip::write::SimpleFileOptions;
    use ::zip::{CompressionMethod, ZipWriter};
    use std::io::{Cursor, Write};
    use std::path::PathBuf;

    fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut w = ZipWriter::new(&mut cursor);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            for (name, data) in files {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn make_zip_with_directory() -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            writer
                .add_directory("empty/", SimpleFileOptions::default())
                .unwrap();
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn temp_dest(label: &str) -> PathBuf {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        std::env::temp_dir().join(format!("sealr-{label}-{suffix}"))
    }

    fn signature_offsets(bytes: &[u8], signature: [u8; 4]) -> Vec<usize> {
        bytes
            .windows(signature.len())
            .enumerate()
            .filter_map(|(index, window)| (window == signature).then_some(index))
            .collect()
    }

    fn make_crc_mismatch_zip() -> Vec<u8> {
        let mut bytes = make_zip(&[("first.txt", b"first"), ("second.txt", b"second")]);
        let local_headers = signature_offsets(&bytes, [0x50, 0x4b, 0x03, 0x04]);
        let central_headers = signature_offsets(&bytes, [0x50, 0x4b, 0x01, 0x02]);
        assert_eq!(local_headers.len(), 2);
        assert_eq!(central_headers.len(), 2);
        let local_crc = local_headers[1] + 14;
        let central_crc = central_headers[1] + 16;
        let mut wrong_crc =
            u32::from_le_bytes(bytes[central_crc..central_crc + 4].try_into().unwrap());
        wrong_crc ^= 1;
        bytes[local_crc..local_crc + 4].copy_from_slice(&wrong_crc.to_le_bytes());
        bytes[central_crc..central_crc + 4].copy_from_slice(&wrong_crc.to_le_bytes());
        bytes
    }

    fn u16_at(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn add_matching_flags(bytes: &mut [u8], flags: u16) {
        let local = signature_offsets(bytes, [0x50, 0x4b, 0x03, 0x04]);
        let central = signature_offsets(bytes, [0x50, 0x4b, 0x01, 0x02]);
        assert_eq!(local.len(), 1);
        assert_eq!(central.len(), 1);
        put_u16(bytes, local[0] + 6, u16_at(bytes, local[0] + 6) | flags);
        put_u16(bytes, central[0] + 8, u16_at(bytes, central[0] + 8) | flags);
    }

    fn extend_declared_deflate_payload(bytes: &mut Vec<u8>, suffix: &[u8]) {
        let local_headers = signature_offsets(bytes, [0x50, 0x4b, 0x03, 0x04]);
        let central_headers = signature_offsets(bytes, [0x50, 0x4b, 0x01, 0x02]);
        let eocd_headers = signature_offsets(bytes, [0x50, 0x4b, 0x05, 0x06]);
        assert_eq!(local_headers.len(), 1);
        assert_eq!(central_headers.len(), 1);
        assert_eq!(eocd_headers.len(), 1);

        let local = local_headers[0];
        let central = central_headers[0];
        let eocd = eocd_headers[0];
        let old_compressed_size = u32_at(bytes, local + 18);
        assert_eq!(u32_at(bytes, central + 20), old_compressed_size);
        let name_len = u16_at(bytes, local + 26) as usize;
        let extra_len = u16_at(bytes, local + 28) as usize;
        let payload_start = local + 30 + name_len + extra_len;
        assert_eq!(
            payload_start + old_compressed_size as usize,
            central,
            "fixture must place the central directory directly after the payload"
        );

        bytes.splice(central..central, suffix.iter().copied());
        let new_compressed_size = old_compressed_size + suffix.len() as u32;
        put_u32(bytes, local + 18, new_compressed_size);
        let shifted_central = central + suffix.len();
        put_u32(bytes, shifted_central + 20, new_compressed_size);
        let shifted_eocd = eocd + suffix.len();
        put_u32(bytes, shifted_eocd + 16, shifted_central as u32);
    }

    fn add_matching_extra_fields(bytes: &mut Vec<u8>, extra: &[u8]) {
        let local = signature_offsets(bytes, [0x50, 0x4b, 0x03, 0x04])[0];
        let central = signature_offsets(bytes, [0x50, 0x4b, 0x01, 0x02])[0];
        let eocd = signature_offsets(bytes, [0x50, 0x4b, 0x05, 0x06])[0];
        let cd_size = u32_at(bytes, eocd + 12);

        let local_name_len = u16_at(bytes, local + 26) as usize;
        let local_extra_len = u16_at(bytes, local + 28) as usize;
        let local_insert = local + 30 + local_name_len + local_extra_len;
        bytes.splice(local_insert..local_insert, extra.iter().copied());
        put_u16(bytes, local + 28, (local_extra_len + extra.len()) as u16);

        let central = central + extra.len();
        let central_name_len = u16_at(bytes, central + 28) as usize;
        let central_extra_len = u16_at(bytes, central + 30) as usize;
        let central_insert = central + 46 + central_name_len + central_extra_len;
        bytes.splice(central_insert..central_insert, extra.iter().copied());
        put_u16(
            bytes,
            central + 30,
            (central_extra_len + extra.len()) as u16,
        );

        let eocd = eocd + extra.len() * 2;
        put_u32(bytes, eocd + 12, cd_size + extra.len() as u32);
        put_u32(bytes, eocd + 16, central as u32);
    }

    fn add_central_comment(bytes: &mut Vec<u8>, comment: &[u8]) {
        let central = signature_offsets(bytes, [0x50, 0x4b, 0x01, 0x02])[0];
        let eocd = signature_offsets(bytes, [0x50, 0x4b, 0x05, 0x06])[0];
        let cd_size = u32_at(bytes, eocd + 12);
        let name_len = u16_at(bytes, central + 28) as usize;
        let extra_len = u16_at(bytes, central + 30) as usize;
        let old_comment_len = u16_at(bytes, central + 32) as usize;
        let insert = central + 46 + name_len + extra_len + old_comment_len;
        bytes.splice(insert..insert, comment.iter().copied());
        put_u16(
            bytes,
            central + 32,
            (old_comment_len + comment.len()) as u16,
        );
        let eocd = eocd + comment.len();
        put_u32(bytes, eocd + 12, cd_size + comment.len() as u32);
    }

    #[test]
    fn inspect_well_formed_zip() {
        let bytes = make_zip(&[("nested/hello.txt", b"hello")]);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("t.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });
        assert!(!out.rejected(), "{:?}", out.view.findings);
        assert!(!out.wrote());
        assert_eq!(out.view.members.len(), 1);
        assert_eq!(out.view.members[0].path, "nested/hello.txt");
        assert!(out.receipt.source.is_available());
        assert_eq!(out.interpretation, InterpretationStatus::Interpreted);
        assert_eq!(out.admission, AdmissionStatus::Admitted);
        assert_eq!(out.verification, VerificationStatus::Complete);
        assert_eq!(out.effect, EffectStatus::NotRequested);
        assert_eq!(out.receipt.schema, "sealr.receipt.v2");
        assert_eq!(out.receipt.source_snapshot, SnapshotKind::MemoryBorrowed);
        assert!(out.verified_archive().is_some());
        let ir = out.archive_ir().expect("admitted inspect has IR");
        assert_eq!(ir.schema, crate::ir::ARCHIVE_IR_SCHEMA);
        assert_eq!(ir.profile, crate::ir::ZIP_STRICT_ASCII_V1);
        assert_eq!(out.cli_exit_code(), 0);
        assert_eq!(out.view.admission, AdmissionStatus::Admitted);
        assert_eq!(out.view.effect, EffectStatus::NotRequested);
        assert_eq!(ir.covering.local_records.offset, 0);
        assert_eq!(
            ir.covering.local_records.len,
            ir.covering.central_directory.offset
        );
        assert_eq!(ir.covering.central_directory.end(), ir.covering.eocd.offset);
        assert_eq!(ir.covering.eocd.len, 22);
        assert_eq!(ir.members.len(), 1);
        assert_eq!(ir.members[0].canonical_path, "nested/hello.txt");
        assert_eq!(ir.members[0].raw_name_bytes, b"nested/hello.txt");
        assert_eq!(ir.members[0].kind, MemberKind::File);
        assert_eq!(
            ir.members[0].verification,
            crate::ir::MemberVerification::Verified
        );
        assert_eq!(ir.profile_digest, crate::ir::zip_strict_ascii_v1_digest());
        assert_eq!(
            out.receipt.identities.interpretation.id,
            crate::ir::ZIP_STRICT_ASCII_V1
        );
        assert!(out.receipt.identities.layout.hex().is_some());
        assert!(out.receipt.identities.content.hex().is_some());
        assert_ne!(
            out.receipt.view_digest.sha256,
            out.receipt.identities.layout.hex().unwrap()
        );
        assert_eq!(out.receipt.policy.id, policy.id);
        assert_eq!(
            out.receipt.materialization.schema,
            "sealr.materialization.v2"
        );
        assert!(!out.receipt.materialization.requested);
        assert_eq!(out.receipt.materialization.backend, "none");
        assert_eq!(out.receipt.materialization.stage_creation_primitive, "none");
        assert_eq!(out.receipt.materialization.outcome, "not-requested");
        assert_eq!(out.receipt.materialization.cleanup, "not-applicable");
    }

    #[test]
    fn path_source_uses_an_owned_memory_snapshot() {
        let bytes = make_zip(&[("nested/hello.txt", b"hello")]);
        let dir = temp_dest("owned-snap");
        fs::create_dir_all(&dir).unwrap();
        let archive = dir.join("t.zip");
        fs::write(&archive, &bytes).unwrap();
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Path(&archive),
            policy: &policy,
            dest: None,
        });
        let digest = hex_sha256(&bytes);
        assert!(!out.rejected(), "{:?}", out.view.findings);
        assert_eq!(out.receipt.source_snapshot, SnapshotKind::MemoryOwned);
        assert_eq!(out.receipt.source.sha256(), Some(digest.as_str()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_bytes_after_the_single_deflate_stream() {
        let policy = Policy::default_v1();
        let control = make_zip(&[("payload.txt", b"payload")]);
        let control_out = apply(Request {
            source: Source::Bytes {
                path: Some("single-stream-control"),
                data: &control,
            },
            policy: &policy,
            dest: None,
        });
        assert!(!control_out.rejected(), "{:?}", control_out.view.findings);

        for (label, suffix) in [
            ("trailing-data", [0xde, 0xad, 0xbe, 0xef].as_slice()),
            ("concatenated-stream", [0x03, 0x00].as_slice()),
        ] {
            let mut bytes = make_zip(&[("payload.txt", b"payload")]);
            extend_declared_deflate_payload(&mut bytes, suffix);
            let out = apply(Request {
                source: Source::Bytes {
                    path: Some(label),
                    data: &bytes,
                },
                policy: &policy,
                dest: None,
            });

            assert!(out.rejected(), "{label} was accepted: {:?}", out.view);
            assert!(out
                .view
                .findings
                .iter()
                .any(|finding| finding.code == FindingCode::CodecDeflateTrailingInput));
        }
    }

    #[test]
    fn classifies_invalid_deflate_syntax_separately_from_crc_failure() {
        let member = ZipMember {
            raw_name: b"invalid.txt".to_vec(),
            name: "invalid.txt".to_owned(),
            method: 8,
            flags: 0,
            crc: 0,
            comp_size: 1,
            uncomp_size: 0,
            lfh_offset: 0,
            data_offset: 0,
            record_end: 1,
            is_dir: false,
            extra_fields: Vec::new(),
            source_ranges: crate::ir::MemberSourceRanges {
                local_header: crate::ir::ByteRange { offset: 0, len: 0 },
                compressed_payload: crate::ir::ByteRange { offset: 0, len: 1 },
                data_descriptor: None,
                central_header: crate::ir::ByteRange { offset: 0, len: 0 },
            },
        };
        let mut sink = io::sink();
        let budget = Policy::default_v1().compile().unwrap().budget;
        let finding = process_member(&[0xff], &member, budget, u64::MAX, &mut sink).unwrap_err();

        assert_eq!(finding.code, FindingCode::CodecDeflateInvalidStream);
    }

    #[test]
    fn materialize_writes_and_matches_inspect_tree() {
        let bytes = make_zip(&[("nested/hello.txt", b"hello")]);
        let policy = Policy::default_v1();
        let inspect = apply(Request {
            source: Source::Bytes {
                path: Some("t.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });
        let dir = temp_dest("mat");
        let _ = fs::remove_dir_all(&dir);
        let mat = apply(Request {
            source: Source::Bytes {
                path: Some("t.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dir),
        });
        assert!(mat.wrote(), "{:?}", mat.view.findings);
        let extracted = dir.join("nested").join("hello.txt");
        assert_eq!(fs::read(&extracted).unwrap(), b"hello");
        let i: Vec<_> = inspect
            .view
            .members
            .iter()
            .map(|m| (&m.path, &m.sha256))
            .collect();
        let m: Vec<_> = mat
            .view
            .members
            .iter()
            .map(|m| (&m.path, &m.sha256))
            .collect();
        assert_eq!(i, m, "inspect and materialize must agree on the tree");
        assert_eq!(
            mat.receipt.materialization.backend,
            "cap-std-component-nofollow-v1"
        );
        assert!(mat.receipt.materialization.requested);
        assert_ne!(mat.receipt.materialization.stage_creation_primitive, "none");
        assert_eq!(
            mat.receipt.materialization.member_resolution,
            "component-handles-nofollow"
        );
        assert_eq!(mat.receipt.materialization.outcome, "committed");
        assert_eq!(
            mat.receipt.materialization.cleanup,
            "not-applicable-after-commit"
        );
        assert_eq!(inspect.interpretation, InterpretationStatus::Interpreted);
        assert_eq!(inspect.admission, AdmissionStatus::Admitted);
        assert_eq!(inspect.effect, EffectStatus::NotRequested);
        assert_eq!(mat.interpretation, InterpretationStatus::Interpreted);
        assert_eq!(mat.admission, AdmissionStatus::Admitted);
        assert_eq!(mat.verification, VerificationStatus::Complete);
        assert_eq!(mat.effect, EffectStatus::Committed);
        assert!(matches!(mat.verdict, Verdict::Allowed { wrote: true }));
        let inspect_ir = inspect.archive_ir().expect("inspect IR");
        let mat_ir = mat.archive_ir().expect("materialize IR");
        assert_eq!(inspect_ir.schema, mat_ir.schema);
        assert_eq!(inspect_ir.profile, mat_ir.profile);
        assert_eq!(inspect_ir.source_digest, mat_ir.source_digest);
        let inspect_ids: Vec<_> = inspect_ir
            .members
            .iter()
            .map(|member| {
                (
                    &member.canonical_path,
                    &member.raw_name_bytes,
                    &member.content_sha256,
                    member.source_ranges.compressed_payload.offset,
                )
            })
            .collect();
        let mat_ids: Vec<_> = mat_ir
            .members
            .iter()
            .map(|member| {
                (
                    &member.canonical_path,
                    &member.raw_name_bytes,
                    &member.content_sha256,
                    member.source_ranges.compressed_payload.offset,
                )
            })
            .collect();
        assert_eq!(
            inspect_ids, mat_ids,
            "inspect and materialize must share one IR"
        );
        assert_eq!(
            inspect.receipt.identities.layout.hex(),
            mat.receipt.identities.layout.hex(),
            "inspect and materialize must share the layout root"
        );
        assert_eq!(
            inspect.receipt.identities.content.hex(),
            mat.receipt.identities.content.hex(),
            "inspect and materialize must share the content-tree root"
        );
        assert_ne!(
            inspect.receipt.view_digest.sha256, mat.receipt.view_digest.sha256,
            "view_digest is invocation evidence and must differ when wrote differs"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_path_traversal_and_writes_nothing() {
        let bytes = make_zip(&[("../outside.txt", b"nope")]);
        let policy = Policy::default_v1();
        let dir = temp_dest("trav");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("bad.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dir),
        });
        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|f| f.code == FindingCode::PathDotDot));
        assert!(out.receipt.source.is_available());
        assert_eq!(out.interpretation, InterpretationStatus::Interpreted);
        assert_eq!(out.admission, AdmissionStatus::Denied);
        assert_eq!(out.effect, EffectStatus::NotRequested);
        assert!(
            out.archive_ir().is_none(),
            "denied archives must not publish an admitted IR"
        );
        assert!(
            out.verified_archive().is_none(),
            "denied archives must not expose verified authority"
        );
        assert!(
            out.receipt.identities.layout.hex().is_none(),
            "denied archives have no layout root"
        );
        assert!(out.receipt.identities.content.hex().is_none());
        assert!(!dir.join("outside.txt").exists());
        let parent = dir.parent().unwrap();
        assert!(!parent.join("outside.txt").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_colon_ads() {
        let bytes = make_zip(&[("safe.txt:hidden", b"x")]);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("ads.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });
        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|f| f.code == FindingCode::PathAds));
    }

    #[test]
    fn encryption_related_flags_cannot_bypass_the_deny_policy() {
        for (label, flag) in [
            ("traditional", 1 << 0),
            ("strong", 1 << 6),
            ("masked-header", 1 << 13),
        ] {
            let mut bytes = make_zip(&[("secret.txt", b"plaintext")]);
            add_matching_flags(&mut bytes, flag);
            let policy = Policy::default_v1();
            let out = apply(Request {
                source: Source::Bytes {
                    path: Some("encrypted-indicator.zip"),
                    data: &bytes,
                },
                policy: &policy,
                dest: None,
            });

            assert!(out.rejected(), "{label} flag was admitted");
            assert!(
                out.view
                    .findings
                    .iter()
                    .any(|finding| finding.code == FindingCode::ZipEncrypted),
                "{label} flag findings: {:?}",
                out.view.findings
            );
        }
    }

    #[test]
    fn rejects_lfh_cdh_name_mismatch() {
        let mut bytes = make_zip(&[("aaaa.txt", b"hello")]);
        let needle = b"aaaa.txt";
        let mut hits = Vec::new();
        for i in 0..bytes.len().saturating_sub(needle.len()) {
            if &bytes[i..i + needle.len()] == needle {
                hits.push(i);
            }
        }
        assert!(hits.len() >= 2, "expected LFH and CDH names");
        bytes[hits[0]] = b'b';
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("diff.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });
        assert!(out.rejected());
        assert!(
            out.view
                .findings
                .iter()
                .any(|f| f.code == FindingCode::ZipDiffA3Name),
            "{:?}",
            out.view.findings
        );
    }

    #[test]
    fn receipt_always_present_on_garbage() {
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("nope.bin"),
                data: b"not a zip",
            },
            policy: &policy,
            dest: None,
        });
        assert!(out.rejected());
        assert!(out.receipt.source.is_available());
        assert_eq!(out.interpretation, InterpretationStatus::Unsupported);
        assert_eq!(out.admission, AdmissionStatus::NotEvaluated);
        assert_eq!(out.view.verdict, "rejected");
    }

    #[test]
    fn rejects_existing_destination_without_changing_it() {
        let bytes = make_zip(&[("new.txt", b"new")]);
        let policy = Policy::default_v1();
        let dir = temp_dest("existing");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("keep.txt"), b"keep").unwrap();

        let out = apply(Request {
            source: Source::Bytes {
                path: Some("existing.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dir),
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::MaterializeExists));
        assert_eq!(fs::read(dir.join("keep.txt")).unwrap(), b"keep");
        assert!(!dir.join("new.txt").exists());
        assert_eq!(out.receipt.materialization.outcome, "setup-failed");
        assert_eq!(out.receipt.materialization.cleanup, "not-created");
        assert_eq!(out.interpretation, InterpretationStatus::Interpreted);
        assert_eq!(out.admission, AdmissionStatus::Admitted);
        assert_eq!(out.verification, VerificationStatus::StructureOnly);
        assert_eq!(out.effect, EffectStatus::Failed);
        assert!(matches!(out.verdict, Verdict::Rejected));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_a_missing_destination_parent_without_creating_it() {
        let bytes = make_zip(&[("approved.txt", b"approved")]);
        let policy = Policy::default_v1();
        let parent = temp_dest("missing-parent");
        let dir = parent.join("output");

        let out = apply(Request {
            source: Source::Bytes {
                path: Some("missing-parent.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dir),
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::MaterializeIo));
        assert!(!parent.exists());
        assert_eq!(out.receipt.materialization.outcome, "setup-failed");
        assert_eq!(out.receipt.materialization.cleanup, "not-created");
        assert_eq!(out.cli_exit_code(), 3);
        assert_eq!(out.view.admission, AdmissionStatus::Admitted);
        assert_eq!(out.view.effect, EffectStatus::Failed);
        assert!(out.archive_ir().is_some());
        assert!(
            out.verified_archive().is_none(),
            "setup failure happens before member verification"
        );
        assert!(
            out.receipt.identities.layout.hex().is_some(),
            "an admitted archive keeps its layout root when the destination fails"
        );
        assert!(
            out.receipt.identities.content.hex().is_none(),
            "content-tree identity requires complete verification"
        );
    }

    #[test]
    fn late_crc_rejection_never_publishes_the_staged_tree() {
        let bytes = make_crc_mismatch_zip();
        let policy = Policy::default_v1();
        let dir = temp_dest("crc");
        let _ = fs::remove_dir_all(&dir);

        let out = apply(Request {
            source: Source::Bytes {
                path: Some("crc.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dir),
        });

        assert!(out.rejected(), "{:?}", out.view.findings);
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::CrcMismatch));
        assert!(!dir.exists(), "rejected output must not become visible");
        assert_eq!(out.receipt.materialization.outcome, "aborted");
        assert_eq!(out.receipt.materialization.cleanup, "removed");
        assert!(
            out.verified_archive().is_none(),
            "failed content verification must not expose authority"
        );
    }

    #[test]
    fn cleanup_retry_finishes_before_receipt_construction() {
        let bytes = make_crc_mismatch_zip();
        let policy = Policy::default_v1();
        let parent = temp_dest("cleanup-retry-parent");
        fs::create_dir(&parent).unwrap();
        let dir = parent.join("output");
        let _guard = crate::materialize::inject_cleanup_failures_for_current_thread(1);

        let out = apply(Request {
            source: Source::Bytes {
                path: Some("cleanup-retry.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dir),
        });

        assert!(out.rejected());
        assert_eq!(out.receipt.materialization.outcome, "aborted");
        assert_eq!(out.receipt.materialization.cleanup, "removed");
        assert_eq!(
            out.view
                .findings
                .iter()
                .filter(|finding| finding.code == FindingCode::MaterializeCleanup)
                .count(),
            1
        );
        assert!(fs::read_dir(&parent).unwrap().next().is_none());
        fs::remove_dir(parent).unwrap();
    }

    #[test]
    fn final_cleanup_failure_receipt_matches_remaining_stage() {
        let bytes = make_crc_mismatch_zip();
        let policy = Policy::default_v1();
        let parent = temp_dest("cleanup-failure-parent");
        fs::create_dir(&parent).unwrap();
        let dir = parent.join("output");
        let _guard = crate::materialize::inject_cleanup_failures_for_current_thread(2);

        let out = apply(Request {
            source: Source::Bytes {
                path: Some("cleanup-failure.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dir),
        });

        assert!(out.rejected());
        assert_eq!(out.receipt.materialization.outcome, "aborted");
        assert_eq!(out.receipt.materialization.cleanup, "failed");
        assert_eq!(
            out.view
                .findings
                .iter()
                .filter(|finding| finding.code == FindingCode::MaterializeCleanup)
                .count(),
            2
        );
        let entries = fs::read_dir(&parent)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].to_string_lossy().starts_with(".sealr-stage-"));
        assert!(!dir.exists());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn rejects_file_directory_topology_conflicts_in_either_order() {
        let policy = Policy::default_v1();
        for files in [
            [("a", b"file".as_slice()), ("a/b", b"child".as_slice())],
            [("a/b", b"child".as_slice()), ("a", b"file".as_slice())],
        ] {
            let bytes = make_zip(&files);
            let out = apply(Request {
                source: Source::Bytes {
                    path: Some("conflict.zip"),
                    data: &bytes,
                },
                policy: &policy,
                dest: None,
            });
            assert!(out.rejected());
            assert!(out
                .view
                .findings
                .iter()
                .any(|finding| finding.code == FindingCode::PathConflict));
        }
    }

    #[test]
    fn materializes_standard_directory_entries() {
        let bytes = make_zip_with_directory();
        let policy = Policy::default_v1();
        let dir = temp_dest("directory");
        let _ = fs::remove_dir_all(&dir);

        let out = apply(Request {
            source: Source::Bytes {
                path: Some("directory.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dir),
        });

        assert!(out.wrote(), "{:?}", out.view.findings);
        assert!(dir.join("empty").is_dir());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_ambiguous_non_ascii_name_bytes() {
        let mut bytes = make_zip(&[("name.txt", b"data")]);
        let offsets: Vec<_> = bytes
            .windows(b"name.txt".len())
            .enumerate()
            .filter_map(|(index, window)| (window == b"name.txt").then_some(index))
            .collect();
        assert_eq!(offsets.len(), 2);
        for offset in offsets {
            bytes[offset] = 0xff;
        }
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("encoding.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipEncoding));
    }

    #[test]
    fn rejects_archive_over_input_cap_before_parsing() {
        let bytes = make_zip(&[("small.txt", b"small")]);
        let mut policy = Policy::default_v1();
        policy.max_archive_bytes = 8;
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("too-large.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::QuotaArchive));
        assert_eq!(out.receipt.policy.id, policy.id);
        let digest = hex_sha256(&bytes);
        assert_eq!(out.receipt.source.sha256(), Some(digest.as_str()));
        assert_eq!(out.interpretation, InterpretationStatus::Indeterminate);
        assert_eq!(out.admission, AdmissionStatus::Denied);
        assert_eq!(out.receipt.source_snapshot, SnapshotKind::MemoryBorrowed);
    }

    #[test]
    fn missing_source_path_marks_digest_unavailable() {
        let policy = Policy::default_v1();
        let missing = temp_dest("missing-source").join("nope.zip");
        let out = apply(Request {
            source: Source::Path(&missing),
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(!out.receipt.source.is_available());
        assert_eq!(out.receipt.source.sha256(), None);
        assert_eq!(out.interpretation, InterpretationStatus::Indeterminate);
        assert_eq!(out.admission, AdmissionStatus::NotEvaluated);
        assert_eq!(out.effect, EffectStatus::NotRequested);
        assert_eq!(out.receipt.source_snapshot, SnapshotKind::Unavailable);
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::SourceIo));
        let json = serde_json::to_value(&out.receipt.source).unwrap();
        assert_eq!(json, serde_json::json!({"status": "unavailable"}));
        assert_ne!(json, serde_json::json!({"sha256": "00".repeat(32)}));
    }

    #[test]
    fn accepts_a_matching_data_descriptor_as_part_of_the_single_layout() {
        let mut bytes = make_zip(&[("descriptor.txt", b"descriptor")]);
        let local = signature_offsets(&bytes, [0x50, 0x4b, 0x03, 0x04])[0];
        let central = signature_offsets(&bytes, [0x50, 0x4b, 0x01, 0x02])[0];
        let crc = u32_at(&bytes, central + 16);
        let comp = u32_at(&bytes, central + 20);
        let uncomp = u32_at(&bytes, central + 24);
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&[0x50, 0x4b, 0x07, 0x08]);
        descriptor.extend_from_slice(&crc.to_le_bytes());
        descriptor.extend_from_slice(&comp.to_le_bytes());
        descriptor.extend_from_slice(&uncomp.to_le_bytes());
        bytes.splice(central..central, descriptor);

        let shifted_central = central + 16;
        let eocd = signature_offsets(&bytes, [0x50, 0x4b, 0x05, 0x06])[0];
        let local_flags = u16_at(&bytes, local + 6) | 0x8;
        let central_flags = u16_at(&bytes, shifted_central + 8) | 0x8;
        put_u16(&mut bytes, local + 6, local_flags);
        put_u16(&mut bytes, shifted_central + 8, central_flags);
        put_u32(&mut bytes, eocd + 16, shifted_central as u32);

        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("descriptor.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(!out.rejected(), "{:?}", out.view.findings);
        assert_eq!(out.view.members[0].uncomp_bytes, 10);
    }

    #[test]
    fn rejects_alternate_unicode_path_extra_fields() {
        let mut bytes = make_zip(&[("original.txt", b"content")]);
        add_matching_extra_fields(&mut bytes, &[0x75, 0x70, 0x01, 0x00, 0x01]);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("unicode-extra.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipDiffA3Name));
    }

    #[test]
    fn rejects_malformed_extra_field_sequences() {
        let mut bytes = make_zip(&[("extra.txt", b"content")]);
        add_matching_extra_fields(&mut bytes, &[0x37, 0x13, 0x02, 0x00, 0x00]);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("malformed-extra.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipExtra));
    }

    #[test]
    fn records_ignored_extra_fields_in_the_ir() {
        let mut bytes = make_zip(&[("extra.txt", b"content")]);
        // Info-ZIP Unix extra field 0x7855 with an empty payload.
        add_matching_extra_fields(&mut bytes, &[0x55, 0x78, 0x00, 0x00]);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("unix-extra.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });
        assert!(!out.rejected(), "{:?}", out.view.findings);
        let ir = out.archive_ir().expect("admitted IR");
        assert!(ir.members[0].extra_fields.iter().any(|extra| {
            extra.id == 0x7855 && extra.disposition == crate::ir::ExtraDisposition::Ignored
        }));
        assert!(ir.members[0]
            .extra_fields
            .iter()
            .any(|extra| extra.site == crate::ir::ExtraSite::Local));
        assert!(ir.members[0]
            .extra_fields
            .iter()
            .any(|extra| extra.site == crate::ir::ExtraSite::Central));
    }

    #[test]
    fn ignored_extras_change_layout_identity_not_content_identity() {
        let base = make_zip(&[("extra.txt", b"content")]);
        let mut with_extra = base.clone();
        add_matching_extra_fields(&mut with_extra, &[0x55, 0x78, 0x00, 0x00]);
        let policy = Policy::default_v1();
        let inspect = |data: &[u8]| {
            apply(Request {
                source: Source::Bytes {
                    path: Some("extra.zip"),
                    data,
                },
                policy: &policy,
                dest: None,
            })
        };
        let without = inspect(&base);
        let with = inspect(&with_extra);
        assert!(!without.rejected(), "{:?}", without.view.findings);
        assert!(!with.rejected(), "{:?}", with.view.findings);
        assert_eq!(
            without.receipt.identities.content.hex(),
            with.receipt.identities.content.hex()
        );
        assert_ne!(
            without.receipt.identities.layout.hex(),
            with.receipt.identities.layout.hex()
        );
        assert_ne!(
            without.receipt.source.sha256(),
            with.receipt.source.sha256()
        );
    }

    #[test]
    fn unsupported_policy_fails_before_source_ingest() {
        let mut policy = Policy::default_v1();
        policy.encrypted = "allow";
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("x.zip"),
                data: b"not-a-zip",
            },
            policy: &policy,
            dest: None,
        });
        assert!(out.rejected());
        assert_eq!(out.interpretation, InterpretationStatus::Indeterminate);
        assert_eq!(out.admission, AdmissionStatus::Denied);
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::PolicyUnsupported));
        assert_eq!(out.receipt.source_snapshot, SnapshotKind::Unavailable);
        assert!(out.receipt.source.sha256().is_none());
        assert!(out.receipt.identities.layout.hex().is_none());
        assert_eq!(
            out.receipt.identities.interpretation.id,
            crate::ir::ZIP_STRICT_ASCII_V1
        );
        assert_eq!(
            out.receipt.identities.interpretation.digest.sha256.len(),
            64
        );
    }

    #[test]
    fn directory_members_record_trailing_slash_normalization() {
        let bytes = make_zip_with_directory();
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("dir.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });
        assert!(!out.rejected(), "{:?}", out.view.findings);
        let ir = out.archive_ir().expect("admitted IR");
        let directory = ir
            .members
            .iter()
            .find(|member| member.kind == MemberKind::Directory)
            .expect("directory member");
        assert!(directory
            .normalization_actions
            .iter()
            .any(|action| { matches!(action, NormalizationAction::StripDirectoryTrailingSlash) }));
        assert!(!directory.canonical_path.ends_with('/'));
    }

    #[test]
    fn rejects_external_directory_attribute_on_a_file() {
        let mut bytes = make_zip(&[("file.txt", b"content")]);
        let central = signature_offsets(&bytes, [0x50, 0x4b, 0x01, 0x02])[0];
        put_u32(&mut bytes, central + 38, 0x10);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("fake-directory.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipDiffA4Dir));
    }

    #[test]
    fn rejects_non_stored_directory_entries() {
        let mut bytes = make_zip_with_directory();
        let local = signature_offsets(&bytes, [0x50, 0x4b, 0x03, 0x04])[0];
        let central = signature_offsets(&bytes, [0x50, 0x4b, 0x01, 0x02])[0];
        put_u16(&mut bytes, local + 8, 8);
        put_u16(&mut bytes, central + 10, 8);

        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("deflated-directory.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipDiffA4Dir));
    }

    #[test]
    fn rejects_directory_entries_with_nonzero_crc() {
        let mut bytes = make_zip_with_directory();
        let local = signature_offsets(&bytes, [0x50, 0x4b, 0x03, 0x04])[0];
        let central = signature_offsets(&bytes, [0x50, 0x4b, 0x01, 0x02])[0];
        put_u32(&mut bytes, local + 14, 1);
        put_u32(&mut bytes, central + 16, 1);

        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("bad-directory-crc.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipDiffA4Dir));
    }

    #[test]
    fn rejects_hidden_zip64_records_in_central_comments() {
        let mut bytes = make_zip(&[("file.txt", b"content")]);
        add_central_comment(&mut bytes, &[0x50, 0x4b, 0x06, 0x06]);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("hidden-zip64.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipDiffC5Zip64));
    }

    #[test]
    fn rejects_stored_descriptor_payload_with_hidden_records() {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            writer.start_file("records.bin", options).unwrap();
            writer.write_all(&[0x50, 0x4b, 0x03, 0x04]).unwrap();
            writer.finish().unwrap();
        }
        let mut bytes = cursor.into_inner();
        let local = signature_offsets(&bytes, [0x50, 0x4b, 0x03, 0x04])[0];
        let central = signature_offsets(&bytes, [0x50, 0x4b, 0x01, 0x02])[0];
        let crc = u32_at(&bytes, central + 16);
        let comp = u32_at(&bytes, central + 20);
        let uncomp = u32_at(&bytes, central + 24);
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&[0x50, 0x4b, 0x07, 0x08]);
        descriptor.extend_from_slice(&crc.to_le_bytes());
        descriptor.extend_from_slice(&comp.to_le_bytes());
        descriptor.extend_from_slice(&uncomp.to_le_bytes());
        bytes.splice(central..central, descriptor);

        let shifted_central = central + 16;
        let eocd = signature_offsets(&bytes, [0x50, 0x4b, 0x05, 0x06])[0];
        let local_flags = u16_at(&bytes, local + 6) | 0x8;
        let central_flags = u16_at(&bytes, shifted_central + 8) | 0x8;
        put_u16(&mut bytes, local + 6, local_flags);
        put_u16(&mut bytes, shifted_central + 8, central_flags);
        put_u32(&mut bytes, eocd + 16, shifted_central as u32);

        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("descriptor-record.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipDiffC1Stream));
    }

    #[test]
    fn rejects_unreferenced_bytes_between_local_records_and_cd() {
        let mut bytes = make_zip(&[("gap.txt", b"gap")]);
        let central = signature_offsets(&bytes, [0x50, 0x4b, 0x01, 0x02])[0];
        bytes.insert(central, 0);
        let shifted_central = central + 1;
        let eocd = signature_offsets(&bytes, [0x50, 0x4b, 0x05, 0x06])[0];
        put_u32(&mut bytes, eocd + 16, shifted_central as u32);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("gap.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipDiffC1Stream));
    }

    #[test]
    fn malformed_and_mutated_inputs_never_panic() {
        fn assert_no_panic(bytes: &[u8], label: &str) {
            let policy = Policy::default_v1();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                apply(Request {
                    source: Source::Bytes {
                        path: None,
                        data: bytes,
                    },
                    policy: &policy,
                    dest: None,
                })
            }));
            assert!(result.is_ok(), "apply panicked for {label}");
        }

        let valid = make_zip(&[("nested/payload.txt", b"payload")]);
        for cutoff in 0..=valid.len() {
            assert_no_panic(&valid[..cutoff], &format!("valid prefix {cutoff}"));
        }

        for index in 0..valid.len() {
            for mask in [0x01, 0x80, 0xff] {
                let mut mutated = valid.clone();
                mutated[index] ^= mask;
                assert_no_panic(&mutated, &format!("mutation {index} xor {mask:02x}"));
            }
        }

        let mut state = 0x243f_6a88_85a3_08d3_u64;
        for len in 0..=1024 {
            let mut bytes = vec![0_u8; len];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            assert_no_panic(&bytes, &format!("deterministic noise length {len}"));
        }
    }

    #[test]
    fn intra_call_directory_component_replacement_never_publishes() {
        let bytes = make_zip(&[("tree/leaf.txt", b"leaf")]);
        let policy = Policy::default_v1();
        let dest = temp_dest("apply-intra-call");
        let outside = temp_dest("apply-intra-call-outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel.txt"), b"outside").unwrap();
        let _guard =
            crate::materialize::inject_directory_component_replacement("tree", outside.clone());

        let out = apply(Request {
            source: Source::Bytes {
                path: Some("intra.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dest),
        });

        assert!(out.rejected(), "{:?}", out.view.findings);
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::MaterializeUnsafeComponent));
        assert!(!dest.exists());
        assert!(!outside.join("leaf.txt").exists());
        assert_eq!(fs::read(outside.join("sentinel.txt")).unwrap(), b"outside");
        assert_eq!(out.cli_exit_code(), 3);
        assert_eq!(out.admission, AdmissionStatus::Admitted);
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn mutated_staged_content_never_publishes() {
        let bytes = make_zip(&[("hello.txt", b"hello")]);
        let policy = Policy::default_v1();
        let dest = temp_dest("apply-stage-mutate");
        let _guard =
            crate::materialize::inject_staged_content_overwrite("hello.txt", b"mutated".to_vec());

        let out = apply(Request {
            source: Source::Bytes {
                path: Some("mutate.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dest),
        });

        assert!(out.rejected(), "{:?}", out.view.findings);
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::MaterializeAudit));
        assert!(!dest.exists());
        assert_eq!(out.receipt.materialization.outcome, "aborted");
        assert_eq!(out.receipt.materialization.cleanup, "removed");
        assert_eq!(out.cli_exit_code(), 3);
        assert_eq!(out.admission, AdmissionStatus::Admitted);
        assert_eq!(out.verification, VerificationStatus::Complete);
        assert_eq!(out.effect, EffectStatus::Failed);
        assert!(
            out.receipt.identities.content.hex().is_some(),
            "members were verified; publication failed on the staged-tree audit"
        );
        assert_eq!(
            out.verified_archive()
                .expect("effect failure preserves verified authority")
                .read_member("hello.txt", 5)
                .unwrap(),
            b"hello"
        );
    }

    #[test]
    fn extra_staged_file_never_publishes() {
        let bytes = make_zip(&[("hello.txt", b"hello")]);
        let policy = Policy::default_v1();
        let dest = temp_dest("apply-stage-extra");
        let _guard = crate::materialize::inject_staged_extra_file("extra.txt", b"nope".to_vec());

        let out = apply(Request {
            source: Source::Bytes {
                path: Some("extra.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dest),
        });

        assert!(out.rejected(), "{:?}", out.view.findings);
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::MaterializeAudit));
        assert!(!dest.exists());
        assert_eq!(out.cli_exit_code(), 3);
        assert_eq!(out.effect, EffectStatus::Failed);
    }
}
