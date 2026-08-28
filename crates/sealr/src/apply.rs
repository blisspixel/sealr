use std::collections::BTreeMap;
use std::io::{self, BufReader, Read};
use std::path::Path;

#[cfg(test)]
use std::fs;

use crate::covering::{
    audit_covering, audit_gzip_wrapper_covering, audit_tar_covering, audit_tar_pax_covering,
    audit_zip64_covering,
};
use crate::findings::{Finding, FindingCode, Severity};
use crate::identity::OutcomeIdentities;
use crate::ir::{
    ArchiveFormat, ArchiveIR, GzipWrapperEvidence, IrMember, MemberKind, MemberVerification,
    NormalizationAction, PaxExtensionEvidence, PaxRecordEvidence, TarArchiveCovering,
    TarGzipInterpretationProfile, TarInterpretationProfile, TarPaxInterpretationProfile,
    ZipInterpretationProfile,
};
use crate::jail::{jail_name_for_profile, portable_name_violation, profile_case_fold};
use crate::materialize::{process_member_to_file, CapabilityMaterializer, MaterializationMeta};
use crate::outcome::{
    AdmissionStatus, DigestHex, EffectStatus, InterpretationStatus, SemanticAxes, SourceDigest,
    StoppingPhase, VerificationStatus, ViewCompleteness,
};
use crate::policy::{
    hex_sha256, ratio_exceeds, CompiledControls, Policy, ResourceBudget,
    POLICY_FORMAT_TAR_GZIP_USTAR, POLICY_FORMAT_TAR_PAX, POLICY_FORMAT_TAR_USTAR,
};
use crate::quota::{QuotaError, QuotaState};
use crate::snapshot::{
    DomainRange, SnapshotDomainId, SnapshotKind, SnapshotSet, SourceSnapshot, TransformGraph,
    TransformProfile,
};
use crate::tar;
use crate::tar_pax;
use crate::verification::{digest_hex, planned_payload_reader, verify_payload, PayloadPlan};
use crate::verified::{RetentionBuild, RetentionPlan, VerifiedArchive};
use crate::zip::{self, ZipMember};
use crate::{gzip, gzip::GzipErrorKind};
use crc32fast::Hasher as Crc;
use serde::Serialize;

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

/// Optional capabilities requested for one archive operation.
///
/// The selected interpretation profile participates in archive admission and
/// interpretation identity, but remains separate from resource-policy
/// identity. A retention request is independently bounded and reports its
/// result through the resulting [`VerifiedArchive`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveSelection {
    Zip(ZipInterpretationProfile),
    TarUstar(TarInterpretationProfile),
    TarGzipUstar(TarGzipInterpretationProfile),
    TarPax(TarPaxInterpretationProfile),
}

impl Default for ArchiveSelection {
    fn default() -> Self {
        Self::Zip(ZipInterpretationProfile::StrictAsciiV1)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ApplyOptions {
    retention: Option<RetentionPlan>,
    selection: ArchiveSelection,
}

impl ApplyOptions {
    /// Create options that request no additional capabilities.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request the supplied bounded retention plan.
    pub fn with_retention(mut self, plan: RetentionPlan) -> Self {
        self.retention = Some(plan);
        self
    }

    /// Select the exact ZIP interpretation used by this operation.
    ///
    /// The default preserves the Alpha.3 `strict-ascii.v1` compatibility
    /// language. Select `StrictAsciiV2` for the closed Alpha.4 flag and
    /// extra-field contract.
    pub fn with_interpretation_profile(mut self, profile: ZipInterpretationProfile) -> Self {
        self.selection = ArchiveSelection::Zip(profile);
        self
    }

    /// Select an exact TAR interpretation for this operation.
    ///
    /// Selecting a TAR profile is explicit. Sealr does not guess between ZIP,
    /// TAR, and future containers from a filename or a recoverable parse.
    pub fn with_tar_interpretation_profile(mut self, profile: TarInterpretationProfile) -> Self {
        self.selection = ArchiveSelection::TarUstar(profile);
        self
    }

    /// Select strict single-member gzip-wrapped portable ustar explicitly.
    pub fn with_tar_gzip_interpretation_profile(
        mut self,
        profile: TarGzipInterpretationProfile,
    ) -> Self {
        self.selection = ArchiveSelection::TarGzipUstar(profile);
        self
    }

    /// Select the restricted raw POSIX PAX profile explicitly.
    pub fn with_tar_pax_interpretation_profile(
        mut self,
        profile: TarPaxInterpretationProfile,
    ) -> Self {
        self.selection = ArchiveSelection::TarPax(profile);
        self
    }

    /// Return the requested retention plan, when present.
    pub fn retention_plan(&self) -> Option<&RetentionPlan> {
        self.retention.as_ref()
    }

    /// Return the ZIP profile value for compatibility with ZIP-only callers.
    ///
    /// Multi-format callers should use [`ApplyOptions::archive_selection`] or
    /// [`ApplyOptions::zip_interpretation_profile`]. TAR selection returns the
    /// compatibility default here; it does not select or authorize ZIP.
    pub fn interpretation_profile(&self) -> ZipInterpretationProfile {
        self.zip_interpretation_profile()
            .unwrap_or(ZipInterpretationProfile::StrictAsciiV1)
    }

    /// Return the selected ZIP profile, or `None` when another format is selected.
    pub fn zip_interpretation_profile(&self) -> Option<ZipInterpretationProfile> {
        match self.selection {
            ArchiveSelection::Zip(profile) => Some(profile),
            ArchiveSelection::TarUstar(_)
            | ArchiveSelection::TarGzipUstar(_)
            | ArchiveSelection::TarPax(_) => None,
        }
    }

    /// Return the selected TAR interpretation, when the operation targets TAR.
    pub fn tar_interpretation_profile(&self) -> Option<TarInterpretationProfile> {
        match self.selection {
            ArchiveSelection::Zip(_) => None,
            ArchiveSelection::TarUstar(profile) => Some(profile),
            ArchiveSelection::TarGzipUstar(_) | ArchiveSelection::TarPax(_) => None,
        }
    }

    /// Return the selected gzip-wrapped TAR interpretation, when requested.
    pub fn tar_gzip_interpretation_profile(&self) -> Option<TarGzipInterpretationProfile> {
        match self.selection {
            ArchiveSelection::TarGzipUstar(profile) => Some(profile),
            ArchiveSelection::Zip(_)
            | ArchiveSelection::TarUstar(_)
            | ArchiveSelection::TarPax(_) => None,
        }
    }

    /// Return the selected restricted PAX interpretation, when requested.
    pub fn tar_pax_interpretation_profile(&self) -> Option<TarPaxInterpretationProfile> {
        match self.selection {
            ArchiveSelection::TarPax(profile) => Some(profile),
            ArchiveSelection::Zip(_)
            | ArchiveSelection::TarUstar(_)
            | ArchiveSelection::TarGzipUstar(_) => None,
        }
    }

    /// Return the explicit container and interpretation selection.
    pub fn archive_selection(&self) -> ArchiveSelection {
        self.selection
    }

    /// Return the container format selected for this operation.
    pub fn archive_format(&self) -> crate::ArchiveFormat {
        match self.selection {
            ArchiveSelection::Zip(profile) => profile.archive_format(),
            ArchiveSelection::TarUstar(_) => crate::ArchiveFormat::TarUstar,
            ArchiveSelection::TarGzipUstar(_) => crate::ArchiveFormat::TarGzipUstar,
            ArchiveSelection::TarPax(_) => crate::ArchiveFormat::TarPax,
        }
    }
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
    /// Effect-independent archive interpretation when planning produced a member list.
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

    /// Process exit class: 0 admitted and completely verified without effect failure,
    /// 2 not admitted or not completely verified, 3 admitted but effect failed.
    pub fn cli_exit_code(&self) -> u8 {
        compat_exit_code(&self.admission, &self.verification, &self.effect)
    }
}

pub fn apply(req: Request<'_>) -> Outcome {
    apply_with_options(req, &ApplyOptions::default())
}

/// Apply policy and optionally request independently bounded capabilities.
///
/// Default options have the same semantics as [`apply`]. Selecting another
/// archive selection changes the accepted container language and recorded
/// interpretation identity; retention alone does not change admission.
pub fn apply_with_options(req: Request<'_>, options: &ApplyOptions) -> Outcome {
    match options.selection {
        ArchiveSelection::TarUstar(profile) => {
            return apply_tar_with_options(&req, options, profile);
        }
        ArchiveSelection::TarGzipUstar(profile) => {
            return apply_tar_gzip_with_options(&req, options, profile);
        }
        ArchiveSelection::TarPax(profile) => {
            return apply_tar_pax_with_options(&req, options, profile);
        }
        ArchiveSelection::Zip(_) => {}
    }
    let ArchiveSelection::Zip(profile) = options.selection else {
        unreachable!("archive selection is closed over implemented variants")
    };
    let planning_context = match PlanningContext::compile(req.policy, profile) {
        Ok(context) => context,
        Err(finding) => {
            return reject_only(
                (None, SourceDigest::unavailable(), req.policy.clone()),
                vec![finding.clone()],
                None,
                MaterializationMeta::not_started(req.dest.is_some(), req.policy.atomic),
                SemanticAxes::policy_compile_failed(&finding),
                SnapshotKind::Unavailable,
                OutcomeIdentities::without_source_for(profile),
            );
        }
    };
    match apply_inner(&req, planning_context, options) {
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
                OutcomeIdentities::unavailable_for(digest, profile),
            )
        }
    }
}

fn apply_tar_with_options(
    req: &Request<'_>,
    options: &ApplyOptions,
    profile: TarInterpretationProfile,
) -> Outcome {
    let policy = req.policy;
    let initial_materialization =
        MaterializationMeta::not_started(req.dest.is_some(), policy.atomic);
    let controls = match policy.compile_for_format(POLICY_FORMAT_TAR_USTAR) {
        Ok(controls) => controls,
        Err(finding) => {
            return reject_only(
                (None, SourceDigest::unavailable(), policy.clone()),
                vec![finding.clone()],
                None,
                initial_materialization,
                SemanticAxes::policy_compile_failed(&finding),
                SnapshotKind::Unavailable,
                OutcomeIdentities::unavailable_for_tar(SourceDigest::unavailable(), profile),
            );
        }
    };
    let snapshot = match read_source(&req.source, controls.budget) {
        Ok(snapshot) => snapshot,
        Err(failure) => {
            let admission = if failure.finding.code == FindingCode::QuotaArchive {
                AdmissionStatus::Denied
            } else {
                AdmissionStatus::NotEvaluated
            };
            let digest = failure.digest.clone();
            return reject_only(
                (failure.path, failure.digest, policy.clone()),
                vec![failure.finding.clone()],
                None,
                initial_materialization,
                SemanticAxes::source_failure(&failure.finding, admission),
                failure.snapshot_kind,
                OutcomeIdentities::unavailable_for_tar(digest, profile),
            );
        }
    };
    let source_digest = snapshot.digest().clone();
    let identities_base = OutcomeIdentities::unavailable_for_tar(source_digest.clone(), profile);
    plan_tar_domains(
        req,
        options,
        SnapshotSet::from_original(snapshot),
        TransformGraph::empty(),
        SnapshotDomainId::ORIGINAL,
        TarPlanProfile::Raw(profile),
        controls,
        controls.budget.max_metadata_bytes,
        source_digest,
        identities_base,
        initial_materialization,
    )
}

fn apply_tar_pax_with_options(
    req: &Request<'_>,
    options: &ApplyOptions,
    profile: TarPaxInterpretationProfile,
) -> Outcome {
    let policy = req.policy;
    let initial_materialization =
        MaterializationMeta::not_started(req.dest.is_some(), policy.atomic);
    let controls = match policy.compile_for_format(POLICY_FORMAT_TAR_PAX) {
        Ok(controls) => controls,
        Err(finding) => {
            return reject_only(
                (None, SourceDigest::unavailable(), policy.clone()),
                vec![finding.clone()],
                None,
                initial_materialization,
                SemanticAxes::policy_compile_failed(&finding),
                SnapshotKind::Unavailable,
                OutcomeIdentities::unavailable_for_tar_pax(SourceDigest::unavailable(), profile),
            );
        }
    };
    let snapshot = match read_source(&req.source, controls.budget) {
        Ok(snapshot) => snapshot,
        Err(failure) => {
            let admission = if failure.finding.code == FindingCode::QuotaArchive {
                AdmissionStatus::Denied
            } else {
                AdmissionStatus::NotEvaluated
            };
            let digest = failure.digest.clone();
            return reject_only(
                (failure.path, failure.digest, policy.clone()),
                vec![failure.finding.clone()],
                None,
                initial_materialization,
                SemanticAxes::source_failure(&failure.finding, admission),
                failure.snapshot_kind,
                OutcomeIdentities::unavailable_for_tar_pax(digest, profile),
            );
        }
    };
    let source_digest = snapshot.digest().clone();
    let identities_base =
        OutcomeIdentities::unavailable_for_tar_pax(source_digest.clone(), profile);
    plan_tar_pax(
        req,
        options,
        SnapshotSet::from_original(snapshot),
        profile,
        controls,
        source_digest,
        identities_base,
        initial_materialization,
    )
}

fn apply_tar_gzip_with_options(
    req: &Request<'_>,
    options: &ApplyOptions,
    profile: TarGzipInterpretationProfile,
) -> Outcome {
    let policy = req.policy;
    let initial_materialization =
        MaterializationMeta::not_started(req.dest.is_some(), policy.atomic);
    let controls = match policy.compile_for_format(POLICY_FORMAT_TAR_GZIP_USTAR) {
        Ok(controls) => controls,
        Err(finding) => {
            return reject_only(
                (None, SourceDigest::unavailable(), policy.clone()),
                vec![finding.clone()],
                None,
                initial_materialization,
                SemanticAxes::policy_compile_failed(&finding),
                SnapshotKind::Unavailable,
                OutcomeIdentities::unavailable_for_tar_gzip(SourceDigest::unavailable(), profile),
            );
        }
    };
    let snapshot = match read_source(&req.source, controls.budget) {
        Ok(snapshot) => snapshot,
        Err(failure) => {
            let admission = if failure.finding.code == FindingCode::QuotaArchive {
                AdmissionStatus::Denied
            } else {
                AdmissionStatus::NotEvaluated
            };
            let digest = failure.digest.clone();
            return reject_only(
                (failure.path, failure.digest, policy.clone()),
                vec![failure.finding.clone()],
                None,
                initial_materialization,
                SemanticAxes::source_failure(&failure.finding, admission),
                failure.snapshot_kind,
                OutcomeIdentities::unavailable_for_tar_gzip(digest, profile),
            );
        }
    };
    let source_digest = snapshot.digest().clone();
    let identities_base =
        OutcomeIdentities::unavailable_for_tar_gzip(source_digest.clone(), profile);
    let mut snapshots = SnapshotSet::from_original(snapshot);
    let mut transforms = TransformGraph::empty();
    let transformed = match gzip::transform_single_member(
        &mut snapshots,
        &mut transforms,
        gzip::GzipLimits {
            max_metadata_bytes: controls.budget.max_metadata_bytes,
            max_output_bytes: controls.budget.max_derived_archive_bytes,
        },
    ) {
        Ok(transformed) => transformed,
        Err(error) => {
            let axes = gzip_failure_axes(&error);
            let finding = error.into_finding();
            let original = snapshots.original();
            let observed_magic = observed_gzip_magic(original);
            return finish(
                (original.path_owned(), source_digest, original.kind()),
                observed_magic,
                policy,
                vec![finding],
                Vec::new(),
                initial_materialization,
                axes,
                identities_base,
            );
        }
    };
    if transformed.output_domain != SnapshotDomainId::FIRST_DERIVED {
        let finding = Finding::error(
            FindingCode::CoveringInconsistent,
            "gzip transform did not produce the expected derived snapshot domain",
        );
        let original = snapshots.original();
        return finish(
            (original.path_owned(), source_digest, original.kind()),
            "gz",
            policy,
            vec![finding.clone()],
            Vec::new(),
            initial_materialization,
            SemanticAxes::structure_stop(
                InterpretationStatus::Indeterminate,
                AdmissionStatus::NotEvaluated,
                &finding,
            ),
            identities_base,
        );
    }
    if let Some(max_ratio) = controls.budget.max_ratio {
        if ratio_exceeds(
            transformed.output_len,
            transformed.compressed_payload.len,
            max_ratio,
        ) {
            let finding = Finding::error(
                FindingCode::QuotaRatio,
                format!(
                    "derived gzip output {}:{} exceeds {max_ratio}:1",
                    transformed.output_len, transformed.compressed_payload.len
                ),
            );
            let original = snapshots.original();
            return finish(
                (original.path_owned(), source_digest, original.kind()),
                "gz",
                policy,
                vec![finding.clone()],
                Vec::new(),
                initial_materialization,
                SemanticAxes::structure_stop(
                    InterpretationStatus::Interpreted,
                    AdmissionStatus::Denied,
                    &finding,
                ),
                identities_base,
            );
        }
    }
    let wrapper = GzipWrapperEvidence {
        flags: transformed.header.flags,
        modification_time: transformed.header.modification_time,
        extra_flags: transformed.header.extra_flags,
        operating_system: transformed.header.operating_system,
        header: transformed.header.header,
        extra: transformed.header.extra,
        extra_subfield_count: transformed.header.extra_subfield_count,
        original_name: transformed.header.original_name,
        comment: transformed.header.comment,
        header_crc16: transformed.header.header_crc16,
        compressed_payload: transformed.compressed_payload,
        trailer: transformed.trailer,
        declared_crc32: transformed.declared_crc32,
        declared_isize: transformed.declared_isize,
        derived_output_len: transformed.output_len,
        derived_output_sha256: transformed.output_sha256,
    };
    if let Err(finding) = audit_gzip_wrapper_covering(snapshots.original(), &wrapper) {
        let original = snapshots.original();
        return finish(
            (original.path_owned(), source_digest, original.kind()),
            "gz",
            policy,
            vec![finding.clone()],
            Vec::new(),
            initial_materialization,
            SemanticAxes::structure_stop(
                InterpretationStatus::Indeterminate,
                AdmissionStatus::NotEvaluated,
                &finding,
            ),
            identities_base,
        );
    }
    let wrapper_metadata = match wrapper.header.len.checked_add(wrapper.trailer.len) {
        Some(value) => value,
        None => {
            let finding = Finding::error(
                FindingCode::QuotaOverflow,
                "gzip wrapper metadata total overflowed u64",
            );
            let original = snapshots.original();
            return finish(
                (original.path_owned(), source_digest, original.kind()),
                "gz",
                policy,
                vec![finding.clone()],
                Vec::new(),
                initial_materialization,
                SemanticAxes::structure_stop(
                    InterpretationStatus::Interpreted,
                    AdmissionStatus::Denied,
                    &finding,
                ),
                identities_base,
            );
        }
    };
    let tar_metadata_budget = controls
        .budget
        .max_metadata_bytes
        .checked_sub(wrapper_metadata)
        .expect("gzip decoder already enforced the wrapper metadata cap");
    plan_tar_domains(
        req,
        options,
        snapshots,
        transforms,
        SnapshotDomainId::FIRST_DERIVED,
        TarPlanProfile::Gzip(profile, wrapper),
        controls,
        tar_metadata_budget,
        source_digest,
        identities_base,
        initial_materialization,
    )
}

enum TarPlanProfile {
    Raw(TarInterpretationProfile),
    Gzip(TarGzipInterpretationProfile, GzipWrapperEvidence),
}

#[allow(clippy::too_many_arguments)]
fn plan_tar_domains(
    req: &Request<'_>,
    options: &ApplyOptions,
    snapshots: SnapshotSet<'_>,
    transforms: TransformGraph,
    tar_domain: SnapshotDomainId,
    profile: TarPlanProfile,
    controls: CompiledControls,
    tar_metadata_budget: u64,
    source_digest: SourceDigest,
    identities_base: OutcomeIdentities,
    initial_materialization: MaterializationMeta,
) -> Outcome {
    let policy = req.policy;
    let magic = match &profile {
        TarPlanProfile::Raw(_) => "tar",
        TarPlanProfile::Gzip(_, _) => "gz",
    };
    let tar_snapshot = snapshots
        .domain(tar_domain)
        .expect("selected TAR domain exists before planning");
    let recognized_tar = tar::recognizes_ustar(tar_snapshot);
    let observed_magic = match &profile {
        TarPlanProfile::Gzip(_, _) => magic,
        TarPlanProfile::Raw(_) if recognized_tar => magic,
        TarPlanProfile::Raw(_) => "unknown",
    };
    let parsed = match tar::parse_ustar_portable_v1(
        tar_snapshot,
        controls.budget.max_files,
        tar_metadata_budget,
    ) {
        Ok(parsed) => parsed,
        Err(finding) => {
            let axes = parse_failure_axes(&finding);
            let original = snapshots.original();
            return finish(
                (original.path_owned(), source_digest, original.kind()),
                observed_magic,
                policy,
                vec![finding],
                Vec::new(),
                initial_materialization,
                axes,
                identities_base,
            );
        }
    };

    let budget = controls.budget;
    let covering = TarArchiveCovering {
        member_records: parsed.member_records,
        terminator: parsed.terminator,
        trailing_zeros: parsed.trailing_zeros,
    };
    let mut findings = Vec::new();
    let mut planned = Vec::new();
    let mut dest_seen: BTreeMap<String, bool> = BTreeMap::new();
    let mut fold_seen: BTreeMap<String, bool> = BTreeMap::new();
    let mut declared_total = QuotaState::new(budget.max_total_bytes);

    for member in parsed.members {
        if member.size > budget.max_member_bytes {
            findings.push(
                Finding::error(FindingCode::QuotaMember, "declared member too large")
                    .on(&member.name),
            );
            continue;
        }
        if let Some(max_ratio) = budget.max_ratio {
            if ratio_exceeds(member.size, member.size, max_ratio) {
                findings.push(
                    Finding::error(
                        FindingCode::QuotaRatio,
                        format!(
                            "declared {}:{} exceeds {max_ratio}:1",
                            member.size, member.size
                        ),
                    )
                    .on(&member.name),
                );
                continue;
            }
        }
        match declared_total.consume(member.size) {
            Ok(_) => {}
            Err(QuotaError::Overflow) => {
                findings.push(Finding::error(
                    FindingCode::QuotaOverflow,
                    "declared uncompressed total overflowed u64",
                ));
                break;
            }
            Err(QuotaError::Exceeded { .. }) => {
                findings.push(Finding::error(
                    FindingCode::QuotaTotal,
                    "declared total too large",
                ));
                break;
            }
        }

        let mut actions = Vec::new();
        let jailed_name = if member.is_dir {
            match member.name.strip_suffix('/') {
                Some(name) => {
                    actions.push(NormalizationAction::StripDirectoryTrailingSlash);
                    name
                }
                None => member.name.as_str(),
            }
        } else {
            &member.name
        };
        match jail_name_for_profile(
            jailed_name,
            budget.max_path_depth,
            ZipInterpretationProfile::PortableUtf8V1,
        ) {
            Ok(jailed) => {
                if let Some(detail) = portable_name_violation(&jailed) {
                    findings.push(
                        Finding::error(FindingCode::PathInvalidChar, detail).on(&member.name),
                    );
                    continue;
                }
                actions.extend(jailed.actions);
                let parts = jailed.components;
                let joined = parts.join("/");
                let fold = profile_case_fold(&joined, ZipInterpretationProfile::PortableUtf8V1);
                if dest_seen.contains_key(&joined) {
                    findings.push(
                        Finding::error(FindingCode::PathConflict, "duplicate destination path")
                            .on(&member.name),
                    );
                    continue;
                }
                if fold_seen.contains_key(&fold) {
                    findings.push(
                        Finding::error(FindingCode::PathCaseFold, "case-fold collision")
                            .on(&member.name),
                    );
                    continue;
                }
                if let Some(conflict) = path_conflict(&dest_seen, &joined, member.is_dir) {
                    findings.push(
                        Finding::error(
                            FindingCode::PathConflict,
                            format!("file/directory conflict with {conflict}"),
                        )
                        .on(&member.name),
                    );
                    continue;
                }
                if let Some(conflict) = path_conflict(&fold_seen, &fold, member.is_dir) {
                    findings.push(
                        Finding::error(
                            FindingCode::PathCaseFold,
                            format!("case-fold topology conflict with {conflict}"),
                        )
                        .on(&member.name),
                    );
                    continue;
                }
                dest_seen.insert(joined, member.is_dir);
                fold_seen.insert(fold, member.is_dir);
                planned.push((member, parts, actions));
            }
            Err(finding) => findings.push(finding),
        }
    }

    if findings
        .iter()
        .any(|finding| finding.severity == Severity::Error)
    {
        let cause = first_error(&findings);
        return finish(
            (
                snapshots.original().path_owned(),
                source_digest,
                snapshots.original().kind(),
            ),
            magic,
            policy,
            findings,
            Vec::new(),
            initial_materialization,
            SemanticAxes::denied_at_admission(&cause),
            identities_base,
        );
    }

    let wrapped = matches!(&profile, TarPlanProfile::Gzip(_, _));
    let payloads = planned
        .iter()
        .map(|(member, _, _)| {
            if wrapped {
                PayloadPlan::from_tar_gzip(member)
            } else {
                PayloadPlan::from_tar(member)
            }
        })
        .collect();
    let members = planned
        .into_iter()
        .map(|(member, components, actions)| {
            if wrapped {
                IrMember::from_tar_gzip_planned(member, components, actions)
            } else {
                IrMember::from_tar_planned(member, components, actions)
            }
        })
        .collect();
    let ir = match profile {
        TarPlanProfile::Raw(profile) => {
            ArchiveIR::with_tar(profile, source_digest.clone(), covering, members)
        }
        TarPlanProfile::Gzip(profile, wrapper) => {
            ArchiveIR::with_tar_gzip(profile, source_digest.clone(), wrapper, covering, members)
        }
    };
    let tar_snapshot = snapshots
        .domain(tar_domain)
        .expect("selected TAR domain remains retained");
    if let Err(finding) = audit_tar_covering(tar_snapshot, &ir) {
        findings.push(finding);
        let cause = first_error(&findings);
        let axes = tar_covering_failure_axes(wrapped, &cause);
        let outcome = finish(
            (
                snapshots.original().path_owned(),
                source_digest,
                snapshots.original().kind(),
            ),
            magic,
            policy,
            findings,
            Vec::new(),
            initial_materialization,
            axes,
            identities_base,
        );
        return with_ir(outcome, ir);
    }
    let ready = ReadyArchive {
        snapshots,
        transforms,
        ir,
        payloads,
        findings,
        budget,
        member_sync: controls.effect.member_sync,
        source_digest,
        identities_base,
        magic,
    };
    match execute_ready_archive(req, options, ready, initial_materialization) {
        Ok(outcome) => outcome,
        Err(_) => unreachable!("ready TAR execution does not reacquire the source"),
    }
}

#[allow(clippy::too_many_arguments)]
fn plan_tar_pax(
    req: &Request<'_>,
    options: &ApplyOptions,
    snapshots: SnapshotSet<'_>,
    profile: TarPaxInterpretationProfile,
    controls: CompiledControls,
    source_digest: SourceDigest,
    identities_base: OutcomeIdentities,
    initial_materialization: MaterializationMeta,
) -> Outcome {
    let policy = req.policy;
    let snapshot = snapshots.original();
    let observed_magic = if tar::recognizes_ustar(snapshot) {
        "tar"
    } else {
        "unknown"
    };
    let parsed = match tar_pax::parse_pax_portable_v1(
        snapshot,
        controls.budget.max_files,
        controls.budget.max_metadata_bytes,
    ) {
        Ok(parsed) => parsed,
        Err(finding) => {
            let axes = parse_failure_axes(&finding);
            return finish(
                (snapshot.path_owned(), source_digest, snapshot.kind()),
                observed_magic,
                policy,
                vec![finding],
                Vec::new(),
                initial_materialization,
                axes,
                identities_base,
            );
        }
    };

    let tar_pax::PaxArchive {
        members: parsed_members,
        extensions: parsed_extensions,
        member_records,
        terminator,
        trailing_zeros,
        metadata_bytes: _,
    } = parsed;
    let covering = TarArchiveCovering {
        member_records,
        terminator,
        trailing_zeros,
    };
    let extensions = parsed_extensions
        .into_iter()
        .map(|extension| PaxExtensionEvidence {
            raw_name_bytes: extension.raw_name,
            kind: extension.kind,
            header: extension.header,
            payload: extension.payload,
            padding: extension.padding,
            mode: extension.mode,
            mtime: extension.mtime,
            header_checksum: extension.header_checksum,
            header_sha256: extension.header_sha256,
            payload_sha256: extension.payload_sha256,
            records: extension
                .records
                .into_iter()
                .map(|record| PaxRecordEvidence {
                    record: record.record,
                    value: record.value_range,
                    keyword: record.keyword,
                    raw_value_bytes: record.raw_value_bytes,
                    parsed_size: match record.value {
                        tar_pax::PaxRecordValue::Path(_) => None,
                        tar_pax::PaxRecordValue::Size(size) => Some(size),
                    },
                })
                .collect(),
        })
        .collect();

    let budget = controls.budget;
    let mut findings = Vec::new();
    let mut planned = Vec::new();
    let mut dest_seen: BTreeMap<String, bool> = BTreeMap::new();
    let mut fold_seen: BTreeMap<String, bool> = BTreeMap::new();
    let mut declared_total = QuotaState::new(budget.max_total_bytes);

    for member in parsed_members {
        if member.size > budget.max_member_bytes {
            findings.push(
                Finding::error(FindingCode::QuotaMember, "declared member too large")
                    .on(&member.name),
            );
            continue;
        }
        if let Some(max_ratio) = budget.max_ratio {
            if ratio_exceeds(member.size, member.size, max_ratio) {
                findings.push(
                    Finding::error(
                        FindingCode::QuotaRatio,
                        format!(
                            "declared {}:{} exceeds {max_ratio}:1",
                            member.size, member.size
                        ),
                    )
                    .on(&member.name),
                );
                continue;
            }
        }
        match declared_total.consume(member.size) {
            Ok(_) => {}
            Err(QuotaError::Overflow) => {
                findings.push(Finding::error(
                    FindingCode::QuotaOverflow,
                    "declared uncompressed total overflowed u64",
                ));
                break;
            }
            Err(QuotaError::Exceeded { .. }) => {
                findings.push(Finding::error(
                    FindingCode::QuotaTotal,
                    "declared total too large",
                ));
                break;
            }
        }

        let mut actions = Vec::new();
        let jailed_name = if member.is_dir {
            match member.name.strip_suffix('/') {
                Some(name) => {
                    actions.push(NormalizationAction::StripDirectoryTrailingSlash);
                    name
                }
                None => member.name.as_str(),
            }
        } else {
            &member.name
        };
        match jail_name_for_profile(
            jailed_name,
            budget.max_path_depth,
            ZipInterpretationProfile::PortableUtf8V1,
        ) {
            Ok(jailed) => {
                if let Some(detail) = portable_name_violation(&jailed) {
                    findings.push(
                        Finding::error(FindingCode::PathInvalidChar, detail).on(&member.name),
                    );
                    continue;
                }
                actions.extend(jailed.actions);
                let parts = jailed.components;
                let joined = parts.join("/");
                let fold = profile_case_fold(&joined, ZipInterpretationProfile::PortableUtf8V1);
                if dest_seen.contains_key(&joined) {
                    findings.push(
                        Finding::error(FindingCode::PathConflict, "duplicate destination path")
                            .on(&member.name),
                    );
                    continue;
                }
                if fold_seen.contains_key(&fold) {
                    findings.push(
                        Finding::error(FindingCode::PathCaseFold, "case-fold collision")
                            .on(&member.name),
                    );
                    continue;
                }
                if let Some(conflict) = path_conflict(&dest_seen, &joined, member.is_dir) {
                    findings.push(
                        Finding::error(
                            FindingCode::PathConflict,
                            format!("file/directory conflict with {conflict}"),
                        )
                        .on(&member.name),
                    );
                    continue;
                }
                if let Some(conflict) = path_conflict(&fold_seen, &fold, member.is_dir) {
                    findings.push(
                        Finding::error(
                            FindingCode::PathCaseFold,
                            format!("case-fold topology conflict with {conflict}"),
                        )
                        .on(&member.name),
                    );
                    continue;
                }
                dest_seen.insert(joined, member.is_dir);
                fold_seen.insert(fold, member.is_dir);
                planned.push((member, parts, actions));
            }
            Err(finding) => findings.push(finding),
        }
    }

    if findings
        .iter()
        .any(|finding| finding.severity == Severity::Error)
    {
        let cause = first_error(&findings);
        return finish(
            (
                snapshots.original().path_owned(),
                source_digest,
                snapshots.original().kind(),
            ),
            "tar",
            policy,
            findings,
            Vec::new(),
            initial_materialization,
            SemanticAxes::denied_at_admission(&cause),
            identities_base,
        );
    }

    let payloads = planned
        .iter()
        .map(|(member, _, _)| PayloadPlan::from_tar_pax(member))
        .collect();
    let members = planned
        .into_iter()
        .map(|(member, components, actions)| {
            let base_size = member.header_size;
            let effective_raw_name_bytes = member.name.as_bytes().to_vec();
            let effective_name = member.name.clone();
            let path_source = member.sources.path;
            let size_source = member.sources.size;
            let tar_member = tar::TarMember {
                raw_name: member.raw_name,
                name: effective_name.clone(),
                size: member.size,
                mode: member.mode,
                mtime: member.mtime,
                header_checksum: member.header_checksum,
                header_sha256: member.header_sha256,
                header: member.header,
                payload: member.payload,
                padding: member.padding,
                is_dir: member.is_dir,
            };
            IrMember::from_tar_pax_planned(
                tar_member,
                base_size,
                effective_raw_name_bytes,
                effective_name,
                components,
                actions,
                path_source,
                size_source,
            )
        })
        .collect();
    let ir = ArchiveIR::with_tar_pax(
        profile,
        source_digest.clone(),
        covering,
        extensions,
        members,
    );
    if let Err(finding) = audit_tar_pax_covering(snapshots.original(), &ir) {
        findings.push(finding);
        let cause = first_error(&findings);
        let outcome = finish(
            (
                snapshots.original().path_owned(),
                source_digest,
                snapshots.original().kind(),
            ),
            "tar",
            policy,
            findings,
            Vec::new(),
            initial_materialization,
            SemanticAxes::structure_stop(
                InterpretationStatus::Malformed,
                AdmissionStatus::Denied,
                &cause,
            ),
            identities_base,
        );
        return with_ir(outcome, ir);
    }
    let ready = ReadyArchive {
        snapshots,
        transforms: TransformGraph::empty(),
        ir,
        payloads,
        findings,
        budget,
        member_sync: controls.effect.member_sync,
        source_digest,
        identities_base,
        magic: "tar",
    };
    match execute_ready_archive(req, options, ready, initial_materialization) {
        Ok(outcome) => outcome,
        Err(_) => unreachable!("ready PAX execution does not reacquire the source"),
    }
}

fn tar_covering_failure_axes(wrapped: bool, finding: &Finding) -> SemanticAxes {
    if wrapped {
        SemanticAxes::structure_stop(
            InterpretationStatus::Indeterminate,
            AdmissionStatus::NotEvaluated,
            finding,
        )
    } else {
        SemanticAxes::structure_stop(
            InterpretationStatus::Malformed,
            AdmissionStatus::Denied,
            finding,
        )
    }
}

fn observed_gzip_magic(source: &SourceSnapshot<'_>) -> &'static str {
    if source.len() < 2 {
        return "unknown";
    }
    let mut magic = [0_u8; 2];
    match source.read_exact_at(0, &mut magic) {
        Ok(()) if magic == [0x1f, 0x8b] => "gz",
        _ => "unknown",
    }
}

fn gzip_failure_axes(error: &gzip::GzipError) -> SemanticAxes {
    let finding = error.finding();
    let (interpretation, admission) = match error.kind {
        GzipErrorKind::Source => (
            InterpretationStatus::Indeterminate,
            AdmissionStatus::NotEvaluated,
        ),
        GzipErrorKind::CompressionMethod
        | GzipErrorKind::ReservedFlags
        | GzipErrorKind::ConcatenatedMember => (
            InterpretationStatus::Unsupported,
            AdmissionStatus::NotEvaluated,
        ),
        GzipErrorKind::HeaderLimit | GzipErrorKind::OutputLimit => {
            (InterpretationStatus::Interpreted, AdmissionStatus::Denied)
        }
        GzipErrorKind::TransformAuthority => (
            InterpretationStatus::Indeterminate,
            AdmissionStatus::NotEvaluated,
        ),
        GzipErrorKind::Magic
        | GzipErrorKind::Truncated
        | GzipErrorKind::TrailingInput
        | GzipErrorKind::ExtraField
        | GzipErrorKind::HeaderChecksum
        | GzipErrorKind::DeflateStream
        | GzipErrorKind::DeflateAccounting
        | GzipErrorKind::DataChecksum
        | GzipErrorKind::DeclaredSize => (
            InterpretationStatus::Malformed,
            AdmissionStatus::NotEvaluated,
        ),
    };
    SemanticAxes::structure_stop(interpretation, admission, finding)
}

#[derive(Debug)]
pub(crate) struct SourceFailure {
    pub(crate) path: Option<String>,
    pub(crate) digest: SourceDigest,
    pub(crate) finding: Finding,
    pub(crate) snapshot_kind: SnapshotKind,
}

fn read_source<'a>(
    src: &Source<'a>,
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
            SourceSnapshot::private_file_from_path(p, path.clone(), budget.max_archive_bytes)
                .map_err(unavailable)
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

#[derive(Debug)]
pub(crate) struct PlanningContext {
    policy_id: String,
    policy_sha256: String,
    profile: ZipInterpretationProfile,
    controls: CompiledControls,
}

impl PlanningContext {
    pub(crate) fn compile(
        policy: &Policy,
        profile: ZipInterpretationProfile,
    ) -> Result<Self, Finding> {
        let controls = policy.compile_for_format(profile.policy_format())?;
        Ok(Self {
            policy_id: policy.id.clone(),
            policy_sha256: policy.digest_hex(),
            profile,
            controls,
        })
    }

    pub(crate) fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub(crate) fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    pub(crate) fn profile(&self) -> ZipInterpretationProfile {
        self.profile
    }

    pub(crate) fn controls(&self) -> CompiledControls {
        self.controls
    }

    fn matches_policy(&self, policy: &Policy) -> bool {
        self.policy_id() == policy.id && self.policy_sha256() == policy.digest_hex()
    }
}

#[derive(Debug)]
pub(crate) struct ReadyPlan<'a> {
    snapshot: SourceSnapshot<'a>,
    ir: ArchiveIR,
    payloads: Vec<PayloadPlan>,
    findings: Vec<Finding>,
    context: PlanningContext,
}

impl<'a> ReadyPlan<'a> {
    pub(crate) fn into_parts(
        self,
    ) -> (
        SourceSnapshot<'a>,
        ArchiveIR,
        Vec<PayloadPlan>,
        Vec<Finding>,
        PlanningContext,
    ) {
        (
            self.snapshot,
            self.ir,
            self.payloads,
            self.findings,
            self.context,
        )
    }
}

#[derive(Debug)]
pub(crate) struct TerminalPlan<'a> {
    snapshot: SourceSnapshot<'a>,
    magic: &'static str,
    ir: Option<ArchiveIR>,
    findings: Vec<Finding>,
    axes: SemanticAxes,
    context: PlanningContext,
}

impl<'a> TerminalPlan<'a> {
    pub(crate) fn into_parts(
        self,
    ) -> (
        SourceSnapshot<'a>,
        &'static str,
        Option<ArchiveIR>,
        Vec<Finding>,
        SemanticAxes,
        PlanningContext,
    ) {
        (
            self.snapshot,
            self.magic,
            self.ir,
            self.findings,
            self.axes,
            self.context,
        )
    }
}

#[derive(Debug)]
pub(crate) enum PlanDecision<'a> {
    Ready(ReadyPlan<'a>),
    Terminal(TerminalPlan<'a>),
}

fn terminal_plan<'a>(
    snapshot: SourceSnapshot<'a>,
    context: PlanningContext,
    magic: &'static str,
    findings: Vec<Finding>,
    ir: Option<ArchiveIR>,
    axes: SemanticAxes,
) -> PlanDecision<'a> {
    PlanDecision::Terminal(TerminalPlan {
        snapshot,
        magic,
        ir,
        findings,
        axes,
        context,
    })
}

/// Acquire, interpret, and admit one immutable source without verifying
/// payloads or requesting effects. This is the single crate-private planning
/// seam used by the public operation and repository semantic-record evidence.
pub(crate) fn plan_source<'a>(
    source: &Source<'a>,
    context: PlanningContext,
) -> Result<PlanDecision<'a>, SourceFailure> {
    let snapshot = read_source(source, context.controls.budget)?;
    Ok(plan_snapshot(snapshot, context))
}

/// Acquire every supervised input as an owned private file before planning so
/// the exact same read-only object can be delegated to authenticated workers.
#[cfg(target_os = "linux")]
pub(crate) fn plan_supervised_source(
    source: &Source<'_>,
    context: PlanningContext,
) -> Result<PlanDecision<'static>, SourceFailure> {
    let budget = context.controls.budget;
    let snapshot = match source {
        Source::Path(path) => {
            let display = Some(path.display().to_string());
            SourceSnapshot::private_file_from_path(path, display.clone(), budget.max_archive_bytes)
                .map_err(|finding| SourceFailure {
                    path: display,
                    digest: SourceDigest::unavailable(),
                    finding,
                    snapshot_kind: SnapshotKind::Unavailable,
                })?
        }
        Source::Bytes { path, data } => {
            let path = path.map(str::to_owned);
            SourceSnapshot::private_file_from_bytes(path.clone(), data, budget.max_archive_bytes)
                .map_err(|finding| SourceFailure {
                    path,
                    digest: SourceDigest::available(hex_sha256(data)),
                    finding,
                    snapshot_kind: SnapshotKind::Unavailable,
                })?
        }
    };
    Ok(plan_snapshot(snapshot, context))
}

fn plan_snapshot<'a>(snapshot: SourceSnapshot<'a>, context: PlanningContext) -> PlanDecision<'a> {
    let interpretation_profile = context.profile;
    let controls = context.controls;
    let budget = controls.budget;

    let magic = match detect_magic(&snapshot, interpretation_profile) {
        Ok(magic) => magic,
        Err(finding) => {
            let axes = parse_failure_axes_for_profile(&finding, interpretation_profile);
            return terminal_plan(snapshot, context, "unknown", vec![finding], None, axes);
        }
    };
    if magic != "zip" {
        let finding = Finding::error(FindingCode::FormatUnsupported, format!("magic {magic}"));
        let axes = SemanticAxes::structure_stop(
            InterpretationStatus::Unsupported,
            AdmissionStatus::NotEvaluated,
            &finding,
        );
        return terminal_plan(snapshot, context, magic, vec![finding], None, axes);
    }
    let parsed = match zip::parse_zip_with_profile(
        &snapshot,
        budget.max_files,
        budget.max_metadata_bytes,
        interpretation_profile,
    ) {
        Ok(parsed) => parsed,
        Err(finding) => {
            let axes = parse_failure_axes_for_profile(&finding, interpretation_profile);
            return terminal_plan(snapshot, context, "zip", vec![finding], None, axes);
        }
    };

    if parsed.members.len() as u64 > budget.max_files {
        let finding = Finding::error(
            FindingCode::QuotaFiles,
            format!("{} entries", parsed.members.len()),
        );
        let axes = SemanticAxes::structure_stop(
            InterpretationStatus::Interpreted,
            AdmissionStatus::Denied,
            &finding,
        );
        return terminal_plan(snapshot, context, "zip", vec![finding], None, axes);
    }
    if parsed.metadata_bytes > budget.max_metadata_bytes {
        let finding = Finding::error(
            FindingCode::QuotaMetadata,
            format!(
                "ZIP metadata is {} bytes; cap is {}",
                parsed.metadata_bytes, budget.max_metadata_bytes
            ),
        );
        let axes = SemanticAxes::structure_stop(
            InterpretationStatus::Interpreted,
            AdmissionStatus::Denied,
            &finding,
        );
        return terminal_plan(snapshot, context, "zip", vec![finding], None, axes);
    }

    let zip32_covering = (!interpretation_profile.is_zip64()).then(|| parsed.covering());
    let zip64_covering = interpretation_profile
        .is_zip64()
        .then(|| parsed.zip64_covering());
    let mut findings = Vec::new();
    let mut planned: Vec<(ZipMember, Vec<String>, Vec<NormalizationAction>)> = Vec::new();
    let mut dest_seen: BTreeMap<String, bool> = BTreeMap::new();
    let mut fold_seen: BTreeMap<String, bool> = BTreeMap::new();
    let mut declared_total = QuotaState::new(budget.max_total_bytes);

    for member in parsed.members {
        if (member.flags & ZIP_ENCRYPTION_FLAGS) != 0 {
            findings.push(
                Finding::error(
                    FindingCode::ZipEncrypted,
                    format!(
                        "encryption-related general-purpose flags 0x{:04x}",
                        member.flags
                    ),
                )
                .on(&member.name),
            );
            continue;
        }
        if member.method != 0 && member.method != 8 {
            findings.push(
                Finding::error(
                    FindingCode::MethodUnsupported,
                    format!("method {}", member.method),
                )
                .on(&member.name),
            );
            continue;
        }
        if member.uncomp_size > budget.max_member_bytes {
            findings.push(
                Finding::error(FindingCode::QuotaMember, "declared member too large")
                    .on(&member.name),
            );
            continue;
        }
        if let Some(max_ratio) = budget.max_ratio {
            if ratio_exceeds(member.uncomp_size, member.comp_size, max_ratio) {
                findings.push(
                    Finding::error(
                        FindingCode::QuotaRatio,
                        format!(
                            "declared {}:{} exceeds {max_ratio}:1",
                            member.uncomp_size, member.comp_size
                        ),
                    )
                    .on(&member.name),
                );
                continue;
            }
        }
        match declared_total.consume(member.uncomp_size) {
            Ok(_) => {}
            Err(QuotaError::Overflow) => {
                findings.push(Finding::error(
                    FindingCode::QuotaOverflow,
                    "declared uncompressed total overflowed u64",
                ));
                break;
            }
            Err(QuotaError::Exceeded { .. }) => {
                findings.push(Finding::error(
                    FindingCode::QuotaTotal,
                    "declared total too large",
                ));
                break;
            }
        }

        let mut actions = Vec::new();
        let jailed_name = if member.is_dir {
            actions.push(NormalizationAction::StripDirectoryTrailingSlash);
            member.name.strip_suffix('/').unwrap_or(&member.name)
        } else {
            &member.name
        };
        match jail_name_for_profile(jailed_name, budget.max_path_depth, interpretation_profile) {
            Ok(jailed) => {
                if interpretation_profile == ZipInterpretationProfile::WheelUtf8V1
                    && !jailed.actions.is_empty()
                {
                    findings.push(
                        Finding::error(
                            FindingCode::PathInvalidChar,
                            "wheel UTF-8 paths may not contain dot components",
                        )
                        .on(&member.name),
                    );
                    continue;
                }
                if interpretation_profile == ZipInterpretationProfile::PortableUtf8V1 {
                    if let Some(detail) = portable_name_violation(&jailed) {
                        findings.push(
                            Finding::error(FindingCode::PathInvalidChar, detail).on(&member.name),
                        );
                        continue;
                    }
                }
                actions.extend(jailed.actions);
                let parts = jailed.components;
                let joined = parts.join("/");
                let fold = profile_case_fold(&joined, interpretation_profile);
                if dest_seen.contains_key(&joined) {
                    findings.push(
                        Finding::error(FindingCode::ZipDiffB1Dup, "duplicate dest path")
                            .on(&member.name),
                    );
                    continue;
                }
                if fold_seen.contains_key(&fold) {
                    findings.push(
                        Finding::error(FindingCode::PathCaseFold, "case-fold collision")
                            .on(&member.name),
                    );
                    continue;
                }
                if let Some(conflict) = path_conflict(&dest_seen, &joined, member.is_dir) {
                    findings.push(
                        Finding::error(
                            FindingCode::PathConflict,
                            format!("file/directory conflict with {conflict}"),
                        )
                        .on(&member.name),
                    );
                    continue;
                }
                if let Some(conflict) = path_conflict(&fold_seen, &fold, member.is_dir) {
                    findings.push(
                        Finding::error(
                            FindingCode::PathCaseFold,
                            format!("case-fold topology conflict with {conflict}"),
                        )
                        .on(&member.name),
                    );
                    continue;
                }
                dest_seen.insert(joined, member.is_dir);
                fold_seen.insert(fold, member.is_dir);
                planned.push((member, parts, actions));
            }
            Err(finding) => findings.push(finding),
        }
    }

    if findings
        .iter()
        .any(|finding| finding.severity == Severity::Error)
    {
        let cause = first_error(&findings);
        let axes = SemanticAxes::denied_at_admission(&cause);
        return terminal_plan(snapshot, context, "zip", findings, None, axes);
    }

    let payloads = planned
        .iter()
        .map(|(member, _, _)| PayloadPlan::from_zip(member))
        .collect();
    let ir_members = planned
        .into_iter()
        .map(|(zip, components, actions)| {
            if interpretation_profile.is_zip64() {
                IrMember::from_zip64_planned(zip, components, actions)
            } else {
                IrMember::from_planned(zip, components, actions)
            }
        })
        .collect();
    let ir = if interpretation_profile.is_zip64() {
        ArchiveIR::with_zip64(
            interpretation_profile,
            snapshot.digest().clone(),
            zip64_covering.expect("ZIP64 parser supplies ZIP64 covering"),
            ir_members,
        )
    } else {
        ArchiveIR::with_covering(
            interpretation_profile,
            snapshot.digest().clone(),
            zip32_covering.expect("ZIP32 parser supplies ZIP32 covering"),
            ir_members,
        )
    };
    let covering_result = if interpretation_profile.is_zip64() {
        audit_zip64_covering(&snapshot, &ir)
    } else {
        audit_covering(&snapshot, &ir)
    };
    if let Err(finding) = covering_result {
        findings.push(finding);
        let cause = first_error(&findings);
        let axes = SemanticAxes::structure_stop(
            InterpretationStatus::Malformed,
            AdmissionStatus::Denied,
            &cause,
        );
        return terminal_plan(snapshot, context, "zip", findings, Some(ir), axes);
    }

    PlanDecision::Ready(ReadyPlan {
        snapshot,
        ir,
        payloads,
        findings,
        context,
    })
}

fn apply_inner(
    req: &Request<'_>,
    planning_context: PlanningContext,
    options: &ApplyOptions,
) -> Result<Outcome, SourceFailure> {
    let policy = req.policy;
    let initial_materialization =
        MaterializationMeta::not_started(req.dest.is_some(), policy.atomic);
    let planning = plan_source(&req.source, planning_context)?;
    let ready = match planning {
        PlanDecision::Ready(ready) => ready,
        PlanDecision::Terminal(terminal) => {
            let (snapshot, magic, ir, findings, axes, context) = terminal.into_parts();
            debug_assert!(context.matches_policy(policy));
            let source_digest = snapshot.digest().clone();
            let identities_base =
                OutcomeIdentities::unavailable_for(source_digest.clone(), context.profile());
            let outcome = finish(
                (snapshot.path_owned(), source_digest, snapshot.kind()),
                magic,
                policy,
                findings,
                Vec::new(),
                initial_materialization,
                axes,
                identities_base,
            );
            return Ok(match ir {
                Some(ir) => with_ir(outcome, ir),
                None => outcome,
            });
        }
    };
    let (snapshot, ir, payloads, findings, context) = ready.into_parts();
    debug_assert!(context.matches_policy(policy));
    let controls = context.controls();
    let budget = controls.budget;
    let member_sync = controls.effect.member_sync;
    let source_digest = snapshot.digest().clone();
    let identities_base =
        OutcomeIdentities::unavailable_for(source_digest.clone(), context.profile());

    let ready = ReadyArchive {
        snapshots: SnapshotSet::from_original(snapshot),
        transforms: TransformGraph::empty(),
        ir,
        payloads,
        findings,
        budget,
        member_sync,
        source_digest,
        identities_base,
        magic: "zip",
    };
    execute_ready_archive(req, options, ready, initial_materialization)
}

#[derive(Debug)]
struct ReadyArchive<'a> {
    snapshots: SnapshotSet<'a>,
    transforms: TransformGraph,
    ir: ArchiveIR,
    payloads: Vec<PayloadPlan>,
    findings: Vec<Finding>,
    budget: ResourceBudget,
    member_sync: bool,
    source_digest: SourceDigest,
    identities_base: OutcomeIdentities,
    magic: &'static str,
}

/// Proof minted only after the ready topology and every completed member have
/// been revalidated immediately before capability construction.
pub(crate) struct VerifiedArchiveAuthority {
    _private: (),
}

#[derive(Debug)]
struct ReadyArchiveAuthority {
    _private: (),
}

fn ready_inconsistent(detail: impl Into<String>) -> Finding {
    Finding::error(FindingCode::CoveringInconsistent, detail)
}

fn validate_ready_source_identity(
    snapshots: &SnapshotSet<'_>,
    ir: &ArchiveIR,
    source_digest: &SourceDigest,
) -> Result<(), Finding> {
    if source_digest != snapshots.original().digest() || source_digest != ir.source_digest() {
        return Err(ready_inconsistent(
            "ready receipt source identity does not match the original snapshot and archive IR",
        ));
    }
    Ok(())
}

fn validate_ready_archive(
    snapshots: &SnapshotSet<'_>,
    transforms: &TransformGraph,
    ir: &ArchiveIR,
    payloads: &[PayloadPlan],
) -> Result<ReadyArchiveAuthority, Finding> {
    if ir.source_digest() != snapshots.original().digest() {
        return Err(ready_inconsistent(
            "archive IR source identity does not match the original snapshot",
        ));
    }
    if payloads.len() != ir.members.len()
        || payloads
            .iter()
            .zip(&ir.members)
            .any(|(payload, member)| !payload.matches_member(member))
    {
        return Err(ready_inconsistent(
            "ready payload plan disagrees with archive evidence",
        ));
    }
    if ir
        .members
        .iter()
        .any(|member| member.format() != ir.format())
    {
        return Err(ready_inconsistent(
            "member evidence variant does not match the archive format",
        ));
    }
    match ir.format() {
        ArchiveFormat::Zip32
        | ArchiveFormat::Zip64
        | ArchiveFormat::TarUstar
        | ArchiveFormat::TarPax => {
            if !transforms.validates(snapshots) || snapshots.len() != 1 || !transforms.is_empty() {
                return Err(ready_inconsistent(
                    "raw archive unexpectedly contains a derived transform graph",
                ));
            }
            Ok(ReadyArchiveAuthority { _private: () })
        }
        ArchiveFormat::TarGzipUstar => {
            audit_tar_gzip_composite(snapshots, transforms, ir)?;
            Ok(ReadyArchiveAuthority { _private: () })
        }
    }
}

fn audit_tar_gzip_composite(
    snapshots: &SnapshotSet<'_>,
    transforms: &TransformGraph,
    ir: &ArchiveIR,
) -> Result<(), Finding> {
    if snapshots.len() != 2 || transforms.records().len() != 1 || !transforms.validates(snapshots) {
        return Err(ready_inconsistent(
            "gzip-wrapped TAR requires exactly two snapshots and one valid transform",
        ));
    }
    let original = snapshots.original();
    let derived = snapshots
        .domain(SnapshotDomainId::FIRST_DERIVED)
        .ok_or_else(|| ready_inconsistent("gzip-derived TAR snapshot is absent"))?;
    let wrapper = ir
        .gzip_evidence()
        .ok_or_else(|| ready_inconsistent("gzip-wrapped TAR has no wrapper evidence"))?;
    let record = &transforms.records()[0];
    let original_sha256 = original
        .digest()
        .sha256()
        .ok_or_else(|| ready_inconsistent("original gzip snapshot digest is unavailable"))?;
    if record.profile != TransformProfile::GzipRfc1952SingleMemberV1
        || record.input
            != (DomainRange {
                domain: SnapshotDomainId::ORIGINAL,
                range: crate::ir::ByteRange {
                    offset: 0,
                    len: original.len(),
                },
            })
        || record.input_sha256 != original_sha256
        || record.output_domain != SnapshotDomainId::FIRST_DERIVED
        || record.output_len != derived.len()
        || record.output_len != wrapper.derived_output_len
        || derived.digest().sha256() != Some(record.output_sha256.as_str())
        || record.output_sha256 != wrapper.derived_output_sha256
    {
        return Err(ready_inconsistent(
            "gzip transform graph does not exactly bind the outer and derived snapshots",
        ));
    }
    audit_gzip_wrapper_covering(original, wrapper)?;
    audit_tar_covering(derived, ir)?;

    let mut reader = derived.reader(0, derived.len())?;
    let mut crc = Crc::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            crate::snapshot::finding_from_io(&error).unwrap_or_else(|| {
                ready_inconsistent(format!(
                    "could not audit gzip-derived TAR integrity: {error}"
                ))
            })
        })?;
        if read == 0 {
            break;
        }
        crc.update(&buffer[..read]);
    }
    if crc.finalize() != wrapper.declared_crc32
        || wrapper.declared_isize != gzip_isize(derived.len())
    {
        return Err(ready_inconsistent(
            "gzip trailer integrity does not match the terminal derived TAR snapshot",
        ));
    }
    Ok(())
}

fn gzip_isize(len: u64) -> u32 {
    u32::try_from(len % (u64::from(u32::MAX) + 1)).expect("gzip ISIZE modulo always fits u32")
}

fn validate_verified_archive_authority(
    _ready: ReadyArchiveAuthority,
    ir: &ArchiveIR,
) -> Result<VerifiedArchiveAuthority, Finding> {
    if ir
        .members()
        .iter()
        .any(|member| !matches!(member.verification, MemberVerification::Verified))
    {
        return Err(ready_inconsistent(
            "verified archive authority contains an unverified member",
        ));
    }
    let mut members_by_path = BTreeMap::new();
    for (index, member) in ir.members().iter().enumerate() {
        if members_by_path
            .insert(member.canonical_path.as_str(), index)
            .is_some()
        {
            return Err(ready_inconsistent(
                "verified archive authority contains duplicate canonical paths",
            ));
        }
    }
    Ok(VerifiedArchiveAuthority { _private: () })
}

fn execute_ready_archive(
    req: &Request<'_>,
    options: &ApplyOptions,
    ready: ReadyArchive<'_>,
    initial_materialization: MaterializationMeta,
) -> Result<Outcome, SourceFailure> {
    let ReadyArchive {
        snapshots,
        transforms,
        mut ir,
        payloads,
        mut findings,
        budget,
        member_sync,
        source_digest,
        identities_base,
        magic,
    } = ready;
    let snapshot = snapshots.original();
    let policy = req.policy;

    let ready_validation = validate_ready_source_identity(&snapshots, &ir, &source_digest)
        .and_then(|()| validate_ready_archive(&snapshots, &transforms, &ir, &payloads));
    let ready_authority = match ready_validation {
        Ok(authority) => authority,
        Err(finding) => {
            let axes = if ir.format() == ArchiveFormat::TarGzipUstar {
                SemanticAxes::structure_stop(
                    InterpretationStatus::Indeterminate,
                    AdmissionStatus::NotEvaluated,
                    &finding,
                )
            } else {
                SemanticAxes::structure_stop(
                    InterpretationStatus::Malformed,
                    AdmissionStatus::Denied,
                    &finding,
                )
            };
            findings.push(finding.clone());
            return Ok(with_ir(
                finish(
                    (snapshot.path_owned(), source_digest, snapshot.kind()),
                    magic,
                    policy,
                    findings,
                    Vec::new(),
                    initial_materialization,
                    axes,
                    identities_base,
                ),
                ir,
            ));
        }
    };

    #[cfg(test)]
    crate::snapshot::arm_test_read_failure();
    let mut retention = RetentionBuild::plan(options.retention_plan(), &ir);
    let planned_count = ir.members.len() as u64;
    let mut members_view = Vec::new();
    let mut actual_total = QuotaState::new(budget.max_total_bytes);
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
                        magic,
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

    for (index, payload_spec) in payloads.iter().copied().enumerate() {
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
                            magic,
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

        let canonical_path = ir.members[index].canonical_path.clone();
        let mut capture = retention.begin_capture(&canonical_path);
        let payload = match planned_payload_reader(
            &snapshots,
            &payload_spec,
            &ir.members[index].decoded_name,
        ) {
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
                        magic,
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
        let payload = BufReader::with_capacity(64 * 1024, payload);
        let remaining = actual_total.remaining();
        let processed = if let Some(stage) = stage.as_ref() {
            stage
                .create_file(&ir.members[index].components)
                .and_then(|file| {
                    process_member_to_file(
                        payload,
                        payload_spec,
                        budget,
                        remaining,
                        member_sync,
                        capture.as_mut(),
                        file,
                    )
                })
        } else {
            match capture.as_mut() {
                Some(bytes) => verify_payload(payload, payload_spec, budget, remaining, bytes),
                None => {
                    let mut sink = io::sink();
                    verify_payload(payload, payload_spec, budget, remaining, &mut sink)
                }
            }
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
                        magic,
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
        if let Err(error) = actual_total.consume(actual) {
            let finding = match error {
                QuotaError::Overflow => Finding::error(
                    FindingCode::QuotaOverflow,
                    "actual uncompressed total overflowed u64",
                ),
                QuotaError::Exceeded { .. } => Finding::error(
                    FindingCode::QuotaTotal,
                    "actual uncompressed total exceeded the archive cap",
                ),
            }
            .on(&ir.members[index].decoded_name);
            ir.members[index].mark_failed(finding.code.as_str());
            findings.push(finding);
            materialization = abort_and_report(&mut stage, &mut findings, materialization);
            let cause = first_error(&findings);
            let verified = members_view.len() as u64;
            return Ok(with_ir(
                finish(
                    (snapshot.path_owned(), source_digest, snapshot.kind()),
                    magic,
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
        retention.finish_capture(&canonical_path, capture);
        ir.members[index].mark_file_verified(actual, crc, digest_hex(&sha));
        members_view.push(member_view(&ir.members[index]));
    }

    let verified_authority = match validate_verified_archive_authority(ready_authority, &ir) {
        Ok(authority) => authority,
        Err(finding) => {
            findings.push(finding.clone());
            materialization = abort_and_report(&mut stage, &mut findings, materialization);
            let source_meta = (snapshot.path_owned(), source_digest, snapshot.kind());
            return Ok(with_ir(
                finish(
                    source_meta,
                    magic,
                    policy,
                    findings,
                    members_view,
                    materialization,
                    SemanticAxes {
                        interpretation: InterpretationStatus::Indeterminate,
                        admission: AdmissionStatus::Admitted,
                        verification: VerificationStatus::Partial {
                            verified_members: planned_count,
                            pending_members: 0,
                        },
                        effect: if write {
                            EffectStatus::Failed
                        } else {
                            EffectStatus::NotRequested
                        },
                        view_completeness: ViewCompleteness::Partial {
                            phase: StoppingPhase::Verification,
                            cause: finding.code.as_str().to_owned(),
                        },
                    },
                    identities_base.clone(),
                ),
                ir,
            ));
        }
    };

    members_view.sort_by(|a, b| a.path.cmp(&b.path));
    if let Some(materializer) = stage.as_mut() {
        if let Err(finding) = materializer.audit_against(&ir) {
            findings.push(finding);
            materialization = abort_and_report(&mut stage, &mut findings, materialization);
            let cause = first_error(&findings);
            let source_meta = (snapshot.path_owned(), source_digest, snapshot.kind());
            let archive = VerifiedArchive::new(
                verified_authority,
                snapshots,
                ir,
                payloads.clone(),
                budget,
                retention,
            );
            return Ok(with_verified_archive(
                finish(
                    source_meta,
                    magic,
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
            let archive = VerifiedArchive::new(
                verified_authority,
                snapshots,
                ir,
                payloads.clone(),
                budget,
                retention,
            );
            return Ok(with_verified_archive(
                finish(
                    source_meta,
                    magic,
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
    let archive = VerifiedArchive::new(
        verified_authority,
        snapshots,
        ir,
        payloads,
        budget,
        retention,
    );
    Ok(with_verified_archive(
        finish(
            source_meta,
            magic,
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

fn detect_magic(
    snapshot: &SourceSnapshot<'_>,
    profile: ZipInterpretationProfile,
) -> Result<&'static str, Finding> {
    let prefix_len =
        usize::try_from(snapshot.len().min(4)).expect("a four-byte prefix always fits usize");
    let mut prefix = [0_u8; 4];
    snapshot.read_exact_at(0, &mut prefix[..prefix_len])?;
    let bytes = &prefix[..prefix_len];
    let legacy_zip_magic = bytes.len() >= 4
        && bytes[0] == 0x50
        && bytes[1] == 0x4b
        && (bytes[2] == 0x03 || bytes[2] == 0x05);
    let selected_empty_zip64_magic =
        profile == ZipInterpretationProfile::Zip64StrictAsciiV1 && bytes == ZIP64_EMPTY_PREFIX;
    if legacy_zip_magic || selected_empty_zip64_magic {
        Ok("zip")
    } else if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        Ok("gz")
    } else {
        Ok("unknown")
    }
}

const ZIP64_EMPTY_PREFIX: &[u8] = &[0x50, 0x4b, 0x06, 0x06];

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
    finish_with_jail(
        (path, source_digest, source_snapshot),
        magic,
        policy,
        findings,
        members,
        materialization,
        axes,
        identities,
        "unavailable",
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_with_jail(
    (path, source_digest, source_snapshot): (Option<String>, SourceDigest, SnapshotKind),
    magic: &'static str,
    policy: &Policy,
    findings: Vec<Finding>,
    members: Vec<MemberView>,
    materialization: MaterializationMeta,
    axes: SemanticAxes,
    identities: OutcomeIdentities,
    kernel_jail: &'static str,
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
            kernel_jail,
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

pub(crate) fn with_ir(mut outcome: Outcome, ir: ArchiveIR) -> Outcome {
    outcome.receipt.identities =
        OutcomeIdentities::from_ir(outcome.receipt.source.clone(), &ir, &outcome.verification);
    outcome.archive_ir = Some(ir);
    outcome
}

pub(crate) fn with_verified_archive(mut outcome: Outcome, archive: VerifiedArchive) -> Outcome {
    outcome.receipt.identities = OutcomeIdentities::from_ir(
        outcome.receipt.source.clone(),
        archive.archive_ir(),
        &outcome.verification,
    );
    outcome.verified_archive = Some(archive);
    outcome
}

pub(crate) fn member_view(member: &IrMember) -> MemberView {
    let (method, declared_comp_size, declared_crc) = match &member.evidence {
        crate::ir::MemberEvidence::Zip(zip) => (
            if zip.method == 0 { "store" } else { "deflate" },
            zip.declared_comp_size,
            zip.declared_crc,
        ),
        crate::ir::MemberEvidence::Zip64(zip64) => (
            if zip64.zip.method == 0 {
                "store"
            } else {
                "deflate"
            },
            zip64.zip.declared_comp_size,
            zip64.zip.declared_crc,
        ),
        crate::ir::MemberEvidence::Tar(tar) | crate::ir::MemberEvidence::TarGzip(tar) => {
            ("raw", tar.payload.len, 0)
        }
        crate::ir::MemberEvidence::TarPax(tar) => ("raw", tar.tar.payload.len, 0),
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
            declared_comp_size
        },
        uncomp_bytes: member.actual_uncomp_size.unwrap_or(0),
        method: if matches!(member.kind, MemberKind::Directory) {
            "store"
        } else {
            method
        },
        crc32: format!("{:08x}", member.actual_crc.unwrap_or(declared_crc)),
        sha256: member.content_sha256.clone().unwrap_or_default(),
    }
}

pub(crate) fn reject_only(
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
    match (&axes.admission, &axes.verification, &axes.effect) {
        (AdmissionStatus::Admitted, VerificationStatus::Complete, EffectStatus::Committed) => {
            Verdict::Allowed { wrote: true }
        }
        (AdmissionStatus::Admitted, VerificationStatus::Complete, EffectStatus::NotRequested) => {
            Verdict::Allowed { wrote: false }
        }
        _ => Verdict::Rejected,
    }
}

fn compat_exit_code(
    admission: &AdmissionStatus,
    verification: &VerificationStatus,
    effect: &EffectStatus,
) -> u8 {
    match (admission, verification, effect) {
        (AdmissionStatus::Admitted, _, EffectStatus::Failed) => 3,
        (
            AdmissionStatus::Admitted,
            VerificationStatus::Complete,
            EffectStatus::Committed | EffectStatus::NotRequested,
        ) => 0,
        _ => 2,
    }
}

pub(crate) fn first_error(findings: &[Finding]) -> Finding {
    findings
        .iter()
        .find(|finding| finding.severity == Severity::Error)
        .cloned()
        .expect("error path records an error finding")
}

fn parse_failure_axes(finding: &Finding) -> SemanticAxes {
    let interpretation = match finding.code {
        FindingCode::SourceIo => InterpretationStatus::Indeterminate,
        FindingCode::FormatUnsupported
        | FindingCode::ZipDiffC5Zip64
        | FindingCode::ZipEncoding
        | FindingCode::TarFeatureUnsupported => InterpretationStatus::Unsupported,
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

fn parse_failure_axes_for_profile(
    finding: &Finding,
    profile: ZipInterpretationProfile,
) -> SemanticAxes {
    if profile.is_zip64() && finding.code == FindingCode::ZipDiffC5Zip64 {
        let interpretation = if finding.detail == "archive contains no ZIP64 construct" {
            InterpretationStatus::Unsupported
        } else {
            InterpretationStatus::Malformed
        };
        return SemanticAxes::structure_stop(
            interpretation,
            AdmissionStatus::NotEvaluated,
            finding,
        );
    }
    parse_failure_axes(finding)
}

#[cfg(test)]
mod tar_gzip_ready_tests {
    use super::*;
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn write_octal(field: &mut [u8], value: u64) {
        field.fill(b'0');
        let octal = format!("{value:o}");
        let digits = field.len() - 1;
        field[digits - octal.len()..digits].copy_from_slice(octal.as_bytes());
        field[digits] = 0;
    }

    fn tar() -> Vec<u8> {
        let body = b"authority";
        let mut header = [0_u8; 512];
        header[..8].copy_from_slice(b"file.txt");
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], body.len() as u64);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[265..269].copy_from_slice(b"root");
        header[297..301].copy_from_slice(b"root");
        write_octal(&mut header[329..337], 0);
        write_octal(&mut header[337..345], 0);
        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
        header[154] = 0;
        header[155] = b' ';
        let mut tar = header.to_vec();
        tar.extend_from_slice(body);
        tar.resize(tar.len().next_multiple_of(512), 0);
        tar.resize(tar.len() + 1024, 0);
        tar
    }

    fn gzip(tar: &[u8]) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(tar).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut source = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        source.extend_from_slice(&compressed);
        let mut crc = Crc::new();
        crc.update(tar);
        source.extend_from_slice(&crc.finalize().to_le_bytes());
        source.extend_from_slice(&(tar.len() as u32).to_le_bytes());
        source
    }

    fn ready<'a>(
        source: &'a [u8],
    ) -> (SnapshotSet<'a>, TransformGraph, ArchiveIR, Vec<PayloadPlan>) {
        let snapshot = SourceSnapshot::borrowed(None, source);
        let source_digest = snapshot.digest().clone();
        let mut snapshots = SnapshotSet::from_original(snapshot);
        let mut transforms = TransformGraph::empty();
        let transformed = gzip::transform_single_member(
            &mut snapshots,
            &mut transforms,
            gzip::GzipLimits {
                max_metadata_bytes: 1024,
                max_output_bytes: 1024 * 1024,
            },
        )
        .unwrap();
        let wrapper = GzipWrapperEvidence {
            flags: transformed.header.flags,
            modification_time: transformed.header.modification_time,
            extra_flags: transformed.header.extra_flags,
            operating_system: transformed.header.operating_system,
            header: transformed.header.header,
            extra: transformed.header.extra,
            extra_subfield_count: transformed.header.extra_subfield_count,
            original_name: transformed.header.original_name,
            comment: transformed.header.comment,
            header_crc16: transformed.header.header_crc16,
            compressed_payload: transformed.compressed_payload,
            trailer: transformed.trailer,
            declared_crc32: transformed.declared_crc32,
            declared_isize: transformed.declared_isize,
            derived_output_len: transformed.output_len,
            derived_output_sha256: transformed.output_sha256,
        };
        let parsed = tar::parse_ustar_portable_v1(
            snapshots.domain(SnapshotDomainId::FIRST_DERIVED).unwrap(),
            10,
            10_000,
        )
        .unwrap();
        let covering = TarArchiveCovering {
            member_records: parsed.member_records,
            terminator: parsed.terminator,
            trailing_zeros: parsed.trailing_zeros,
        };
        let payloads = parsed
            .members
            .iter()
            .map(PayloadPlan::from_tar_gzip)
            .collect();
        let members = parsed
            .members
            .into_iter()
            .map(|member| {
                IrMember::from_tar_gzip_planned(member, vec!["file.txt".to_owned()], Vec::new())
            })
            .collect();
        let ir = ArchiveIR::with_tar_gzip(
            TarGzipInterpretationProfile::UstarPortableV1,
            source_digest,
            wrapper,
            covering,
            members,
        );
        (snapshots, transforms, ir, payloads)
    }

    #[test]
    fn ready_composite_rejects_graph_domain_evidence_and_member_variant_drift() {
        let tar = tar();
        let source = gzip(&tar);
        let (snapshots, transforms, ir, payloads) = ready(&source);
        validate_ready_archive(&snapshots, &transforms, &ir, &payloads).unwrap();
        assert!(validate_ready_source_identity(
            &snapshots,
            &ir,
            &SourceDigest::available("00".repeat(32))
        )
        .is_err());

        let (snapshots, mut transforms, ir, payloads) = ready(&source);
        transforms.records_mut()[0].input.range.offset = 1;
        assert_eq!(
            validate_ready_archive(&snapshots, &transforms, &ir, &payloads)
                .unwrap_err()
                .code,
            FindingCode::CoveringInconsistent
        );

        let (snapshots, transforms, ir, mut payloads) = ready(&source);
        payloads[0].set_test_domain(SnapshotDomainId::ORIGINAL);
        assert!(validate_ready_archive(&snapshots, &transforms, &ir, &payloads).is_err());

        let (snapshots, transforms, mut ir, payloads) = ready(&source);
        let crate::ir::ArchiveEvidence::TarGzip(evidence) = &mut ir.evidence else {
            panic!("expected gzip-wrapped TAR evidence");
        };
        evidence.gzip.derived_output_len += 1;
        assert!(validate_ready_archive(&snapshots, &transforms, &ir, &payloads).is_err());

        let (snapshots, transforms, mut ir, payloads) = ready(&source);
        let crate::ir::MemberEvidence::TarGzip(evidence) = &ir.members[0].evidence else {
            panic!("expected gzip-wrapped TAR member evidence");
        };
        ir.members[0].evidence = crate::ir::MemberEvidence::Tar(evidence.clone());
        assert!(validate_ready_archive(&snapshots, &transforms, &ir, &payloads).is_err());
        assert!(crate::identity::encode_tar_gzip_layout(&ir).is_none());

        let (snapshots, _transforms, ir, payloads) = ready(&source);
        assert!(
            validate_ready_archive(&snapshots, &TransformGraph::empty(), &ir, &payloads).is_err()
        );
    }

    #[test]
    fn post_parser_covering_drift_is_an_integrity_failure_for_wrapped_tar() {
        let finding = Finding::error(
            FindingCode::CoveringInconsistent,
            "injected post-parser covering mismatch",
        );
        let wrapped = tar_covering_failure_axes(true, &finding);
        assert_eq!(wrapped.interpretation, InterpretationStatus::Indeterminate);
        assert_eq!(wrapped.admission, AdmissionStatus::NotEvaluated);

        let raw = tar_covering_failure_axes(false, &finding);
        assert_eq!(raw.interpretation, InterpretationStatus::Malformed);
        assert_eq!(raw.admission, AdmissionStatus::Denied);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::zip::write::SimpleFileOptions;
    use ::zip::{CompressionMethod, ZipWriter};
    use std::io::{Cursor, Read, Write};
    use std::path::PathBuf;

    struct ChunkedReader<R> {
        inner: R,
        max_read: usize,
    }

    impl<R: Read> Read for ChunkedReader<R> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let limit = output.len().min(self.max_read);
            self.inner.read(&mut output[..limit])
        }
    }

    struct FailingSnapshotReader {
        bytes: Vec<u8>,
        position: usize,
        fail_at: usize,
    }

    impl Read for FailingSnapshotReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.position >= self.fail_at {
                return Err(crate::snapshot::as_io_error(Finding::error(
                    FindingCode::SourceIo,
                    "injected private snapshot read failure",
                )));
            }
            let count = output
                .len()
                .min(7)
                .min(self.fail_at - self.position)
                .min(self.bytes.len() - self.position);
            output[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
            self.position += count;
            Ok(count)
        }
    }

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

    fn apply_strict_ascii_v2(bytes: &[u8]) -> Outcome {
        let policy = Policy::default_v1();
        let options = ApplyOptions::new()
            .with_interpretation_profile(ZipInterpretationProfile::StrictAsciiV2);
        apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("strict-v2.zip"),
                    data: bytes,
                },
                policy: &policy,
                dest: None,
            },
            &options,
        )
    }

    fn apply_wheel_utf8_v1(bytes: &[u8]) -> Outcome {
        let policy = Policy::default_v1();
        let options =
            ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::WheelUtf8V1);
        apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("wheel-utf8-v1.zip"),
                    data: bytes,
                },
                policy: &policy,
                dest: None,
            },
            &options,
        )
    }

    fn apply_portable_utf8_v1(bytes: &[u8]) -> Outcome {
        let policy = Policy::default_v1();
        let options = ApplyOptions::new()
            .with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
        apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("portable-utf8-v1.zip"),
                    data: bytes,
                },
                policy: &policy,
                dest: None,
            },
            &options,
        )
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
        let covering = ir.covering().expect("ZIP covering");
        assert_eq!(covering.local_records.offset, 0);
        assert_eq!(
            covering.local_records.len,
            covering.central_directory.offset
        );
        assert_eq!(covering.central_directory.end(), covering.eocd.offset);
        assert_eq!(covering.eocd.len, 22);
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
    fn path_source_uses_a_private_file_snapshot_that_outlives_the_caller_path() {
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
        assert_eq!(out.receipt.source_snapshot, SnapshotKind::PrivateFile);
        assert_eq!(out.receipt.source.sha256(), Some(digest.as_str()));
        fs::remove_file(&archive).unwrap();
        assert_eq!(
            out.verified_archive()
                .unwrap()
                .read_member("nested/hello.txt", 5)
                .unwrap(),
            b"hello"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn private_file_and_borrowed_snapshot_backends_have_semantic_parity() {
        let bytes = make_zip(&[("nested/hello.txt", b"hello"), ("other.bin", b"bytes")]);
        let dir = temp_dest("snapshot-parity");
        fs::create_dir_all(&dir).unwrap();
        let archive = dir.join("same.zip");
        fs::write(&archive, &bytes).unwrap();
        let displayed_path = archive.to_string_lossy();
        let policy = Policy::default_v1();

        let borrowed = apply(Request {
            source: Source::Bytes {
                path: Some(&displayed_path),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });
        let private = apply(Request {
            source: Source::Path(&archive),
            policy: &policy,
            dest: None,
        });

        assert_eq!(
            serde_json::to_value(&private.view).unwrap(),
            serde_json::to_value(&borrowed.view).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&private.receipt.identities).unwrap(),
            serde_json::to_value(&borrowed.receipt.identities).unwrap()
        );
        assert_eq!(
            serde_json::to_value(private.archive_ir().unwrap()).unwrap(),
            serde_json::to_value(borrowed.archive_ir().unwrap()).unwrap()
        );
        assert_eq!(
            private
                .verified_archive()
                .unwrap()
                .read_member("nested/hello.txt", 5)
                .unwrap(),
            borrowed
                .verified_archive()
                .unwrap()
                .read_member("nested/hello.txt", 5)
                .unwrap()
        );
        assert_eq!(private.receipt.source_snapshot, SnapshotKind::PrivateFile);
        assert_eq!(
            borrowed.receipt.source_snapshot,
            SnapshotKind::MemoryBorrowed
        );
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
            creator_system: 0,
            external_attributes: 0,
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
            zip64_evidence: None,
        };
        let mut sink = io::sink();
        let budget = Policy::default_v1().compile().unwrap().budget;
        let finding = verify_payload(
            &[0xff][..],
            PayloadPlan::from_zip(&member),
            budget,
            u64::MAX,
            &mut sink,
        )
        .unwrap_err();

        assert_eq!(finding.code, FindingCode::CodecDeflateInvalidStream);
    }

    #[test]
    fn deflate_preserves_private_snapshot_io_failure_identity() {
        let mut state = 0x91e1_0da5_u32;
        let payload: Vec<u8> = std::iter::repeat_with(|| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .take(128 * 1024)
        .collect();
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let member = ZipMember {
            raw_name: b"io-failure.bin".to_vec(),
            name: "io-failure.bin".to_owned(),
            method: 8,
            flags: 0,
            creator_system: 0,
            external_attributes: 0,
            crc: crc32fast::hash(&payload),
            comp_size: compressed.len() as u64,
            uncomp_size: payload.len() as u64,
            lfh_offset: 0,
            data_offset: 0,
            record_end: compressed.len() as u64,
            is_dir: false,
            extra_fields: Vec::new(),
            source_ranges: crate::ir::MemberSourceRanges {
                local_header: crate::ir::ByteRange { offset: 0, len: 0 },
                compressed_payload: crate::ir::ByteRange {
                    offset: 0,
                    len: compressed.len() as u64,
                },
                data_descriptor: None,
                central_header: crate::ir::ByteRange { offset: 0, len: 0 },
            },
            zip64_evidence: None,
        };
        let fail_at = compressed.len() / 2;
        let reader = BufReader::with_capacity(
            13,
            FailingSnapshotReader {
                bytes: compressed,
                position: 0,
                fail_at,
            },
        );
        let budget = Policy::default_v1().compile().unwrap().budget;
        let mut sink = io::sink();

        let finding = verify_payload(
            reader,
            PayloadPlan::from_zip(&member),
            budget,
            u64::MAX,
            &mut sink,
        )
        .unwrap_err();

        assert_eq!(finding.code, FindingCode::SourceIo);
        assert_eq!(finding.detail, "injected private snapshot read failure");
    }

    #[test]
    fn stored_member_verification_handles_repeated_short_reads() {
        let payload: Vec<u8> = (0_u8..=255).cycle().take(200_000).collect();
        let member = ZipMember {
            raw_name: b"stream.bin".to_vec(),
            name: "stream.bin".to_owned(),
            method: 0,
            flags: 0,
            creator_system: 0,
            external_attributes: 0,
            crc: crc32fast::hash(&payload),
            comp_size: payload.len() as u64,
            uncomp_size: payload.len() as u64,
            lfh_offset: 0,
            data_offset: 0,
            record_end: payload.len() as u64,
            is_dir: false,
            extra_fields: Vec::new(),
            source_ranges: crate::ir::MemberSourceRanges {
                local_header: crate::ir::ByteRange { offset: 0, len: 0 },
                compressed_payload: crate::ir::ByteRange {
                    offset: 0,
                    len: payload.len() as u64,
                },
                data_descriptor: None,
                central_header: crate::ir::ByteRange { offset: 0, len: 0 },
            },
            zip64_evidence: None,
        };
        let chunked = ChunkedReader {
            inner: Cursor::new(&payload),
            max_read: 7,
        };
        let reader = BufReader::with_capacity(11, chunked);
        let budget = Policy::default_v1().compile().unwrap().budget;
        let mut output = Vec::new();

        let (actual, _, _) = verify_payload(
            reader,
            PayloadPlan::from_zip(&member),
            budget,
            u64::MAX,
            &mut output,
        )
        .unwrap();

        assert_eq!(actual, payload.len() as u64);
        assert_eq!(output, payload);
    }

    #[test]
    fn deflate_member_verification_handles_repeated_short_reads() {
        let mut state = 0x6d2b_79f5_u32;
        let payload: Vec<u8> = std::iter::repeat_with(|| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .take(200_000)
        .collect();
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let member = ZipMember {
            raw_name: b"stream.deflate".to_vec(),
            name: "stream.deflate".to_owned(),
            method: 8,
            flags: 0,
            creator_system: 0,
            external_attributes: 0,
            crc: crc32fast::hash(&payload),
            comp_size: compressed.len() as u64,
            uncomp_size: payload.len() as u64,
            lfh_offset: 0,
            data_offset: 0,
            record_end: compressed.len() as u64,
            is_dir: false,
            extra_fields: Vec::new(),
            source_ranges: crate::ir::MemberSourceRanges {
                local_header: crate::ir::ByteRange { offset: 0, len: 0 },
                compressed_payload: crate::ir::ByteRange {
                    offset: 0,
                    len: compressed.len() as u64,
                },
                data_descriptor: None,
                central_header: crate::ir::ByteRange { offset: 0, len: 0 },
            },
            zip64_evidence: None,
        };
        let chunked = ChunkedReader {
            inner: Cursor::new(&compressed),
            max_read: 3,
        };
        let reader = BufReader::with_capacity(5, chunked);
        let budget = Policy::default_v1().compile().unwrap().budget;
        let mut output = Vec::new();

        let (actual, _, _) = verify_payload(
            reader,
            PayloadPlan::from_zip(&member),
            budget,
            u64::MAX,
            &mut output,
        )
        .unwrap();

        assert_eq!(actual, payload.len() as u64);
        assert_eq!(output, payload);
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
                    member
                        .zip_evidence()
                        .expect("ZIP member evidence")
                        .source_ranges
                        .compressed_payload
                        .offset,
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
                    member
                        .zip_evidence()
                        .expect("ZIP member evidence")
                        .source_ranges
                        .compressed_payload
                        .offset,
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
    fn snapshot_read_failure_is_indeterminate_not_malformed() {
        let finding = Finding::error(FindingCode::SourceIo, "snapshot read failed");
        let axes = parse_failure_axes(&finding);

        assert_eq!(axes.interpretation, InterpretationStatus::Indeterminate);
        assert_eq!(axes.admission, AdmissionStatus::NotEvaluated);
        assert_eq!(axes.verification, VerificationStatus::StructureOnly);
    }

    #[test]
    fn partial_verification_never_projects_as_compatibility_success() {
        let finding = Finding::error(FindingCode::SourceIo, "snapshot read failed");
        for (dest_requested, expected_exit) in [(false, 2), (true, 3)] {
            let axes = SemanticAxes::admitted_verification_stop(0, 1, &finding, dest_requested);
            assert!(matches!(compat_verdict(&axes), Verdict::Rejected));
            assert_eq!(
                compat_exit_code(&axes.admission, &axes.verification, &axes.effect),
                expected_exit
            );
        }
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
    fn destination_setup_failure_precedes_hostile_payload_verification() {
        let bytes = make_crc_mismatch_zip();
        let policy = Policy::default_v1();
        let dir = temp_dest("existing-hostile-payload");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("keep.txt"), b"keep").unwrap();
        crate::verification::reset_verify_payload_calls();

        let out = apply(Request {
            source: Source::Bytes {
                path: Some("existing-hostile-payload.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dir),
        });

        assert_eq!(crate::verification::verify_payload_calls(), 0);
        assert_eq!(out.interpretation, InterpretationStatus::Interpreted);
        assert_eq!(out.admission, AdmissionStatus::Admitted);
        assert_eq!(out.verification, VerificationStatus::StructureOnly);
        assert_eq!(out.effect, EffectStatus::Failed);
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::MaterializeExists));
        assert!(!out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::CrcMismatch));
        assert_eq!(fs::read(dir.join("keep.txt")).unwrap(), b"keep");
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

        let options = ApplyOptions::new()
            .with_interpretation_profile(ZipInterpretationProfile::StrictAsciiV2);
        let strict = apply_with_options(
            Request {
                source: Source::Path(&missing),
                policy: &policy,
                dest: None,
            },
            &options,
        );
        assert_eq!(
            strict.receipt.identities.interpretation.id,
            crate::ir::ZIP_STRICT_ASCII_V2
        );
        assert_eq!(
            strict.receipt.identities.interpretation.digest.sha256,
            crate::ir::zip_strict_ascii_v2_digest()
        );
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

        let strict = apply_strict_ascii_v2(&bytes);
        assert!(!strict.rejected(), "{:?}", strict.view.findings);
        assert_eq!(
            strict.receipt.identities.interpretation.id,
            crate::ir::ZIP_STRICT_ASCII_V2
        );
        assert_eq!(
            strict.archive_ir().unwrap().members[0]
                .zip_evidence()
                .unwrap()
                .flags,
            0x0008
        );
    }

    #[test]
    fn strict_ascii_v2_denies_every_non_descriptor_flag_bit() {
        for bit in 0..16 {
            if bit == 3 {
                continue;
            }
            let mut bytes = make_zip(&[("flags.txt", b"content")]);
            add_matching_flags(&mut bytes, 1 << bit);
            let out = apply_strict_ascii_v2(&bytes);
            assert!(out.rejected(), "flag bit {bit} was admitted");
            assert!(
                out.view
                    .findings
                    .iter()
                    .any(|finding| finding.code == FindingCode::ZipFlags),
                "flag bit {bit} findings: {:?}",
                out.view.findings
            );
            assert_eq!(
                out.receipt.identities.interpretation.id,
                crate::ir::ZIP_STRICT_ASCII_V2
            );
            assert!(out.archive_ir().is_none());
        }
    }

    #[test]
    fn strict_ascii_v2_denies_the_full_extra_field_id_domain() {
        for id in [0x0000_u16, 0x0001, 0x7855, 0x7075, 0xffff] {
            let mut bytes = make_zip(&[("extra.txt", b"content")]);
            let [lo, hi] = id.to_le_bytes();
            add_matching_extra_fields(&mut bytes, &[lo, hi, 0x00, 0x00]);
            let out = apply_strict_ascii_v2(&bytes);
            assert!(out.rejected(), "extra field 0x{id:04x} was admitted");
            assert!(
                out.view
                    .findings
                    .iter()
                    .any(|finding| finding.code == FindingCode::ZipExtra),
                "extra field 0x{id:04x} findings: {:?}",
                out.view.findings
            );
            assert!(out.archive_ir().is_none());
        }
    }

    #[test]
    fn strict_ascii_v2_denies_utf8_flag_even_for_ascii_names() {
        let mut bytes = make_zip(&[("ascii.txt", b"content")]);
        add_matching_flags(&mut bytes, 1 << 11);
        let out = apply_strict_ascii_v2(&bytes);
        assert!(out.rejected());
        assert!(out.view.findings.iter().any(|finding| {
            finding.code == FindingCode::ZipFlags && finding.detail.contains("0x0800")
        }));
    }

    #[test]
    fn wheel_utf8_v1_admits_nfc_unicode_and_binds_the_profile() {
        let bytes = make_zip(&[("caf\u{e9}.txt", b"content")]);
        let out = apply_wheel_utf8_v1(&bytes);
        assert!(!out.rejected(), "{:?}", out.view.findings);
        let ir = out.archive_ir().expect("admitted archive IR");
        assert_eq!(ir.members[0].canonical_path, "caf\u{e9}.txt");
        assert_eq!(ir.members[0].zip_evidence().unwrap().flags & 0x0800, 0x0800);
        assert_eq!(
            out.receipt.identities.interpretation.id,
            crate::ir::ZIP_WHEEL_UTF8_V1
        );
        assert_eq!(
            out.receipt.identities.interpretation.digest.sha256,
            crate::ir::zip_wheel_utf8_v1_digest()
        );
    }

    #[test]
    fn portable_utf8_v1_admits_nfc_unicode_and_binds_the_profile() {
        let bytes = make_zip(&[("caf\u{e9}.txt", b"content")]);
        let out = apply_portable_utf8_v1(&bytes);
        assert!(!out.rejected(), "{:?}", out.view.findings);
        let ir = out.archive_ir().expect("admitted archive IR");
        assert_eq!(ir.members[0].canonical_path, "caf\u{e9}.txt");
        assert_eq!(ir.members[0].zip_evidence().unwrap().flags & 0x0800, 0x0800);
        assert_eq!(
            out.receipt.identities.interpretation.id,
            crate::ir::ZIP_PORTABLE_UTF8_V1
        );
        assert_eq!(
            out.receipt.identities.interpretation.digest.sha256,
            crate::ir::zip_portable_utf8_v1_digest()
        );
    }

    #[test]
    fn portable_utf8_v1_denies_noncanonical_and_oversized_components() {
        for name in [
            "cafe\u{301}.txt".to_owned(),
            "./member.txt".to_owned(),
            "a".repeat(crate::jail::PORTABLE_NAME_MAX_COMPONENT_UTF8_BYTES + 1),
        ] {
            let bytes = make_zip(&[(&name, b"content")]);
            let out = apply_portable_utf8_v1(&bytes);
            assert!(out.rejected(), "{name:?} was admitted");
            assert!(out.view.findings.iter().any(|finding| matches!(
                finding.code,
                FindingCode::PathUnicode | FindingCode::PathInvalidChar
            )));
        }

        let sigma_collision = make_zip(&[("\u{3c3}.txt", b"sigma"), ("\u{3c2}.txt", b"final")]);
        let out = apply_portable_utf8_v1(&sigma_collision);
        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::PathCaseFold));

        let private_use = make_zip(&[("\u{e000}.txt", b"private")]);
        let out = apply_portable_utf8_v1(&private_use);
        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::PathInvalidChar));
    }

    #[test]
    fn portable_utf8_v1_materializes_nfc_unicode_without_path_drift() {
        let canonical_path = "caf\u{e9}/na\u{ef}ve.txt";
        let payload = b"portable unicode materialization";
        let bytes = make_zip(&[(canonical_path, payload)]);
        let policy = Policy::default_v1();
        let options = ApplyOptions::new()
            .with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
        let destination = temp_dest("portable-unicode-mat");
        assert!(!destination.exists());
        let outcome = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("portable-unicode.zip"),
                    data: &bytes,
                },
                policy: &policy,
                dest: Some(&destination),
            },
            &options,
        );
        assert!(outcome.wrote(), "{:?}", outcome.view.findings);
        assert_eq!(outcome.effect, EffectStatus::Committed);
        assert_eq!(
            outcome.archive_ir().unwrap().profile,
            crate::ZIP_PORTABLE_UTF8_V1
        );
        assert_eq!(
            outcome.view.members[0].path, canonical_path,
            "published path must equal the admitted NFC path"
        );
        assert_eq!(
            fs::read(destination.join("caf\u{e9}").join("na\u{ef}ve.txt")).unwrap(),
            payload
        );
        fs::remove_dir_all(&destination).unwrap();
    }

    #[test]
    fn wheel_utf8_v1_denies_non_nfc_names() {
        let bytes = make_zip(&[("cafe\u{301}.txt", b"content")]);
        let out = apply_wheel_utf8_v1(&bytes);
        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::PathUnicode));
    }

    #[test]
    fn wheel_utf8_v1_denies_unicode_case_collisions() {
        let bytes = make_zip(&[("\u{c9}.txt", b"one"), ("\u{e9}.txt", b"two")]);
        let out = apply_wheel_utf8_v1(&bytes);
        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::PathCaseFold));
    }

    #[test]
    fn wheel_utf8_v1_denies_data_descriptors_and_dot_normalization() {
        let mut descriptor = make_zip(&[("descriptor.txt", b"content")]);
        add_matching_flags(&mut descriptor, 0x0008);
        let descriptor_out = apply_wheel_utf8_v1(&descriptor);
        assert!(descriptor_out.rejected());
        assert!(descriptor_out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipFlags));

        let dot = make_zip(&[("./member.txt", b"content")]);
        let dot_out = apply_wheel_utf8_v1(&dot);
        assert!(dot_out.rejected());
        assert!(dot_out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::PathInvalidChar));
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
        let extras = &ir.members[0].zip_evidence().unwrap().extra_fields;
        assert!(extras.iter().any(|extra| {
            extra.id == 0x7855 && extra.disposition == crate::ir::ExtraDisposition::Ignored
        }));
        assert!(extras
            .iter()
            .any(|extra| extra.site == crate::ir::ExtraSite::Local));
        assert!(extras
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

        let options = ApplyOptions::new()
            .with_interpretation_profile(ZipInterpretationProfile::StrictAsciiV2);
        let strict = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("x.zip"),
                    data: b"not-a-zip",
                },
                policy: &policy,
                dest: None,
            },
            &options,
        );
        assert_eq!(
            strict.receipt.identities.interpretation.id,
            crate::ir::ZIP_STRICT_ASCII_V2
        );
        assert_eq!(
            strict.receipt.identities.interpretation.digest.sha256,
            crate::ir::zip_strict_ascii_v2_digest()
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
    fn rejects_nonzero_central_member_disk_start() {
        let mut bytes = make_zip(&[("file.txt", b"content")]);
        let central = signature_offsets(&bytes, [0x50, 0x4b, 0x01, 0x02]);
        assert_eq!(central.len(), 1);
        put_u16(&mut bytes, central[0] + 34, 1);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("spanned-member.zip"),
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
            .any(|finding| finding.code == FindingCode::ZipDiffC3Count));

        put_u16(&mut bytes, central[0] + 34, u16::MAX);
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("zip64-member-disk.zip"),
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
    fn rejects_stored_descriptor_signature_split_across_reader_buffers() {
        let mut payload = vec![0_u8; 65_538];
        payload[65_534..65_538].copy_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            writer.start_file("records.bin", options).unwrap();
            writer.write_all(&payload).unwrap();
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
