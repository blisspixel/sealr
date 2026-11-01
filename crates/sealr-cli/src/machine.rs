//! Versioned machine result for one parsed sealr invocation.
//!
//! `sealr.command-result.v1` is a CLI classification document. It is not an
//! evidence lineage, a canonical receipt, or an authentication claim. Embedded
//! finding objects are copies of the library findings for typed branching.
//! They are not the digested `--view` or `--receipt` bytes.
//!
//! `failure.detail` is a diagnostic. Consumers branch on `schema`, `category`,
//! `evaluated`, the semantic axes, finding `code`s, `failure.code`, and
//! `output.status`. Any other category is unknown and is not an admission.

use sealr::{
    AdmissionStatus, EffectStatus, Finding, InterpretationStatus, Outcome, SupervisionErrorKind,
    VerificationStatus, ViewCompleteness,
};
use serde::Serialize;

pub const SCHEMA: &str = "sealr.command-result.v1";

#[derive(Serialize)]
pub struct CommandResult {
    pub schema: &'static str,
    pub category: &'static str,
    pub evaluated: bool,
    pub exit: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_exit: Option<u8>,
    pub output: OutputDelivery,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic: Option<SemanticResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureResult>,
}

#[derive(Serialize)]
pub struct OutputDelivery {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<&'static str>,
}

impl OutputDelivery {
    pub fn not_requested() -> Self {
        Self {
            status: "not-requested",
            stage: None,
        }
    }

    pub fn delivered() -> Self {
        Self {
            status: "delivered",
            stage: None,
        }
    }

    pub fn failed(stage: &'static str) -> Self {
        Self {
            status: "failed",
            stage: Some(stage),
        }
    }
}

#[derive(Serialize)]
pub struct SemanticResult {
    pub interpretation: InterpretationStatus,
    pub admission: AdmissionStatus,
    pub verification: VerificationStatus,
    pub effect: EffectStatus,
    pub view_completeness: ViewCompleteness,
    pub wrote: bool,
    pub findings: Vec<Finding>,
}

#[derive(Serialize)]
pub struct FailureResult {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_code: Option<&'static str>,
    pub detail: String,
}

pub fn semantic_result(
    outcome: &Outcome,
    output: OutputDelivery,
    process_exit: u8,
) -> CommandResult {
    CommandResult {
        schema: SCHEMA,
        category: "semantic",
        evaluated: true,
        exit: process_exit,
        semantic_exit: Some(outcome.cli_exit_code()),
        output,
        semantic: Some(SemanticResult {
            interpretation: outcome.interpretation.clone(),
            admission: outcome.admission.clone(),
            verification: outcome.verification.clone(),
            effect: outcome.effect.clone(),
            view_completeness: outcome.view_completeness.clone(),
            wrote: outcome.view.wrote,
            findings: outcome.view.findings.clone(),
        }),
        failure: None,
    }
}

pub fn setup_result(
    category: &'static str,
    exit: u8,
    failure: FailureResult,
    output: OutputDelivery,
) -> CommandResult {
    CommandResult {
        schema: SCHEMA,
        category,
        evaluated: false,
        exit,
        semantic_exit: None,
        output,
        semantic: None,
        failure: Some(failure),
    }
}

pub fn worker_code(kind: SupervisionErrorKind) -> &'static str {
    match kind {
        SupervisionErrorKind::IsolationUnavailable => "worker.isolation_unavailable",
        SupervisionErrorKind::HelperArtifact => "worker.helper_artifact",
        SupervisionErrorKind::Spawn => "worker.spawn",
        SupervisionErrorKind::Authentication => "worker.authentication",
        SupervisionErrorKind::RestrictionUnavailable => "worker.restriction_unavailable",
        SupervisionErrorKind::Protocol => "worker.protocol",
        SupervisionErrorKind::TimedOut => "worker.timed_out",
        SupervisionErrorKind::WorkerExit => "worker.exit",
        SupervisionErrorKind::Reap => "worker.reap",
        SupervisionErrorKind::Cleanup => "worker.cleanup",
        SupervisionErrorKind::Source => "worker.source",
        SupervisionErrorKind::IntegrityMismatch => "worker.integrity_mismatch",
        SupervisionErrorKind::Internal => "worker.internal",
        _ => "worker.internal",
    }
}
