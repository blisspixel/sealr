use std::path::Path;

use super::{
    clone_source, execute_initial, prepare_operation, random_operation_id, PreparedOperation,
    ReadyOperation, WorkerReadAuthority, NOT_ENTERED_JAIL, SUPERVISED_JAIL,
};
use crate::apply::{
    finish_with_jail, first_error, member_view, with_ir, with_verified_archive, ApplyOptions,
    Source,
};
use crate::identity::OutcomeIdentities;
use crate::materialize::{CapabilityMaterializer, MaterializationMeta};
use crate::outcome::{EffectStatus, SemanticAxes, VerificationStatus};
use crate::semantic_record::worker_runtime::{self, OperationKind};
use crate::verified::VerifiedArchive;
use crate::{LinuxWorker, Policy, SupervisionError, SupervisionErrorKind};

pub(super) fn run(
    source: Source<'_>,
    destination: &Path,
    policy: &Policy,
    options: &ApplyOptions,
    worker: &LinuxWorker,
) -> Result<crate::Outcome, SupervisionError> {
    let ready = match prepare_operation(&source, policy, options, true) {
        PreparedOperation::Outcome(outcome) => return Ok(*outcome),
        PreparedOperation::Ready(ready) => *ready,
    };
    let ReadyOperation {
        snapshot,
        ir,
        mut findings,
        context,
    } = ready;
    let source_digest = snapshot.digest().clone();
    let identities = OutcomeIdentities::unavailable_for(source_digest.clone(), context.profile());

    let mut stage = match CapabilityMaterializer::create(destination, policy.atomic) {
        Ok(stage) => stage,
        Err(setup_error) => {
            let (setup_findings, cleanup, windows) = setup_error.into_parts();
            findings.extend(setup_findings);
            let materialization =
                MaterializationMeta::setup_failed(policy.atomic, cleanup, windows);
            let cause = first_error(&findings);
            let outcome = finish_with_jail(
                (snapshot.path_owned(), source_digest, snapshot.kind()),
                "zip",
                policy,
                findings,
                Vec::new(),
                materialization,
                SemanticAxes::admitted_setup_failed(&cause),
                identities,
                NOT_ENTERED_JAIL,
            );
            return Ok(with_ir(outcome, ir));
        }
    };

    let operation_id = match random_operation_id() {
        Ok(operation_id) => operation_id,
        Err(error) => return Err(abort_infrastructure(&mut stage, error)),
    };
    let target = match stage.target_digest() {
        Ok(target) => target,
        Err(finding) => {
            return Err(abort_infrastructure(
                &mut stage,
                SupervisionError::new(
                    SupervisionErrorKind::RestrictionUnavailable,
                    format_finding("binding destination authority", &finding),
                ),
            ));
        }
    };
    let planning = match worker_runtime::prepare_ready_plan(
        &snapshot,
        &ir,
        &findings,
        &context,
        operation_id,
        OperationKind::Materialize,
        Some(target),
        options.retention_plan(),
    ) {
        Ok(planning) => planning,
        Err(detail) => {
            return Err(abort_infrastructure(
                &mut stage,
                SupervisionError::new(SupervisionErrorKind::Internal, detail),
            ));
        }
    };
    let stage_descriptor = match stage.try_clone_worker_file() {
        Ok(descriptor) => descriptor,
        Err(finding) => {
            return Err(abort_infrastructure(
                &mut stage,
                SupervisionError::new(
                    SupervisionErrorKind::RestrictionUnavailable,
                    format_finding("cloning stage authority", &finding),
                ),
            ));
        }
    };
    let source_len = snapshot.len();
    let result = match execute_initial(
        worker,
        &snapshot,
        operation_id,
        &planning,
        Some(&stage_descriptor),
        OperationKind::Materialize,
    ) {
        Ok(result) => result,
        Err(error) => return Err(abort_infrastructure(&mut stage, error)),
    };
    drop(stage_descriptor);

    let replay_source = match clone_source(&snapshot) {
        Ok(source) => source,
        Err(error) => return Err(abort_infrastructure(&mut stage, error)),
    };
    let authorized = match worker_runtime::authorize_execution(
        replay_source,
        source_len,
        operation_id,
        &planning,
        &result.completion,
        &result.retained,
        OperationKind::Materialize,
    ) {
        Ok(authorized) => authorized,
        Err(detail) => {
            return Err(abort_infrastructure(
                &mut stage,
                SupervisionError::new(SupervisionErrorKind::IntegrityMismatch, detail),
            ));
        }
    };

    let evidence = authorized.completion_evidence();
    if evidence.member_count != authorized.archive_ir().members().len() as u64 {
        return Err(abort_infrastructure(
            &mut stage,
            SupervisionError::new(
                SupervisionErrorKind::IntegrityMismatch,
                "authorized member count differs from the authorized IR",
            ),
        ));
    }
    let mut members = authorized
        .archive_ir()
        .members()
        .iter()
        .filter(|member| matches!(member.verification, crate::MemberVerification::Verified))
        .map(member_view)
        .collect::<Vec<_>>();
    members.sort_by(|left, right| left.path.cmp(&right.path));

    if !matches!(authorized.verification, VerificationStatus::Complete) {
        let mut outcome_findings = authorized.findings.clone();
        let materialization = abort_semantic(&mut stage, &mut outcome_findings);
        let axes = SemanticAxes {
            interpretation: authorized.interpretation.clone(),
            admission: authorized.admission.clone(),
            verification: authorized.verification.clone(),
            effect: EffectStatus::Failed,
            view_completeness: authorized.view_completeness.clone(),
        };
        let outcome = finish_with_jail(
            (snapshot.path_owned(), source_digest, snapshot.kind()),
            "zip",
            policy,
            outcome_findings,
            members,
            materialization,
            axes,
            identities,
            SUPERVISED_JAIL,
        );
        return Ok(with_ir(outcome, authorized.ir));
    }

    if !evidence.complete
        || evidence.verified_members != evidence.member_count
        || authorized
            .archive_ir()
            .members()
            .iter()
            .any(|member| !matches!(member.verification, crate::MemberVerification::Verified))
    {
        return Err(abort_infrastructure(
            &mut stage,
            SupervisionError::new(
                SupervisionErrorKind::IntegrityMismatch,
                "complete worker evidence contains an unverified member",
            ),
        ));
    }

    let mut outcome_findings = authorized.findings.clone();
    let publication_error = if let Err(finding) = stage.audit_against(authorized.archive_ir()) {
        Some(finding)
    } else {
        stage.commit().err()
    };
    let (materialization, axes) = match publication_error {
        Some(finding) => {
            outcome_findings.push(finding);
            let materialization = abort_semantic(&mut stage, &mut outcome_findings);
            let cause = first_error(&outcome_findings);
            (
                materialization,
                SemanticAxes::admitted_publication_failed(&cause),
            )
        }
        None => (stage.report(), SemanticAxes::materialize_committed()),
    };

    let outcome = finish_with_jail(
        (snapshot.path_owned(), source_digest, snapshot.kind()),
        "zip",
        policy,
        outcome_findings,
        members,
        materialization,
        axes,
        identities,
        SUPERVISED_JAIL,
    );
    let authority = WorkerReadAuthority::new(
        snapshot,
        worker.clone(),
        operation_id,
        planning,
        result.completion,
        OperationKind::Materialize,
    );
    let archive = VerifiedArchive::new_supervised(
        authority,
        authorized.ir,
        context.controls().budget,
        authorized.retention,
    );
    Ok(with_verified_archive(outcome, archive))
}

fn abort_semantic(
    stage: &mut CapabilityMaterializer,
    findings: &mut Vec<crate::Finding>,
) -> MaterializationMeta {
    if let Err(finding) = stage.abort() {
        findings.push(finding);
        if let Err(finding) = stage.abort() {
            findings.push(finding);
        }
    }
    stage.report()
}

fn abort_infrastructure(
    stage: &mut CapabilityMaterializer,
    original: SupervisionError,
) -> SupervisionError {
    let Err(first) = stage.abort() else {
        return original;
    };
    let Err(second) = stage.abort() else {
        return original;
    };
    SupervisionError::new(
        SupervisionErrorKind::Cleanup,
        format!(
            "{original}; stage cleanup failed twice: {}; {}",
            format_finding("first cleanup", &first),
            format_finding("final cleanup", &second)
        ),
    )
}

fn format_finding(context: &str, finding: &crate::Finding) -> String {
    format!("{context}: {}: {}", finding.code.as_str(), finding.detail)
}
