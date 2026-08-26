//! Plan-native inspect execution for the dormant semantic-record experiment.

use std::collections::BTreeMap;
use std::io::{self, BufReader};

use sha2::{Digest, Sha256};

use super::{
    encode_completion, retained_content, validate_snapshot_binding, CompletionDisposition,
    CompletionRecord, MemberCompletion, PlanningDisposition, RecordError, RecordErrorKind,
    RequestedEffect, RetentionBinding, ValidatedPlanningRecord,
};
use crate::findings::{Finding, FindingCode};
use crate::ir::{IrMember, MemberKind};
use crate::materialize::{process_member_to_file, StageWriteRoot};
use crate::quota::{QuotaError, QuotaState};
use crate::snapshot::SourceSnapshot;
use crate::verification::{verify_payload, PayloadSpec};
use crate::verified::{RetentionBuild, RetentionEntry};
use crate::zip;

#[cfg(test)]
thread_local! {
    static FAIL_STATE_RESERVATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Debug)]
pub(super) struct ValidatedInspectPlan<'source> {
    planning: ValidatedPlanningRecord,
    snapshot: SourceSnapshot<'source>,
}

#[derive(Debug)]
pub(super) struct ExecutedInspectPlan<'source> {
    planning: ValidatedPlanningRecord,
    _snapshot: SourceSnapshot<'source>,
    completion: Vec<u8>,
    retained_content: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct ValidatedMaterializePlan<'source> {
    planning: ValidatedPlanningRecord,
    snapshot: SourceSnapshot<'source>,
    stage: Option<StageWriteRoot>,
}

#[derive(Debug)]
pub(super) struct ExecutedMaterializePlan<'source> {
    planning: ValidatedPlanningRecord,
    _snapshot: SourceSnapshot<'source>,
    _stage: Option<StageWriteRoot>,
    completion: Vec<u8>,
    retained_content: Vec<u8>,
}

struct ExecutionOutput {
    completion: Vec<u8>,
    retained_content: Vec<u8>,
}

impl ValidatedPlanningRecord {
    pub(super) fn bind_inspect_execution<'source>(
        self,
        snapshot: SourceSnapshot<'source>,
    ) -> Result<ValidatedInspectPlan<'source>, RecordError> {
        if !matches!(
            self.record.disposition,
            PlanningDisposition::ReadyForVerification
        ) || self.record.ir.is_none()
        {
            return Err(RecordError::new(
                RecordErrorKind::PhaseMismatch,
                0,
                "only a ready plan with a pending IR can enter inspect execution",
            ));
        }
        if self.record.binding.requested_effect != RequestedEffect::Inspect {
            return Err(RecordError::new(
                RecordErrorKind::PhaseMismatch,
                0,
                "materialization planning cannot enter inspect execution",
            ));
        }
        if let RetentionBinding::Plan {
            max_member_bytes,
            max_total_bytes,
            ..
        } = &self.record.binding.retention
        {
            if *max_member_bytes > retained_content::MAX_TRANSFER_CONTENT_BYTES as u64
                || *max_total_bytes > retained_content::MAX_TRANSFER_CONTENT_BYTES as u64
            {
                return Err(RecordError::new(
                    RecordErrorKind::LimitExceeded,
                    0,
                    "retention plan exceeds the isolated transfer content bound",
                ));
            }
        }
        validate_snapshot_binding(&snapshot, &self.record.binding)?;
        Ok(ValidatedInspectPlan {
            planning: self,
            snapshot,
        })
    }

    pub(super) fn bind_materialize_execution<'source>(
        self,
        snapshot: SourceSnapshot<'source>,
        stage: StageWriteRoot,
    ) -> Result<ValidatedMaterializePlan<'source>, RecordError> {
        self.bind_materialize(snapshot, Some(stage))
    }

    pub(super) fn bind_materialize_replay<'source>(
        self,
        snapshot: SourceSnapshot<'source>,
    ) -> Result<ValidatedMaterializePlan<'source>, RecordError> {
        self.bind_materialize(snapshot, None)
    }

    fn bind_materialize<'source>(
        self,
        snapshot: SourceSnapshot<'source>,
        stage: Option<StageWriteRoot>,
    ) -> Result<ValidatedMaterializePlan<'source>, RecordError> {
        if !matches!(
            self.record.disposition,
            PlanningDisposition::ReadyForVerification
        ) || self.record.ir.is_none()
        {
            return Err(RecordError::new(
                RecordErrorKind::PhaseMismatch,
                0,
                "only a ready plan with a pending IR can enter materialize execution",
            ));
        }
        if self.record.binding.requested_effect != RequestedEffect::Materialize {
            return Err(RecordError::new(
                RecordErrorKind::PhaseMismatch,
                0,
                "inspect planning cannot enter materialize execution",
            ));
        }
        if self.record.binding.target_sha256.is_none()
            || !matches!(self.record.binding.retention, RetentionBinding::None)
        {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "materialize execution requires a target binding and no retention transfer",
            ));
        }
        validate_snapshot_binding(&snapshot, &self.record.binding)?;
        Ok(ValidatedMaterializePlan {
            planning: self,
            snapshot,
            stage,
        })
    }
}

impl<'source> ValidatedInspectPlan<'source> {
    pub(super) fn execute(self) -> Result<ExecutedInspectPlan<'source>, RecordError> {
        let output = execute_completion(&self.planning, &self.snapshot, None)?;
        Ok(ExecutedInspectPlan {
            planning: self.planning,
            _snapshot: self.snapshot,
            completion: output.completion,
            retained_content: output.retained_content,
        })
    }
}

impl ExecutedInspectPlan<'_> {
    pub(super) fn planning(&self) -> &ValidatedPlanningRecord {
        &self.planning
    }

    pub(super) fn completion(&self) -> &[u8] {
        &self.completion
    }

    pub(super) fn retained_content(&self) -> &[u8] {
        &self.retained_content
    }
}

impl<'source> ValidatedMaterializePlan<'source> {
    pub(super) fn execute(self) -> Result<ExecutedMaterializePlan<'source>, RecordError> {
        let output = execute_completion(&self.planning, &self.snapshot, self.stage.as_ref())?;
        Ok(ExecutedMaterializePlan {
            planning: self.planning,
            _snapshot: self.snapshot,
            _stage: self.stage,
            completion: output.completion,
            retained_content: output.retained_content,
        })
    }
}

impl ExecutedMaterializePlan<'_> {
    pub(super) fn planning(&self) -> &ValidatedPlanningRecord {
        &self.planning
    }

    pub(super) fn completion(&self) -> &[u8] {
        &self.completion
    }

    pub(super) fn retained_content(&self) -> &[u8] {
        &self.retained_content
    }
}

fn execute_completion(
    planning: &ValidatedPlanningRecord,
    snapshot: &SourceSnapshot<'_>,
    stage: Option<&StageWriteRoot>,
) -> Result<ExecutionOutput, RecordError> {
    let ir = planning.record.ir.as_ref().ok_or_else(|| {
        RecordError::new(
            RecordErrorKind::PhaseMismatch,
            0,
            "ready execution plan lost its pending IR",
        )
    })?;
    let mut members = Vec::new();
    reserve_member_states(&mut members, ir.members.len())?;
    let mut actual_total = QuotaState::new(planning.record.binding.budget.max_total_bytes);
    let retention_plan = retained_content::retention_plan(&planning.record.binding.retention)?;
    let mut retention = RetentionBuild::plan(retention_plan.as_ref(), ir);

    #[cfg(test)]
    crate::snapshot::arm_test_read_failure();

    for member in &ir.members {
        if matches!(member.kind, MemberKind::Directory) {
            if let Some(stage) = stage {
                if let Err(finding) =
                    stage.create_directory(&member.components, &member.decoded_name)
                {
                    let completion =
                        stopped_completion(planning, members, ir.members.len(), finding)?;
                    return finish_execution(planning, completion, retention.into_entries());
                }
            }
            members.push(MemberCompletion::Verified {
                actual_uncomp_size: 0,
                actual_crc: 0,
                content_sha256: Sha256::digest([]).into(),
            });
            continue;
        }

        let payload = match zip::planned_payload_reader(snapshot, member) {
            Ok(payload) => payload,
            Err(finding) => {
                let completion = stopped_completion(planning, members, ir.members.len(), finding)?;
                return finish_execution(planning, completion, retention.into_entries());
            }
        };
        let payload = BufReader::with_capacity(64 * 1024, payload);
        let mut capture = retention.begin_capture(&member.canonical_path);
        let verified = if let Some(stage) = stage {
            stage.create_file(&member.components).and_then(|file| {
                process_member_to_file(
                    payload,
                    PayloadSpec::from_ir(member),
                    planning.record.binding.budget,
                    actual_total.remaining(),
                    planning.record.binding.member_sync,
                    capture.as_mut(),
                    file,
                )
            })
        } else {
            match capture.as_mut() {
                Some(bytes) => verify_payload(
                    payload,
                    PayloadSpec::from_ir(member),
                    planning.record.binding.budget,
                    actual_total.remaining(),
                    bytes,
                ),
                None => {
                    let mut sink = io::sink();
                    verify_payload(
                        payload,
                        PayloadSpec::from_ir(member),
                        planning.record.binding.budget,
                        actual_total.remaining(),
                        &mut sink,
                    )
                }
            }
        };
        let (actual, crc, content_sha256) = match verified {
            Ok(verified) => verified,
            Err(finding) => {
                let finding = finding.on(&member.decoded_name);
                if !execution_failure_reachable(planning, member, finding.code) {
                    return Err(unreachable_execution_failure(finding.code));
                }
                let completion = stopped_completion(planning, members, ir.members.len(), finding)?;
                return finish_execution(planning, completion, retention.into_entries());
            }
        };
        if crc != member.declared_crc {
            let finding = Finding::error(
                FindingCode::CrcMismatch,
                format!("got {crc:08x} want {:08x}", member.declared_crc),
            )
            .on(&member.decoded_name);
            let completion = stopped_completion(planning, members, ir.members.len(), finding)?;
            return finish_execution(planning, completion, retention.into_entries());
        }
        actual_total.consume(actual).map_err(|error| {
            let detail = match error {
                QuotaError::Overflow => {
                    "validated execution actual-size aggregate overflowed unexpectedly"
                }
                QuotaError::Exceeded { .. } => {
                    "validated execution exceeded its admitted aggregate unexpectedly"
                }
            };
            RecordError::new(RecordErrorKind::InvalidSemanticState, 0, detail)
        })?;
        retention.finish_capture(&member.canonical_path, capture);
        members.push(MemberCompletion::Verified {
            actual_uncomp_size: actual,
            actual_crc: crc,
            content_sha256,
        });
    }

    let completion = encode_completion(
        &CompletionRecord {
            operation_id: planning.record.binding.operation_id,
            request_id: planning.request_id,
            plan_id: planning.plan_id,
            disposition: CompletionDisposition::Complete,
            members,
            findings: Vec::new(),
        },
        planning,
    )?;
    finish_execution(planning, completion, retention.into_entries())
}

fn finish_execution(
    planning: &ValidatedPlanningRecord,
    completion: Vec<u8>,
    retention: BTreeMap<String, RetentionEntry>,
) -> Result<ExecutionOutput, RecordError> {
    let retained_content = retained_content::encode(planning, &completion, &retention)?;
    Ok(ExecutionOutput {
        completion,
        retained_content,
    })
}

fn stopped_completion(
    planning: &ValidatedPlanningRecord,
    mut members: Vec<MemberCompletion>,
    total_members: usize,
    finding: Finding,
) -> Result<Vec<u8>, RecordError> {
    let verified_members = members.len() as u64;
    let cause = finding.code;
    members.push(MemberCompletion::Failed { cause });
    while members.len() < total_members {
        members.push(MemberCompletion::Pending);
    }
    encode_completion(
        &CompletionRecord {
            operation_id: planning.record.binding.operation_id,
            request_id: planning.request_id,
            plan_id: planning.plan_id,
            disposition: CompletionDisposition::Stopped {
                verified_members,
                pending_members: total_members as u64 - verified_members,
            },
            members,
            findings: vec![finding],
        },
        planning,
    )
}

fn execution_failure_reachable(
    planning: &ValidatedPlanningRecord,
    member: &IrMember,
    code: FindingCode,
) -> bool {
    (planning.record.binding.requested_effect == RequestedEffect::Materialize
        && matches!(
            code,
            FindingCode::MaterializeIo | FindingCode::MaterializeUnsafeComponent
        ))
        || inspect_failure_reachable(member, code)
}

pub(super) fn inspect_failure_reachable(member: &IrMember, code: FindingCode) -> bool {
    if matches!(member.kind, MemberKind::Directory) {
        return false;
    }
    matches!(
        code,
        FindingCode::SourceIo | FindingCode::QuotaDeclaredLie | FindingCode::CrcMismatch
    ) || (member.method == 8
        && matches!(
            code,
            FindingCode::CodecDeflateInvalidStream | FindingCode::CodecDeflateTrailingInput
        ))
}

fn unreachable_execution_failure(code: FindingCode) -> RecordError {
    RecordError::new(
        RecordErrorKind::InvalidSemanticState,
        0,
        match code {
            FindingCode::QuotaMember => {
                "validated execution reached an impossible member-quota failure"
            }
            FindingCode::QuotaTotal => {
                "validated execution reached an impossible total-quota failure"
            }
            FindingCode::QuotaRatio => {
                "validated execution reached an impossible ratio-quota failure"
            }
            FindingCode::QuotaOverflow => {
                "validated execution reached an impossible quota-overflow failure"
            }
            FindingCode::MethodUnsupported => {
                "validated execution reached an impossible method failure"
            }
            _ => "validated execution reached a member-incoherent failure",
        },
    )
}

fn reserve_member_states(
    members: &mut Vec<MemberCompletion>,
    count: usize,
) -> Result<(), RecordError> {
    #[cfg(test)]
    if FAIL_STATE_RESERVATION.with(std::cell::Cell::get) {
        return Err(RecordError::new(
            RecordErrorKind::AllocationFailed,
            0,
            "bounded execution member-state allocation failed",
        ));
    }
    members.try_reserve_exact(count).map_err(|_| {
        RecordError::new(
            RecordErrorKind::AllocationFailed,
            0,
            "bounded execution member-state allocation failed",
        )
    })
}

#[cfg(test)]
pub(super) struct StateReservationFailureGuard {
    previous: bool,
}

#[cfg(test)]
impl Drop for StateReservationFailureGuard {
    fn drop(&mut self) {
        FAIL_STATE_RESERVATION.with(|enabled| enabled.set(self.previous));
    }
}

#[cfg(test)]
pub(super) fn fail_state_reservation() -> StateReservationFailureGuard {
    let previous = FAIL_STATE_RESERVATION.with(|enabled| enabled.replace(true));
    StateReservationFailureGuard { previous }
}
