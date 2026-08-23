//! Plan-native inspect execution for the dormant semantic-record experiment.

use std::io::{self, BufReader};

use sha2::{Digest, Sha256};

use super::{
    encode_completion, validate_snapshot_binding, CompletionDisposition, CompletionRecord,
    MemberCompletion, PlanningDisposition, RecordError, RecordErrorKind, RequestedEffect,
    RetentionBinding, ValidatedPlanningRecord,
};
use crate::findings::{Finding, FindingCode};
use crate::ir::{IrMember, MemberKind};
use crate::quota::{QuotaError, QuotaState};
use crate::snapshot::SourceSnapshot;
use crate::verification::{verify_payload, PayloadSpec};
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
        if !matches!(self.record.binding.retention, RetentionBinding::None) {
            return Err(RecordError::new(
                RecordErrorKind::PhaseMismatch,
                0,
                "retention planning cannot enter execution before content transfer exists",
            ));
        }
        validate_snapshot_binding(&snapshot, &self.record.binding)?;
        Ok(ValidatedInspectPlan {
            planning: self,
            snapshot,
        })
    }
}

impl<'source> ValidatedInspectPlan<'source> {
    pub(super) fn execute(self) -> Result<ExecutedInspectPlan<'source>, RecordError> {
        let completion = execute_completion(&self.planning, &self.snapshot)?;
        Ok(ExecutedInspectPlan {
            planning: self.planning,
            _snapshot: self.snapshot,
            completion,
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
}

fn execute_completion(
    planning: &ValidatedPlanningRecord,
    snapshot: &SourceSnapshot<'_>,
) -> Result<Vec<u8>, RecordError> {
    let ir = planning.record.ir.as_ref().ok_or_else(|| {
        RecordError::new(
            RecordErrorKind::PhaseMismatch,
            0,
            "ready inspect plan lost its pending IR",
        )
    })?;
    let mut members = Vec::new();
    reserve_member_states(&mut members, ir.members.len())?;
    let mut actual_total = QuotaState::new(planning.record.binding.budget.max_total_bytes);

    #[cfg(test)]
    crate::snapshot::arm_test_read_failure();

    for member in &ir.members {
        if matches!(member.kind, MemberKind::Directory) {
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
                return stopped_completion(planning, members, ir.members.len(), finding);
            }
        };
        let payload = BufReader::with_capacity(64 * 1024, payload);
        let mut sink = io::sink();
        let verified = verify_payload(
            payload,
            PayloadSpec::from_ir(member),
            planning.record.binding.budget,
            actual_total.remaining(),
            &mut sink,
        );
        let (actual, crc, content_sha256) = match verified {
            Ok(verified) => verified,
            Err(finding) => {
                let finding = finding.on(&member.decoded_name);
                if !inspect_failure_reachable(member, finding.code) {
                    return Err(unreachable_execution_failure(finding.code));
                }
                return stopped_completion(planning, members, ir.members.len(), finding);
            }
        };
        if crc != member.declared_crc {
            let finding = Finding::error(
                FindingCode::CrcMismatch,
                format!("got {crc:08x} want {:08x}", member.declared_crc),
            )
            .on(&member.decoded_name);
            return stopped_completion(planning, members, ir.members.len(), finding);
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
        members.push(MemberCompletion::Verified {
            actual_uncomp_size: actual,
            actual_crc: crc,
            content_sha256,
        });
    }

    encode_completion(
        &CompletionRecord {
            operation_id: planning.record.binding.operation_id,
            request_id: planning.request_id,
            plan_id: planning.plan_id,
            disposition: CompletionDisposition::Complete,
            members,
            findings: Vec::new(),
        },
        planning,
    )
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
