//! Feature-gated bridge for the repository-only Linux worker lab.

use super::{
    decode_completion, decode_planning, encode_planning, parse_hex_32, InvocationBinding,
    PlanningDisposition, PlanningRecord, RequestedEffect, RetentionBinding,
};
use crate::apply::{plan_source, PlanDecision, PlanningContext, Source};
use crate::ir::{MemberVerification, ZipInterpretationProfile};
use crate::outcome::VerificationStatus;
use crate::policy::Policy;
use crate::snapshot::SourceSnapshot;

/// Bounded semantic result observed by the repository worker lab.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InspectCompletionEvidence {
    /// Whether every planned member completed verification.
    pub complete: bool,
    /// Total members carried by the validated planning record.
    pub member_count: u64,
    /// Members with a completed verification state.
    pub verified_members: u64,
}

/// Plan one inspect operation and return its canonical semantic record.
pub fn plan_inspect(source: &[u8], operation_id: [u8; 16]) -> Result<Vec<u8>, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let source = Source::Bytes {
        path: Some("worker-lab.zip"),
        data: source,
    };
    let ready = match plan_source(&source, context).map_err(debug_error)? {
        PlanDecision::Ready(ready) => ready,
        PlanDecision::Terminal(terminal) => {
            return Err(format!(
                "worker-lab source reached terminal planning: {terminal:?}"
            ));
        }
    };
    let (snapshot, ir, findings, context) = ready.into_parts();
    let binding = inspect_binding(&snapshot, &context, operation_id)?;
    encode_planning(&PlanningRecord {
        binding,
        disposition: PlanningDisposition::ReadyForVerification,
        ir: Some(ir),
        findings,
    })
    .map_err(debug_error)
}

/// Validate one canonical plan against the exact source and execute only its
/// planned payload ranges, returning a canonical completion record.
pub fn execute_inspect(
    source: &[u8],
    operation_id: [u8; 16],
    planning: &[u8],
) -> Result<Vec<u8>, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let snapshot = SourceSnapshot::borrowed(Some("worker-lab.zip".into()), source);
    let binding = inspect_binding(&snapshot, &context, operation_id)?;
    let planning = decode_planning(planning, &binding, &snapshot).map_err(debug_error)?;
    planning
        .bind_inspect_execution(snapshot)
        .map_err(debug_error)?
        .execute()
        .map(|executed| executed.completion().to_vec())
        .map_err(debug_error)
}

/// Validate a worker completion as a canonical, plan-bound proposal. This does
/// not grant independent content authority or activate public semantic state.
pub fn validate_inspect_completion(
    source: &[u8],
    operation_id: [u8; 16],
    planning: &[u8],
    completion: &[u8],
) -> Result<InspectCompletionEvidence, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let snapshot = SourceSnapshot::borrowed(Some("worker-lab.zip".into()), source);
    let binding = inspect_binding(&snapshot, &context, operation_id)?;
    let planning = decode_planning(planning, &binding, &snapshot).map_err(debug_error)?;
    let proposal = decode_completion(completion, &planning).map_err(debug_error)?;
    let verified_members = proposal
        .ir
        .members
        .iter()
        .filter(|member| matches!(member.verification, MemberVerification::Verified))
        .count() as u64;
    Ok(InspectCompletionEvidence {
        complete: proposal.verification == VerificationStatus::Complete,
        member_count: proposal.ir.members.len() as u64,
        verified_members,
    })
}

fn context(policy: &Policy) -> Result<PlanningContext, String> {
    PlanningContext::compile(policy, ZipInterpretationProfile::StrictAsciiV2).map_err(debug_error)
}

fn inspect_binding(
    snapshot: &SourceSnapshot<'_>,
    context: &PlanningContext,
    operation_id: [u8; 16],
) -> Result<InvocationBinding, String> {
    let controls = context.controls();
    let source_sha256 = parse_hex_32(
        snapshot
            .digest()
            .sha256()
            .ok_or_else(|| "worker-lab snapshot digest is unavailable".to_owned())?,
    )
    .ok_or_else(|| "worker-lab snapshot digest is not SHA-256".to_owned())?;
    let profile_sha256 = parse_hex_32(&context.profile().digest())
        .ok_or_else(|| "worker-lab profile digest is not SHA-256".to_owned())?;
    let policy_sha256 = parse_hex_32(context.policy_sha256())
        .ok_or_else(|| "worker-lab policy digest is not SHA-256".to_owned())?;
    Ok(InvocationBinding {
        operation_id,
        source_len: snapshot.len(),
        source_sha256,
        profile: context.profile(),
        profile_sha256,
        policy_id: context.policy_id().to_owned(),
        policy_sha256,
        budget: controls.budget,
        target: controls.target,
        consumer: controls.consumer,
        requested_effect: RequestedEffect::Inspect,
        target_sha256: None,
        member_sync: controls.effect.member_sync,
        retention: RetentionBinding::None,
    })
}

fn debug_error(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;

    fn source() -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .last_modified_time(zip::DateTime::default());
            writer.start_file("planned.txt", options).unwrap();
            writer.write_all(b"planned payload").unwrap();
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    #[test]
    fn bridge_executes_real_plan_without_structural_reparse() {
        let source = source();
        let operation_id = [0x41; 16];
        let planning = plan_inspect(&source, operation_id).unwrap();

        crate::zip::reset_parse_calls();
        crate::verification::reset_verify_payload_calls();
        let completion = execute_inspect(&source, operation_id, &planning).unwrap();
        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(crate::verification::verify_payload_calls(), 1);

        let evidence =
            validate_inspect_completion(&source, operation_id, &planning, &completion).unwrap();
        assert_eq!(
            evidence,
            InspectCompletionEvidence {
                complete: true,
                member_count: 1,
                verified_members: 1,
            }
        );
        assert_eq!(crate::zip::parse_calls(), 0);
    }

    #[test]
    fn bridge_rejects_operation_and_source_drift() {
        let source = source();
        let operation_id = [0x41; 16];
        let planning = plan_inspect(&source, operation_id).unwrap();
        assert!(execute_inspect(&source, [0x42; 16], &planning).is_err());

        let mut drifted = source;
        drifted[0] ^= 1;
        assert!(execute_inspect(&drifted, operation_id, &planning).is_err());
    }
}
