//! Feature-gated bridge for the repository-only Linux worker lab.

use std::fs::File;

use super::{
    decode_completion, decode_planning, encode_planning, parse_hex_32, InvocationBinding,
    PlanningDisposition, PlanningRecord, RequestedEffect, RetentionBinding,
};
use crate::apply::{plan_source, PlanDecision, PlanningContext, Source};
use crate::ir::{MemberVerification, ZipInterpretationProfile};
use crate::outcome::VerificationStatus;
use crate::policy::Policy;
use crate::snapshot::SourceSnapshot;

/// A canonical planning record bound to the exact worker source descriptor.
#[derive(Debug)]
pub struct ValidatedInspectOperation {
    planning: super::ValidatedPlanningRecord,
    snapshot: SourceSnapshot<'static>,
}

/// Completed execution that retains the exact source through observation.
#[derive(Debug)]
pub struct ExecutedInspectOperation {
    executed: super::executor::ExecutedInspectPlan<'static>,
}

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

/// Validate one canonical plan against the exact read-only source descriptor.
pub fn validate_inspect(
    source: File,
    source_len: u64,
    operation_id: [u8; 16],
    planning: &[u8],
) -> Result<ValidatedInspectOperation, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let snapshot = SourceSnapshot::worker_lab_from_file(
        source,
        Some("worker-lab.zip".into()),
        source_len,
        context.controls().budget.max_archive_bytes,
    )
    .map_err(debug_error)?;
    let binding = inspect_binding(&snapshot, &context, operation_id)?;
    let planning = decode_planning(planning, &binding, &snapshot).map_err(debug_error)?;
    Ok(ValidatedInspectOperation { planning, snapshot })
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
    Ok(completion_evidence(proposal))
}

/// Replay one accepted plan against the supervisor's exact retained source and
/// require the worker completion to equal the source-derived canonical bytes.
/// This is independent of worker output, but deliberately reuses the same
/// bounded verifier implementation.
pub fn authorize_inspect_completion(
    source: File,
    source_len: u64,
    operation_id: [u8; 16],
    planning: &[u8],
    completion: &[u8],
) -> Result<InspectCompletionEvidence, String> {
    let policy = Policy::default_v1();
    let context = context(&policy)?;
    let snapshot = SourceSnapshot::worker_lab_from_file(
        source,
        Some("worker-lab-supervisor.zip".into()),
        source_len,
        context.controls().budget.max_archive_bytes,
    )
    .map_err(debug_error)?;
    let binding = inspect_binding(&snapshot, &context, operation_id)?;
    let planning = decode_planning(planning, &binding, &snapshot).map_err(debug_error)?;
    let executed = planning
        .bind_inspect_execution(snapshot)
        .map_err(debug_error)?
        .execute()
        .map_err(debug_error)?;
    if executed.completion() != completion {
        return Err(
            "worker completion differs from the supervisor's source-derived replay".to_owned(),
        );
    }
    let proposal =
        decode_completion(executed.completion(), executed.planning()).map_err(debug_error)?;
    Ok(completion_evidence(proposal))
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

impl ValidatedInspectOperation {
    /// Read the existing authority probe byte through the bound snapshot.
    pub fn source_probe(&self) -> Result<u8, String> {
        let mut byte = [0_u8; 1];
        self.snapshot
            .read_exact_at(0, &mut byte)
            .map_err(debug_error)?;
        Ok(byte[0])
    }

    /// Consume the validated plan and execute only its planned payload ranges.
    pub fn execute(self) -> Result<ExecutedInspectOperation, String> {
        let executed = self
            .planning
            .bind_inspect_execution(self.snapshot)
            .map_err(debug_error)?
            .execute()
            .map_err(debug_error)?;
        Ok(ExecutedInspectOperation { executed })
    }
}

impl ExecutedInspectOperation {
    /// Return the canonical semantic completion bytes.
    pub fn completion(&self) -> &[u8] {
        self.executed.completion()
    }

    /// Revalidate the generated completion against its retained planning state.
    pub fn evidence(&self) -> Result<InspectCompletionEvidence, String> {
        let proposal = decode_completion(self.executed.completion(), self.executed.planning())
            .map_err(debug_error)?;
        Ok(completion_evidence(proposal))
    }
}

fn completion_evidence(proposal: super::BoundCompletionProposal) -> InspectCompletionEvidence {
    let verified_members = proposal
        .ir
        .members
        .iter()
        .filter(|member| matches!(member.verification, MemberVerification::Verified))
        .count() as u64;
    InspectCompletionEvidence {
        complete: proposal.verification == VerificationStatus::Complete,
        member_count: proposal.ir.members.len() as u64,
        verified_members,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::{Cursor, Write};
    use std::path::PathBuf;

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

    fn source_file(source: &[u8]) -> (File, PathBuf) {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("sealr-worker-lab-{suffix}.zip"));
        let mut writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        writer.write_all(source).unwrap();
        drop(writer);
        (File::open(&path).unwrap(), path)
    }

    #[test]
    fn bridge_executes_real_plan_without_structural_reparse() {
        let source = source();
        let operation_id = [0x41; 16];
        let planning = plan_inspect(&source, operation_id).unwrap();

        crate::zip::reset_parse_calls();
        crate::verification::reset_verify_payload_calls();
        let (file, path) = source_file(&source);
        let operation =
            validate_inspect(file, source.len() as u64, operation_id, &planning).unwrap();
        assert_eq!(operation.source_probe().unwrap(), source[0]);
        let executed = operation.execute().unwrap();
        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(crate::verification::verify_payload_calls(), 1);

        let evidence = executed.evidence().unwrap();
        assert_eq!(
            evidence,
            InspectCompletionEvidence {
                complete: true,
                member_count: 1,
                verified_members: 1,
            }
        );
        assert_eq!(crate::zip::parse_calls(), 0);
        validate_inspect_completion(&source, operation_id, &planning, executed.completion())
            .unwrap();
        let authority = authorize_inspect_completion(
            File::open(&path).unwrap(),
            source.len() as u64,
            operation_id,
            &planning,
            executed.completion(),
        )
        .unwrap();
        assert_eq!(authority, evidence);
        assert_eq!(crate::zip::parse_calls(), 0);
        assert_eq!(crate::verification::verify_payload_calls(), 2);
        drop(executed);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn bridge_rejects_operation_and_source_drift() {
        let source = source();
        let operation_id = [0x41; 16];
        let planning = plan_inspect(&source, operation_id).unwrap();
        let (file, path) = source_file(&source);
        assert!(validate_inspect(file, source.len() as u64, [0x42; 16], &planning).is_err());
        fs::remove_file(path).unwrap();

        let mut drifted = source;
        drifted[0] ^= 1;
        let (file, path) = source_file(&drifted);
        assert!(validate_inspect(file, drifted.len() as u64, operation_id, &planning).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn supervisor_replay_rejects_a_canonical_forged_content_digest() {
        use crate::semantic_record::{
            encode_completion, CompletionDisposition, CompletionRecord, MemberCompletion,
        };

        let source = source();
        let operation_id = [0x41; 16];
        let planning_bytes = plan_inspect(&source, operation_id).unwrap();
        let (file, path) = source_file(&source);
        let executed = validate_inspect(file, source.len() as u64, operation_id, &planning_bytes)
            .unwrap()
            .execute()
            .unwrap();
        let planning = executed.executed.planning();
        let forged = encode_completion(
            &CompletionRecord {
                operation_id,
                request_id: planning.request_id,
                plan_id: planning.plan_id,
                disposition: CompletionDisposition::Complete,
                members: vec![MemberCompletion::Verified {
                    actual_uncomp_size: b"planned payload".len() as u64,
                    actual_crc: crc32fast::hash(b"planned payload"),
                    content_sha256: [0xA5; 32],
                }],
                findings: Vec::new(),
            },
            planning,
        )
        .unwrap();
        assert!(
            validate_inspect_completion(&source, operation_id, &planning_bytes, &forged)
                .unwrap()
                .complete
        );
        let error = authorize_inspect_completion(
            File::open(&path).unwrap(),
            source.len() as u64,
            operation_id,
            &planning_bytes,
            &forged,
        )
        .unwrap_err();
        assert!(error.contains("source-derived replay"));
        drop(executed);
        fs::remove_file(path).unwrap();
    }
}
