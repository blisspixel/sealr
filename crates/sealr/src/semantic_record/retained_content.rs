//! Canonical retained-content transfer for the dormant worker experiment.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::{
    decode_completion, Encoder, RecordError, RecordErrorKind, RetentionBinding,
    ValidatedPlanningRecord, KIND_RETAINED_CONTENT, MAX_RECORD_BYTES,
};
use crate::ir::{MemberKind, MemberVerification};
use crate::verified::{RetentionBuild, RetentionEntry, RetentionPlan};
use crate::verified::{MAX_RETENTION_PATHS, MAX_RETENTION_PATH_BYTES};

pub(super) const MAX_TRANSFER_CONTENT_BYTES: usize = 63 * 1024 * 1024;
const MIN_ENTRY_BYTES: usize = 12;

const STATUS_RETAINED: u8 = 1;
const STATUS_NOT_FOUND: u8 = 2;
const STATUS_NOT_FILE: u8 = 3;
const STATUS_MEMBER_LIMIT: u8 = 4;
const STATUS_TOTAL_LIMIT: u8 = 5;
const STATUS_PLATFORM_LIMIT: u8 = 6;
const STATUS_ALLOCATION_FAILED: u8 = 7;
const STATUS_INTEGRITY_MISMATCH: u8 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RetainedContentEvidence {
    pub(super) requested_paths: u64,
    pub(super) retained_members: u64,
    pub(super) retained_bytes: u64,
}

pub(super) fn retention_plan(
    binding: &RetentionBinding,
) -> Result<Option<RetentionPlan>, RecordError> {
    let RetentionBinding::Plan {
        paths,
        max_member_bytes,
        max_total_bytes,
    } = binding
    else {
        return Ok(None);
    };
    let mut plan = RetentionPlan::new(*max_member_bytes, *max_total_bytes);
    for path in paths {
        plan.add_path(path.clone()).map_err(|_| {
            RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "validated retention binding could not reconstruct its retention plan",
            )
        })?;
    }
    Ok(Some(plan))
}

pub(super) fn encode(
    planning: &ValidatedPlanningRecord,
    completion: &[u8],
    entries: &BTreeMap<String, RetentionEntry>,
) -> Result<Vec<u8>, RecordError> {
    let mut encoder = Encoder::new(KIND_RETAINED_CONTENT);
    encoder.fixed(&planning.record.binding.operation_id);
    encoder.fixed(&planning.request_id);
    encoder.fixed(&planning.plan_id);
    let completion_sha256: [u8; 32] = Sha256::digest(completion).into();
    encoder.fixed(&completion_sha256);
    encoder.u32(u32::try_from(entries.len()).map_err(|_| {
        RecordError::new(
            RecordErrorKind::LimitExceeded,
            0,
            "retained-content entry count exceeds the record integer limit",
        )
    })?);
    for (path, entry) in entries {
        encoder.string(path)?;
        encoder.u8(status_tag(entry));
        encoder.u8(0);
        encoder.u16(0);
        match entry {
            RetentionEntry::Retained(bytes) => encoder.bytes(bytes)?,
            _ => encoder.bytes(&[])?,
        }
    }
    let encoded = encoder.finish()?;
    validate(planning, completion, &encoded)?;
    Ok(encoded)
}

pub(super) fn validate(
    planning: &ValidatedPlanningRecord,
    completion: &[u8],
    input: &[u8],
) -> Result<RetainedContentEvidence, RecordError> {
    decode_inner(planning, completion, input, false).map(|(_, evidence)| evidence)
}

pub(super) fn decode(
    planning: &ValidatedPlanningRecord,
    completion: &[u8],
    input: &[u8],
) -> Result<(RetentionBuild, RetainedContentEvidence), RecordError> {
    let (entries, evidence) = decode_inner(planning, completion, input, true)?;
    let entries = entries.ok_or_else(|| {
        RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "retained-content reconstruction did not produce entries",
        )
    })?;
    Ok((RetentionBuild::from_entries(entries), evidence))
}

fn decode_inner(
    planning: &ValidatedPlanningRecord,
    completion: &[u8],
    input: &[u8],
    reconstruct: bool,
) -> Result<
    (
        Option<BTreeMap<String, RetentionEntry>>,
        RetainedContentEvidence,
    ),
    RecordError,
> {
    let proposal = decode_completion(completion, planning)?;
    let plan = retention_plan(&planning.record.binding.retention)?;
    let expected = RetentionBuild::plan(
        plan.as_ref(),
        planning.record.ir.as_ref().ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::PhaseMismatch,
                0,
                "retained content requires a ready plan with IR",
            )
        })?,
    )
    .into_entries();

    let mut cursor = super::Cursor::frame(input, KIND_RETAINED_CONTENT)?;
    if cursor.fixed::<16>()? != planning.record.binding.operation_id
        || cursor.fixed::<32>()? != planning.request_id
        || cursor.fixed::<32>()? != planning.plan_id
    {
        return Err(RecordError::new(
            RecordErrorKind::BindingMismatch,
            0,
            "retained content does not match the accepted operation and plan",
        ));
    }
    let completion_sha256: [u8; 32] = Sha256::digest(completion).into();
    if cursor.fixed::<32>()? != completion_sha256 {
        return Err(RecordError::new(
            RecordErrorKind::BindingMismatch,
            0,
            "retained content does not match the accepted completion",
        ));
    }
    let count = cursor.count(
        MAX_RETENTION_PATHS,
        MIN_ENTRY_BYTES,
        "retained-content entry count exceeds its bound or remaining bytes",
    )?;
    if count != expected.len() {
        return Err(RecordError::new(
            RecordErrorKind::BindingMismatch,
            cursor.offset(),
            "retained-content entry count differs from the retention plan",
        ));
    }

    let mut retained_members = 0_u64;
    let mut retained_bytes = 0_u64;
    let mut decoded = reconstruct.then(BTreeMap::new);
    for ((expected_path, expected_entry), index) in expected.iter().zip(0..count) {
        let path = cursor.string(
            MAX_RETENTION_PATH_BYTES,
            "retained-content path exceeds its byte bound",
        )?;
        if path != *expected_path {
            return Err(RecordError::new(
                RecordErrorKind::NonCanonicalOrder,
                cursor.offset(),
                "retained-content paths do not exactly match canonical plan order",
            ));
        }
        let status = cursor.u8()?;
        if cursor.u8()? != 0 || cursor.u16()? != 0 {
            return Err(RecordError::new(
                RecordErrorKind::ReservedNonZero,
                cursor.offset().saturating_sub(3),
                "retained-content entry reserved fields are nonzero",
            ));
        }
        let bytes = cursor.bytes_ref(
            MAX_TRANSFER_CONTENT_BYTES,
            "retained-content member exceeds the transfer bound",
        )?;
        validate_entry(expected_path, expected_entry, status, bytes, &proposal.ir)?;
        if let Some(decoded) = &mut decoded {
            let decoded_entry = decode_entry(status, bytes, cursor.offset())?;
            decoded.insert(path, decoded_entry);
        }
        if status == STATUS_RETAINED {
            retained_members = retained_members.checked_add(1).ok_or_else(|| {
                RecordError::new(
                    RecordErrorKind::IntegerOverflow,
                    index,
                    "retained-content member count overflowed",
                )
            })?;
            retained_bytes = retained_bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| {
                    RecordError::new(
                        RecordErrorKind::IntegerOverflow,
                        index,
                        "retained-content byte count overflowed",
                    )
                })?;
        }
    }
    cursor.finish()?;
    let max_total = match &planning.record.binding.retention {
        RetentionBinding::None => 0,
        RetentionBinding::Plan {
            max_total_bytes, ..
        } => *max_total_bytes,
    };
    if retained_bytes > max_total || retained_bytes > MAX_TRANSFER_CONTENT_BYTES as u64 {
        return Err(RecordError::new(
            RecordErrorKind::LimitExceeded,
            input.len(),
            "retained-content aggregate exceeds its bound",
        ));
    }
    Ok((
        decoded,
        RetainedContentEvidence {
            requested_paths: count as u64,
            retained_members,
            retained_bytes,
        },
    ))
}

fn decode_entry(status: u8, bytes: &[u8], offset: usize) -> Result<RetentionEntry, RecordError> {
    Ok(match status {
        STATUS_RETAINED => {
            let mut retained = Vec::new();
            retained.try_reserve_exact(bytes.len()).map_err(|_| {
                RecordError::new(
                    RecordErrorKind::AllocationFailed,
                    offset,
                    "bounded retained-content allocation failed",
                )
            })?;
            retained.extend_from_slice(bytes);
            RetentionEntry::Retained(retained)
        }
        STATUS_NOT_FOUND => RetentionEntry::NotFound,
        STATUS_NOT_FILE => RetentionEntry::NotFile,
        STATUS_MEMBER_LIMIT => RetentionEntry::MemberLimitExceeded,
        STATUS_TOTAL_LIMIT => RetentionEntry::TotalLimitExceeded,
        STATUS_PLATFORM_LIMIT => RetentionEntry::PlatformLimit,
        STATUS_ALLOCATION_FAILED => RetentionEntry::AllocationFailed,
        STATUS_INTEGRITY_MISMATCH => RetentionEntry::IntegrityMismatch,
        _ => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidEnum,
                offset,
                "retained-content status tag is invalid",
            ));
        }
    })
}

fn validate_entry(
    path: &str,
    expected: &RetentionEntry,
    status: u8,
    bytes: &[u8],
    ir: &crate::ir::ArchiveIR,
) -> Result<(), RecordError> {
    match expected {
        RetentionEntry::Selected { .. } => {
            if !matches!(
                status,
                STATUS_RETAINED
                    | STATUS_PLATFORM_LIMIT
                    | STATUS_ALLOCATION_FAILED
                    | STATUS_INTEGRITY_MISMATCH
            ) {
                return Err(status_mismatch());
            }
        }
        RetentionEntry::NotFound if status != STATUS_NOT_FOUND => return Err(status_mismatch()),
        RetentionEntry::NotFile if status != STATUS_NOT_FILE => return Err(status_mismatch()),
        RetentionEntry::MemberLimitExceeded if status != STATUS_MEMBER_LIMIT => {
            return Err(status_mismatch());
        }
        RetentionEntry::TotalLimitExceeded if status != STATUS_TOTAL_LIMIT => {
            return Err(status_mismatch());
        }
        RetentionEntry::PlatformLimit if status != STATUS_PLATFORM_LIMIT => {
            return Err(status_mismatch());
        }
        RetentionEntry::AllocationFailed if status != STATUS_ALLOCATION_FAILED => {
            return Err(status_mismatch());
        }
        RetentionEntry::IntegrityMismatch if status != STATUS_INTEGRITY_MISMATCH => {
            return Err(status_mismatch());
        }
        RetentionEntry::Retained(_) => {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "fresh retention selection unexpectedly contains retained bytes",
            ));
        }
        _ => {}
    }
    if status != STATUS_RETAINED {
        if !bytes.is_empty() {
            return Err(RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "non-retained status carries member bytes",
            ));
        }
        return Ok(());
    }

    let member = ir
        .members()
        .iter()
        .find(|member| member.canonical_path == path)
        .ok_or_else(status_mismatch)?;
    if matches!(member.kind, MemberKind::Directory)
        || !matches!(member.verification, MemberVerification::Verified)
        || member.actual_uncomp_size != Some(bytes.len() as u64)
        || member.actual_crc != Some(crc32fast::hash(bytes))
        || member
            .content_sha256
            .as_deref()
            .and_then(super::parse_hex_32)
            != Some(Sha256::digest(bytes).into())
    {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "retained member bytes disagree with completed verification evidence",
        ));
    }
    Ok(())
}

fn status_tag(entry: &RetentionEntry) -> u8 {
    match entry {
        RetentionEntry::Retained(_) => STATUS_RETAINED,
        RetentionEntry::NotFound => STATUS_NOT_FOUND,
        RetentionEntry::NotFile => STATUS_NOT_FILE,
        RetentionEntry::MemberLimitExceeded => STATUS_MEMBER_LIMIT,
        RetentionEntry::TotalLimitExceeded => STATUS_TOTAL_LIMIT,
        RetentionEntry::PlatformLimit => STATUS_PLATFORM_LIMIT,
        RetentionEntry::AllocationFailed => STATUS_ALLOCATION_FAILED,
        RetentionEntry::Selected { .. } | RetentionEntry::IntegrityMismatch => {
            STATUS_INTEGRITY_MISMATCH
        }
    }
}

fn status_mismatch() -> RecordError {
    RecordError::new(
        RecordErrorKind::InvalidSemanticState,
        0,
        "retained-content status disagrees with the accepted retention plan",
    )
}

const _: () = assert!(MAX_TRANSFER_CONTENT_BYTES < MAX_RECORD_BYTES);
