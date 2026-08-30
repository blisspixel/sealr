//! Canonical isolated member-read requests for the supervised worker boundary.

use sha2::{Digest, Sha256};

use super::{
    components_equal_path, decode_completion, validate_jailed_name, Encoder, RecordError,
    RecordErrorKind, ValidatedPlanningRecord, KIND_MEMBER_PREFIX_READ_REQUEST,
    KIND_MEMBER_READ_REQUEST, MAX_ISOLATED_READ_BYTES, MAX_NAME_BYTES,
};
use crate::ir::{ArchiveIR, IrMember, MemberKind, MemberVerification};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MemberReadKind {
    Full,
    Prefix,
}

impl MemberReadKind {
    fn record_kind(self) -> u8 {
        match self {
            Self::Full => KIND_MEMBER_READ_REQUEST,
            Self::Prefix => KIND_MEMBER_PREFIX_READ_REQUEST,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct MemberReadRequest {
    pub(super) read_operation_id: [u8; 16],
    pub(super) path: String,
    pub(super) max_bytes: u64,
    pub(super) kind: MemberReadKind,
    pub(super) member_index: usize,
    pub(super) expected_size: u64,
    pub(super) expected_crc: u32,
    pub(super) expected_sha256: [u8; 32],
}

pub(super) struct MemberReadStreamEvidence {
    pub(super) actual_bytes: u64,
    pub(super) actual_crc: u32,
    pub(super) actual_sha256: [u8; 32],
    pub(super) retained_bytes: u64,
}

pub(super) fn encode(
    planning: &ValidatedPlanningRecord,
    completion: &[u8],
    read_operation_id: [u8; 16],
    path: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, RecordError> {
    encode_kind(
        planning,
        completion,
        read_operation_id,
        path,
        max_bytes,
        MemberReadKind::Full,
    )
}

pub(super) fn encode_prefix(
    planning: &ValidatedPlanningRecord,
    completion: &[u8],
    read_operation_id: [u8; 16],
    path: &str,
    prefix_cap: u64,
) -> Result<Vec<u8>, RecordError> {
    encode_kind(
        planning,
        completion,
        read_operation_id,
        path,
        prefix_cap,
        MemberReadKind::Prefix,
    )
}

fn encode_kind(
    planning: &ValidatedPlanningRecord,
    completion: &[u8],
    read_operation_id: [u8; 16],
    path: &str,
    max_bytes: u64,
    kind: MemberReadKind,
) -> Result<Vec<u8>, RecordError> {
    if read_operation_id == [0; 16] {
        return Err(RecordError::new(
            RecordErrorKind::BindingMismatch,
            0,
            "member-read operation ID is zero",
        ));
    }
    let proposal = decode_completion(completion, planning)?;
    let (member_index, _) = selected_member(&proposal.ir, path, max_bytes, kind)?;
    let mut encoder = Encoder::new(kind.record_kind());
    encoder.fixed(&read_operation_id);
    encoder.fixed(&planning.record.binding.operation_id);
    encoder.fixed(&planning.request_id);
    encoder.fixed(&planning.plan_id);
    let completion_sha256: [u8; 32] = Sha256::digest(completion).into();
    encoder.fixed(&completion_sha256);
    encoder.u32(u32::try_from(member_index).map_err(|_| {
        RecordError::new(
            RecordErrorKind::LimitExceeded,
            0,
            "member-read index exceeds the request integer limit",
        )
    })?);
    encoder.u32(0);
    encoder.u64(max_bytes);
    encoder.string(path)?;
    let encoded = encoder.finish()?;
    decode_kind(planning, completion, &encoded, read_operation_id, kind)?;
    Ok(encoded)
}

pub(super) fn decode(
    planning: &ValidatedPlanningRecord,
    completion: &[u8],
    input: &[u8],
    expected_read_operation_id: [u8; 16],
) -> Result<MemberReadRequest, RecordError> {
    decode_kind(
        planning,
        completion,
        input,
        expected_read_operation_id,
        MemberReadKind::Full,
    )
}

pub(super) fn decode_prefix(
    planning: &ValidatedPlanningRecord,
    completion: &[u8],
    input: &[u8],
    expected_read_operation_id: [u8; 16],
) -> Result<MemberReadRequest, RecordError> {
    decode_kind(
        planning,
        completion,
        input,
        expected_read_operation_id,
        MemberReadKind::Prefix,
    )
}

fn decode_kind(
    planning: &ValidatedPlanningRecord,
    completion: &[u8],
    input: &[u8],
    expected_read_operation_id: [u8; 16],
    kind: MemberReadKind,
) -> Result<MemberReadRequest, RecordError> {
    let proposal = decode_completion(completion, planning)?;
    let mut cursor = super::Cursor::frame(input, kind.record_kind())?;
    let read_operation_id = cursor.fixed::<16>()?;
    if read_operation_id == [0; 16] || read_operation_id != expected_read_operation_id {
        return Err(RecordError::new(
            RecordErrorKind::BindingMismatch,
            0,
            "member-read operation does not match the process boundary",
        ));
    }
    if cursor.fixed::<16>()? != planning.record.binding.operation_id
        || cursor.fixed::<32>()? != planning.request_id
        || cursor.fixed::<32>()? != planning.plan_id
    {
        return Err(RecordError::new(
            RecordErrorKind::BindingMismatch,
            0,
            "member-read request does not match the accepted operation and plan",
        ));
    }
    let completion_sha256: [u8; 32] = Sha256::digest(completion).into();
    if cursor.fixed::<32>()? != completion_sha256 {
        return Err(RecordError::new(
            RecordErrorKind::BindingMismatch,
            0,
            "member-read request does not match the accepted completion",
        ));
    }
    let member_index = cursor.u32()? as usize;
    if cursor.u32()? != 0 {
        return Err(RecordError::new(
            RecordErrorKind::ReservedNonZero,
            cursor.offset().saturating_sub(4),
            "member-read request reserved field is nonzero",
        ));
    }
    let max_bytes = cursor.u64()?;
    if kind == MemberReadKind::Full && max_bytes > MAX_ISOLATED_READ_BYTES {
        return Err(RecordError::new(
            RecordErrorKind::LimitExceeded,
            cursor.offset().saturating_sub(8),
            "member-read caller limit exceeds the isolated backend ceiling",
        ));
    }
    let path = cursor.string(MAX_NAME_BYTES, "member-read path exceeds its byte bound")?;
    cursor.finish()?;
    let jailed = validate_jailed_name(&path, u32::MAX, "member-read path is not canonical")?;
    if !jailed.actions.is_empty() || !components_equal_path(&jailed.components, &path) {
        return Err(RecordError::new(
            RecordErrorKind::InvalidString,
            0,
            "member-read path is not canonical",
        ));
    }
    let (selected_index, member) = selected_member(&proposal.ir, &path, max_bytes, kind)?;
    let expected_size = member.actual_uncomp_size.ok_or_else(|| {
        RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "verified member lacks an actual size",
        )
    })?;
    let retained_bytes = match kind {
        MemberReadKind::Full => expected_size,
        MemberReadKind::Prefix => expected_size.min(max_bytes),
    };
    if retained_bytes > MAX_ISOLATED_READ_BYTES {
        return Err(RecordError::new(
            RecordErrorKind::LimitExceeded,
            0,
            "retained member-read bytes exceed the isolated backend ceiling",
        ));
    }
    if member_index != selected_index {
        return Err(RecordError::new(
            RecordErrorKind::BindingMismatch,
            0,
            "member-read index does not match its canonical path",
        ));
    }
    Ok(MemberReadRequest {
        read_operation_id,
        path,
        max_bytes,
        kind,
        member_index,
        expected_size,
        expected_crc: member.actual_crc.ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "verified member lacks an actual CRC32",
            )
        })?,
        expected_sha256: member
            .content_sha256
            .as_deref()
            .and_then(super::parse_hex_32)
            .ok_or_else(|| {
                RecordError::new(
                    RecordErrorKind::InvalidSemanticState,
                    0,
                    "verified member lacks a canonical SHA-256",
                )
            })?,
    })
}

pub(super) fn validate_result(
    planning: &ValidatedPlanningRecord,
    completion: &[u8],
    request: &[u8],
    read_operation_id: [u8; 16],
    bytes: &[u8],
) -> Result<MemberReadRequest, RecordError> {
    let request = decode(planning, completion, request, read_operation_id)?;
    if request.kind != MemberReadKind::Full
        || bytes.len() as u64 != request.expected_size
        || crc32fast::hash(bytes) != request.expected_crc
        || <[u8; 32]>::from(Sha256::digest(bytes)) != request.expected_sha256
    {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "isolated member-read bytes disagree with authorized completion evidence",
        ));
    }
    Ok(request)
}

pub(super) fn validate_stream_result(
    planning: &ValidatedPlanningRecord,
    completion: &[u8],
    request: &[u8],
    read_operation_id: [u8; 16],
    evidence: MemberReadStreamEvidence,
    kind: MemberReadKind,
) -> Result<MemberReadRequest, RecordError> {
    let request = decode_kind(planning, completion, request, read_operation_id, kind)?;
    if evidence.actual_bytes != request.expected_size
        || evidence.actual_crc != request.expected_crc
        || evidence.actual_sha256 != request.expected_sha256
        || evidence.retained_bytes != request.retained_bytes()
    {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "isolated member-read stream disagrees with authorized completion evidence",
        ));
    }
    Ok(request)
}

impl MemberReadRequest {
    pub(super) fn retained_bytes(&self) -> u64 {
        match self.kind {
            MemberReadKind::Full => self.expected_size,
            MemberReadKind::Prefix => self.expected_size.min(self.max_bytes),
        }
    }
}

fn selected_member<'a>(
    ir: &'a ArchiveIR,
    path: &str,
    max_bytes: u64,
    kind: MemberReadKind,
) -> Result<(usize, &'a IrMember), RecordError> {
    let (index, member) = ir
        .members()
        .iter()
        .enumerate()
        .find(|(_, member)| member.canonical_path == path)
        .ok_or_else(|| {
            RecordError::new(
                RecordErrorKind::InvalidSemanticState,
                0,
                "member-read path is absent from the authorized archive",
            )
        })?;
    if matches!(member.kind, MemberKind::Directory) {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "member-read path names a directory",
        ));
    }
    if !matches!(member.verification, MemberVerification::Verified) {
        return Err(RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "member-read path is not completely verified",
        ));
    }
    let actual = member.actual_uncomp_size.ok_or_else(|| {
        RecordError::new(
            RecordErrorKind::InvalidSemanticState,
            0,
            "verified member lacks an actual size",
        )
    })?;
    if kind == MemberReadKind::Full && actual > max_bytes {
        return Err(RecordError::new(
            RecordErrorKind::LimitExceeded,
            0,
            "verified member exceeds the caller's byte limit",
        ));
    }
    if kind == MemberReadKind::Full && actual > MAX_ISOLATED_READ_BYTES {
        return Err(RecordError::new(
            RecordErrorKind::LimitExceeded,
            0,
            "verified member exceeds the isolated backend ceiling",
        ));
    }
    let retained = match kind {
        MemberReadKind::Full => actual,
        MemberReadKind::Prefix => actual.min(max_bytes),
    };
    usize::try_from(retained).map_err(|_| {
        RecordError::new(
            RecordErrorKind::LimitExceeded,
            0,
            "retained member-read size does not fit this platform",
        )
    })?;
    Ok((index, member))
}
