//! Shared bounded member-payload verification.

use std::io::{BufRead, Read, Write};

use crc32fast::Hasher as Crc;
use flate2::bufread::DeflateDecoder;
use sha2::{Digest, Sha256};

use crate::findings::{Finding, FindingCode};
use crate::ir::IrMember;
use crate::policy::{ratio_exceeds, ResourceBudget};
use crate::quota::{QuotaError, QuotaState};
use crate::snapshot::finding_from_io;

#[derive(Clone, Copy)]
pub(crate) struct PayloadSpec {
    method: u16,
    compressed_size: u64,
    uncompressed_size: u64,
}

impl PayloadSpec {
    pub(crate) fn from_ir(member: &IrMember) -> Self {
        Self {
            method: member.method,
            compressed_size: member.declared_comp_size,
            uncompressed_size: member.declared_uncomp_size,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_zip(member: &crate::zip::ZipMember) -> Self {
        Self {
            method: member.method,
            compressed_size: member.comp_size,
            uncompressed_size: member.uncomp_size,
        }
    }
}

#[cfg(test)]
thread_local! {
    static VERIFY_PAYLOAD_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_verify_payload_calls() {
    VERIFY_PAYLOAD_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(crate) fn verify_payload_calls() -> u64 {
    VERIFY_PAYLOAD_CALLS.with(std::cell::Cell::get)
}

pub(crate) fn verify_payload(
    mut payload: impl BufRead,
    member: PayloadSpec,
    budget: ResourceBudget,
    remaining_total: u64,
    writer: &mut impl Write,
) -> Result<(u64, u32, [u8; 32]), Finding> {
    #[cfg(test)]
    VERIFY_PAYLOAD_CALLS.with(|calls| calls.set(calls.get() + 1));

    let mut actual = QuotaState::new(u64::MAX);
    let mut crc = Crc::new();
    let mut sha = Sha256::new();
    let mut consume = |chunk: &[u8]| -> Result<(), Finding> {
        let actual_bytes = actual
            .consume(chunk.len() as u64)
            .map_err(|error| match error {
                QuotaError::Overflow => Finding::error(
                    FindingCode::QuotaOverflow,
                    "actual member size overflowed u64",
                ),
                QuotaError::Exceeded { .. } => {
                    unreachable!("u64::MAX quota cannot be exceeded without overflow")
                }
            })?;
        if actual_bytes > member.uncompressed_size {
            return Err(Finding::error(
                FindingCode::QuotaDeclaredLie,
                "actual bytes exceeded the declared uncompressed size",
            ));
        }
        if actual_bytes > budget.max_member_bytes {
            return Err(Finding::error(
                FindingCode::QuotaMember,
                "actual bytes exceeded the member cap",
            ));
        }
        if actual_bytes > remaining_total {
            return Err(Finding::error(
                FindingCode::QuotaTotal,
                "actual bytes exceeded the remaining archive cap",
            ));
        }
        if let Some(max_ratio) = budget.max_ratio {
            if ratio_exceeds(actual_bytes, member.compressed_size, max_ratio) {
                return Err(Finding::error(
                    FindingCode::QuotaRatio,
                    format!(
                        "actual {}:{} exceeded {max_ratio}:1",
                        actual_bytes, member.compressed_size
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
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = payload.read(&mut buffer).map_err(|error| {
                    finding_from_io(&error).unwrap_or_else(|| {
                        Finding::error(
                            FindingCode::SourceIo,
                            format!("read stored member payload: {error}"),
                        )
                    })
                })?;
                if read == 0 {
                    break;
                }
                consume(&buffer[..read])?;
            }
        }
        8 => {
            let mut decoder = DeflateDecoder::new(payload);
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = decoder.read(&mut buffer).map_err(|error| {
                    finding_from_io(&error).unwrap_or_else(|| {
                        Finding::error(
                            FindingCode::CodecDeflateInvalidStream,
                            format!("deflate: {error}"),
                        )
                    })
                })?;
                if read == 0 {
                    break;
                }
                consume(&buffer[..read])?;
            }
            let consumed = decoder.total_in();
            if consumed != member.compressed_size {
                return Err(Finding::error(
                    FindingCode::CodecDeflateTrailingInput,
                    format!(
                        "deflate consumed {consumed} of {} declared compressed bytes",
                        member.compressed_size
                    ),
                ));
            }
            if decoder.total_out() != actual.used() {
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
    let actual = actual.used();
    if actual != member.uncompressed_size {
        return Err(Finding::error(
            FindingCode::QuotaDeclaredLie,
            format!(
                "actual size {actual} != declared size {}",
                member.uncompressed_size
            ),
        ));
    }
    Ok((actual, crc.finalize(), sha.finalize().into()))
}

pub(crate) fn digest_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
