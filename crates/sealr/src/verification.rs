//! Shared bounded member-payload verification.

use std::io::{BufRead, Read, Write};

use crc32fast::Hasher as Crc;
use flate2::bufread::DeflateDecoder;
use sha2::{Digest, Sha256};

use crate::findings::{Finding, FindingCode};
use crate::ir::{IrMember, MemberEvidence};
use crate::policy::{ratio_exceeds, ResourceBudget};
use crate::quota::{QuotaError, QuotaState};
use crate::snapshot::finding_from_io;
use crate::snapshot::{DomainRange, SnapshotDomainId, SnapshotSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PayloadPlan {
    source: DomainRange,
    codec: PayloadCodec,
    compressed_size: u64,
    uncompressed_size: u64,
    integrity: PayloadIntegrity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PayloadCodec {
    Raw,
    Deflate,
    Unsupported(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PayloadIntegrity {
    None,
    Crc32(u32),
}

pub(crate) fn planned_payload_reader<'s, 'a>(
    snapshots: &'s SnapshotSet<'a>,
    plan: &PayloadPlan,
    member_name: &str,
) -> Result<crate::snapshot::SnapshotRangeReader<'s, 'a>, Finding> {
    snapshots
        .reader(plan.source)
        .map_err(|finding| finding.on(member_name))
}

impl PayloadPlan {
    pub(crate) fn from_ir(member: &IrMember) -> Self {
        match &member.evidence {
            MemberEvidence::Zip(zip) => Self {
                source: DomainRange::original(zip.source_ranges.compressed_payload),
                codec: payload_codec_from_zip_method(zip.method),
                compressed_size: zip.declared_comp_size,
                uncompressed_size: member.declared_uncomp_size,
                integrity: PayloadIntegrity::Crc32(zip.declared_crc),
            },
            MemberEvidence::Zip64(zip64) => Self {
                source: DomainRange::original(zip64.zip.source_ranges.compressed_payload),
                codec: payload_codec_from_zip_method(zip64.zip.method),
                compressed_size: zip64.zip.declared_comp_size,
                uncompressed_size: member.declared_uncomp_size,
                integrity: PayloadIntegrity::Crc32(zip64.zip.declared_crc),
            },
            MemberEvidence::Tar(tar) => Self {
                source: DomainRange::original(tar.payload),
                codec: PayloadCodec::Raw,
                compressed_size: tar.payload.len,
                uncompressed_size: member.declared_uncomp_size,
                integrity: PayloadIntegrity::None,
            },
            MemberEvidence::TarGzip(tar) => Self {
                source: DomainRange {
                    domain: SnapshotDomainId::FIRST_DERIVED,
                    range: tar.payload,
                },
                codec: PayloadCodec::Raw,
                compressed_size: tar.payload.len,
                uncompressed_size: member.declared_uncomp_size,
                integrity: PayloadIntegrity::None,
            },
        }
    }

    pub(crate) fn from_zip(member: &crate::zip::ZipMember) -> Self {
        Self {
            source: DomainRange::original(member.source_ranges.compressed_payload),
            codec: payload_codec_from_zip_method(member.method),
            compressed_size: member.comp_size,
            uncompressed_size: member.uncomp_size,
            integrity: PayloadIntegrity::Crc32(member.crc),
        }
    }

    pub(crate) fn from_tar(member: &crate::tar::TarMember) -> Self {
        Self {
            source: DomainRange::original(member.payload),
            codec: PayloadCodec::Raw,
            compressed_size: member.payload.len,
            uncompressed_size: member.size,
            integrity: PayloadIntegrity::None,
        }
    }

    pub(crate) fn from_tar_gzip(member: &crate::tar::TarMember) -> Self {
        Self {
            source: DomainRange {
                domain: SnapshotDomainId::FIRST_DERIVED,
                range: member.payload,
            },
            codec: PayloadCodec::Raw,
            compressed_size: member.payload.len,
            uncompressed_size: member.size,
            integrity: PayloadIntegrity::None,
        }
    }

    pub(crate) fn matches_member(self, member: &IrMember) -> bool {
        self == Self::from_ir(member)
    }

    #[cfg(test)]
    pub(crate) fn set_test_domain(&mut self, domain: SnapshotDomainId) {
        self.source.domain = domain;
    }
}

fn payload_codec_from_zip_method(method: u16) -> PayloadCodec {
    match method {
        0 => PayloadCodec::Raw,
        8 => PayloadCodec::Deflate,
        method => PayloadCodec::Unsupported(method),
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
    member: PayloadPlan,
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

    match member.codec {
        PayloadCodec::Raw => {
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
        PayloadCodec::Deflate => {
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
        PayloadCodec::Unsupported(method) => {
            return Err(Finding::error(
                FindingCode::MethodUnsupported,
                format!("method {method}"),
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
    let crc = crc.finalize();
    if let PayloadIntegrity::Crc32(expected) = member.integrity {
        if crc != expected {
            return Err(Finding::error(
                FindingCode::CrcMismatch,
                format!("got {crc:08x} want {expected:08x}"),
            ));
        }
    }
    Ok((actual, crc, sha.finalize().into()))
}

pub(crate) fn digest_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
