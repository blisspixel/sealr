//! Bounded immutable blob transport for the repository-only Linux worker lab.

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{FileType, MemfdFlags, OFlags, SealFlags};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAGIC: [u8; 8] = *b"SLRBLOB1";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 56;
pub(crate) const MAX_PAYLOAD_LEN: usize = 64 * 1024 * 1024;
const REQUIRED_SEALS: SealFlags = SealFlags::SEAL
    .union(SealFlags::SHRINK)
    .union(SealFlags::GROW)
    .union(SealFlags::WRITE);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum BlobRole {
    Planning = 1,
    Completion = 2,
    RetainedContent = 3,
    MemberReadRequest = 4,
}

impl BlobRole {
    fn name(self) -> &'static str {
        match self {
            Self::Planning => "sealr-planning",
            Self::Completion => "sealr-completion",
            Self::RetainedContent => "sealr-retained-content",
            Self::MemberReadRequest => "sealr-member-read-request",
        }
    }
}

#[derive(Debug)]
pub(crate) struct ValidatedBlob {
    bytes: Vec<u8>,
}

impl ValidatedBlob {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) fn create(role: BlobRole, payload: &[u8]) -> Result<OwnedFd, BlobError> {
    let header = encode_header(role, payload)?;
    let fd =
        rustix::fs::memfd_create(role.name(), MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)?;
    write_all(&fd, &header)?;
    write_all(&fd, payload)?;
    rustix::fs::fcntl_add_seals(&fd, REQUIRED_SEALS)?;
    require_seals(&fd)?;
    Ok(fd)
}

pub(crate) fn create_unsealed_for_conformance(
    role: BlobRole,
    payload: &[u8],
) -> Result<OwnedFd, BlobError> {
    let header = encode_header(role, payload)?;
    let fd = rustix::fs::memfd_create(
        "sealr-unsealed-conformance",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?;
    write_all(&fd, &header)?;
    write_all(&fd, payload)?;
    Ok(fd)
}

pub(crate) fn validate(
    fd: &OwnedFd,
    expected_role: BlobRole,
    declared_total_len: u64,
) -> Result<ValidatedBlob, BlobError> {
    let stat = rustix::fs::fstat(fd)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file() {
        return Err(BlobError::NotRegular);
    }
    let actual_total_len = u64::try_from(stat.st_size).map_err(|_| BlobError::NegativeLength)?;
    if actual_total_len != declared_total_len {
        return Err(BlobError::DeclaredLength {
            declared: declared_total_len,
            actual: actual_total_len,
        });
    }
    let max_total_len = (HEADER_LEN as u64)
        .checked_add(MAX_PAYLOAD_LEN as u64)
        .expect("blob maximum fits u64");
    if actual_total_len < HEADER_LEN as u64 || actual_total_len > max_total_len {
        return Err(BlobError::TotalLength(actual_total_len));
    }

    let access = rustix::fs::fcntl_getfl(fd)?;
    if access.contains(OFlags::PATH) || access & OFlags::RWMODE == OFlags::WRONLY {
        return Err(BlobError::UnreadableDescriptor);
    }
    require_seals(fd)?;

    let mut header = [0_u8; HEADER_LEN];
    read_exact_at(fd, 0, &mut header)?;
    if header[..8] != MAGIC {
        return Err(BlobError::Magic);
    }
    let version = u16::from_le_bytes([header[8], header[9]]);
    if version != VERSION {
        return Err(BlobError::Version(version));
    }
    if header[10] != expected_role as u8 {
        return Err(BlobError::Role {
            expected: expected_role as u8,
            actual: header[10],
        });
    }
    if header[11] != 0 || header[52..].iter().any(|byte| *byte != 0) {
        return Err(BlobError::Reserved);
    }

    let payload_len = u64::from_le_bytes(
        header[12..20]
            .try_into()
            .expect("fixed payload length field"),
    );
    if payload_len > MAX_PAYLOAD_LEN as u64 {
        return Err(BlobError::PayloadLength(payload_len));
    }
    let encoded_total_len = (HEADER_LEN as u64)
        .checked_add(payload_len)
        .ok_or(BlobError::PayloadLength(payload_len))?;
    if encoded_total_len != actual_total_len {
        return Err(BlobError::EnvelopeLength {
            encoded: encoded_total_len,
            actual: actual_total_len,
        });
    }

    let payload_len = usize::try_from(payload_len).map_err(|_| BlobError::Allocation)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(payload_len)
        .map_err(|_| BlobError::Allocation)?;
    bytes.resize(payload_len, 0);
    read_exact_at(fd, HEADER_LEN as u64, &mut bytes)?;

    let sha256: [u8; 32] = Sha256::digest(&bytes).into();
    if header[20..52] != sha256 {
        return Err(BlobError::Digest);
    }
    Ok(ValidatedBlob { bytes })
}

pub(crate) const fn total_len(payload_len: usize) -> Option<u64> {
    if payload_len > MAX_PAYLOAD_LEN {
        return None;
    }
    (HEADER_LEN as u64).checked_add(payload_len as u64)
}

fn encode_header(role: BlobRole, payload: &[u8]) -> Result<[u8; HEADER_LEN], BlobError> {
    let payload_len = total_len(payload.len()).ok_or(BlobError::PayloadLength(
        u64::try_from(payload.len()).unwrap_or(u64::MAX),
    ))? - HEADER_LEN as u64;
    let mut header = [0_u8; HEADER_LEN];
    header[..8].copy_from_slice(&MAGIC);
    header[8..10].copy_from_slice(&VERSION.to_le_bytes());
    header[10] = role as u8;
    header[12..20].copy_from_slice(&payload_len.to_le_bytes());
    header[20..52].copy_from_slice(&Sha256::digest(payload));
    Ok(header)
}

fn write_all(fd: impl AsFd, mut bytes: &[u8]) -> Result<(), BlobError> {
    while !bytes.is_empty() {
        match rustix::io::write(fd.as_fd(), bytes) {
            Ok(0) => return Err(BlobError::WriteZero),
            Ok(written) => bytes = &bytes[written..],
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn read_exact_at(fd: impl AsFd, mut offset: u64, mut output: &mut [u8]) -> Result<(), BlobError> {
    while !output.is_empty() {
        match rustix::io::pread(fd.as_fd(), &mut *output, offset) {
            Ok(0) => return Err(BlobError::UnexpectedEof),
            Ok(read) => {
                offset = offset
                    .checked_add(read as u64)
                    .ok_or(BlobError::ReadOffset)?;
                output = &mut output[read..];
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn require_seals(fd: impl AsFd) -> Result<(), BlobError> {
    let actual = rustix::fs::fcntl_get_seals(fd.as_fd())?;
    if !actual.contains(REQUIRED_SEALS) {
        return Err(BlobError::Seals {
            required: REQUIRED_SEALS.bits(),
            actual: actual.bits(),
        });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum BlobError {
    #[error(transparent)]
    System(#[from] rustix::io::Errno),
    #[error("sealed blob is not a regular file")]
    NotRegular,
    #[error("sealed blob has a negative file length")]
    NegativeLength,
    #[error("sealed blob declared length {declared} differs from descriptor length {actual}")]
    DeclaredLength { declared: u64, actual: u64 },
    #[error("sealed blob total length {0} is outside its bound")]
    TotalLength(u64),
    #[error("sealed blob descriptor is not readable")]
    UnreadableDescriptor,
    #[error("sealed blob lacks required seals 0x{required:x}; observed 0x{actual:x}")]
    Seals { required: u32, actual: u32 },
    #[error("sealed blob magic is invalid")]
    Magic,
    #[error("sealed blob version {0} is unsupported")]
    Version(u16),
    #[error("sealed blob role {actual} does not match expected role {expected}")]
    Role { expected: u8, actual: u8 },
    #[error("sealed blob reserved fields are nonzero")]
    Reserved,
    #[error("sealed blob payload length {0} exceeds its bound")]
    PayloadLength(u64),
    #[error("sealed blob encoded total length {encoded} differs from descriptor length {actual}")]
    EnvelopeLength { encoded: u64, actual: u64 },
    #[error("sealed blob payload allocation failed")]
    Allocation,
    #[error("sealed blob payload digest is invalid")]
    Digest,
    #[error("sealed blob write returned zero")]
    WriteZero,
    #[error("sealed blob ended before its declared length")]
    UnexpectedEof,
    #[error("sealed blob read offset overflowed")]
    ReadOffset,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed_with_header(header: &[u8; HEADER_LEN], payload: &[u8]) -> OwnedFd {
        let fd = rustix::fs::memfd_create(
            "sealr-malformed",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .unwrap();
        write_all(&fd, header).unwrap();
        write_all(&fd, payload).unwrap();
        rustix::fs::fcntl_add_seals(&fd, REQUIRED_SEALS).unwrap();
        fd
    }

    #[test]
    fn sealed_blob_round_trips_both_roles() {
        for role in [
            BlobRole::Planning,
            BlobRole::Completion,
            BlobRole::RetainedContent,
            BlobRole::MemberReadRequest,
        ] {
            let payload = b"bound semantic handoff";
            let fd = create(role, payload).unwrap();
            let validated = validate(&fd, role, total_len(payload.len()).unwrap()).unwrap();
            assert_eq!(validated.bytes(), payload);
        }
    }

    #[test]
    fn required_seals_block_every_content_or_length_change() {
        let fd = create(BlobRole::Planning, b"immutable").unwrap();
        assert_eq!(
            rustix::io::pwrite(&fd, b"x", HEADER_LEN as u64),
            Err(rustix::io::Errno::PERM)
        );
        assert_eq!(
            rustix::fs::ftruncate(&fd, HEADER_LEN as u64),
            Err(rustix::io::Errno::PERM)
        );
        assert_eq!(
            rustix::fs::ftruncate(&fd, total_len(10).unwrap()),
            Err(rustix::io::Errno::PERM)
        );
    }

    #[test]
    fn unsealed_blob_is_rejected_before_decode() {
        let payload = b"not sealed";
        let header = encode_header(BlobRole::Planning, payload).unwrap();
        let fd = rustix::fs::memfd_create(
            "sealr-unsealed",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .unwrap();
        write_all(&fd, &header).unwrap();
        write_all(&fd, payload).unwrap();
        assert!(matches!(
            validate(&fd, BlobRole::Planning, total_len(payload.len()).unwrap()),
            Err(BlobError::Seals { .. })
        ));
    }

    #[test]
    fn digest_and_envelope_length_are_independently_checked() {
        let payload = b"payload";
        let mut bad_digest = encode_header(BlobRole::Planning, payload).unwrap();
        bad_digest[20] ^= 1;
        let fd = sealed_with_header(&bad_digest, payload);
        assert!(matches!(
            validate(&fd, BlobRole::Planning, total_len(payload.len()).unwrap()),
            Err(BlobError::Digest)
        ));

        let mut bad_length = encode_header(BlobRole::Planning, payload).unwrap();
        bad_length[12..20].copy_from_slice(&(payload.len() as u64 - 1).to_le_bytes());
        let fd = sealed_with_header(&bad_length, payload);
        assert!(matches!(
            validate(&fd, BlobRole::Planning, total_len(payload.len()).unwrap()),
            Err(BlobError::EnvelopeLength { .. })
        ));
    }

    #[test]
    fn caller_declared_length_and_role_are_checked() {
        let payload = b"payload";
        let fd = create(BlobRole::Planning, payload).unwrap();
        assert!(matches!(
            validate(
                &fd,
                BlobRole::Planning,
                total_len(payload.len()).unwrap() + 1
            ),
            Err(BlobError::DeclaredLength { .. })
        ));
        assert!(matches!(
            validate(&fd, BlobRole::Completion, total_len(payload.len()).unwrap()),
            Err(BlobError::Role { .. })
        ));
    }

    #[test]
    fn structural_envelope_fields_and_payload_cap_fail_closed() {
        let payload = b"payload";
        let mut bad_magic = encode_header(BlobRole::Planning, payload).unwrap();
        bad_magic[0] ^= 1;
        let fd = sealed_with_header(&bad_magic, payload);
        assert!(matches!(
            validate(&fd, BlobRole::Planning, total_len(payload.len()).unwrap()),
            Err(BlobError::Magic)
        ));

        let mut bad_version = encode_header(BlobRole::Planning, payload).unwrap();
        bad_version[8..10].copy_from_slice(&2_u16.to_le_bytes());
        let fd = sealed_with_header(&bad_version, payload);
        assert!(matches!(
            validate(&fd, BlobRole::Planning, total_len(payload.len()).unwrap()),
            Err(BlobError::Version(2))
        ));

        let mut bad_reserved = encode_header(BlobRole::Planning, payload).unwrap();
        bad_reserved[55] = 1;
        let fd = sealed_with_header(&bad_reserved, payload);
        assert!(matches!(
            validate(&fd, BlobRole::Planning, total_len(payload.len()).unwrap()),
            Err(BlobError::Reserved)
        ));
        assert_eq!(total_len(MAX_PAYLOAD_LEN + 1), None);
    }
}
