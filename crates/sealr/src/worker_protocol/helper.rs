//! Authentication and immutable retention for the Linux worker executable.

use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::fs::{FileType, MemfdFlags, Mode, OFlags, ResolveFlags, SealFlags};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

const MAX_HELPER_LEN: u64 = 64 * 1024 * 1024;
const COPY_CHUNK_LEN: usize = 64 * 1024;
const BASE_SEALS: SealFlags = SealFlags::SEAL
    .union(SealFlags::SHRINK)
    .union(SealFlags::GROW)
    .union(SealFlags::WRITE)
    .union(SealFlags::FUTURE_WRITE);

#[derive(Clone, Debug)]
pub struct HelperArtifact {
    inner: Arc<HelperArtifactInner>,
}

#[derive(Debug)]
struct HelperArtifactInner {
    executable: OwnedFd,
    digest: [u8; 32],
    len: u64,
    source_device: u64,
    source_inode: u64,
}

impl HelperArtifact {
    pub fn load(
        path: &Path,
        expected_len: u64,
        expected_digest: [u8; 32],
    ) -> Result<Self, HelperError> {
        if !path.is_absolute() {
            return Err(HelperError::RelativePath(path.to_path_buf()));
        }
        if expected_len == 0 || expected_len > MAX_HELPER_LEN {
            return Err(HelperError::Length {
                actual: expected_len,
                maximum: MAX_HELPER_LEN,
            });
        }
        let root = rustix::fs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let relative = path
            .strip_prefix("/")
            .map_err(|_| HelperError::RelativePath(path.to_path_buf()))?;
        let pinned = rustix::fs::openat2(
            &root,
            relative,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|source| HelperError::Open {
            path: path.to_path_buf(),
            source,
        })?;
        let stat = rustix::fs::fstat(&pinned)?;
        if !FileType::from_raw_mode(stat.st_mode).is_file() {
            return Err(HelperError::NotRegular(path.to_path_buf()));
        }
        let len = u64::try_from(stat.st_size).map_err(|_| HelperError::NegativeLength)?;
        if len != expected_len {
            return Err(HelperError::LengthMismatch {
                expected: expected_len,
                actual: len,
            });
        }
        let source = rustix::fs::open(
            format!("/proc/self/fd/{}", pinned.as_raw_fd()),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let readable_stat = rustix::fs::fstat(&source)?;
        if !same_source_fingerprint(&stat, &readable_stat) {
            return Err(HelperError::SourceIdentity);
        }

        let (writable, explicit_exec) = create_executable_memfd()?;
        let writable_stat = rustix::fs::fstat(&writable)?;
        if writable_stat.st_mode & 0o111 == 0 {
            return Err(HelperError::NotExecutableMemfd);
        }
        let copied_digest = copy_and_hash(&source, &writable, len)?;
        let post_pinned = rustix::fs::fstat(&pinned)?;
        let post_readable = rustix::fs::fstat(&source)?;
        if !same_source_fingerprint(&stat, &post_pinned)
            || !same_source_fingerprint(&stat, &post_readable)
        {
            return Err(HelperError::SourceChanged);
        }
        if copied_digest != expected_digest {
            return Err(HelperError::DigestMismatch {
                expected: encode_digest(expected_digest),
                actual: encode_digest(copied_digest),
            });
        }
        let required_seals = if explicit_exec {
            BASE_SEALS | SealFlags::EXEC
        } else {
            BASE_SEALS
        };
        rustix::fs::fcntl_add_seals(&writable, required_seals)?;
        require_seals(&writable, required_seals)?;

        let retained_path = format!("/proc/self/fd/{}", writable.as_raw_fd());
        let executable = rustix::fs::open(
            retained_path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let executable = if executable.as_raw_fd() < 3 {
            rustix::io::fcntl_dupfd_cloexec(&executable, 3)?
        } else {
            executable
        };
        let retained_stat = rustix::fs::fstat(&executable)?;
        if retained_stat.st_dev != writable_stat.st_dev
            || retained_stat.st_ino != writable_stat.st_ino
        {
            return Err(HelperError::RetainedIdentity);
        }
        require_seals(&executable, required_seals)?;
        drop(writable);
        let retained_len =
            u64::try_from(retained_stat.st_size).map_err(|_| HelperError::NegativeLength)?;
        if retained_len != len {
            return Err(HelperError::RetainedLength {
                expected: len,
                actual: retained_len,
            });
        }
        let retained_digest = hash_exact(&executable, len)?;
        if retained_digest != expected_digest {
            return Err(HelperError::RetainedDigestMismatch);
        }

        Ok(Self {
            inner: Arc::new(HelperArtifactInner {
                executable,
                digest: expected_digest,
                len,
                source_device: stat.st_dev,
                source_inode: stat.st_ino,
            }),
        })
    }

    pub fn execution_path(&self) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}",
            self.inner.executable.as_raw_fd()
        ))
    }

    pub fn verify_process_executable(&self, pid: u32) -> Result<(), HelperError> {
        let observed = rustix::fs::open(
            format!("/proc/{pid}/exe"),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let expected = rustix::fs::fstat(&self.inner.executable)?;
        let actual = rustix::fs::fstat(&observed)?;
        if actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino {
            return Err(HelperError::ExecutedIdentity);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> String {
        encode_digest(self.inner.digest)
    }

    pub fn len(&self) -> u64 {
        self.inner.len
    }

    pub fn is_empty(&self) -> bool {
        self.inner.len == 0
    }

    pub fn source_matches(&self, path: &Path) -> Result<bool, HelperError> {
        let candidate = rustix::fs::open(path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())?;
        let stat = rustix::fs::fstat(candidate)?;
        Ok(stat.st_dev == self.inner.source_device && stat.st_ino == self.inner.source_inode)
    }

    #[cfg(test)]
    fn digest(&self) -> [u8; 32] {
        self.inner.digest
    }
}

pub fn parse_digest(value: &str) -> Result<[u8; 32], HelperError> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(HelperError::DigestSyntax);
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = (decode_nibble(value.as_bytes()[offset])? << 4)
            | decode_nibble(value.as_bytes()[offset + 1])?;
    }
    Ok(digest)
}

fn decode_nibble(byte: u8) -> Result<u8, HelperError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(HelperError::DigestSyntax),
    }
}

fn encode_digest(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn create_executable_memfd() -> Result<(OwnedFd, bool), HelperError> {
    let common = MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING;
    match rustix::fs::memfd_create("sealr-worker-authenticated", common | MemfdFlags::EXEC) {
        Ok(fd) => Ok((fd, true)),
        Err(rustix::io::Errno::INVAL) => {
            rustix::fs::memfd_create("sealr-worker-authenticated", common)
                .map(|fd| (fd, false))
                .map_err(Into::into)
        }
        Err(error) => Err(error.into()),
    }
}

fn copy_and_hash(
    source: impl AsFd,
    destination: impl AsFd,
    len: u64,
) -> Result<[u8; 32], HelperError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; COPY_CHUNK_LEN];
    let mut offset = 0_u64;
    while offset < len {
        let remaining = usize::try_from((len - offset).min(COPY_CHUNK_LEN as u64))
            .expect("bounded helper chunk fits usize");
        read_exact_at(source.as_fd(), offset, &mut buffer[..remaining])?;
        write_all(destination.as_fd(), &buffer[..remaining])?;
        hasher.update(&buffer[..remaining]);
        offset += remaining as u64;
    }
    let mut trailing = [0_u8; 1];
    loop {
        match rustix::io::pread(source.as_fd(), &mut trailing, len) {
            Ok(0) => break,
            Ok(_) => return Err(HelperError::SourceGrew),
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(hasher.finalize().into())
}

fn hash_exact(fd: impl AsFd, len: u64) -> Result<[u8; 32], HelperError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; COPY_CHUNK_LEN];
    let mut offset = 0_u64;
    while offset < len {
        let remaining = usize::try_from((len - offset).min(COPY_CHUNK_LEN as u64))
            .expect("bounded helper chunk fits usize");
        read_exact_at(fd.as_fd(), offset, &mut buffer[..remaining])?;
        hasher.update(&buffer[..remaining]);
        offset += remaining as u64;
    }
    Ok(hasher.finalize().into())
}

fn write_all(fd: impl AsFd, mut bytes: &[u8]) -> Result<(), HelperError> {
    while !bytes.is_empty() {
        match rustix::io::write(fd.as_fd(), bytes) {
            Ok(0) => return Err(HelperError::WriteZero),
            Ok(written) => bytes = &bytes[written..],
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn read_exact_at(fd: impl AsFd, mut offset: u64, mut output: &mut [u8]) -> Result<(), HelperError> {
    while !output.is_empty() {
        match rustix::io::pread(fd.as_fd(), &mut *output, offset) {
            Ok(0) => return Err(HelperError::UnexpectedEof),
            Ok(read) => {
                offset = offset.checked_add(read as u64).ok_or(HelperError::Offset)?;
                output = &mut output[read..];
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn require_seals(fd: impl AsFd, required: SealFlags) -> Result<(), HelperError> {
    let actual = rustix::fs::fcntl_get_seals(fd.as_fd())?;
    if !actual.contains(required) {
        return Err(HelperError::Seals {
            required: required.bits(),
            actual: actual.bits(),
        });
    }
    Ok(())
}

fn same_source_fingerprint(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
}

#[derive(Debug, Error)]
pub enum HelperError {
    #[error(transparent)]
    System(#[from] rustix::io::Errno),
    #[error("worker helper path must be absolute: {0}")]
    RelativePath(PathBuf),
    #[error("opening worker helper {path} failed: {source}")]
    Open {
        path: PathBuf,
        source: rustix::io::Errno,
    },
    #[error("worker helper is not a regular file: {0}")]
    NotRegular(PathBuf),
    #[error("worker helper has a negative length")]
    NegativeLength,
    #[error("worker helper length {actual} is outside 1..={maximum} bytes")]
    Length { actual: u64, maximum: u64 },
    #[error("worker helper length mismatch: expected {expected}, observed {actual}")]
    LengthMismatch { expected: u64, actual: u64 },
    #[error("worker helper readable descriptor differs from its pinned object")]
    SourceIdentity,
    #[error("worker helper changed while its bytes were authenticated")]
    SourceChanged,
    #[error("worker helper SHA-256 must contain exactly 64 hexadecimal characters")]
    DigestSyntax,
    #[error("worker helper SHA-256 mismatch: expected {expected}, observed {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error("worker helper changed length while it was authenticated")]
    SourceGrew,
    #[error("authenticated worker helper length changed from {expected} to {actual}")]
    RetainedLength { expected: u64, actual: u64 },
    #[error("authenticated worker helper memfd is not executable")]
    NotExecutableMemfd,
    #[error("authenticated worker helper read-only descriptor changed object identity")]
    RetainedIdentity,
    #[error("authenticated worker helper digest changed after sealing")]
    RetainedDigestMismatch,
    #[error(
        "authenticated worker helper lacks required seals 0x{required:x}; observed 0x{actual:x}"
    )]
    Seals { required: u32, actual: u32 },
    #[error("authenticated worker helper write returned zero")]
    WriteZero,
    #[error("worker helper ended before its authenticated length")]
    UnexpectedEof,
    #[error("worker helper read offset overflowed")]
    Offset,
    #[error("executed worker identity differs from the authenticated helper")]
    ExecutedIdentity,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn file_digest(path: &Path) -> [u8; 32] {
        Sha256::digest(fs::read(path).expect("fixture reads")).into()
    }

    fn unique_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sealr-helper-{name}-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    #[test]
    fn digest_parser_is_exact_and_case_insensitive() {
        assert_eq!(parse_digest(&"00".repeat(32)).unwrap(), [0; 32]);
        assert_eq!(parse_digest(&"aF".repeat(32)).unwrap(), [0xaf; 32]);
        assert!(parse_digest(&"0".repeat(63)).is_err());
        assert!(parse_digest(&format!("{}g", "0".repeat(63))).is_err());
    }

    #[test]
    fn helper_is_copied_authenticated_and_sealed() {
        let source = std::env::current_exe().expect("current test executable resolves");
        let expected = file_digest(&source);
        let expected_len = fs::metadata(&source).unwrap().len();
        let helper =
            HelperArtifact::load(&source, expected_len, expected).expect("helper authenticates");
        assert_eq!(helper.digest(), expected);
        assert_eq!(helper.len(), expected_len);
        assert!(!helper.is_empty());
        assert!(helper.execution_path().is_absolute());
        let seals = rustix::fs::fcntl_get_seals(&helper.inner.executable).unwrap();
        assert!(seals.contains(BASE_SEALS));
    }

    #[test]
    fn helper_rejects_relative_symlink_nonregular_zero_and_wrong_digest() {
        assert!(matches!(
            HelperArtifact::load(Path::new("sealr-worker"), 1, [0; 32]),
            Err(HelperError::RelativePath(_))
        ));
        assert!(matches!(
            HelperArtifact::load(Path::new("/dev/null"), 1, [0; 32]),
            Err(HelperError::NotRegular(_))
        ));

        let zero = unique_path("zero");
        fs::write(&zero, []).expect("zero fixture writes");
        assert!(matches!(
            HelperArtifact::load(&zero, 0, [0; 32]),
            Err(HelperError::Length { actual: 0, .. })
        ));

        let source = std::env::current_exe().expect("current test executable resolves");
        let source_len = fs::metadata(&source).unwrap().len();
        assert!(matches!(
            HelperArtifact::load(&source, source_len, [0; 32]),
            Err(HelperError::DigestMismatch { .. })
        ));

        let link = unique_path("link");
        symlink(&source, &link).expect("symlink fixture creates");
        assert!(matches!(
            HelperArtifact::load(&link, source_len, file_digest(&source)),
            Err(HelperError::Open { .. })
        ));
        fs::remove_file(link).expect("symlink fixture removes");
        fs::remove_file(zero).expect("zero fixture removes");
    }

    #[test]
    fn authenticated_helper_survives_source_removal_and_path_spaces() {
        let source = std::env::current_exe().expect("current test executable resolves");
        let copy = unique_path("path with spaces");
        fs::copy(&source, &copy).expect("helper fixture copies");
        let expected_len = fs::metadata(&copy).unwrap().len();
        let expected_digest = file_digest(&copy);
        let helper = HelperArtifact::load(&copy, expected_len, expected_digest)
            .expect("copied helper authenticates");
        fs::remove_file(&copy).expect("authenticated source removes");

        assert_eq!(
            hash_exact(&helper.inner.executable, expected_len).unwrap(),
            expected_digest
        );
        assert_eq!(helper.execution_path(), helper.execution_path());
        assert!(helper.source_matches(&copy).is_err());
    }

    #[test]
    fn helper_rejects_length_drift_and_oversized_specs() {
        let source = std::env::current_exe().expect("current test executable resolves");
        let source_len = fs::metadata(&source).unwrap().len();
        let digest = file_digest(&source);
        assert!(matches!(
            HelperArtifact::load(&source, source_len - 1, digest),
            Err(HelperError::LengthMismatch { .. })
        ));
        assert!(matches!(
            HelperArtifact::load(&source, MAX_HELPER_LEN + 1, digest),
            Err(HelperError::Length { .. })
        ));
    }
}
