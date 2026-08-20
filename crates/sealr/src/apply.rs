use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::findings::{Finding, FindingCode, Severity};
use crate::jail::jail_relative;
use crate::policy::{hex_sha256, Policy};
use crate::zip::{self, ZipMember};
use cap_std::ambient_authority;
use cap_std::fs::{Dir as CapDir, File as CapFile, OpenOptions as CapOpenOptions};
use crc32fast::Hasher as Crc;
use flate2::read::DeflateDecoder;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub enum Source<'a> {
    Path(&'a Path),
    Bytes {
        path: Option<&'a str>,
        data: &'a [u8],
    },
}

#[derive(Clone, Debug)]
pub struct Request<'a> {
    pub source: Source<'a>,
    pub policy: &'a Policy,
    pub dest: Option<&'a Path>,
}

#[derive(Clone, Debug, Serialize)]
pub enum Verdict {
    Allowed { wrote: bool },
    Rejected,
}

#[derive(Clone, Debug, Serialize)]
pub struct MemberView {
    pub path: String,
    pub kind: &'static str,
    pub comp_bytes: u64,
    pub uncomp_bytes: u64,
    pub method: &'static str,
    pub crc32: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct View {
    pub schema: &'static str,
    pub source: SourceMeta,
    pub policy: PolicyMeta,
    pub verdict: &'static str,
    pub wrote: bool,
    pub findings: Vec<Finding>,
    pub members: Vec<MemberView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceMeta {
    pub path: Option<String>,
    pub digest: DigestHex,
    pub magic: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct PolicyMeta {
    pub id: String,
    pub digest: DigestHex,
}

#[derive(Clone, Debug, Serialize)]
pub struct DigestHex {
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Receipt {
    pub verdict: &'static str,
    pub wrote: bool,
    pub source: DigestHex,
    pub policy: PolicyMeta,
    pub view_digest: DigestHex,
    pub tool: ToolMeta,
    pub environment: EnvMeta,
    pub signed: bool,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolMeta {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct EnvMeta {
    pub os: &'static str,
    pub arch: &'static str,
    pub kernel_jail: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct Outcome {
    pub verdict: Verdict,
    pub receipt: Receipt,
    pub view: View,
}

impl Outcome {
    pub fn rejected(&self) -> bool {
        matches!(self.verdict, Verdict::Rejected)
    }

    pub fn wrote(&self) -> bool {
        matches!(self.verdict, Verdict::Allowed { wrote: true })
    }
}

pub fn apply(req: Request<'_>) -> Outcome {
    match apply_inner(&req) {
        Ok(o) => o,
        Err(finding) => reject_only(request_fallback_meta(&req), vec![finding], None),
    }
}

struct SourceData<'a> {
    path: Option<String>,
    bytes: Cow<'a, [u8]>,
}

fn read_source<'a>(src: &'a Source<'a>, policy: &Policy) -> Result<SourceData<'a>, Finding> {
    match src {
        Source::Path(p) => {
            let len = fs::metadata(p)
                .map_err(|e| Finding::error(FindingCode::SourceIo, format!("metadata: {e}")))?
                .len();
            if len > policy.max_archive_bytes {
                return Err(Finding::error(
                    FindingCode::QuotaArchive,
                    format!(
                        "archive is {len} bytes; cap is {}",
                        policy.max_archive_bytes
                    ),
                ));
            }
            let mut file = File::open(p)
                .map_err(|e| Finding::error(FindingCode::SourceIo, format!("open: {e}")))?;
            let initial_capacity = usize::try_from(len)
                .unwrap_or(usize::MAX)
                .min(8 * 1024 * 1024);
            let mut bytes = Vec::with_capacity(initial_capacity);
            (&mut file)
                .take(policy.max_archive_bytes.saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(|e| Finding::error(FindingCode::SourceIo, format!("read: {e}")))?;
            if bytes.len() as u64 > policy.max_archive_bytes {
                return Err(Finding::error(
                    FindingCode::QuotaArchive,
                    "archive grew beyond the input cap while being read",
                ));
            }
            Ok(SourceData {
                path: Some(p.display().to_string()),
                bytes: Cow::Owned(bytes),
            })
        }
        Source::Bytes { path, data } => {
            if data.len() as u64 > policy.max_archive_bytes {
                return Err(Finding::error(
                    FindingCode::QuotaArchive,
                    format!(
                        "archive is {} bytes; cap is {}",
                        data.len(),
                        policy.max_archive_bytes
                    ),
                ));
            }
            Ok(SourceData {
                path: path.map(|s| s.to_string()),
                bytes: Cow::Borrowed(data),
            })
        }
    }
}

fn request_fallback_meta(req: &Request<'_>) -> (Option<String>, String, Policy) {
    let path = match &req.source {
        Source::Path(path) => Some(path.display().to_string()),
        Source::Bytes { path, .. } => path.map(str::to_owned),
    };
    (path, "00".repeat(32), req.policy.clone())
}

fn apply_inner(req: &Request<'_>) -> Result<Outcome, Finding> {
    let policy = req.policy;
    let src = read_source(&req.source, policy)?;
    let source_digest = hex_sha256(&src.bytes);
    let magic = detect_magic(&src.bytes);
    if magic != "zip" {
        let f = Finding::error(FindingCode::FormatUnsupported, format!("magic {magic}"));
        return Ok(reject_only(
            (src.path.clone(), source_digest, policy.clone()),
            vec![f],
            Some(magic),
        ));
    }
    if !policy.allows_format("zip") {
        let f = Finding::error(FindingCode::FormatUnsupported, "zip not in policy.formats");
        return Ok(reject_only(
            (src.path.clone(), source_digest, policy.clone()),
            vec![f],
            Some("zip"),
        ));
    }

    let parsed = match zip::parse_zip(&src.bytes, policy.max_files, policy.max_metadata_bytes) {
        Ok(z) => z,
        Err(f) => {
            return Ok(reject_only(
                (src.path.clone(), source_digest, policy.clone()),
                vec![f],
                Some("zip"),
            ));
        }
    };

    if parsed.members.len() as u64 > policy.max_files {
        let f = Finding::error(
            FindingCode::QuotaFiles,
            format!("{} entries", parsed.members.len()),
        );
        return Ok(reject_only(
            (src.path.clone(), source_digest, policy.clone()),
            vec![f],
            Some("zip"),
        ));
    }
    if parsed.metadata_bytes > policy.max_metadata_bytes {
        let f = Finding::error(
            FindingCode::QuotaMetadata,
            format!(
                "ZIP metadata is {} bytes; cap is {}",
                parsed.metadata_bytes, policy.max_metadata_bytes
            ),
        );
        return Ok(reject_only(
            (src.path.clone(), source_digest, policy.clone()),
            vec![f],
            Some("zip"),
        ));
    }

    let mut findings = Vec::new();
    let mut planned: Vec<(ZipMember, Vec<String>)> = Vec::new();
    let mut dest_seen: BTreeMap<String, bool> = BTreeMap::new();
    let mut fold_seen: BTreeMap<String, bool> = BTreeMap::new();
    let mut declared_total: u64 = 0;

    for m in parsed.members {
        if (m.flags & 1) != 0 {
            findings
                .push(Finding::error(FindingCode::ZipEncrypted, "encrypted member").on(&m.name));
            continue;
        }
        if m.method != 0 && m.method != 8 {
            findings.push(
                Finding::error(
                    FindingCode::MethodUnsupported,
                    format!("method {}", m.method),
                )
                .on(&m.name),
            );
            continue;
        }
        if m.uncomp_size > policy.max_member_bytes {
            findings.push(
                Finding::error(FindingCode::QuotaMember, "declared member too large").on(&m.name),
            );
            continue;
        }
        if m.comp_size > 0 {
            if let Some(max_r) = policy.max_ratio {
                let ratio = m.uncomp_size as f64 / m.comp_size as f64;
                if ratio > max_r {
                    findings.push(
                        Finding::error(FindingCode::QuotaRatio, format!("ratio {ratio:.1}"))
                            .on(&m.name),
                    );
                    continue;
                }
            }
        }
        declared_total = declared_total.saturating_add(m.uncomp_size);
        if declared_total > policy.max_total_bytes {
            findings.push(Finding::error(
                FindingCode::QuotaTotal,
                "declared total too large",
            ));
            break;
        }

        let jailed_name = if m.is_dir {
            m.name.strip_suffix('/').unwrap_or(&m.name)
        } else {
            &m.name
        };
        match jail_relative(jailed_name, policy.max_path_depth) {
            Ok(parts) => {
                let joined = parts.join("/");
                let fold = joined.to_ascii_lowercase();
                if dest_seen.contains_key(&joined) {
                    findings.push(
                        Finding::error(FindingCode::ZipDiffB1Dup, "duplicate dest path")
                            .on(&m.name),
                    );
                    continue;
                }
                if fold_seen.contains_key(&fold) {
                    findings.push(
                        Finding::error(FindingCode::PathCaseFold, "case-fold collision")
                            .on(&m.name),
                    );
                    continue;
                }
                if let Some(conflict) = path_conflict(&dest_seen, &joined, m.is_dir) {
                    findings.push(
                        Finding::error(
                            FindingCode::PathConflict,
                            format!("file/directory conflict with {conflict}"),
                        )
                        .on(&m.name),
                    );
                    continue;
                }
                if let Some(conflict) = path_conflict(&fold_seen, &fold, m.is_dir) {
                    findings.push(
                        Finding::error(
                            FindingCode::PathCaseFold,
                            format!("case-fold topology conflict with {conflict}"),
                        )
                        .on(&m.name),
                    );
                    continue;
                }
                dest_seen.insert(joined, m.is_dir);
                fold_seen.insert(fold, m.is_dir);
                planned.push((m, parts));
            }
            Err(f) => findings.push(f),
        }
    }

    let fatal = findings.iter().any(|f| f.severity == Severity::Error);
    if fatal {
        return Ok(finish(
            src.path,
            source_digest,
            "zip",
            policy,
            Verdict::Rejected,
            findings,
            Vec::new(),
        ));
    }

    let mut members_view = Vec::new();
    let mut actual_total: u64 = 0;
    let mut stage = match req.dest {
        None => None,
        Some(dest) => match StageDir::create(dest) {
            Ok(stage) => Some(stage),
            Err(finding) => {
                findings.push(finding);
                return Ok(finish(
                    src.path,
                    source_digest,
                    "zip",
                    policy,
                    Verdict::Rejected,
                    findings,
                    members_view,
                ));
            }
        },
    };
    let write = stage.is_some();

    for (m, parts) in planned {
        let kind = if m.is_dir { "dir" } else { "file" };
        let method = if m.method == 0 { "store" } else { "deflate" };

        if m.is_dir {
            if let Some(stage) = stage.as_ref() {
                if let Err(finding) = stage.create_directory(&parts, &m.name) {
                    findings.push(finding);
                    return Ok(finish(
                        src.path,
                        source_digest,
                        "zip",
                        policy,
                        Verdict::Rejected,
                        findings,
                        members_view,
                    ));
                }
            }
            members_view.push(MemberView {
                path: parts.join("/"),
                kind,
                comp_bytes: 0,
                uncomp_bytes: 0,
                method: "store",
                crc32: format!("{:08x}", m.crc),
                sha256: hex_sha256(&[]),
            });
            continue;
        }

        let payload = match zip::payload(&src.bytes, &m) {
            Ok(payload) => payload,
            Err(finding) => {
                findings.push(finding);
                return Ok(finish(
                    src.path,
                    source_digest,
                    "zip",
                    policy,
                    Verdict::Rejected,
                    findings,
                    members_view,
                ));
            }
        };
        let remaining = policy.max_total_bytes.saturating_sub(actual_total);
        let processed = if let Some(stage) = stage.as_ref() {
            stage
                .create_file(&parts)
                .and_then(|file| process_member_to_file(payload, &m, policy, remaining, file))
        } else {
            let mut sink = io::sink();
            process_member(payload, &m, policy, remaining, &mut sink)
        };
        let (actual, crc, sha) = match processed {
            Ok(result) => result,
            Err(finding) => {
                findings.push(finding.on(&m.name));
                return Ok(finish(
                    src.path,
                    source_digest,
                    "zip",
                    policy,
                    Verdict::Rejected,
                    findings,
                    members_view,
                ));
            }
        };
        if crc != m.crc {
            findings.push(
                Finding::error(
                    FindingCode::CrcMismatch,
                    format!("got {crc:08x} want {:08x}", m.crc),
                )
                .on(&m.name),
            );
            return Ok(finish(
                src.path,
                source_digest,
                "zip",
                policy,
                Verdict::Rejected,
                findings,
                members_view,
            ));
        }
        actual_total = actual_total.saturating_add(actual);

        members_view.push(MemberView {
            path: parts.join("/"),
            kind,
            comp_bytes: m.comp_size,
            uncomp_bytes: actual,
            method,
            crc32: format!("{crc:08x}"),
            sha256: sha,
        });
    }

    members_view.sort_by(|a, b| a.path.cmp(&b.path));
    if let Some(stage) = stage.as_mut() {
        if let Err(finding) = stage.commit() {
            findings.push(finding);
            return Ok(finish(
                src.path,
                source_digest,
                "zip",
                policy,
                Verdict::Rejected,
                findings,
                members_view,
            ));
        }
    }
    Ok(finish(
        src.path,
        source_digest,
        "zip",
        policy,
        Verdict::Allowed { wrote: write },
        findings,
        members_view,
    ))
}

fn path_conflict(seen: &BTreeMap<String, bool>, path: &str, is_dir: bool) -> Option<String> {
    for (index, _) in path.match_indices('/') {
        let ancestor = &path[..index];
        if matches!(seen.get(ancestor), Some(false)) {
            return Some(ancestor.to_owned());
        }
    }
    if !is_dir {
        let prefix = format!("{path}/");
        if let Some((candidate, _)) = seen.range(prefix.clone()..).next() {
            if candidate.starts_with(&prefix) {
                return Some(candidate.clone());
            }
        }
    }
    None
}

struct StageDir {
    parent: CapDir,
    parent_path: PathBuf,
    root: Option<CapDir>,
    stage_name: PathBuf,
    final_name: PathBuf,
    committed: bool,
}

impl StageDir {
    fn create(dest: &Path) -> Result<Self, Finding> {
        let file_name = dest.file_name().ok_or_else(|| {
            Finding::error(
                FindingCode::MaterializeIo,
                "destination must name a directory below an existing root",
            )
        })?;
        let parent_input = dest
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent_input).map_err(|error| {
            Finding::error(
                FindingCode::MaterializeIo,
                format!("create destination parent: {error}"),
            )
        })?;
        let parent_path = fs::canonicalize(parent_input).map_err(|error| {
            Finding::error(
                FindingCode::MaterializeIo,
                format!("resolve destination parent: {error}"),
            )
        })?;
        let parent =
            CapDir::open_ambient_dir(&parent_path, ambient_authority()).map_err(|error| {
                Finding::error(
                    FindingCode::MaterializeIo,
                    format!("open destination parent capability: {error}"),
                )
            })?;
        let final_name = PathBuf::from(file_name);
        if capability_path_exists(&parent, &final_name)? {
            return Err(Finding::error(
                FindingCode::MaterializeExists,
                "destination already exists; replacement is not implemented",
            ));
        }

        for _ in 0..128 {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(|error| {
                Finding::error(
                    FindingCode::MaterializeIo,
                    format!("generate staging name: {error}"),
                )
            })?;
            let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let stage_name = PathBuf::from(format!(".sealr-stage-{suffix}"));
            match create_private_stage(&parent, &stage_name) {
                Ok(()) => match parent.open_dir(&stage_name) {
                    Ok(root) => {
                        return Ok(Self {
                            parent,
                            parent_path,
                            root: Some(root),
                            stage_name,
                            final_name,
                            committed: false,
                        });
                    }
                    Err(error) => {
                        let _ = parent.remove_dir_all(&stage_name);
                        return Err(Finding::error(
                            FindingCode::MaterializeIo,
                            format!("open staging capability: {error}"),
                        ));
                    }
                },
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(Finding::error(
                        FindingCode::MaterializeIo,
                        format!("create staging directory through capability: {error}"),
                    ));
                }
            }
        }
        Err(Finding::error(
            FindingCode::MaterializeIo,
            "could not allocate a unique staging directory",
        ))
    }

    fn root(&self) -> Result<&CapDir, Finding> {
        self.root.as_ref().ok_or_else(|| {
            Finding::error(
                FindingCode::MaterializeIo,
                "staging capability is unavailable",
            )
        })
    }

    fn create_directory(&self, parts: &[String], member: &str) -> Result<(), Finding> {
        let path = relative_parts(parts)?;
        self.root()?.create_dir_all(&path).map_err(|error| {
            Finding::error(
                FindingCode::MaterializeIo,
                format!("create directory through capability: {error}"),
            )
            .on(member)
        })
    }

    fn create_file(&self, parts: &[String]) -> Result<CapFile, Finding> {
        let path = relative_parts(parts)?;
        if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
            self.root()?.create_dir_all(parent).map_err(|error| {
                Finding::error(
                    FindingCode::MaterializeIo,
                    format!("create parent through capability: {error}"),
                )
            })?;
        }
        let mut options = CapOpenOptions::new();
        options.write(true).create_new(true);
        self.root()?.open_with(&path, &options).map_err(|error| {
            Finding::error(
                FindingCode::MaterializeIo,
                format!("create member through capability: {error}"),
            )
        })
    }

    fn commit(&mut self) -> Result<(), Finding> {
        drop(self.root.take());
        rename_noreplace(
            &self.parent,
            &self.parent_path,
            &self.stage_name,
            &self.final_name,
        )
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                Finding::error(
                    FindingCode::MaterializeExists,
                    "destination appeared while materializing",
                )
            } else {
                Finding::error(
                    FindingCode::MaterializeCommit,
                    format!("publish staging directory: {error}"),
                )
            }
        })?;
        self.committed = true;
        Ok(())
    }
}

#[cfg(unix)]
fn create_private_stage(parent: &CapDir, name: &Path) -> io::Result<()> {
    use cap_std::fs::{DirBuilder, DirBuilderExt};

    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    parent.create_dir_with(name, &builder)
}

#[cfg(not(unix))]
fn create_private_stage(parent: &CapDir, name: &Path) -> io::Result<()> {
    parent.create_dir(name)
}

impl Drop for StageDir {
    fn drop(&mut self) {
        if !self.committed {
            drop(self.root.take());
            let _ = self.parent.remove_dir_all(&self.stage_name);
        }
    }
}

fn relative_parts(parts: &[String]) -> Result<PathBuf, Finding> {
    if parts.is_empty() {
        return Err(Finding::error(
            FindingCode::MaterializeIo,
            "canonical member has no path components",
        ));
    }
    let mut path = PathBuf::new();
    for part in parts {
        path.push(part);
    }
    Ok(path)
}

fn capability_path_exists(dir: &CapDir, path: &Path) -> Result<bool, Finding> {
    match dir.symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Finding::error(
            FindingCode::MaterializeIo,
            format!("inspect destination: {error}"),
        )),
    }
}

#[cfg(any(target_os = "android", target_os = "linux", target_vendor = "apple"))]
fn rename_noreplace(
    parent: &CapDir,
    _parent_path: &Path,
    from: &Path,
    to: &Path,
) -> io::Result<()> {
    Ok(rustix::fs::renameat_with(
        parent,
        from,
        parent,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )?)
}

#[cfg(windows)]
fn rename_noreplace(parent: &CapDir, parent_path: &Path, from: &Path, to: &Path) -> io::Result<()> {
    let from = parent_path.join(from);
    let to_full = parent_path.join(to);
    let from = from.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "staging path is not valid Unicode",
        )
    })?;
    let to_full = to_full.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination path is not valid Unicode",
        )
    })?;
    match winsafe::MoveFile(from, to_full) {
        Ok(()) => Ok(()),
        Err(error) => match parent.symlink_metadata(to) {
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "destination exists",
            )),
            Err(inspect_error) if inspect_error.kind() == io::ErrorKind::NotFound => {
                Err(io::Error::other(format!("MoveFileW: {error}")))
            }
            Err(inspect_error) => Err(inspect_error),
        },
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "linux",
    target_vendor = "apple",
    windows
)))]
fn rename_noreplace(
    parent: &CapDir,
    _parent_path: &Path,
    from: &Path,
    to: &Path,
) -> io::Result<()> {
    match parent.symlink_metadata(to) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "destination exists",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => parent.rename(from, parent, to),
        Err(error) => Err(error),
    }
}

fn process_member_to_file(
    payload: &[u8],
    member: &ZipMember,
    policy: &Policy,
    remaining_total: u64,
    mut file: CapFile,
) -> Result<(u64, u32, String), Finding> {
    let result = process_member(payload, member, policy, remaining_total, &mut file)?;
    file.flush().map_err(|error| {
        Finding::error(FindingCode::MaterializeIo, format!("flush member: {error}"))
    })?;
    if policy.atomic {
        file.sync_all().map_err(|error| {
            Finding::error(FindingCode::MaterializeIo, format!("sync member: {error}"))
        })?;
    }
    Ok(result)
}

fn process_member(
    payload: &[u8],
    member: &ZipMember,
    policy: &Policy,
    remaining_total: u64,
    writer: &mut impl Write,
) -> Result<(u64, u32, String), Finding> {
    let mut actual = 0_u64;
    let mut crc = Crc::new();
    let mut sha = Sha256::new();
    let mut consume = |chunk: &[u8]| -> Result<(), Finding> {
        actual = actual.saturating_add(chunk.len() as u64);
        if actual > member.uncomp_size {
            return Err(Finding::error(
                FindingCode::QuotaDeclaredLie,
                "actual bytes exceeded the declared uncompressed size",
            ));
        }
        if actual > policy.max_member_bytes {
            return Err(Finding::error(
                FindingCode::QuotaMember,
                "actual bytes exceeded the member cap",
            ));
        }
        if actual > remaining_total {
            return Err(Finding::error(
                FindingCode::QuotaTotal,
                "actual bytes exceeded the remaining archive cap",
            ));
        }
        if member.comp_size > 0 {
            if let Some(max_ratio) = policy.max_ratio {
                let ratio = actual as f64 / member.comp_size as f64;
                if ratio > max_ratio {
                    return Err(Finding::error(
                        FindingCode::QuotaRatio,
                        format!("actual ratio {ratio:.1} exceeded {max_ratio:.1}"),
                    ));
                }
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
            for chunk in payload.chunks(64 * 1024) {
                consume(chunk)?;
            }
        }
        8 => {
            let mut decoder = DeflateDecoder::new(payload);
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = decoder.read(&mut buffer).map_err(|error| {
                    Finding::error(FindingCode::CrcMismatch, format!("deflate: {error}"))
                })?;
                if read == 0 {
                    break;
                }
                consume(&buffer[..read])?;
            }
        }
        _ => {
            return Err(Finding::error(
                FindingCode::MethodUnsupported,
                format!("method {}", member.method),
            ));
        }
    }
    if actual != member.uncomp_size {
        return Err(Finding::error(
            FindingCode::QuotaDeclaredLie,
            format!(
                "actual size {actual} != declared size {}",
                member.uncomp_size
            ),
        ));
    }
    let digest = sha.finalize();
    let sha256 = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok((actual, crc.finalize(), sha256))
}

fn detect_magic(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 4
        && bytes[0] == 0x50
        && bytes[1] == 0x4b
        && (bytes[2] == 0x03 || bytes[2] == 0x05)
    {
        "zip"
    } else if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        "gz"
    } else {
        "unknown"
    }
}

fn finish(
    path: Option<String>,
    source_digest: String,
    magic: &'static str,
    policy: &Policy,
    verdict: Verdict,
    findings: Vec<Finding>,
    members: Vec<MemberView>,
) -> Outcome {
    let (verdict_s, wrote) = match &verdict {
        Verdict::Allowed { wrote } => ("allowed", *wrote),
        Verdict::Rejected => ("rejected", false),
    };
    let view = View {
        schema: "sealr.view.v1",
        source: SourceMeta {
            path,
            digest: DigestHex {
                sha256: source_digest.clone(),
            },
            magic,
        },
        policy: PolicyMeta {
            id: policy.id.clone(),
            digest: DigestHex {
                sha256: policy.digest_hex(),
            },
        },
        verdict: verdict_s,
        wrote,
        findings: findings.clone(),
        members,
    };
    let view_json = serde_json::to_vec(&view).expect("view json");
    let receipt = Receipt {
        verdict: verdict_s,
        wrote,
        source: DigestHex {
            sha256: source_digest,
        },
        policy: view.policy.clone(),
        view_digest: DigestHex {
            sha256: hex_sha256(&view_json),
        },
        tool: ToolMeta {
            name: "sealr",
            version: env!("CARGO_PKG_VERSION"),
        },
        environment: EnvMeta {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            kernel_jail: "unavailable",
        },
        signed: false,
        findings,
    };
    Outcome {
        verdict,
        receipt,
        view,
    }
}

fn reject_only(
    (path, digest, policy): (Option<String>, String, Policy),
    findings: Vec<Finding>,
    magic: Option<&'static str>,
) -> Outcome {
    finish(
        path,
        digest,
        magic.unwrap_or("unknown"),
        &policy,
        Verdict::Rejected,
        findings,
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::zip::write::SimpleFileOptions;
    use ::zip::{CompressionMethod, ZipWriter};
    use std::io::{Cursor, Write};

    fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut w = ZipWriter::new(&mut cursor);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            for (name, data) in files {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn make_zip_with_directory() -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            writer
                .add_directory("empty/", SimpleFileOptions::default())
                .unwrap();
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn temp_dest(label: &str) -> PathBuf {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        std::env::temp_dir().join(format!("sealr-{label}-{suffix}"))
    }

    fn signature_offsets(bytes: &[u8], signature: [u8; 4]) -> Vec<usize> {
        bytes
            .windows(signature.len())
            .enumerate()
            .filter_map(|(index, window)| (window == signature).then_some(index))
            .collect()
    }

    fn u16_at(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn add_matching_extra_fields(bytes: &mut Vec<u8>, extra: &[u8]) {
        let local = signature_offsets(bytes, [0x50, 0x4b, 0x03, 0x04])[0];
        let central = signature_offsets(bytes, [0x50, 0x4b, 0x01, 0x02])[0];
        let eocd = signature_offsets(bytes, [0x50, 0x4b, 0x05, 0x06])[0];
        let cd_size = u32_at(bytes, eocd + 12);

        let local_name_len = u16_at(bytes, local + 26) as usize;
        let local_extra_len = u16_at(bytes, local + 28) as usize;
        let local_insert = local + 30 + local_name_len + local_extra_len;
        bytes.splice(local_insert..local_insert, extra.iter().copied());
        put_u16(bytes, local + 28, (local_extra_len + extra.len()) as u16);

        let central = central + extra.len();
        let central_name_len = u16_at(bytes, central + 28) as usize;
        let central_extra_len = u16_at(bytes, central + 30) as usize;
        let central_insert = central + 46 + central_name_len + central_extra_len;
        bytes.splice(central_insert..central_insert, extra.iter().copied());
        put_u16(
            bytes,
            central + 30,
            (central_extra_len + extra.len()) as u16,
        );

        let eocd = eocd + extra.len() * 2;
        put_u32(bytes, eocd + 12, cd_size + extra.len() as u32);
        put_u32(bytes, eocd + 16, central as u32);
    }

    fn add_central_comment(bytes: &mut Vec<u8>, comment: &[u8]) {
        let central = signature_offsets(bytes, [0x50, 0x4b, 0x01, 0x02])[0];
        let eocd = signature_offsets(bytes, [0x50, 0x4b, 0x05, 0x06])[0];
        let cd_size = u32_at(bytes, eocd + 12);
        let name_len = u16_at(bytes, central + 28) as usize;
        let extra_len = u16_at(bytes, central + 30) as usize;
        let old_comment_len = u16_at(bytes, central + 32) as usize;
        let insert = central + 46 + name_len + extra_len + old_comment_len;
        bytes.splice(insert..insert, comment.iter().copied());
        put_u16(
            bytes,
            central + 32,
            (old_comment_len + comment.len()) as u16,
        );
        let eocd = eocd + comment.len();
        put_u32(bytes, eocd + 12, cd_size + comment.len() as u32);
    }

    #[test]
    fn inspect_well_formed_zip() {
        let bytes = make_zip(&[("nested/hello.txt", b"hello")]);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("t.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });
        assert!(!out.rejected(), "{:?}", out.view.findings);
        assert!(!out.wrote());
        assert_eq!(out.view.members.len(), 1);
        assert_eq!(out.view.members[0].path, "nested/hello.txt");
        assert!(!out.receipt.source.sha256.is_empty());
        assert_eq!(out.receipt.policy.id, policy.id);
    }

    #[test]
    fn materialize_writes_and_matches_inspect_tree() {
        let bytes = make_zip(&[("nested/hello.txt", b"hello")]);
        let policy = Policy::default_v1();
        let inspect = apply(Request {
            source: Source::Bytes {
                path: Some("t.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });
        let dir = temp_dest("mat");
        let _ = fs::remove_dir_all(&dir);
        let mat = apply(Request {
            source: Source::Bytes {
                path: Some("t.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dir),
        });
        assert!(mat.wrote(), "{:?}", mat.view.findings);
        let extracted = dir.join("nested").join("hello.txt");
        assert_eq!(fs::read(&extracted).unwrap(), b"hello");
        let i: Vec<_> = inspect
            .view
            .members
            .iter()
            .map(|m| (&m.path, &m.sha256))
            .collect();
        let m: Vec<_> = mat
            .view
            .members
            .iter()
            .map(|m| (&m.path, &m.sha256))
            .collect();
        assert_eq!(i, m, "inspect and materialize must agree on the tree");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_path_traversal_and_writes_nothing() {
        let bytes = make_zip(&[("../outside.txt", b"nope")]);
        let policy = Policy::default_v1();
        let dir = temp_dest("trav");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("bad.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dir),
        });
        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|f| f.code == FindingCode::PathDotDot));
        assert!(!out.receipt.source.sha256.is_empty());
        assert!(!dir.join("outside.txt").exists());
        let parent = dir.parent().unwrap();
        assert!(!parent.join("outside.txt").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_colon_ads() {
        let bytes = make_zip(&[("safe.txt:hidden", b"x")]);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("ads.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });
        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|f| f.code == FindingCode::PathAds));
    }

    #[test]
    fn rejects_lfh_cdh_name_mismatch() {
        let mut bytes = make_zip(&[("aaaa.txt", b"hello")]);
        let needle = b"aaaa.txt";
        let mut hits = Vec::new();
        for i in 0..bytes.len().saturating_sub(needle.len()) {
            if &bytes[i..i + needle.len()] == needle {
                hits.push(i);
            }
        }
        assert!(hits.len() >= 2, "expected LFH and CDH names");
        bytes[hits[0]] = b'b';
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("diff.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });
        assert!(out.rejected());
        assert!(
            out.view
                .findings
                .iter()
                .any(|f| f.code == FindingCode::ZipDiffA3Name),
            "{:?}",
            out.view.findings
        );
    }

    #[test]
    fn receipt_always_present_on_garbage() {
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("nope.bin"),
                data: b"not a zip",
            },
            policy: &policy,
            dest: None,
        });
        assert!(out.rejected());
        assert!(!out.receipt.source.sha256.is_empty());
        assert_eq!(out.view.verdict, "rejected");
    }

    #[test]
    fn rejects_existing_destination_without_changing_it() {
        let bytes = make_zip(&[("new.txt", b"new")]);
        let policy = Policy::default_v1();
        let dir = temp_dest("existing");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("keep.txt"), b"keep").unwrap();

        let out = apply(Request {
            source: Source::Bytes {
                path: Some("existing.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dir),
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::MaterializeExists));
        assert_eq!(fs::read(dir.join("keep.txt")).unwrap(), b"keep");
        assert!(!dir.join("new.txt").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn commit_preserves_a_destination_that_appears_after_staging() {
        let dest = temp_dest("appeared");
        let mut stage = StageDir::create(&dest).unwrap();
        let mut file = stage.create_file(&["inside.txt".to_owned()]).unwrap();
        file.write_all(b"staged").unwrap();
        drop(file);

        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("owner.txt"), b"existing").unwrap();
        let error = stage.commit().unwrap_err();

        assert_eq!(error.code, FindingCode::MaterializeExists);
        assert_eq!(fs::read(dest.join("owner.txt")).unwrap(), b"existing");
        drop(stage);
        fs::remove_dir_all(dest).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn capability_writer_refuses_a_symlink_that_leaves_staging() {
        use std::os::unix::fs::symlink;

        let dest = temp_dest("capability");
        let outside = temp_dest("outside");
        fs::create_dir(&outside).unwrap();
        let stage = StageDir::create(&dest).unwrap();
        let stage_path = dest.parent().unwrap().join(&stage.stage_name);
        symlink(&outside, stage_path.join("escape")).unwrap();

        let result = stage.create_file(&["escape".to_owned(), "written.txt".to_owned()]);
        assert!(result.is_err());
        assert!(!outside.join("written.txt").exists());

        drop(stage);
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn late_crc_rejection_never_publishes_the_staged_tree() {
        let mut bytes = make_zip(&[("first.txt", b"first"), ("second.txt", b"second")]);
        let local_headers = signature_offsets(&bytes, [0x50, 0x4b, 0x03, 0x04]);
        let central_headers = signature_offsets(&bytes, [0x50, 0x4b, 0x01, 0x02]);
        assert_eq!(local_headers.len(), 2);
        assert_eq!(central_headers.len(), 2);
        let local_crc = local_headers[1] + 14;
        let central_crc = central_headers[1] + 16;
        let mut wrong_crc =
            u32::from_le_bytes(bytes[central_crc..central_crc + 4].try_into().unwrap());
        wrong_crc ^= 1;
        bytes[local_crc..local_crc + 4].copy_from_slice(&wrong_crc.to_le_bytes());
        bytes[central_crc..central_crc + 4].copy_from_slice(&wrong_crc.to_le_bytes());
        let policy = Policy::default_v1();
        let dir = temp_dest("crc");
        let _ = fs::remove_dir_all(&dir);

        let out = apply(Request {
            source: Source::Bytes {
                path: Some("crc.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dir),
        });

        assert!(out.rejected(), "{:?}", out.view.findings);
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::CrcMismatch));
        assert!(!dir.exists(), "rejected output must not become visible");
    }

    #[test]
    fn rejects_file_directory_topology_conflicts_in_either_order() {
        let policy = Policy::default_v1();
        for files in [
            [("a", b"file".as_slice()), ("a/b", b"child".as_slice())],
            [("a/b", b"child".as_slice()), ("a", b"file".as_slice())],
        ] {
            let bytes = make_zip(&files);
            let out = apply(Request {
                source: Source::Bytes {
                    path: Some("conflict.zip"),
                    data: &bytes,
                },
                policy: &policy,
                dest: None,
            });
            assert!(out.rejected());
            assert!(out
                .view
                .findings
                .iter()
                .any(|finding| finding.code == FindingCode::PathConflict));
        }
    }

    #[test]
    fn materializes_standard_directory_entries() {
        let bytes = make_zip_with_directory();
        let policy = Policy::default_v1();
        let dir = temp_dest("directory");
        let _ = fs::remove_dir_all(&dir);

        let out = apply(Request {
            source: Source::Bytes {
                path: Some("directory.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&dir),
        });

        assert!(out.wrote(), "{:?}", out.view.findings);
        assert!(dir.join("empty").is_dir());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_ambiguous_non_ascii_name_bytes() {
        let mut bytes = make_zip(&[("name.txt", b"data")]);
        let offsets: Vec<_> = bytes
            .windows(b"name.txt".len())
            .enumerate()
            .filter_map(|(index, window)| (window == b"name.txt").then_some(index))
            .collect();
        assert_eq!(offsets.len(), 2);
        for offset in offsets {
            bytes[offset] = 0xff;
        }
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("encoding.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipEncoding));
    }

    #[test]
    fn rejects_archive_over_input_cap_before_parsing() {
        let bytes = make_zip(&[("small.txt", b"small")]);
        let mut policy = Policy::default_v1();
        policy.max_archive_bytes = 8;
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("too-large.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::QuotaArchive));
        assert_eq!(out.receipt.policy.id, policy.id);
    }

    #[test]
    fn accepts_a_matching_data_descriptor_as_part_of_the_single_layout() {
        let mut bytes = make_zip(&[("descriptor.txt", b"descriptor")]);
        let local = signature_offsets(&bytes, [0x50, 0x4b, 0x03, 0x04])[0];
        let central = signature_offsets(&bytes, [0x50, 0x4b, 0x01, 0x02])[0];
        let crc = u32_at(&bytes, central + 16);
        let comp = u32_at(&bytes, central + 20);
        let uncomp = u32_at(&bytes, central + 24);
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&[0x50, 0x4b, 0x07, 0x08]);
        descriptor.extend_from_slice(&crc.to_le_bytes());
        descriptor.extend_from_slice(&comp.to_le_bytes());
        descriptor.extend_from_slice(&uncomp.to_le_bytes());
        bytes.splice(central..central, descriptor);

        let shifted_central = central + 16;
        let eocd = signature_offsets(&bytes, [0x50, 0x4b, 0x05, 0x06])[0];
        let local_flags = u16_at(&bytes, local + 6) | 0x8;
        let central_flags = u16_at(&bytes, shifted_central + 8) | 0x8;
        put_u16(&mut bytes, local + 6, local_flags);
        put_u16(&mut bytes, shifted_central + 8, central_flags);
        put_u32(&mut bytes, eocd + 16, shifted_central as u32);

        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("descriptor.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(!out.rejected(), "{:?}", out.view.findings);
        assert_eq!(out.view.members[0].uncomp_bytes, 10);
    }

    #[test]
    fn rejects_alternate_unicode_path_extra_fields() {
        let mut bytes = make_zip(&[("original.txt", b"content")]);
        add_matching_extra_fields(&mut bytes, &[0x75, 0x70, 0x01, 0x00, 0x01]);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("unicode-extra.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipDiffA3Name));
    }

    #[test]
    fn rejects_malformed_extra_field_sequences() {
        let mut bytes = make_zip(&[("extra.txt", b"content")]);
        add_matching_extra_fields(&mut bytes, &[0x37, 0x13, 0x02, 0x00, 0x00]);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("malformed-extra.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipExtra));
    }

    #[test]
    fn rejects_external_directory_attribute_on_a_file() {
        let mut bytes = make_zip(&[("file.txt", b"content")]);
        let central = signature_offsets(&bytes, [0x50, 0x4b, 0x01, 0x02])[0];
        put_u32(&mut bytes, central + 38, 0x10);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("fake-directory.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipDiffA4Dir));
    }

    #[test]
    fn rejects_hidden_zip64_records_in_central_comments() {
        let mut bytes = make_zip(&[("file.txt", b"content")]);
        add_central_comment(&mut bytes, &[0x50, 0x4b, 0x06, 0x06]);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("hidden-zip64.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipDiffC5Zip64));
    }

    #[test]
    fn rejects_stored_descriptor_payload_with_hidden_records() {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut cursor);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            writer.start_file("records.bin", options).unwrap();
            writer.write_all(&[0x50, 0x4b, 0x03, 0x04]).unwrap();
            writer.finish().unwrap();
        }
        let mut bytes = cursor.into_inner();
        let local = signature_offsets(&bytes, [0x50, 0x4b, 0x03, 0x04])[0];
        let central = signature_offsets(&bytes, [0x50, 0x4b, 0x01, 0x02])[0];
        let crc = u32_at(&bytes, central + 16);
        let comp = u32_at(&bytes, central + 20);
        let uncomp = u32_at(&bytes, central + 24);
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(&[0x50, 0x4b, 0x07, 0x08]);
        descriptor.extend_from_slice(&crc.to_le_bytes());
        descriptor.extend_from_slice(&comp.to_le_bytes());
        descriptor.extend_from_slice(&uncomp.to_le_bytes());
        bytes.splice(central..central, descriptor);

        let shifted_central = central + 16;
        let eocd = signature_offsets(&bytes, [0x50, 0x4b, 0x05, 0x06])[0];
        let local_flags = u16_at(&bytes, local + 6) | 0x8;
        let central_flags = u16_at(&bytes, shifted_central + 8) | 0x8;
        put_u16(&mut bytes, local + 6, local_flags);
        put_u16(&mut bytes, shifted_central + 8, central_flags);
        put_u32(&mut bytes, eocd + 16, shifted_central as u32);

        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("descriptor-record.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipDiffC1Stream));
    }

    #[test]
    fn rejects_unreferenced_bytes_between_local_records_and_cd() {
        let mut bytes = make_zip(&[("gap.txt", b"gap")]);
        let central = signature_offsets(&bytes, [0x50, 0x4b, 0x01, 0x02])[0];
        bytes.insert(central, 0);
        let shifted_central = central + 1;
        let eocd = signature_offsets(&bytes, [0x50, 0x4b, 0x05, 0x06])[0];
        put_u32(&mut bytes, eocd + 16, shifted_central as u32);
        let policy = Policy::default_v1();
        let out = apply(Request {
            source: Source::Bytes {
                path: Some("gap.zip"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        });

        assert!(out.rejected());
        assert!(out
            .view
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ZipDiffC1Stream));
    }

    #[test]
    fn malformed_and_mutated_inputs_never_panic() {
        fn assert_no_panic(bytes: &[u8], label: &str) {
            let policy = Policy::default_v1();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                apply(Request {
                    source: Source::Bytes {
                        path: None,
                        data: bytes,
                    },
                    policy: &policy,
                    dest: None,
                })
            }));
            assert!(result.is_ok(), "apply panicked for {label}");
        }

        let valid = make_zip(&[("nested/payload.txt", b"payload")]);
        for cutoff in 0..=valid.len() {
            assert_no_panic(&valid[..cutoff], &format!("valid prefix {cutoff}"));
        }

        for index in 0..valid.len() {
            for mask in [0x01, 0x80, 0xff] {
                let mut mutated = valid.clone();
                mutated[index] ^= mask;
                assert_no_panic(&mutated, &format!("mutation {index} xor {mask:02x}"));
            }
        }

        let mut state = 0x243f_6a88_85a3_08d3_u64;
        for len in 0..=1024 {
            let mut bytes = vec![0_u8; len];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            assert_no_panic(&bytes, &format!("deterministic noise length {len}"));
        }
    }
}
