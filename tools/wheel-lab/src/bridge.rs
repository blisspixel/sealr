use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use sealr::{MemberKind, VerifiedArchive};
use serde::Serialize;

use crate::model::{RecordBinding, WheelArtifactIR, WheelInstallPlan, WheelLimits};

const BRIDGE_SCHEMA: &str = "sealr.installer-bridge.v1";
const BRIDGE_ID: &str = "pypa-installer-0.7.0-wheel-source";
const INSTALLER_VERSION: &str = "0.7.0";
const INSTALLER_WHEEL_SHA256: &str =
    "05d1933f0a5ba7d8d6296bb6d5018e7c94fa473ceb10cf198a92ccea19c27b53";
const MAX_DESCRIPTOR_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct BridgeError {
    detail: String,
}

impl BridgeError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for BridgeError {}

#[derive(Debug)]
pub struct BridgeStage {
    descriptor_path: PathBuf,
}

impl BridgeStage {
    pub fn descriptor_path(&self) -> &Path {
        &self.descriptor_path
    }
}

#[derive(Serialize)]
struct BridgeDescriptor<'a> {
    schema: &'static str,
    bridge: &'static str,
    installer_version: &'static str,
    installer_wheel_sha256: &'static str,
    interpreter: &'static str,
    artifact: &'a WheelArtifactIR,
    plan: &'a WheelInstallPlan,
    members: Vec<BridgeMember>,
}

#[derive(Serialize)]
struct BridgeMember {
    member_index: usize,
    path: String,
    blob: String,
    sha256: String,
    size: u64,
    record_hash: String,
    record_size: String,
    executable: bool,
}

pub fn stage_installer_bridge(
    root: &Path,
    archive: &VerifiedArchive,
    artifact: &WheelArtifactIR,
    plan: &WheelInstallPlan,
    limits: WheelLimits,
) -> Result<BridgeStage, BridgeError> {
    if root.exists() {
        return Err(BridgeError::new(
            "installer bridge root already exists; exclusive staging is required",
        ));
    }
    fs::create_dir(root)
        .map_err(|error| BridgeError::new(format!("create bridge root: {error}")))?;
    let blobs = root.join("members");
    fs::create_dir(&blobs)
        .map_err(|error| BridgeError::new(format!("create bridge member directory: {error}")))?;

    let records = artifact
        .record
        .iter()
        .map(|record| (record.path.as_str(), record))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut total = 0_u64;
    let mut members = Vec::new();
    for (member_index, member) in archive.members().iter().enumerate() {
        if matches!(member.kind, MemberKind::Directory) {
            continue;
        }
        let size = member
            .actual_uncomp_size
            .ok_or_else(|| BridgeError::new("verified bridge member lacks measured size"))?;
        if size > limits.max_bridge_member_bytes {
            return Err(BridgeError::new(format!(
                "bridge member {} exceeds the {}-byte cap",
                member.canonical_path, limits.max_bridge_member_bytes
            )));
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| BridgeError::new("bridge member byte total overflowed u64"))?;
        if total > limits.max_bridge_total_bytes {
            return Err(BridgeError::new(format!(
                "bridge members exceed the {}-byte aggregate cap",
                limits.max_bridge_total_bytes
            )));
        }
        let bytes = archive
            .read_member(&member.canonical_path, limits.max_bridge_member_bytes)
            .map_err(|error| {
                BridgeError::new(format!(
                    "read verified bridge member {}: {error}",
                    member.canonical_path
                ))
            })?;
        if bytes.len() as u64 != size {
            return Err(BridgeError::new(
                "verified bridge read disagrees with measured member size",
            ));
        }
        let digest = member
            .content_sha256
            .as_deref()
            .ok_or_else(|| BridgeError::new("verified bridge member lacks SHA-256 evidence"))?;
        let record = records
            .get(member.canonical_path.as_str())
            .ok_or_else(|| BridgeError::new("bridge member is absent from bound RECORD"))?;
        let facts = member
            .container_facts()
            .ok_or_else(|| BridgeError::new("bridge member lacks ZIP container facts"))?;
        let blob = format!("{member_index:06}.bin");
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(blobs.join(&blob))
            .map_err(|error| BridgeError::new(format!("create bridge member blob: {error}")))?;
        output
            .write_all(&bytes)
            .and_then(|()| output.flush())
            .map_err(|error| BridgeError::new(format!("write bridge member blob: {error}")))?;
        members.push(BridgeMember {
            member_index,
            path: member.canonical_path.clone(),
            blob,
            sha256: digest.to_owned(),
            size,
            record_hash: record_hash(record)?,
            record_size: record
                .size
                .map_or_else(String::new, |value| value.to_string()),
            executable: facts.pypa_installer_0_7_executable(),
        });
    }

    let descriptor = BridgeDescriptor {
        schema: BRIDGE_SCHEMA,
        bridge: BRIDGE_ID,
        installer_version: INSTALLER_VERSION,
        installer_wheel_sha256: INSTALLER_WHEEL_SHA256,
        interpreter: "/sealr/python3",
        artifact,
        plan,
        members,
    };
    let mut encoded = serde_json::to_vec_pretty(&descriptor)
        .map_err(|error| BridgeError::new(format!("encode bridge descriptor: {error}")))?;
    if encoded.len() > MAX_DESCRIPTOR_BYTES {
        return Err(BridgeError::new(format!(
            "bridge descriptor exceeds the {MAX_DESCRIPTOR_BYTES}-byte cap"
        )));
    }
    encoded.push(b'\n');
    let descriptor_path = root.join("descriptor.json");
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&descriptor_path)
        .map_err(|error| BridgeError::new(format!("create bridge descriptor: {error}")))?;
    output
        .write_all(&encoded)
        .and_then(|()| output.flush())
        .map_err(|error| BridgeError::new(format!("write bridge descriptor: {error}")))?;
    Ok(BridgeStage { descriptor_path })
}

fn record_hash(record: &RecordBinding) -> Result<String, BridgeError> {
    let Some(value) = record.sha256.as_deref() else {
        return Ok(String::new());
    };
    if value.len() != 64 {
        return Err(BridgeError::new(
            "bound RECORD SHA-256 is not a 32-byte hexadecimal digest",
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let text = std::str::from_utf8(pair)
            .map_err(|_| BridgeError::new("bound RECORD SHA-256 is not ASCII"))?;
        digest[index] = u8::from_str_radix(text, 16)
            .map_err(|_| BridgeError::new("bound RECORD SHA-256 is not hexadecimal"))?;
    }
    Ok(format!("sha256={}", base64url(&digest)))
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(ALPHABET[((value >> 18) & 63) as usize] as char);
        output.push(ALPHABET[((value >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[((value >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(value & 63) as usize] as char);
        }
    }
    output
}
