use std::fs;
#[cfg(unix)]
use std::net::Shutdown;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Stdio;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

#[path = "../../../scripts/walkthrough_fixtures.rs"]
mod walkthrough_fixtures;

const ALLOWED_SHA256: &str = "580606f3b53229ab60ff1d786bac90c91f75c054269c11142cd971f380d3fc25";
const REJECTED_SHA256: &str = "5039cccff40a5df0d0b61a2734b5dafeb8224f914603cae870f1638990f58140";
const PROFILE_DIGEST: &str = "da3a2145d48decf8f8995ea01f1ddd0adb587f7f3544d4642bb8bb07b8f039f5";
const ALLOWED_LAYOUT: &str = "9986381ec4a61fd34452fb759ccaf44b82ee58c8147ee032f077722c1ccac3a3";
const ALLOWED_CONTENT: &str = "ccae362a7daa3508aace90d589c4538c27f13ff517a82a049e47005724073f38";

static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct RunDirectory {
    path: PathBuf,
}

impl RunDirectory {
    fn create(label: &str) -> Self {
        let target_tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(&target_tmp).expect("Cargo target temp directory should be creatable");
        let sequence = RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = target_tmp.join(format!(
            "sealr-cli-{label}-{}-{sequence}",
            std::process::id()
        ));
        assert!(!path.exists(), "unique test directory already exists");
        fs::create_dir(&path).expect("test directory should be creatable");
        Self { path }
    }
}

impl Drop for RunDirectory {
    fn drop(&mut self) {
        let target_tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        assert!(self.path.starts_with(&target_tmp));
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn sealr(arguments: &[&Path]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sealr"));
    for argument in arguments {
        command.arg(argument);
    }
    command.output().expect("sealr should start")
}

fn sealr_text(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sealr"))
        .args(arguments)
        .output()
        .expect("sealr should start")
}

#[cfg(unix)]
fn sealr_with_unwritable_stdout(arguments: &[&Path]) -> Output {
    let (_reader, writer) = UnixStream::pair().expect("stdout socket pair should be created");
    writer
        .shutdown(Shutdown::Write)
        .expect("stdout socket writes should be disabled");
    let mut command = Command::new(env!("CARGO_BIN_EXE_sealr"));
    for argument in arguments {
        command.arg(argument);
    }
    command
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::piped())
        .output()
        .expect("sealr should start with unwritable stdout")
}

fn json(bytes: &[u8], stream: &str) -> Value {
    serde_json::from_slice(bytes).unwrap_or_else(|error| {
        panic!(
            "{stream} should contain exactly one JSON document: {error}\n{}",
            String::from_utf8_lossy(bytes)
        )
    })
}

fn fixture_set(label: &str) -> (RunDirectory, walkthrough_fixtures::FixturePaths) {
    let run = RunDirectory::create(label);
    let fixtures = walkthrough_fixtures::generate(&run.path.join("fixtures"))
        .expect("walkthrough fixtures should generate");
    (run, fixtures)
}

fn write_octal(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let octal = format!("{value:o}");
    let digits = field.len() - 1;
    field[digits - octal.len()..digits].copy_from_slice(octal.as_bytes());
    field[digits] = 0;
}

fn tar_fixture_bytes() -> Vec<u8> {
    let name = b"mission/status.txt";
    let body = b"nominal\n";
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name);
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], body.len() as u64);
    write_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    write_octal(&mut header[329..337], 0);
    write_octal(&mut header[337..345], 0);
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    let encoded = format!("{checksum:06o}");
    header[148..154].copy_from_slice(encoded.as_bytes());
    header[154] = 0;
    header[155] = b' ';

    let mut bytes = header.to_vec();
    bytes.extend_from_slice(body);
    bytes.resize(bytes.len().next_multiple_of(512), 0);
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

fn write_tar_fixture(path: &Path) {
    fs::write(path, tar_fixture_bytes()).expect("TAR fixture should be writable");
}

fn pax_record(keyword: &str, value: &str) -> Vec<u8> {
    let suffix = format!(" {keyword}={value}\n");
    let mut length = suffix.len() + 1;
    loop {
        let exact = suffix.len() + length.to_string().len();
        if exact == length {
            return format!("{length}{suffix}").into_bytes();
        }
        length = exact;
    }
}

fn tar_header(name: &[u8], size: u64, typeflag: u8) -> [u8; 512] {
    assert!(
        name.len() <= 100,
        "fixture name should fit the ustar name field"
    );
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name);
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], size);
    write_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = typeflag;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    write_octal(&mut header[329..337], 0);
    write_octal(&mut header[337..345], 0);
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    let encoded = format!("{checksum:06o}");
    header[148..154].copy_from_slice(encoded.as_bytes());
    header[154] = 0;
    header[155] = b' ';
    header
}

fn append_tar_record(bytes: &mut Vec<u8>, header: [u8; 512], payload: &[u8]) {
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().next_multiple_of(512), 0);
}

fn tar_pax_fixture_bytes() -> Vec<u8> {
    let body = b"nominal\n";
    let extension = pax_record("path", "mission/status.txt");
    let mut bytes = Vec::new();
    append_tar_record(
        &mut bytes,
        tar_header(b"PaxHeader", extension.len() as u64, b'x'),
        &extension,
    );
    append_tar_record(
        &mut bytes,
        tar_header(b"placeholder", body.len() as u64, b'0'),
        body,
    );
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

fn write_tar_pax_fixture(path: &Path) {
    fs::write(path, tar_pax_fixture_bytes()).expect("PAX TAR fixture should be writable");
}

fn old_gnu_header(name: &[u8], size: u64, typeflag: u8) -> [u8; 512] {
    assert!(!name.is_empty() && name.len() <= 100);
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name);
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], size);
    write_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = typeflag;
    header[257..265].copy_from_slice(b"ustar  \0");
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
    header[154] = 0;
    header[155] = b' ';
    header
}

fn tar_gnu_longname_fixture_bytes() -> (Vec<u8>, String) {
    let member_path = format!("mission/{}/status.txt", "segment".repeat(15));
    let body = b"nominal\n";
    let mut carrier_payload = member_path.as_bytes().to_vec();
    carrier_payload.push(0);
    let mut bytes = Vec::new();
    append_tar_record(
        &mut bytes,
        old_gnu_header(b"producer-carrier", carrier_payload.len() as u64, b'L'),
        &carrier_payload,
    );
    append_tar_record(
        &mut bytes,
        old_gnu_header(b"opaque-base", body.len() as u64, b'0'),
        body,
    );
    bytes.resize(bytes.len() + 1024, 0);
    (bytes, member_path)
}

fn write_tar_gnu_longname_fixture(path: &Path) -> String {
    let (bytes, member_path) = tar_gnu_longname_fixture_bytes();
    fs::write(path, bytes).expect("GNU long-name TAR fixture should be writable");
    member_path
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

fn gzip_fixture_bytes(tar: &[u8]) -> Vec<u8> {
    let len = u16::try_from(tar.len()).expect("CLI TAR fixture fits one stored Deflate block");
    let mut bytes = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255, 0x01];
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(&(!len).to_le_bytes());
    bytes.extend_from_slice(tar);
    bytes.extend_from_slice(&crc32(tar).to_le_bytes());
    bytes.extend_from_slice(&(tar.len() as u32).to_le_bytes());
    bytes
}

fn write_tar_gzip_fixture(path: &Path) {
    fs::write(path, gzip_fixture_bytes(&tar_fixture_bytes()))
        .expect("gzip-wrapped TAR fixture should be writable");
}

fn write_tar_gzip_pax_fixture(path: &Path) {
    fs::write(path, gzip_fixture_bytes(&tar_pax_fixture_bytes()))
        .expect("gzip-wrapped PAX TAR fixture should be writable");
}

fn write_tar_gzip_gnu_longname_fixture(path: &Path) -> String {
    let (tar, member_path) = tar_gnu_longname_fixture_bytes();
    fs::write(path, gzip_fixture_bytes(&tar))
        .expect("gzip-wrapped GNU long-name TAR fixture should be writable");
    member_path
}

/// Zstandard CLI v1.5.7 default-level output for the conformance derived TAR
/// holding `mission/plan.txt` with `verify twice, decode once`.
const TAR_ZSTD_FIXTURE_HEX: &str = "28b52ffd640007a5030062c5121880a96dc0ffd67f1bf321d16a06b6620b6d\
e647c162f422038a129f1e8cf43843d126fa1683558a6866f59b3abd0e3f43c424598ac944438c94ff7fa6e0ffad150d\
4887600824deb5b6100e004fc10f92c40c35149a94c11c58d301c0907b01a0133cf00e83dc50ab0238562e1326b004ca\
51b2db";

fn write_tar_zstd_fixture(path: &Path) {
    let (pairs, remainder) = TAR_ZSTD_FIXTURE_HEX.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    let bytes: Vec<u8> = pairs
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ASCII"), 16)
                .expect("zstd-wrapped TAR fixture hex is valid")
        })
        .collect();
    fs::write(path, bytes).expect("zstd-wrapped TAR fixture should be writable");
}

/// XZ Utils v5.8.1 `xz -6 -T1` output for the same conformance derived TAR
/// holding `mission/plan.txt` with `verify twice, decode once`.
const TAR_XZ_FIXTURE_HEX: &str = "fd377a585a000004e6d6b4460200210116000000742fe5a3e007ff00705d\
00369a4adff3ff4173689225555d5c3da569f20e0f1e46ed67823a5dcf0c5c5749d5f12bb878efa1897bcfa2a38633f7\
d28fc607eaad183da7c2063caa76c99a73e3434b174e4fa5f5dd59582a4d6308d2ffca92620af736cdb6f7b1240ae876\
99d3cfb3eb7748f4ff4a5b315efe8cd37d00ec921496b86e87ef00018c0180100000853c3866b1c467fb020000000004\
595a";

fn write_tar_xz_fixture(path: &Path) {
    let (pairs, remainder) = TAR_XZ_FIXTURE_HEX.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    let bytes: Vec<u8> = pairs
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ASCII"), 16)
                .expect("xz-wrapped TAR fixture hex is valid")
        })
        .collect();
    fs::write(path, bytes).expect("xz-wrapped TAR fixture should be writable");
}

/// CPython 3.12.10 `bz2.compress(tar, 9)` output (bundled libbz2 1.0.8;
/// byte-identical to `bzip2 -9`) for the same conformance derived TAR
/// holding `mission/plan.txt` with `verify twice, decode once`.
const TAR_BZIP2_FIXTURE_HEX: &str = "425a68393141592653597b1dc2a70000447b91ca0000404005ff004000\
6f27dfe0040000400008200074226a64f51a64d0340640c4d064a0d341a680034d001e6587e2308c005913503e46a288\
0842162fc4d83544cc801bd752180f90d0c026e224716664838d467b58fbfac1cf118147687b09c160a4ad2080f498e7\
5a99561f215194f509f0637e2ee48a70a120f63b854e";

fn write_tar_bzip2_fixture(path: &Path) {
    let (pairs, remainder) = TAR_BZIP2_FIXTURE_HEX.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    let bytes: Vec<u8> = pairs
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ASCII"), 16)
                .expect("bzip2-wrapped TAR fixture hex is valid")
        })
        .collect();
    fs::write(path, bytes).expect("bzip2-wrapped TAR fixture should be writable");
}

fn write_zip64_fixture(path: &Path) {
    let hex = "504b03042d0000000800000021000b5704bbffffffffffffffff010014006101001000100000000000000005000000000000007374440500504b01022d002d0000000800000021000b5704bb050000001000000001000000000000000000000080010000000061504b050600000000010001002f000000380000000000";
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    let bytes: Vec<u8> = pairs
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ASCII"), 16)
                .expect("ZIP64 fixture hex is valid")
        })
        .collect();
    fs::write(path, bytes).expect("ZIP64 fixture should be writable");
}

fn assert_allowed_streams(output: &Output, wrote: bool) -> (Value, Value) {
    assert_eq!(output.status.code(), Some(0));
    let view = json(&output.stdout, "stdout");
    let receipt = json(&output.stderr, "stderr");

    assert_eq!(view["schema"], "sealr.view.v1");
    assert_eq!(receipt["schema"], "sealr.receipt.v2");
    assert_eq!(view["verdict"], "allowed");
    assert_eq!(view["wrote"], wrote);
    assert_eq!(view["interpretation"]["status"], "interpreted");
    assert_eq!(view["admission"]["status"], "admitted");
    assert_eq!(view["verification"]["status"], "complete");
    assert_eq!(receipt["verdict"], "allowed");
    assert_eq!(receipt["wrote"], wrote);
    assert_eq!(receipt["interpretation"]["status"], "interpreted");
    assert_eq!(receipt["admission"]["status"], "admitted");
    assert_eq!(receipt["verification"]["status"], "complete");
    assert_eq!(
        receipt["effect"]["status"],
        if wrote { "committed" } else { "not-requested" }
    );
    assert_eq!(receipt["view_completeness"]["status"], "complete");
    assert_eq!(receipt["source_snapshot"], "private-file");
    assert_eq!(receipt["signed"], false);
    assert_eq!(receipt["source"], view["source"]["digest"]);
    assert_eq!(receipt["policy"], view["policy"]);
    assert!(receipt["source"].get("status").is_none());
    assert_eq!(
        receipt["identities"]["interpretation"]["id"],
        "sealr.profile.zip.strict-ascii.v1"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["digest"]["sha256"],
        PROFILE_DIGEST
    );
    assert_eq!(
        receipt["identities"]["layout"]["sealrTreeV1"],
        ALLOWED_LAYOUT
    );
    assert_eq!(
        receipt["identities"]["content"]["sealrTreeV1"],
        ALLOWED_CONTENT
    );
    assert_ne!(
        receipt["identities"]["layout"]["sealrTreeV1"],
        receipt["view_digest"]["sha256"]
    );
    (view, receipt)
}

#[test]
fn help_and_version_use_stdout_and_exit_zero() {
    let help = sealr_text(&["--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(help.stderr.is_empty());
    let help_text = String::from_utf8(help.stdout).expect("help should be UTF-8");
    assert!(help_text.contains("Usage: sealr"));
    assert!(help_text.contains("[ARCHIVE]"));
    assert!(help_text.contains("--dest <DEST>"));
    assert!(help_text.contains("--format <FORMAT>"));
    assert!(help_text.contains("zip64"));
    assert!(help_text.contains("tar-ustar"));
    assert!(help_text.contains("tar-gzip-ustar"));
    assert!(help_text.contains("tar-pax"));
    assert!(help_text.contains("tar-gnu-longname"));
    assert!(help_text.contains("tar-gzip-pax"));
    assert!(help_text.contains("tar-gzip-gnu-longname"));
    assert!(help_text.contains("tar-zstd-ustar"));
    assert!(help_text.contains("tar-xz-ustar"));
    assert!(help_text.contains("tar-bzip2-ustar"));
    assert!(help_text.contains("7z-copy"));
    assert!(help_text.contains("--worker-manifest <ABSOLUTE_PATH>"));
    assert!(help_text.contains("--view <NEW_FILE>"));
    assert!(help_text.contains("--receipt <NEW_FILE>"));
    assert!(help_text.contains("--policy <FILE>"));
    assert!(help_text.contains("--canonical"));
    assert!(help_text.contains("inspect"));
    assert!(help_text.contains("materialize"));
    assert!(help_text.contains("--version"));

    let version = sealr_text(&["--version"]);
    assert_eq!(version.status.code(), Some(0));
    assert!(version.stderr.is_empty());
    assert_eq!(
        String::from_utf8(version.stdout).expect("version should be UTF-8"),
        format!("sealr {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn explicit_tar_format_inspects_and_materializes() {
    let run = RunDirectory::create("tar");
    let archive = run.path.join("mission.tar");
    write_tar_fixture(&archive);

    let inspect = sealr(&[Path::new("--format"), Path::new("tar-ustar"), &archive]);
    assert_eq!(
        inspect.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let view = json(&inspect.stdout, "TAR stdout");
    let receipt = json(&inspect.stderr, "TAR stderr");
    assert_eq!(view["source"]["magic"], "tar");
    assert_eq!(view["members"][0]["path"], "mission/status.txt");
    assert_eq!(
        receipt["identities"]["interpretation"]["id"],
        "sealr.profile.tar.ustar-portable.v1"
    );
    assert!(receipt["identities"]["layout"].get("sealrTreeV2").is_some());

    let destination = run.path.join("materialized");
    let materialize = sealr(&[
        Path::new("--format"),
        Path::new("tar-ustar"),
        &archive,
        Path::new("--dest"),
        &destination,
    ]);
    assert_eq!(materialize.status.code(), Some(0));
    assert_eq!(
        fs::read(destination.join("mission/status.txt")).unwrap(),
        b"nominal\n"
    );
}

#[test]
fn explicit_tar_gzip_format_inspects_and_materializes() {
    let run = RunDirectory::create("tar-gzip");
    let archive = run.path.join("mission.tar.gz");
    write_tar_gzip_fixture(&archive);

    let inspect = sealr(&[Path::new("--format"), Path::new("tar-gzip-ustar"), &archive]);
    assert_eq!(
        inspect.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let view = json(&inspect.stdout, "gzip TAR stdout");
    let receipt = json(&inspect.stderr, "gzip TAR stderr");
    assert_eq!(view["source"]["magic"], "gz");
    assert_eq!(view["members"][0]["path"], "mission/status.txt");
    assert_eq!(
        receipt["identities"]["interpretation"]["id"],
        "sealr.profile.tar-gzip.ustar-portable.v1"
    );
    assert!(receipt["identities"]["layout"].get("sealrTreeV4").is_some());

    let destination = run.path.join("materialized");
    let materialize = sealr(&[
        Path::new("--format"),
        Path::new("tar-gzip-ustar"),
        &archive,
        Path::new("--dest"),
        &destination,
    ]);
    assert_eq!(materialize.status.code(), Some(0));
    assert_eq!(
        fs::read(destination.join("mission/status.txt")).unwrap(),
        b"nominal\n"
    );
}

#[test]
fn explicit_tar_pax_format_inspects_materializes_and_is_not_autodetected() {
    let run = RunDirectory::create("tar-pax");
    let archive = run.path.join("mission.pax.tar");
    write_tar_pax_fixture(&archive);

    let inspect = sealr(&[Path::new("--format"), Path::new("tar-pax"), &archive]);
    assert_eq!(
        inspect.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let view = json(&inspect.stdout, "PAX TAR stdout");
    let receipt = json(&inspect.stderr, "PAX TAR stderr");
    assert_eq!(view["source"]["magic"], "tar");
    assert_eq!(view["members"].as_array().map(Vec::len), Some(1));
    assert_eq!(view["members"][0]["path"], "mission/status.txt");
    assert_eq!(view["members"][0]["method"], "raw");
    assert_eq!(view["members"][0]["uncomp_bytes"], 8);
    assert_eq!(view["policy"]["id"], "sealr:policy/default/v5");
    assert_eq!(
        receipt["identities"]["interpretation"]["id"],
        "sealr.profile.tar.pax-portable.v1"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["digest"]["sha256"],
        "db951f620acf54e67845144e138f9f16994439847a97601e20a424dfea7f4445"
    );
    assert!(receipt["identities"]["layout"].get("sealrTreeV5").is_some());
    assert!(receipt["identities"]["layout"].get("sealrTreeV1").is_none());
    assert!(receipt["identities"]["content"]
        .get("sealrTreeV1")
        .is_some());
    assert_eq!(receipt["policy"], view["policy"]);

    let destination = run.path.join("materialized");
    let materialize = sealr(&[
        Path::new("--format"),
        Path::new("tar-pax"),
        &archive,
        Path::new("--dest"),
        &destination,
    ]);
    assert_eq!(
        materialize.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&materialize.stdout),
        String::from_utf8_lossy(&materialize.stderr)
    );
    assert_eq!(
        fs::read(destination.join("mission/status.txt")).unwrap(),
        b"nominal\n"
    );
    assert!(!destination.join("PaxHeader").exists());
    assert!(!destination.join("placeholder").exists());

    for format in [
        None,
        Some("tar-ustar"),
        Some("tar-gzip-ustar"),
        Some("tar-gzip-pax"),
        Some("tar-gzip-gnu-longname"),
        Some("tar-zstd-ustar"),
        Some("tar-xz-ustar"),
        Some("tar-bzip2-ustar"),
        Some("7z-copy"),
        Some("zip64"),
    ] {
        let output = match format {
            Some(format) => sealr(&[Path::new("--format"), Path::new(format), &archive]),
            None => sealr(&[&archive]),
        };
        assert_eq!(
            output.status.code(),
            Some(2),
            "PAX fixture should not be detected under format selection {format:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn explicit_tar_gnu_longname_inspects_materializes_and_is_not_autodetected() {
    let run = RunDirectory::create("tar-gnu-longname");
    let archive = run.path.join("mission.gnu.tar");
    let member_path = write_tar_gnu_longname_fixture(&archive);

    let inspect = sealr(&[
        Path::new("--format"),
        Path::new("tar-gnu-longname"),
        &archive,
    ]);
    assert_eq!(
        inspect.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let view = json(&inspect.stdout, "GNU TAR stdout");
    let receipt = json(&inspect.stderr, "GNU TAR stderr");
    assert_eq!(view["members"].as_array().map(Vec::len), Some(1));
    assert_eq!(view["members"][0]["path"], member_path);
    assert_eq!(view["members"][0]["method"], "raw");
    assert_eq!(view["members"][0]["uncomp_bytes"], 8);
    assert_eq!(view["policy"]["id"], "sealr:policy/default/v6");
    assert_eq!(
        receipt["identities"]["interpretation"]["id"],
        "sealr.profile.tar.gnu-longname-portable.v1"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["digest"]["sha256"],
        "08fe2698806da997bc42e7e13a45cbf412a4a7056dec39c62456202680b91fa4"
    );
    assert!(receipt["identities"]["layout"].get("sealrTreeV6").is_some());
    assert!(receipt["identities"]["content"]
        .get("sealrTreeV1")
        .is_some());

    let destination = run.path.join("materialized");
    let materialize = sealr(&[
        Path::new("--format"),
        Path::new("tar-gnu-longname"),
        &archive,
        Path::new("--dest"),
        &destination,
    ]);
    assert_eq!(materialize.status.code(), Some(0));
    assert_eq!(
        fs::read(destination.join(&member_path)).unwrap(),
        b"nominal\n"
    );
    assert!(!destination.join("producer-carrier").exists());
    assert!(!destination.join("opaque-base").exists());

    for format in [
        None,
        Some("tar-ustar"),
        Some("tar-pax"),
        Some("tar-gzip-pax"),
        Some("tar-gzip-gnu-longname"),
        Some("tar-zstd-ustar"),
        Some("tar-xz-ustar"),
        Some("tar-bzip2-ustar"),
        Some("7z-copy"),
        Some("zip64"),
    ] {
        let output = match format {
            Some(format) => sealr(&[Path::new("--format"), Path::new(format), &archive]),
            None => sealr(&[&archive]),
        };
        assert_eq!(
            output.status.code(),
            Some(2),
            "GNU fixture should not be detected under format selection {format:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn explicit_tar_gzip_pax_format_inspects_and_materializes() {
    let run = RunDirectory::create("tar-gzip-pax");
    let archive = run.path.join("mission.pax.tar.gz");
    write_tar_gzip_pax_fixture(&archive);

    let inspect = sealr(&[Path::new("--format"), Path::new("tar-gzip-pax"), &archive]);
    assert_eq!(
        inspect.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let view = json(&inspect.stdout, "gzip PAX stdout");
    let receipt = json(&inspect.stderr, "gzip PAX stderr");
    assert_eq!(view["verdict"], "allowed");
    assert_eq!(view["source"]["magic"], "gz");
    assert_eq!(view["members"].as_array().map(Vec::len), Some(1));
    assert_eq!(view["members"][0]["path"], "mission/status.txt");
    assert_eq!(view["members"][0]["method"], "raw");
    assert_eq!(view["members"][0]["uncomp_bytes"], 8);
    assert_eq!(view["policy"]["id"], "sealr:policy/default/v7");
    assert_eq!(
        view["policy"]["digest"]["sha256"],
        "92d576984b718e8a02bc6044090f8e2b335dbd1abd136d53e5b02d0ffbd978ef"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["id"],
        "sealr.profile.tar-gzip.pax-portable.v1"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["digest"]["sha256"],
        "6cc91b2b8563b5b070b44bf357a5c62e5d9dda0aedc374d7a08cd80da9c5434f"
    );
    assert!(receipt["identities"]["layout"].get("sealrTreeV7").is_some());
    assert!(receipt["identities"]["layout"].get("sealrTreeV5").is_none());
    assert!(receipt["identities"]["content"]
        .get("sealrTreeV1")
        .is_some());
    assert_eq!(receipt["policy"], view["policy"]);

    let destination = run.path.join("materialized");
    let materialize = sealr(&[
        Path::new("--format"),
        Path::new("tar-gzip-pax"),
        &archive,
        Path::new("--dest"),
        &destination,
    ]);
    assert_eq!(
        materialize.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&materialize.stdout),
        String::from_utf8_lossy(&materialize.stderr)
    );
    assert_eq!(
        fs::read(destination.join("mission/status.txt")).unwrap(),
        b"nominal\n"
    );
    assert!(!destination.join("PaxHeader").exists());
    assert!(!destination.join("placeholder").exists());

    for format in [
        None,
        Some("zip"),
        Some("zip64"),
        Some("tar-ustar"),
        Some("tar-gzip-ustar"),
        Some("tar-pax"),
        Some("tar-gnu-longname"),
        Some("tar-gzip-gnu-longname"),
        Some("tar-zstd-ustar"),
        Some("tar-xz-ustar"),
        Some("tar-bzip2-ustar"),
        Some("7z-copy"),
    ] {
        let output = match format {
            Some(format) => sealr(&[Path::new("--format"), Path::new(format), &archive]),
            None => sealr(&[&archive]),
        };
        assert_eq!(
            output.status.code(),
            Some(2),
            "gzip-wrapped PAX fixture should not be admitted under format selection {format:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn explicit_tar_gzip_gnu_longname_format_inspects_and_materializes() {
    let run = RunDirectory::create("tar-gzip-gnu-longname");
    let archive = run.path.join("mission.gnu.tar.gz");
    let member_path = write_tar_gzip_gnu_longname_fixture(&archive);

    let inspect = sealr(&[
        Path::new("--format"),
        Path::new("tar-gzip-gnu-longname"),
        &archive,
    ]);
    assert_eq!(
        inspect.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let view = json(&inspect.stdout, "gzip GNU stdout");
    let receipt = json(&inspect.stderr, "gzip GNU stderr");
    assert_eq!(view["verdict"], "allowed");
    assert_eq!(view["source"]["magic"], "gz");
    assert_eq!(view["members"].as_array().map(Vec::len), Some(1));
    assert_eq!(view["members"][0]["path"], member_path);
    assert_eq!(view["members"][0]["method"], "raw");
    assert_eq!(view["members"][0]["uncomp_bytes"], 8);
    assert_eq!(view["policy"]["id"], "sealr:policy/default/v7");
    assert_eq!(
        view["policy"]["digest"]["sha256"],
        "92d576984b718e8a02bc6044090f8e2b335dbd1abd136d53e5b02d0ffbd978ef"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["id"],
        "sealr.profile.tar-gzip.gnu-longname-portable.v1"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["digest"]["sha256"],
        "622943e9629c4acc7cfeb446eb9f2d16bb245db589c1a200e885a9d69a02295a"
    );
    assert!(receipt["identities"]["layout"].get("sealrTreeV8").is_some());
    assert!(receipt["identities"]["layout"].get("sealrTreeV6").is_none());
    assert!(receipt["identities"]["content"]
        .get("sealrTreeV1")
        .is_some());
    assert_eq!(receipt["policy"], view["policy"]);

    let destination = run.path.join("materialized");
    let materialize = sealr(&[
        Path::new("--format"),
        Path::new("tar-gzip-gnu-longname"),
        &archive,
        Path::new("--dest"),
        &destination,
    ]);
    assert_eq!(
        materialize.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&materialize.stdout),
        String::from_utf8_lossy(&materialize.stderr)
    );
    assert_eq!(
        fs::read(destination.join(&member_path)).unwrap(),
        b"nominal\n"
    );
    assert!(!destination.join("producer-carrier").exists());
    assert!(!destination.join("opaque-base").exists());

    for format in [
        None,
        Some("zip"),
        Some("zip64"),
        Some("tar-ustar"),
        Some("tar-gzip-ustar"),
        Some("tar-pax"),
        Some("tar-gnu-longname"),
        Some("tar-gzip-pax"),
        Some("tar-zstd-ustar"),
        Some("tar-xz-ustar"),
        Some("tar-bzip2-ustar"),
        Some("7z-copy"),
    ] {
        let output = match format {
            Some(format) => sealr(&[Path::new("--format"), Path::new(format), &archive]),
            None => sealr(&[&archive]),
        };
        assert_eq!(
            output.status.code(),
            Some(2),
            "gzip-wrapped GNU fixture should not be admitted under format selection {format:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn explicit_tar_zstd_ustar_format_inspects_and_materializes() {
    let run = RunDirectory::create("tar-zstd");
    let archive = run.path.join("mission.tar.zst");
    write_tar_zstd_fixture(&archive);

    let inspect = sealr(&[Path::new("--format"), Path::new("tar-zstd-ustar"), &archive]);
    assert_eq!(
        inspect.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let view = json(&inspect.stdout, "zstd TAR stdout");
    let receipt = json(&inspect.stderr, "zstd TAR stderr");
    assert_eq!(view["verdict"], "allowed");
    assert_eq!(view["source"]["magic"], "zst");
    assert_eq!(view["members"].as_array().map(Vec::len), Some(1));
    assert_eq!(view["members"][0]["path"], "mission/plan.txt");
    assert_eq!(view["members"][0]["method"], "raw");
    assert_eq!(view["members"][0]["uncomp_bytes"], 25);
    assert_eq!(view["policy"]["id"], "sealr:policy/default/v8");
    assert_eq!(
        view["policy"]["digest"]["sha256"],
        "d0cfdf4d40e3a88c8e80170494b23e91761802304265e41ce19cb616fa8a1c42"
    );
    assert_eq!(
        receipt["source"]["sha256"],
        "4a467796ef2cd9a9e1a6ed670fa1d1ef15174b95be29b087af7339c32b078dcb"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["id"],
        "sealr.profile.tar-zstd.ustar-portable.v1"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["digest"]["sha256"],
        "c7d2e708f2f5258eddfb99fbf13661bd2f671a2daa4a45bc1d9603d30d472ae7"
    );
    assert_eq!(
        receipt["identities"]["layout"]["sealrTreeV9"],
        "8638eff6b2507614edc81eaccf4c3168e245febe0d1ee0eeb7651b018233fb63"
    );
    assert!(receipt["identities"]["layout"].get("sealrTreeV4").is_none());
    assert_eq!(
        receipt["identities"]["content"]["sealrTreeV1"],
        "bc8f6d6f7870aeab647cff08db25471a729bd2a41e095d49d6254c49afc34278"
    );
    assert_eq!(receipt["policy"], view["policy"]);

    let destination = run.path.join("materialized");
    let materialize = sealr(&[
        Path::new("--format"),
        Path::new("tar-zstd-ustar"),
        &archive,
        Path::new("--dest"),
        &destination,
    ]);
    assert_eq!(
        materialize.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&materialize.stdout),
        String::from_utf8_lossy(&materialize.stderr)
    );
    assert_eq!(
        fs::read(destination.join("mission/plan.txt")).unwrap(),
        b"verify twice, decode once"
    );

    for format in [
        None,
        Some("zip"),
        Some("zip64"),
        Some("tar-ustar"),
        Some("tar-gzip-ustar"),
        Some("tar-pax"),
        Some("tar-gnu-longname"),
        Some("tar-gzip-pax"),
        Some("tar-gzip-gnu-longname"),
        Some("tar-xz-ustar"),
        Some("tar-bzip2-ustar"),
        Some("7z-copy"),
    ] {
        let output = match format {
            Some(format) => sealr(&[Path::new("--format"), Path::new(format), &archive]),
            None => sealr(&[&archive]),
        };
        assert_eq!(
            output.status.code(),
            Some(2),
            "zstd-wrapped ustar fixture should not be admitted under format selection {format:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn explicit_tar_xz_ustar_format_inspects_and_materializes() {
    let run = RunDirectory::create("tar-xz");
    let archive = run.path.join("mission.tar.xz");
    write_tar_xz_fixture(&archive);

    let inspect = sealr(&[Path::new("--format"), Path::new("tar-xz-ustar"), &archive]);
    assert_eq!(
        inspect.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let view = json(&inspect.stdout, "xz TAR stdout");
    let receipt = json(&inspect.stderr, "xz TAR stderr");
    assert_eq!(view["verdict"], "allowed");
    assert_eq!(view["source"]["magic"], "xz");
    assert_eq!(view["members"].as_array().map(Vec::len), Some(1));
    assert_eq!(view["members"][0]["path"], "mission/plan.txt");
    assert_eq!(view["members"][0]["method"], "raw");
    assert_eq!(view["members"][0]["uncomp_bytes"], 25);
    assert_eq!(view["policy"]["id"], "sealr:policy/default/v9");
    assert_eq!(
        view["policy"]["digest"]["sha256"],
        "c512895c09453f16c07ebeae94712099191b197ba9edaae384dba0fe7bb8b39e"
    );
    assert_eq!(
        receipt["source"]["sha256"],
        "54f88a8a4b418364e2c3f7747d9a40aecee3624d0d0880727e674a9cbc60a8ca"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["id"],
        "sealr.profile.tar-xz.ustar-portable.v1"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["digest"]["sha256"],
        "16ec815ab3b2c3c5f877ec04e592d1dd1a6ec41f2c7d843dd7aa2bc6b50cfd05"
    );
    assert_eq!(
        receipt["identities"]["layout"]["sealrTreeV10"],
        "558d5f8e75966e1ab4b1892e71fcf871f9670f07b3e6ef47ae6e57b6a4e05f8d"
    );
    assert!(receipt["identities"]["layout"].get("sealrTreeV9").is_none());
    assert_eq!(
        receipt["identities"]["content"]["sealrTreeV1"],
        "bc8f6d6f7870aeab647cff08db25471a729bd2a41e095d49d6254c49afc34278"
    );
    assert_eq!(receipt["policy"], view["policy"]);

    let destination = run.path.join("materialized");
    let materialize = sealr(&[
        Path::new("--format"),
        Path::new("tar-xz-ustar"),
        &archive,
        Path::new("--dest"),
        &destination,
    ]);
    assert_eq!(
        materialize.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&materialize.stdout),
        String::from_utf8_lossy(&materialize.stderr)
    );
    assert_eq!(
        fs::read(destination.join("mission/plan.txt")).unwrap(),
        b"verify twice, decode once"
    );

    for format in [
        None,
        Some("zip"),
        Some("zip64"),
        Some("tar-ustar"),
        Some("tar-gzip-ustar"),
        Some("tar-pax"),
        Some("tar-gnu-longname"),
        Some("tar-gzip-pax"),
        Some("tar-gzip-gnu-longname"),
        Some("tar-zstd-ustar"),
        Some("tar-bzip2-ustar"),
        Some("7z-copy"),
    ] {
        let output = match format {
            Some(format) => sealr(&[Path::new("--format"), Path::new(format), &archive]),
            None => sealr(&[&archive]),
        };
        assert_eq!(
            output.status.code(),
            Some(2),
            "xz-wrapped ustar fixture should not be admitted under format selection {format:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn explicit_tar_bzip2_ustar_format_inspects_and_materializes() {
    let run = RunDirectory::create("tar-bzip2");
    let archive = run.path.join("mission.tar.bz2");
    write_tar_bzip2_fixture(&archive);

    let inspect = sealr(&[
        Path::new("--format"),
        Path::new("tar-bzip2-ustar"),
        &archive,
    ]);
    assert_eq!(
        inspect.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let view = json(&inspect.stdout, "bzip2 TAR stdout");
    let receipt = json(&inspect.stderr, "bzip2 TAR stderr");
    assert_eq!(view["verdict"], "allowed");
    assert_eq!(view["source"]["magic"], "bz2");
    assert_eq!(view["members"].as_array().map(Vec::len), Some(1));
    assert_eq!(view["members"][0]["path"], "mission/plan.txt");
    assert_eq!(view["members"][0]["method"], "raw");
    assert_eq!(view["members"][0]["uncomp_bytes"], 25);
    assert_eq!(view["policy"]["id"], "sealr:policy/default/v10");
    assert_eq!(
        view["policy"]["digest"]["sha256"],
        "eada8150e14c0f05dcb25b6c9a90b87d3821fbb5f754192aceaea6d942e9f374"
    );
    assert_eq!(
        receipt["source"]["sha256"],
        "6cf9b27f72fca2d3c665b7012e2ee8cfc24e7f1b7d5cc0f3aa8c239812ea5e87"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["id"],
        "sealr.profile.tar-bzip2.ustar-portable.v1"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["digest"]["sha256"],
        "f6711c0c98cff6e3a2c6b266d159413ef891c202b4898b4e1665081dce0f29ee"
    );
    assert_eq!(
        receipt["identities"]["layout"]["sealrTreeV11"],
        "6adec7927d150611af780ea135964e96cf1581d42a407f637ee752b63ac3894e"
    );
    assert!(receipt["identities"]["layout"]
        .get("sealrTreeV10")
        .is_none());
    assert_eq!(
        receipt["identities"]["content"]["sealrTreeV1"],
        "bc8f6d6f7870aeab647cff08db25471a729bd2a41e095d49d6254c49afc34278"
    );
    assert_eq!(receipt["policy"], view["policy"]);

    let destination = run.path.join("materialized");
    let materialize = sealr(&[
        Path::new("--format"),
        Path::new("tar-bzip2-ustar"),
        &archive,
        Path::new("--dest"),
        &destination,
    ]);
    assert_eq!(
        materialize.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&materialize.stdout),
        String::from_utf8_lossy(&materialize.stderr)
    );
    assert_eq!(
        fs::read(destination.join("mission/plan.txt")).unwrap(),
        b"verify twice, decode once"
    );

    for format in [
        None,
        Some("zip"),
        Some("zip64"),
        Some("tar-ustar"),
        Some("tar-gzip-ustar"),
        Some("tar-pax"),
        Some("tar-gnu-longname"),
        Some("tar-gzip-pax"),
        Some("tar-gzip-gnu-longname"),
        Some("tar-zstd-ustar"),
        Some("tar-xz-ustar"),
        Some("7z-copy"),
    ] {
        let output = match format {
            Some(format) => sealr(&[Path::new("--format"), Path::new(format), &archive]),
            None => sealr(&[&archive]),
        };
        assert_eq!(
            output.status.code(),
            Some(2),
            "bzip2-wrapped ustar fixture should not be admitted under format selection {format:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// 7-Zip 26.02 `7z a -m0=Copy -mhc=off` output holding exactly
/// `mission/plan.txt` with `verify twice, decode once`: one Copy folder and
/// a raw next header.
const SEVENZ_COPY_FIXTURE_HEX: &str = "377abcaf271c000435c12a4919000000000000005a00000000000000eaaeb7e67665726966792074776963652c206465636f6465206f6e63650104060001091900070b01000101000c1900080a0103b44165000005011123006d0069007300730069006f006e002f0070006c0061006e002e0074007800740000001900140a01000000d4bda237dd0115060100200000000000";

fn write_sevenz_copy_fixture(path: &Path) {
    let (pairs, remainder) = SEVENZ_COPY_FIXTURE_HEX.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    let bytes: Vec<u8> = pairs
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ASCII"), 16)
                .expect("7z Copy fixture hex is valid")
        })
        .collect();
    fs::write(path, bytes).expect("7z Copy fixture should be writable");
}

#[test]
fn explicit_sevenz_copy_format_inspects_and_materializes() {
    let run = RunDirectory::create("sevenz-copy");
    let archive = run.path.join("mission.7z");
    write_sevenz_copy_fixture(&archive);

    let inspect = sealr(&[Path::new("--format"), Path::new("7z-copy"), &archive]);
    assert_eq!(
        inspect.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let view = json(&inspect.stdout, "7z stdout");
    let receipt = json(&inspect.stderr, "7z stderr");
    assert_eq!(view["verdict"], "allowed");
    assert_eq!(view["source"]["magic"], "7z");
    assert_eq!(view["members"].as_array().map(Vec::len), Some(1));
    assert_eq!(view["members"][0]["path"], "mission/plan.txt");
    assert_eq!(view["members"][0]["method"], "copy");
    assert_eq!(view["members"][0]["uncomp_bytes"], 25);
    assert_eq!(view["policy"]["id"], "sealr:policy/default/v11");
    assert_eq!(
        view["policy"]["digest"]["sha256"],
        "afa0aeb04ceca00706b31dfd250216a87f2af0ada6e98d3815873de0d15172fc"
    );
    assert_eq!(
        receipt["source"]["sha256"],
        "ebefe20d0dfd944e29a0987e4b182c80595e2a7ec4d1efe3217123e22259c289"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["id"],
        "sealr.profile.7z.copy-portable.v1"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["digest"]["sha256"],
        "7b6604ad59b5aecf9ebdfa42d7d48d3df663813798992741dd6d74ea56f60b75"
    );
    assert_eq!(
        receipt["identities"]["layout"]["sealrTreeV12"],
        "df4c1271279959b9fbd90e56078913779e134f52a69c52d959878ad76bff9a9d"
    );
    assert!(receipt["identities"]["layout"]
        .get("sealrTreeV11")
        .is_none());
    assert_eq!(
        receipt["identities"]["content"]["sealrTreeV1"],
        "bc8f6d6f7870aeab647cff08db25471a729bd2a41e095d49d6254c49afc34278"
    );
    assert_eq!(receipt["policy"], view["policy"]);

    let destination = run.path.join("materialized");
    let materialize = sealr(&[
        Path::new("--format"),
        Path::new("7z-copy"),
        &archive,
        Path::new("--dest"),
        &destination,
    ]);
    assert_eq!(
        materialize.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&materialize.stdout),
        String::from_utf8_lossy(&materialize.stderr)
    );
    assert_eq!(
        fs::read(destination.join("mission/plan.txt")).unwrap(),
        b"verify twice, decode once"
    );

    for format in [
        None,
        Some("zip"),
        Some("zip64"),
        Some("tar-ustar"),
        Some("tar-gzip-ustar"),
        Some("tar-pax"),
        Some("tar-gnu-longname"),
        Some("tar-gzip-pax"),
        Some("tar-gzip-gnu-longname"),
        Some("tar-zstd-ustar"),
        Some("tar-xz-ustar"),
        Some("tar-bzip2-ustar"),
    ] {
        let output = match format {
            Some(format) => sealr(&[Path::new("--format"), Path::new(format), &archive]),
            None => sealr(&[&archive]),
        };
        assert_eq!(
            output.status.code(),
            Some(2),
            "7z Copy fixture should not be admitted under format selection {format:?}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn explicit_zip64_format_inspects_materializes_and_does_not_alias_zip32() {
    let run = RunDirectory::create("zip64");
    let archive = run.path.join("forced-small.zip");
    write_zip64_fixture(&archive);

    let inspect = sealr(&[Path::new("--format"), Path::new("zip64"), &archive]);
    assert_eq!(
        inspect.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let view = json(&inspect.stdout, "ZIP64 stdout");
    let receipt = json(&inspect.stderr, "ZIP64 stderr");
    assert_eq!(view["source"]["magic"], "zip");
    assert_eq!(view["members"][0]["path"], "a");
    assert_eq!(
        receipt["identities"]["interpretation"]["id"],
        "sealr.profile.zip64.strict-ascii.v1"
    );
    assert_eq!(
        receipt["identities"]["interpretation"]["digest"]["sha256"],
        "167a6d226bbe74e88189ec61c61df10ae5ed35c0294ad0cf3b5194d2f0bc23e2"
    );
    assert_eq!(
        receipt["identities"]["layout"]["sealrTreeV3"],
        "c074e18efe379d4c1544380e734fbf09a9185805942e20ad96f72cfe6460e95f"
    );
    assert_eq!(
        receipt["identities"]["content"]["sealrTreeV1"],
        "9b878b8f52b46ababb846c3796dbb4cdd3de990a828d5affd183e91f2639ddbd"
    );

    let destination = run.path.join("materialized");
    let materialize = sealr(&[
        Path::new("--format"),
        Path::new("zip64"),
        &archive,
        Path::new("--dest"),
        &destination,
    ]);
    assert_eq!(materialize.status.code(), Some(0));
    assert_eq!(fs::read(destination.join("a")).unwrap(), vec![b'A'; 16]);

    let compatibility_default = sealr(&[&archive]);
    assert_eq!(compatibility_default.status.code(), Some(2));
    assert!(!compatibility_default.stdout.is_empty());

    let fixtures = walkthrough_fixtures::generate(&run.path.join("zip32-fixtures"))
        .expect("ZIP32 fixtures should generate");
    let selected_on_zip32 = sealr(&[Path::new("--format"), Path::new("zip64"), &fixtures.allowed]);
    assert_eq!(selected_on_zip32.status.code(), Some(2));
}

#[test]
fn selected_supervision_failure_has_no_in_process_fallback() {
    let (run, fixtures) = fixture_set("supervision-failure");
    let missing_manifest = run.path.join("sealr-worker.manifest");
    let output = sealr(&[
        Path::new("--worker-manifest"),
        &missing_manifest,
        &fixtures.allowed,
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("diagnostic should be UTF-8");
    assert!(stderr.contains("sealr: supervised execution failed:"));
}

#[test]
fn walkthrough_fixtures_are_byte_stable() {
    let (_run, fixtures) = fixture_set("fixtures");
    let allowed = fs::read(fixtures.allowed).expect("allowed fixture should be readable");
    let rejected = fs::read(fixtures.rejected).expect("rejected fixture should be readable");

    assert_eq!(sealr::hex_sha256(&allowed), ALLOWED_SHA256);
    assert_eq!(sealr::hex_sha256(&rejected), REJECTED_SHA256);
}

#[test]
fn inspect_allow_writes_view_to_stdout_and_receipt_to_stderr() {
    let (run, fixtures) = fixture_set("inspect");
    let output = sealr(&[&fixtures.allowed]);
    let (view, receipt) = assert_allowed_streams(&output, false);

    assert_eq!(view["findings"].as_array().map(Vec::len), Some(0));
    let members = view["members"]
        .as_array()
        .expect("members should be an array");
    assert_eq!(members.len(), 2);
    assert_eq!(members[0]["path"], walkthrough_fixtures::CONFIG_PATH);
    assert_eq!(members[0]["method"], "store");
    assert_eq!(members[0]["uncomp_bytes"], 14);
    assert_eq!(members[1]["path"], walkthrough_fixtures::HELLO_PATH);
    assert_eq!(members[1]["method"], "store");
    assert_eq!(members[1]["uncomp_bytes"], 17);
    assert_eq!(receipt["source"]["sha256"], ALLOWED_SHA256);

    assert!(!run.path.join("materialized").exists());
    assert!(!run.path.join("outside.txt").exists());
}

#[test]
fn rejected_parent_path_exits_two_and_never_writes() {
    let (run, fixtures) = fixture_set("reject");
    let destination = run.path.join("blocked");
    let output = sealr(&[&fixtures.rejected, Path::new("--dest"), &destination]);

    assert_eq!(output.status.code(), Some(2));
    let view = json(&output.stdout, "stdout");
    let receipt = json(&output.stderr, "stderr");
    assert_eq!(view["verdict"], "rejected");
    assert_eq!(view["wrote"], false);
    assert_eq!(view["members"].as_array().map(Vec::len), Some(0));
    assert_eq!(receipt["verdict"], "rejected");
    assert_eq!(receipt["wrote"], false);
    assert_eq!(receipt["source"]["sha256"], REJECTED_SHA256);
    assert_eq!(receipt["source"], view["source"]["digest"]);
    assert_eq!(receipt["schema"], "sealr.receipt.v2");
    assert_eq!(receipt["interpretation"]["status"], "interpreted");
    assert_eq!(receipt["admission"]["status"], "denied");
    assert_eq!(receipt["verification"]["status"], "structure-only");
    assert_eq!(receipt["effect"]["status"], "not-requested");

    let findings = view["findings"]
        .as_array()
        .expect("findings should be an array");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["code"], "path.dotdot");
    assert_eq!(findings[0]["severity"], "error");
    assert_eq!(findings[0]["member"], walkthrough_fixtures::REJECTED_PATH);
    assert_eq!(findings[0]["detail"], "parent component");
    assert_eq!(receipt["findings"], view["findings"]);

    assert!(!destination.exists());
    assert!(!run.path.join("outside.txt").exists());
}

#[test]
fn materialization_exits_zero_and_matches_the_inspected_members() {
    let (run, fixtures) = fixture_set("materialize");
    let inspect = sealr(&[&fixtures.allowed]);
    let (inspect_view, _) = assert_allowed_streams(&inspect, false);

    let destination = run.path.join("materialized");
    assert!(!destination.exists());
    let materialize = sealr(&[&fixtures.allowed, Path::new("--dest"), &destination]);
    let (materialized_view, receipt) = assert_allowed_streams(&materialize, true);

    assert_eq!(inspect_view["members"], materialized_view["members"]);
    let inspect_receipt = json(&inspect.stderr, "inspect stderr");
    assert_eq!(
        inspect_receipt["identities"]["layout"],
        receipt["identities"]["layout"]
    );
    assert_eq!(
        inspect_receipt["identities"]["content"],
        receipt["identities"]["content"]
    );
    assert_ne!(
        inspect_receipt["view_digest"], receipt["view_digest"],
        "view_digest covers the invocation, not the tree"
    );
    assert_eq!(receipt["source"]["sha256"], ALLOWED_SHA256);
    assert_eq!(
        fs::read(destination.join(walkthrough_fixtures::CONFIG_PATH))
            .expect("config should materialize"),
        walkthrough_fixtures::CONFIG_BYTES
    );
    assert_eq!(
        fs::read(destination.join(walkthrough_fixtures::HELLO_PATH))
            .expect("hello should materialize"),
        walkthrough_fixtures::HELLO_BYTES
    );
    assert!(!run.path.join("outside.txt").exists());
}

#[cfg(unix)]
#[test]
fn unwritable_stdout_preserves_inspect_and_materialize_receipts() {
    let (run, fixtures) = fixture_set("unwritable-stdout");

    let inspect = sealr_with_unwritable_stdout(&[&fixtures.allowed]);
    assert_eq!(inspect.status.code(), Some(1));
    assert!(inspect.stdout.is_empty());
    let inspect_receipt = json(&inspect.stderr, "inspect stderr");
    assert_eq!(inspect_receipt["schema"], "sealr.receipt.v2");
    assert_eq!(inspect_receipt["verdict"], "allowed");
    assert_eq!(inspect_receipt["wrote"], false);
    assert_eq!(inspect_receipt["effect"]["status"], "not-requested");

    let destination = run.path.join("materialized");
    let materialize =
        sealr_with_unwritable_stdout(&[&fixtures.allowed, Path::new("--dest"), &destination]);
    assert_eq!(materialize.status.code(), Some(1));
    assert!(materialize.stdout.is_empty());
    let materialize_receipt = json(&materialize.stderr, "materialize stderr");
    assert_eq!(materialize_receipt["schema"], "sealr.receipt.v2");
    assert_eq!(materialize_receipt["verdict"], "allowed");
    assert_eq!(materialize_receipt["wrote"], true);
    assert_eq!(materialize_receipt["effect"]["status"], "committed");
    assert_eq!(
        fs::read(destination.join(walkthrough_fixtures::HELLO_PATH))
            .expect("materialization should complete even when stdout is unwritable"),
        walkthrough_fixtures::HELLO_BYTES
    );
}

#[test]
fn missing_destination_parent_rejects_without_creating_it() {
    let (run, fixtures) = fixture_set("missing-parent");
    let parent = run.path.join("missing");
    let destination = parent.join("materialized");

    let output = sealr(&[&fixtures.allowed, Path::new("--dest"), &destination]);

    assert_eq!(output.status.code(), Some(3));
    let view = json(&output.stdout, "stdout");
    let receipt = json(&output.stderr, "stderr");
    assert_eq!(view["verdict"], "rejected");
    assert_eq!(view["wrote"], false);
    assert_eq!(view["admission"]["status"], "admitted");
    assert_eq!(view["effect"]["status"], "failed");
    assert_eq!(receipt["verdict"], "rejected");
    assert_eq!(receipt["wrote"], false);
    assert_eq!(receipt["admission"]["status"], "admitted");
    assert_eq!(receipt["effect"]["status"], "failed");
    assert_eq!(receipt["materialization"]["outcome"], "setup-failed");
    assert_eq!(receipt["materialization"]["cleanup"], "not-created");
    assert_eq!(view["findings"][0]["code"], "materialize.io");
    assert_eq!(receipt["schema"], "sealr.receipt.v2");
    assert_eq!(receipt["interpretation"]["status"], "interpreted");
    assert_eq!(receipt["admission"]["status"], "admitted");
    assert_eq!(receipt["verification"]["status"], "structure-only");
    assert_eq!(receipt["effect"]["status"], "failed");
    assert!(!parent.exists());
    assert!(!destination.exists());
}

#[test]
fn missing_archive_exits_two_without_a_source_digest() {
    let run = RunDirectory::create("missing-archive");
    let missing = run.path.join("nope.zip");
    let output = sealr(&[&missing]);

    assert_eq!(output.status.code(), Some(2));
    let view = json(&output.stdout, "stdout");
    let receipt = json(&output.stderr, "stderr");
    assert_eq!(view["verdict"], "rejected");
    assert_eq!(receipt["schema"], "sealr.receipt.v2");
    assert_eq!(receipt["source"]["status"], "unavailable");
    assert!(receipt["source"].get("sha256").is_none());
    assert_eq!(view["source"]["digest"]["status"], "unavailable");
    assert_eq!(receipt["interpretation"]["status"], "indeterminate");
    assert_eq!(receipt["admission"]["status"], "not-evaluated");
    assert_eq!(receipt["effect"]["status"], "not-requested");
    assert_eq!(receipt["source_snapshot"], "unavailable");
}

#[test]
fn view_and_receipt_files_carry_the_stream_documents_and_silence_the_streams() {
    let (run, fixtures) = fixture_set("output-files");
    let view_path = run.path.join("evidence.view.json");
    let receipt_path = run.path.join("evidence.receipt.json");

    let output = sealr(&[
        &fixtures.allowed,
        Path::new("--view"),
        &view_path,
        Path::new("--receipt"),
        &receipt_path,
    ]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "stdout must stay silent");
    assert!(output.stderr.is_empty(), "stderr must stay silent");

    let view_bytes = fs::read(&view_path).expect("view file should exist");
    let receipt_bytes = fs::read(&receipt_path).expect("receipt file should exist");
    let view = json(&view_bytes, "view file");
    let receipt = json(&receipt_bytes, "receipt file");
    assert_eq!(view["schema"], "sealr.view.v1");
    assert_eq!(view["verdict"], "allowed");
    assert_eq!(receipt["schema"], "sealr.receipt.v2");
    assert_eq!(receipt["verdict"], "allowed");
    assert_eq!(receipt["source"]["sha256"], ALLOWED_SHA256);

    let streamed = sealr(&[&fixtures.allowed]);
    assert_eq!(streamed.status.code(), Some(0));
    assert_eq!(view_bytes, streamed.stdout, "view file must equal stdout");
    assert_eq!(
        receipt_bytes, streamed.stderr,
        "receipt file must equal stderr"
    );
}

#[test]
fn semantic_exit_codes_survive_file_redirection() {
    let (run, fixtures) = fixture_set("output-files-reject");
    let view_path = run.path.join("rejected.view.json");
    let receipt_path = run.path.join("rejected.receipt.json");

    let output = sealr(&[
        &fixtures.rejected,
        Path::new("--view"),
        &view_path,
        Path::new("--receipt"),
        &receipt_path,
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    let view = json(&fs::read(&view_path).expect("view file"), "view file");
    let receipt = json(
        &fs::read(&receipt_path).expect("receipt file"),
        "receipt file",
    );
    assert_eq!(view["verdict"], "rejected");
    assert_eq!(receipt["verdict"], "rejected");
    assert_eq!(view["findings"][0]["code"], "path.dotdot");
}

#[test]
fn existing_output_files_refuse_before_any_effect_and_are_never_overwritten() {
    let (run, fixtures) = fixture_set("output-files-existing");
    let view_path = run.path.join("evidence.view.json");
    fs::write(&view_path, b"prior evidence\n").expect("pre-existing file");
    let destination = run.path.join("materialized");

    let output = sealr(&[
        &fixtures.allowed,
        Path::new("--dest"),
        &destination,
        Path::new("--view"),
        &view_path,
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.starts_with("sealr: view output file "),
        "unexpected diagnostic: {message}"
    );
    assert_eq!(
        fs::read(&view_path).expect("pre-existing file remains"),
        b"prior evidence\n",
        "an existing output file must never be overwritten"
    );
    assert!(
        !destination.exists(),
        "output destinations are claimed before any materialization effect"
    );
}

#[test]
fn shared_view_and_receipt_path_is_refused() {
    let (run, fixtures) = fixture_set("output-files-shared");
    let shared = run.path.join("evidence.json");

    let output = sealr(&[
        &fixtures.allowed,
        Path::new("--view"),
        &shared,
        Path::new("--receipt"),
        &shared,
    ]);

    assert_eq!(output.status.code(), Some(1));
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.starts_with("sealr: receipt output file "),
        "unexpected diagnostic: {message}"
    );
    assert!(
        !shared.exists(),
        "a refused run must leave the filesystem unchanged"
    );
}

fn policy_json(mutate: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut value = serde_json::to_value(sealr::Policy::default_v1()).expect("policy serializes");
    mutate(&mut value);
    serde_json::to_string_pretty(&value).expect("policy renders")
}

#[test]
fn a_validated_policy_file_replaces_the_default_and_binds_its_identity() {
    let (run, fixtures) = fixture_set("policy-file");
    let policy_path = run.path.join("caller-policy.json");
    fs::write(
        &policy_path,
        policy_json(|value| {
            value["id"] = serde_json::json!("sealr:policy/caller/one");
        }),
    )
    .expect("write policy file");

    let output = sealr(&[&fixtures.allowed, Path::new("--policy"), &policy_path]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt = json(&output.stderr, "stderr");
    assert_eq!(receipt["verdict"], "allowed");
    assert_eq!(receipt["policy"]["id"], "sealr:policy/caller/one");
    assert_ne!(
        receipt["policy"]["digest"]["sha256"],
        json(&sealr(&[&fixtures.allowed]).stderr, "default stderr")["policy"]["digest"]["sha256"],
        "a caller policy with its own id must carry its own digest"
    );
}

#[test]
fn a_policy_file_that_does_not_authorize_the_selected_format_rejects_with_evidence() {
    let run = RunDirectory::create("policy-file-format");
    let archive = run.path.join("mission.tar");
    write_tar_fixture(&archive);
    let policy_path = run.path.join("zip-only.json");
    fs::write(&policy_path, policy_json(|_| {})).expect("write policy file");

    let output = sealr(&[
        Path::new("--format"),
        Path::new("tar-ustar"),
        &archive,
        Path::new("--policy"),
        &policy_path,
    ]);

    assert_eq!(output.status.code(), Some(2));
    let view = json(&output.stdout, "stdout");
    assert_eq!(view["verdict"], "rejected", "{view}");
}

#[test]
fn invalid_policy_files_are_refused_before_any_evaluation() {
    let (run, fixtures) = fixture_set("policy-file-invalid");

    let unknown_field = run.path.join("unknown-field.json");
    fs::write(
        &unknown_field,
        policy_json(|value| {
            value["insecure"] = serde_json::json!(true);
        }),
    )
    .expect("write policy file");
    let output = sealr(&[&fixtures.allowed, Path::new("--policy"), &unknown_field]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stdout.is_empty(),
        "no view JSON for a refused policy"
    );
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("unknown field"), "{message}");

    let bad_vocabulary = run.path.join("bad-vocabulary.json");
    fs::write(
        &bad_vocabulary,
        policy_json(|value| {
            value["symlinks"] = serde_json::json!("allow");
        }),
    )
    .expect("write policy file");
    let output = sealr(&[&fixtures.allowed, Path::new("--policy"), &bad_vocabulary]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("policy.unsupported"), "{message}");

    let missing = run.path.join("missing.json");
    let output = sealr(&[&fixtures.allowed, Path::new("--policy"), &missing]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn canonical_evidence_files_carry_exactly_the_digested_bytes() {
    let (run, fixtures) = fixture_set("canonical-files");
    let view_path = run.path.join("evidence.view.json");
    let receipt_path = run.path.join("evidence.receipt.json");

    let output = sealr(&[
        &fixtures.allowed,
        Path::new("--canonical"),
        Path::new("--view"),
        &view_path,
        Path::new("--receipt"),
        &receipt_path,
    ]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "stdout must stay silent");
    assert!(output.stderr.is_empty(), "stderr must stay silent");

    let view_bytes = fs::read(&view_path).expect("view file");
    let receipt_bytes = fs::read(&receipt_path).expect("receipt file");
    assert_eq!(*view_bytes.last().unwrap(), b'}', "no trailing newline");
    assert_eq!(*receipt_bytes.last().unwrap(), b'}', "no trailing newline");

    let view = json(&view_bytes, "canonical view");
    let receipt = json(&receipt_bytes, "canonical receipt");
    assert_eq!(view["schema"], "sealr.view.v2");
    assert_eq!(receipt["schema"], "sealr.receipt.v3");
    assert_eq!(receipt["canonicalization"], "rfc8785");
    assert_eq!(receipt["view_schema"], "sealr.view.v2");
    assert_eq!(
        receipt["view_digest"]["sha256"],
        sealr::hex_sha256(&view_bytes).as_str(),
        "hashing the view file must reproduce the receipt's view_digest"
    );

    let again_view = run.path.join("again.view.json");
    let again_receipt = run.path.join("again.receipt.json");
    let output = sealr(&[
        &fixtures.allowed,
        Path::new("--canonical"),
        Path::new("--view"),
        &again_view,
        Path::new("--receipt"),
        &again_receipt,
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        fs::read(&again_view).expect("second view file"),
        view_bytes,
        "same-machine canonical emission is byte-deterministic"
    );
}

#[test]
fn canonical_rejection_evidence_holds_the_same_property() {
    let (run, fixtures) = fixture_set("canonical-rejected");
    let view_path = run.path.join("rejected.view.json");
    let receipt_path = run.path.join("rejected.receipt.json");

    let output = sealr(&[
        &fixtures.rejected,
        Path::new("--canonical"),
        Path::new("--view"),
        &view_path,
        Path::new("--receipt"),
        &receipt_path,
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    let view_bytes = fs::read(&view_path).expect("view file");
    let receipt = json(&fs::read(&receipt_path).expect("receipt file"), "receipt");
    assert_eq!(receipt["verdict"], "rejected");
    assert_eq!(
        receipt["view_digest"]["sha256"],
        sealr::hex_sha256(&view_bytes).as_str()
    );
}

#[test]
fn canonical_requires_both_evidence_file_flags() {
    let (run, fixtures) = fixture_set("canonical-flags");
    let view_path = run.path.join("only.view.json");

    let output = sealr(&[&fixtures.allowed, Path::new("--canonical")]);
    assert_eq!(output.status.code(), Some(2), "clap usage error expected");
    assert!(output.stdout.is_empty());

    let output = sealr(&[
        &fixtures.allowed,
        Path::new("--canonical"),
        Path::new("--view"),
        &view_path,
    ]);
    assert_eq!(output.status.code(), Some(2), "clap usage error expected");
    assert!(!view_path.exists(), "no file is claimed on a usage error");
}

#[test]
fn the_inspect_subcommand_is_byte_identical_to_the_compatibility_form() {
    let (_run, fixtures) = fixture_set("subcommand-inspect");

    let bare = sealr(&[&fixtures.allowed]);
    let subcommand = sealr(&[Path::new("inspect"), &fixtures.allowed]);

    assert_eq!(subcommand.status.code(), Some(0));
    assert_eq!(subcommand.stdout, bare.stdout, "view streams must agree");
    assert_eq!(subcommand.stderr, bare.stderr, "receipt streams must agree");
}

#[test]
fn the_materialize_subcommand_publishes_the_same_tree_as_the_dest_flag() {
    let (run, fixtures) = fixture_set("subcommand-materialize");
    let destination = run.path.join("materialized");

    let output = sealr(&[
        Path::new("materialize"),
        &fixtures.allowed,
        Path::new("--dest"),
        &destination,
    ]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let view = json(&output.stdout, "stdout");
    let receipt = json(&output.stderr, "stderr");
    assert_eq!(view["verdict"], "allowed");
    assert_eq!(view["wrote"], true);
    assert_eq!(receipt["effect"]["status"], "committed");
    assert!(destination
        .join(walkthrough_fixtures::CONFIG_PATH)
        .is_file());
    assert!(destination.join(walkthrough_fixtures::HELLO_PATH).is_file());
}

#[test]
fn the_inspect_subcommand_refuses_a_destination() {
    let (run, fixtures) = fixture_set("subcommand-inspect-dest");
    let destination = run.path.join("blocked");

    let output = sealr(&[
        Path::new("inspect"),
        &fixtures.allowed,
        Path::new("--dest"),
        &destination,
    ]);

    assert_eq!(output.status.code(), Some(2), "clap usage error expected");
    assert!(output.stdout.is_empty(), "no view JSON on a usage error");
    assert!(!destination.exists());
}

#[test]
fn the_materialize_subcommand_requires_a_destination() {
    let (_run, fixtures) = fixture_set("subcommand-materialize-nodest");
    let output = sealr(&[Path::new("materialize"), &fixtures.allowed]);
    assert_eq!(output.status.code(), Some(2), "clap usage error expected");
    assert!(output.stdout.is_empty());
}

#[test]
fn top_level_arguments_conflict_with_subcommands() {
    let (run, fixtures) = fixture_set("subcommand-conflict");
    let destination = run.path.join("blocked");

    let output = sealr(&[
        Path::new("--dest"),
        &destination,
        Path::new("inspect"),
        &fixtures.allowed,
    ]);

    assert_eq!(output.status.code(), Some(2), "clap usage error expected");
    assert!(output.stdout.is_empty());
    assert!(!destination.exists());
}

#[test]
fn a_missing_archive_and_subcommand_is_a_usage_error() {
    let output = sealr_text(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.contains("an archive path or a subcommand is required"),
        "unexpected diagnostic: {message}"
    );
}
