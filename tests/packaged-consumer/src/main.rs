use std::collections::BTreeMap;
use std::io::{Cursor, Write};

use sealr::wheel::{evaluate_wheel, WheelEvaluation, WheelLimits, CONSUMER_PROFILE_ID};
use sealr::{
    apply_supervised, apply_with_options, ApplyOptions, ArchiveFormat, LinuxWorker,
    MemberReadErrorKind, Policy, Request, RetentionPlan, RetentionStatus, Source,
    TarInterpretationProfile, TarPaxInterpretationProfile, TreeRoot, VerifiedArchive,
    ZipInterpretationProfile, TAR_PAX_PORTABLE_V1, TAR_USTAR_PORTABLE_V1,
    ZIP_STRICT_ASCII_V2,
};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

// A canonical ZIP32 archive containing stored `hello.txt` with bytes `hello`.
const HELLO_ZIP: &[u8] = &[
    // Local file header.
    0x50, 0x4b, 0x03, 0x04, // signature
    0x14, 0x00, // version needed
    0x00, 0x00, // flags
    0x00, 0x00, // Store
    0x00, 0x00, 0x00, 0x00, // time and date
    0x86, 0xa6, 0x10, 0x36, // CRC32
    0x05, 0x00, 0x00, 0x00, // compressed size
    0x05, 0x00, 0x00, 0x00, // uncompressed size
    0x09, 0x00, // filename length
    0x00, 0x00, // extra length
    b'h', b'e', b'l', b'l', b'o', b'.', b't', b'x', b't', // hello.txt
    b'h', b'e', b'l', b'l', b'o', // payload
    // Central directory header.
    0x50, 0x4b, 0x01, 0x02, // signature
    0x14, 0x00, // version made by
    0x14, 0x00, // version needed
    0x00, 0x00, // flags
    0x00, 0x00, // Store
    0x00, 0x00, 0x00, 0x00, // time and date
    0x86, 0xa6, 0x10, 0x36, // CRC32
    0x05, 0x00, 0x00, 0x00, // compressed size
    0x05, 0x00, 0x00, 0x00, // uncompressed size
    0x09, 0x00, // filename length
    0x00, 0x00, // extra length
    0x00, 0x00, // comment length
    0x00, 0x00, // disk start
    0x00, 0x00, // internal attributes
    0x00, 0x00, 0x00, 0x00, // external attributes
    0x00, 0x00, 0x00, 0x00, // local-header offset
    b'h', b'e', b'l', b'l', b'o', b'.', b't', b'x', b't', // hello.txt
    // End of central directory.
    0x50, 0x4b, 0x05, 0x06, // signature
    0x00, 0x00, 0x00, 0x00, // disk numbers
    0x01, 0x00, 0x01, 0x00, // entry counts
    0x37, 0x00, 0x00, 0x00, // central-directory size: 55
    0x2c, 0x00, 0x00, 0x00, // central-directory offset: 44
    0x00, 0x00, // comment length
];

fn main() {
    let mut args = std::env::args_os().skip(1);
    assert_eq!(
        args.next().as_deref(),
        Some(std::ffi::OsStr::new("--worker-manifest")),
        "usage: sealr-packaged-consumer --worker-manifest <absolute-path>"
    );
    let manifest = args
        .next()
        .expect("worker manifest path is required for the packaged consumer");
    assert!(
        args.next().is_none(),
        "packaged consumer rejects unexpected arguments"
    );
    let worker = LinuxWorker::load_from_manifest(std::path::Path::new(&manifest))
        .expect("packaged crate must authenticate the selected production helper");
    let policy = Policy::default_v1();
    let retention = RetentionPlan::new(5, 5)
        .with_path("hello.txt")
        .expect("canonical bounded path");
    let options = ApplyOptions::new()
        .with_interpretation_profile(ZipInterpretationProfile::StrictAsciiV2)
        .with_retention(retention);
    let outcome = apply_supervised(
        Request {
            source: Source::Bytes {
                path: Some("hello.zip"),
                data: HELLO_ZIP,
            },
            policy: &policy,
            dest: None,
        },
        &options,
        &worker,
    )
    .expect("packaged crate must complete through the supervised boundary");

    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
    assert_eq!(outcome.archive_ir().unwrap().profile(), ZIP_STRICT_ASCII_V2);
    let archive: &VerifiedArchive = outcome
        .verified_archive()
        .expect("admitted archive must expose verified authority");
    assert_eq!(
        archive.retention_status("hello.txt"),
        RetentionStatus::Retained
    );
    assert_eq!(
        archive.retained_member("hello.txt"),
        Some(b"hello".as_slice())
    );
    assert_eq!(archive.read_member("hello.txt", 5).unwrap(), b"hello");
    assert_eq!(
        archive.read_member("hello.txt", 4).unwrap_err().kind(),
        MemberReadErrorKind::LimitExceeded
    );

    let retained: VerifiedArchive = outcome
        .into_verified_archive()
        .expect("capability remains available when taken from the outcome");
    assert_eq!(retained.member("hello.txt").unwrap().canonical_path, "hello.txt");

    let wheel_bytes = wheel_bytes();
    let wheel_options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
    let wheel_outcome = apply_supervised(
        Request {
            source: Source::Bytes {
                path: Some("demo-1.0-py3-none-any.whl"),
                data: &wheel_bytes,
            },
            policy: &policy,
            dest: None,
        },
        &wheel_options,
        &worker,
    )
    .expect("packaged crate must verify the portable wheel through the supervisor");
    assert!(!wheel_outcome.rejected(), "{:?}", wheel_outcome.view.findings);
    let evaluation = evaluate_wheel(
        "demo-1.0-py3-none-any.whl",
        wheel_outcome
            .verified_archive()
            .expect("verified wheel authority"),
        WheelLimits::default(),
    );
    let WheelEvaluation::Admitted {
        artifact,
        plan,
        identities,
        ..
    } = evaluation
    else {
        panic!("packaged wheel evaluator did not admit its canonical fixture");
    };
    assert_eq!(artifact.consumer_profile, CONSUMER_PROFILE_ID);
    assert!(artifact
        .record
        .iter()
        .any(|binding| binding.path == "demo/caf\u{e9}.py"));
    assert_eq!(plan.artifact_sha256(), identities.artifact_sha256);

    let tar_policy = Policy::default_v2();
    let tar_options = ApplyOptions::new()
        .with_tar_interpretation_profile(TarInterpretationProfile::UstarPortableV1)
        .with_retention(
            RetentionPlan::new(8, 8)
                .with_path("retained.txt")
                .expect("canonical TAR retention path"),
        );
    let tar_outcome = {
        let tar_bytes = portable_tar();
        apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("portable.tar"),
                    data: &tar_bytes,
                },
                policy: &tar_policy,
                dest: None,
            },
            &tar_options,
        )
    };
    assert!(!tar_outcome.rejected(), "{:?}", tar_outcome.view.findings);
    let tar_ir = tar_outcome.archive_ir().expect("portable TAR IR");
    assert_eq!(tar_ir.format(), ArchiveFormat::TarUstar);
    assert_eq!(tar_ir.profile(), TAR_USTAR_PORTABLE_V1);
    assert!(matches!(
        tar_outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV2 { .. }
    ));
    let tar_archive = tar_outcome
        .into_verified_archive()
        .expect("portable TAR must expose verified authority");
    assert_eq!(
        tar_archive.retention_status("retained.txt"),
        RetentionStatus::Retained
    );
    assert_eq!(
        tar_archive.retained_member("retained.txt"),
        Some(b"retained".as_slice())
    );
    assert_eq!(tar_archive.read_member("later.txt", 5).unwrap(), b"later");

    let pax_policy = Policy::default_v5();
    let pax_options = ApplyOptions::new()
        .with_tar_pax_interpretation_profile(TarPaxInterpretationProfile::PortableV1)
        .with_retention(
            RetentionPlan::new(4, 4)
                .with_path("mars/retained.txt")
                .expect("canonical PAX retention path"),
        );
    let pax_outcome = {
        let pax_bytes = portable_pax();
        apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("portable-pax.tar"),
                    data: &pax_bytes,
                },
                policy: &pax_policy,
                dest: None,
            },
            &pax_options,
        )
    };
    assert!(!pax_outcome.rejected(), "{:?}", pax_outcome.view.findings);
    let pax_ir = pax_outcome.archive_ir().expect("portable PAX IR");
    assert_eq!(pax_ir.format(), ArchiveFormat::TarPax);
    assert_eq!(pax_ir.profile(), TAR_PAX_PORTABLE_V1);
    assert_eq!(pax_ir.pax_extensions().expect("PAX extension evidence").len(), 1);
    assert!(matches!(
        pax_outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV5 { .. }
    ));
    let pax_archive = pax_outcome
        .into_verified_archive()
        .expect("portable PAX must expose verified authority");
    assert_eq!(
        pax_archive.retention_status("mars/retained.txt"),
        RetentionStatus::Retained
    );
    assert_eq!(
        pax_archive.retained_member("mars/retained.txt"),
        Some(b"mars".as_slice())
    );
    assert_eq!(
        pax_archive.read_member("mars/retained.txt", 4).unwrap(),
        b"mars"
    );
}

fn portable_tar() -> Vec<u8> {
    let mut bytes = Vec::new();
    for (name, body) in [
        ("retained.txt", b"retained".as_slice()),
        ("later.txt", b"later".as_slice()),
    ] {
        bytes.extend_from_slice(&ustar_header(name, body.len()));
        bytes.extend_from_slice(body);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
    }
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

fn portable_pax() -> Vec<u8> {
    let payload = [pax_record("path", "mars/retained.txt"), pax_record("size", "4")].concat();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&ustar_header_with_type("PaxHeaders/entry", payload.len(), b'x'));
    bytes.extend_from_slice(&payload);
    bytes.resize(bytes.len().next_multiple_of(512), 0);
    bytes.extend_from_slice(&ustar_header_with_type("placeholder", 99, b'0'));
    bytes.extend_from_slice(b"mars");
    bytes.resize(bytes.len().next_multiple_of(512), 0);
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let body = format!(" {key}={value}\n");
    let mut digits = 1_usize;
    loop {
        let length = digits + body.len();
        let next_digits = length.to_string().len();
        if digits == next_digits {
            return format!("{length}{body}").into_bytes();
        }
        digits = next_digits;
    }
}

fn ustar_header(name: &str, body_len: usize) -> [u8; 512] {
    ustar_header_with_type(name, body_len, b'0')
}

fn ustar_header_with_type(name: &str, body_len: usize, typeflag: u8) -> [u8; 512] {
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    write_ustar_octal(&mut header[100..108], 0o644);
    write_ustar_octal(&mut header[108..116], 0);
    write_ustar_octal(&mut header[116..124], 0);
    write_ustar_octal(&mut header[124..136], body_len as u64);
    write_ustar_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = typeflag;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
    header[154] = 0;
    header[155] = b' ';
    header
}

fn write_ustar_octal(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let octal = format!("{value:o}");
    let digit_len = field.len() - 1;
    field[digit_len - octal.len()..digit_len].copy_from_slice(octal.as_bytes());
    field[digit_len] = 0;
}

fn wheel_bytes() -> Vec<u8> {
    let mut files = BTreeMap::new();
    files.insert("demo/__init__.py".to_owned(), b"VALUE = 1\n".to_vec());
    files.insert(
        "demo/caf\u{e9}.py".to_owned(),
        b"VALUE = 'unicode'\n".to_vec(),
    );
    files.insert(
        "demo-1.0.dist-info/WHEEL".to_owned(),
        b"Wheel-Version: 1.0\nGenerator: packaged-consumer\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n".to_vec(),
    );
    files.insert(
        "demo-1.0.dist-info/METADATA".to_owned(),
        b"Metadata-Version: 2.4\nName: demo\nVersion: 1.0\n\n".to_vec(),
    );
    let mut record = String::new();
    for (path, bytes) in &files {
        record.push_str(path);
        record.push_str(",sha256=");
        record.push_str(&base64url(&Sha256::digest(bytes)));
        record.push(',');
        record.push_str(&bytes.len().to_string());
        record.push('\n');
    }
    record.push_str("demo-1.0.dist-info/RECORD,,\n");
    files.insert("demo-1.0.dist-info/RECORD".to_owned(), record.into_bytes());

    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        let options =
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (path, bytes) in files {
            writer.start_file(path, options).expect("start wheel member");
            writer.write_all(&bytes).expect("write wheel member");
        }
        writer.finish().expect("finish wheel");
    }
    cursor.into_inner()
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
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
