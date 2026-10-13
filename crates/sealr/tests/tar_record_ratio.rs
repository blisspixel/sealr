//! Mandatory TAR record padding is framing, not payload expansion.
//!
//! The captured blobs are one-member GNU tar archives padded to one 10240-byte
//! record. Hostile payloads and zeros past that record stay in the numerator.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crc32fast::Hasher as Crc;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use sealr::{
    apply_with_options, hex_sha256, tar_gzip_gnu_longname_portable_v1_digest,
    tar_gzip_ustar_portable_v1_digest, tar_ustar_portable_v1_digest,
    tar_zstd_ustar_portable_v1_digest, AdmissionStatus, ApplyOptions, Finding, FindingCode,
    NormalizationAction, Policy, Request, Source, TarGzipInterpretationProfile,
    TarInterpretationProfile, TarZstdInterpretationProfile, ZipInterpretationProfile,
};

const ONE_TAR_ZST: &str = "28b52ffd0458d50200920410178019a80360648613aa091e4b07778dec12f230a212dd650518145b8bb1944a87aed4105f5650245a1fcd83df2526bf1443f28a779efb8b68fe8b06820022040800f005f04f03540c850320fc01900660d60a5775025b07de9903";
const EMPTY_FILE_TAR_GZ: &str = "1f8b0800000000000003edce310e82401404d03d8a27307f815dce63416924ba247a7bb1d0586905d57bcd1433c54ce7b93d8eedded276625587e195792cf19d6f2997aef67d44a95d8a9c4b8ce9101b7efa586eed745dafcccb74f9b5fbd7030000000000000000c08e9e7039789a00280000";
const EMPTY_DIR_TAR_GZ: &str = "1f8b0800000000000003edce310e82401404d03d0a377017fcec794ca4b030128482db8b85c64a2bacde6ba6982966b88ef37abe4c87b49fbca911cf2c35f267bea4126ddf753947dfa65cca316a6a62c74f6fcb7d3e4ddb9571196edf76bf7a000000000000000000f8a3079b24963800280000";
const GNU_DEFAULT_TAR_GZ: &str = "1f8b0800000000000003edce3d0a83401884e1afce29f608dfba3fa98558a6c90d04058b8515a3e4fa49d8c6caa41111dea79962a6984753dfee8dec4a3fa2f7dfb4d7a0eb2cac171baae89c6a8895a855ef8218ddf756b13ce7763246c6a5cf5bbb5ffd490d7d4ad9bcf294bacbd15f0000000000000000000000000000ff7b036e037ca000280000";

fn decode_hex(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn write_octal(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let octal = format!("{value:o}");
    let digits = field.len() - 1;
    field[digits - octal.len()..digits].copy_from_slice(octal.as_bytes());
    field[digits] = 0;
}

fn header(name: &str, body_len: u64, typeflag: u8, linkname: &str) -> [u8; 512] {
    let mut header = [0_u8; 512];
    assert!(name.len() < 100);
    header[..name.len()].copy_from_slice(name.as_bytes());
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], body_len);
    write_octal(&mut header[136..148], 1_788_000_000);
    header[148..156].fill(b' ');
    header[156] = typeflag;
    assert!(linkname.len() < 100);
    header[157..157 + linkname.len()].copy_from_slice(linkname.as_bytes());
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    write_octal(&mut header[329..337], 0);
    write_octal(&mut header[337..345], 0);
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
    header[154] = 0;
    header[155] = b' ';
    header
}

fn ustar_entry(name: &str, body: &[u8], typeflag: u8, linkname: &str) -> Vec<u8> {
    let mut tar = header(name, body.len() as u64, typeflag, linkname).to_vec();
    tar.extend_from_slice(body);
    tar.resize(tar.len().next_multiple_of(512), 0);
    tar
}

fn finish_tar(mut members: Vec<u8>) -> Vec<u8> {
    members.resize(members.len() + 1024, 0);
    members
}

fn pad_record(mut tar: Vec<u8>) -> Vec<u8> {
    let padded = tar.len().next_multiple_of(10_240);
    tar.resize(padded, 0);
    tar
}

fn gzip_bytes(payload: &[u8]) -> Vec<u8> {
    let mut deflater = DeflateEncoder::new(Vec::new(), Compression::default());
    deflater.write_all(payload).unwrap();
    let compressed = deflater.finish().unwrap();
    let mut bytes = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    bytes.extend_from_slice(&compressed);
    let mut crc = Crc::new();
    crc.update(payload);
    bytes.extend_from_slice(&crc.finalize().to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes
}

fn inspect(
    bytes: &[u8],
    path: &str,
    policy: &Policy,
    options: &ApplyOptions,
    dest: Option<&std::path::Path>,
) -> sealr::Outcome {
    apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some(path),
                data: bytes,
            },
            policy,
            dest,
        },
        options,
    )
}

fn gzip_ustar_options() -> ApplyOptions {
    ApplyOptions::new()
        .with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::UstarPortableV1)
}

fn assert_admitted(outcome: &sealr::Outcome, label: &str) {
    assert!(
        matches!(outcome.admission, AdmissionStatus::Admitted),
        "{label} findings: {:?}",
        outcome
            .view
            .findings
            .iter()
            .map(|finding| (finding.code.as_str(), finding.detail.as_str()))
            .collect::<Vec<_>>()
    );
    assert!(outcome.view.findings.is_empty(), "{label}");
    let json = serde_json::to_string(&outcome.view.findings).unwrap();
    assert!(
        !json.contains("hint"),
        "{label} admitted findings omit hint"
    );
}

fn ratio_finding(outcome: &sealr::Outcome) -> &Finding {
    outcome
        .view
        .findings
        .iter()
        .find(|finding| finding.code == FindingCode::QuotaRatio)
        .unwrap_or_else(|| {
            panic!(
                "expected quota.ratio, got {:?}",
                outcome
                    .view
                    .findings
                    .iter()
                    .map(|finding| finding.code.as_str())
                    .collect::<Vec<_>>()
            )
        })
}

fn charged_numerator(detail: &str) -> u64 {
    let rest = detail
        .split_once("output ")
        .unwrap_or_else(|| panic!("detail {detail}"))
        .1;
    rest.split_once(':')
        .unwrap()
        .0
        .parse()
        .unwrap_or_else(|_| panic!("numerator in {detail}"))
}

#[test]
fn captured_minimal_gnu_records_are_admitted_at_the_default_ratio() {
    let one = decode_hex(ONE_TAR_ZST);
    let empty_file = decode_hex(EMPTY_FILE_TAR_GZ);
    let empty_dir = decode_hex(EMPTY_DIR_TAR_GZ);
    let zstd = inspect(
        &one,
        "one.tar.zst",
        &Policy::default_v8(),
        &ApplyOptions::new()
            .with_tar_zstd_interpretation_profile(TarZstdInterpretationProfile::UstarPortableV1),
        None,
    );
    assert_admitted(&zstd, "one.tar.zst");
    assert_eq!(zstd.view.members.len(), 1);
    assert_eq!(zstd.view.members[0].path, "README");
    assert_eq!(
        zstd.verified_archive()
            .unwrap()
            .read_member("README", 64)
            .unwrap(),
        b"hello world\n"
    );
    assert_eq!(
        zstd.receipt.identities.interpretation.digest.sha256,
        tar_zstd_ustar_portable_v1_digest()
    );
    assert_eq!(
        zstd.receipt.source.sha256(),
        Some(hex_sha256(&one).as_str())
    );

    let file = inspect(
        &empty_file,
        "emptyfile.tar.gz",
        &Policy::default_v4(),
        &gzip_ustar_options(),
        None,
    );
    assert_admitted(&file, "emptyfile.tar.gz");
    assert_eq!(file.view.members[0].path, "empty.txt");
    assert_eq!(file.view.members[0].uncomp_bytes, 0);
    assert_eq!(
        file.receipt.identities.interpretation.digest.sha256,
        tar_gzip_ustar_portable_v1_digest()
    );

    let dir = inspect(
        &empty_dir,
        "emptydir.tar.gz",
        &Policy::default_v4(),
        &gzip_ustar_options(),
        None,
    );
    assert_admitted(&dir, "emptydir.tar.gz");
    assert_eq!(dir.view.members[0].path, "emptydir");
    assert_eq!(dir.view.members[0].kind, "dir");

    let mut tight = Policy::default_v8();
    tight.max_ratio = Some(1);
    let still_bounded = inspect(
        &one,
        "one.tar.zst",
        &tight,
        &ApplyOptions::new()
            .with_tar_zstd_interpretation_profile(TarZstdInterpretationProfile::UstarPortableV1),
        None,
    );
    let finding = ratio_finding(&still_bounded);
    let numerator = charged_numerator(&finding.detail);
    assert!(
        numerator < 10_240,
        "framing must leave the numerator: {numerator}"
    );
    assert!(numerator > 0);
}

#[test]
fn real_high_ratio_payloads_and_extra_zero_records_stay_rejected() {
    let body = vec![0_u8; 256 * 1024];
    let member = pad_record(finish_tar(ustar_entry("zeros.bin", &body, b'0', "")));
    let wrapped = gzip_bytes(&member);
    let outcome = inspect(
        &wrapped,
        "zeros.tar.gz",
        &Policy::default_v4(),
        &gzip_ustar_options(),
        None,
    );
    assert!(matches!(outcome.admission, AdmissionStatus::Denied));
    let finding = ratio_finding(&outcome);
    let numerator = charged_numerator(&finding.detail);
    assert!(
        numerator > 256 * 1024,
        "member payload stays charged, numerator {numerator}, detail {}",
        finding.detail
    );
    assert!(numerator + 10_240 >= member.len() as u64);
    assert_eq!(outcome.view.findings.len(), 1);

    let tiny = pad_record(finish_tar(ustar_entry("a.txt", b"hi", b'0', "")));
    let admitted = inspect(
        &gzip_bytes(&tiny),
        "tiny.tar.gz",
        &Policy::default_v4(),
        &gzip_ustar_options(),
        None,
    );
    assert_admitted(&admitted, "one record of padding");

    let mut bomb = tiny.clone();
    bomb.extend(std::iter::repeat_n(0_u8, 20 * 10_240));
    let rejected = inspect(
        &gzip_bytes(&bomb),
        "tail.tar.gz",
        &Policy::default_v4(),
        &gzip_ustar_options(),
        None,
    );
    let tail = ratio_finding(&rejected);
    let tail_numerator = charged_numerator(&tail.detail);
    assert!(
        tail_numerator > 20 * 10_240,
        "zeros past the terminator record stay charged: {}",
        tail.detail
    );

    let unstructured = gzip_bytes(&vec![0_u8; 100_000]);
    let garbage = inspect(
        &unstructured,
        "zeros.gz",
        &Policy::default_v4(),
        &gzip_ustar_options(),
        None,
    );
    let full = ratio_finding(&garbage);
    assert_eq!(charged_numerator(&full.detail), 100_000);
    assert_eq!(garbage.view.findings.len(), 1);
}

#[test]
fn gnu_magic_under_ustar_names_the_gnu_gzip_profile_without_selecting_it() {
    let bytes = decode_hex(GNU_DEFAULT_TAR_GZ);
    let outcome = inspect(
        &bytes,
        "gnudefault.tar.gz",
        &Policy::default_v4(),
        &gzip_ustar_options(),
        None,
    );
    assert!(
        outcome.rejected(),
        "gnu-under-ustar {:?} {:?}",
        outcome.admission,
        outcome
            .view
            .findings
            .iter()
            .map(|finding| (finding.code.as_str(), finding.detail.as_str()))
            .collect::<Vec<_>>()
    );
    assert!(matches!(outcome.admission, AdmissionStatus::NotEvaluated));
    assert!(outcome
        .view
        .findings
        .iter()
        .all(|finding| finding.code != FindingCode::QuotaRatio));
    let finding = outcome
        .view
        .findings
        .iter()
        .find(|finding| finding.code == FindingCode::TarDialect)
        .expect("tar.dialect");
    let hint = finding.hint.as_ref().expect("dialect hint");
    assert_eq!(hint.formats, vec!["tar-gzip-gnu-longname".to_owned()]);
    assert!(hint.observed.contains("GNU"));
    assert!(!hint.observed.contains("gnudefault"));
    assert_eq!(
        outcome.receipt.identities.interpretation.digest.sha256,
        tar_gzip_ustar_portable_v1_digest()
    );
    assert_eq!(
        outcome.receipt.source.sha256(),
        Some(hex_sha256(&bytes).as_str())
    );

    let admitted = inspect(
        &bytes,
        "renamed.bin",
        &Policy::default_v7(),
        &ApplyOptions::new().with_tar_gzip_interpretation_profile(
            TarGzipInterpretationProfile::GnuLongNamePortableV1,
        ),
        None,
    );
    assert_admitted(&admitted, "gnu profile");
    assert_eq!(admitted.view.members[0].path, "README");
    assert_eq!(
        admitted.receipt.identities.interpretation.digest.sha256,
        tar_gzip_gnu_longname_portable_v1_digest()
    );
}

#[test]
fn leading_dot_slash_is_normalized_and_escapes_stay_rejected() {
    let policy = Policy::default_v2();
    let options = ApplyOptions::new()
        .with_tar_interpretation_profile(TarInterpretationProfile::UstarPortableV1);

    let readme = finish_tar(ustar_entry("./README", b"hello\n", b'0', ""));
    let admitted = inspect(&readme, "dot.tar", &policy, &options, None);
    assert_admitted(&admitted, "./README");
    assert_eq!(admitted.view.members[0].path, "README");
    let member = &admitted.archive_ir().unwrap().members()[0];
    assert!(member.normalization_actions.is_empty());
    assert_eq!(
        admitted
            .verified_archive()
            .unwrap()
            .read_member("README", 64)
            .unwrap(),
        b"hello\n"
    );
    assert_eq!(
        admitted.receipt.identities.interpretation.digest.sha256,
        tar_ustar_portable_v1_digest()
    );

    let plain = finish_tar(ustar_entry("README", b"hello\n", b'0', ""));
    let plain_outcome = inspect(&plain, "plain.tar", &policy, &options, None);
    assert_eq!(
        admitted.receipt.identities.content.hex(),
        plain_outcome.receipt.identities.content.hex()
    );

    let mut tree = ustar_entry("./", b"", b'5', "");
    tree.extend(ustar_entry("./README", b"hello\n", b'0', ""));
    let tree = finish_tar(tree);
    let parent = temp_parent("dot-tree");
    let dest = parent.join("out");
    let published = inspect(&tree, "tree.tar", &policy, &options, Some(&dest));
    assert_admitted(&published, "archive root");
    assert!(published.wrote());
    assert_eq!(fs::read(dest.join("README")).unwrap(), b"hello\n");
    let children = fs::read_dir(&dest)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(children.len(), 1);
    assert!(published
        .archive_ir()
        .unwrap()
        .members()
        .iter()
        .any(|member| member.canonical_path.is_empty()
            && member.normalization_actions
                == vec![NormalizationAction::StripDirectoryTrailingSlash]));
    fs::remove_dir_all(&parent).unwrap();

    let cases = [
        ("./../x", b'0', "", FindingCode::PathDotDot),
        ("/etc/passwd", b'0', "", FindingCode::PathAbsolute),
        ("C:/Windows", b'0', "", FindingCode::PathAbsolute),
        ("a/./b", b'0', "", FindingCode::PathInvalidChar),
        (".", b'0', "", FindingCode::PathEmpty),
        (
            "./escape",
            b'2',
            "../../../../etc/passwd",
            FindingCode::TarFeatureUnsupported,
        ),
    ];
    for (name, typeflag, linkname, code) in cases {
        let bytes = finish_tar(ustar_entry(name, b"", typeflag, linkname));
        let outcome = inspect(&bytes, "hostile.tar", &policy, &options, None);
        assert!(outcome.rejected(), "{name} was admitted");
        assert!(
            outcome
                .view
                .findings
                .iter()
                .any(|finding| finding.code == code),
            "{name} findings {:?}",
            outcome
                .view
                .findings
                .iter()
                .map(|finding| finding.code.as_str())
                .collect::<Vec<_>>()
        );
        assert!(outcome.verified_archive().is_none());
    }

    let mut duplicate = ustar_entry("./README", b"one", b'0', "");
    duplicate.extend(ustar_entry("README", b"two", b'0', ""));
    let duplicate = finish_tar(duplicate);
    let conflict = inspect(&duplicate, "dup.tar", &policy, &options, None);
    assert!(conflict
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::PathConflict));
}

#[test]
fn zip_dot_slash_and_filename_do_not_become_a_tar_hint() {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("./member.txt", options).unwrap();
        writer.write_all(b"text").unwrap();
        writer.finish().unwrap();
    }
    let dotted = cursor.into_inner();
    let zip_options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
    let rejected = inspect(
        &dotted,
        "dotted.zip",
        &Policy::default_v1(),
        &zip_options,
        None,
    );
    assert!(rejected
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::PathInvalidChar
            || finding.code == FindingCode::PathEmpty));

    let gzip_member = decode_hex(EMPTY_FILE_TAR_GZ);
    let as_archive = inspect(
        &gzip_member,
        "good.tar.gz",
        &Policy::default_v1(),
        &ApplyOptions::new(),
        None,
    );
    let as_notes = inspect(
        &gzip_member,
        "notes.zip",
        &Policy::default_v1(),
        &ApplyOptions::new(),
        None,
    );
    let hint = as_archive.view.findings[0].hint.clone().expect("gzip hint");
    assert_eq!(as_notes.view.findings[0].hint.as_ref(), Some(&hint));
    assert_eq!(hint.observed, "gzip member");
    assert_eq!(
        hint.formats,
        vec![
            "tar-gzip-ustar".to_owned(),
            "tar-gzip-pax".to_owned(),
            "tar-gzip-gnu-longname".to_owned()
        ]
    );
    let rendered = serde_json::to_string(&as_archive.view.findings[0]).unwrap();
    assert!(!rendered.contains("good.tar.gz"));
    assert!(!rendered.contains("notes.zip"));
    assert_eq!(
        as_archive.view.findings[0].code,
        FindingCode::FormatUnsupported
    );
    assert_eq!(
        as_archive.receipt.identities.interpretation.digest.sha256,
        as_notes.receipt.identities.interpretation.digest.sha256
    );

    let named_zip = inspect(
        &dotted,
        "not-gzip.tar.gz",
        &Policy::default_v1(),
        &ApplyOptions::new(),
        None,
    );
    assert!(named_zip.view.findings.iter().all(|finding| {
        finding.hint.as_ref().is_none_or(|hint| {
            hint.observed != "gzip member"
                && hint.formats.iter().all(|format| !format.contains("gzip"))
        })
    }));
    assert_ne!(
        named_zip.view.findings.first().map(|finding| finding.code),
        Some(FindingCode::FormatUnsupported)
    );
}

fn temp_parent(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sealr-ratio-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}
