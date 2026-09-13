use std::fs;
use std::io::Write;
use std::path::PathBuf;

use crc32fast::Hasher as Crc;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use sealr::{
    apply_with_options, tar_gzip_pax_portable_v1_canonical_bytes, tar_gzip_pax_portable_v1_digest,
    tar_pax_portable_v1_digest, AdmissionStatus, ApplyOptions, ArchiveFormat, FindingCode,
    InterpretationStatus, PaxValueSource, Policy, Request, RetentionPlan, Source,
    TarGzipInterpretationProfile, TarPaxInterpretationProfile, TreeRoot, VerificationStatus,
    TAR_GZIP_PAX_ARCHIVE_IR_SCHEMA, TAR_GZIP_PAX_PORTABLE_V1,
};

fn write_octal(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let octal = format!("{value:o}");
    let digits = field.len() - 1;
    field[digits - octal.len()..digits].copy_from_slice(octal.as_bytes());
    field[digits] = 0;
}

fn header(name: &[u8], size: u64, typeflag: u8) -> [u8; 512] {
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

fn record(keyword: &str, value: &str) -> Vec<u8> {
    let body = format!(" {keyword}={value}\n");
    let mut digits = 1_usize;
    loop {
        let len = digits + body.len();
        let next_digits = len.to_string().len();
        if digits == next_digits {
            return format!("{len}{body}").into_bytes();
        }
        digits = next_digits;
    }
}

fn append_record(bytes: &mut Vec<u8>, header: [u8; 512], payload: &[u8]) {
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().next_multiple_of(512), 0);
}

fn finish(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

fn local_path_and_size(path: &str, content: &[u8]) -> Vec<u8> {
    let payload = [
        record("path", path),
        record("size", &content.len().to_string()),
    ]
    .concat();
    let mut bytes = Vec::new();
    append_record(
        &mut bytes,
        header(b"metadata-only-carrier", payload.len() as u64, b'x'),
        &payload,
    );
    append_record(
        &mut bytes,
        header(b"placeholder", content.len() as u64, b'0'),
        content,
    );
    finish(bytes)
}

fn plain_ustar(name: &str, content: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_record(
        &mut bytes,
        header(name.as_bytes(), content.len() as u64, b'0'),
        content,
    );
    finish(bytes)
}

fn gzip(tar: &[u8], mtime: u32, extra: Option<&[u8]>) -> Vec<u8> {
    let mut deflater = DeflateEncoder::new(Vec::new(), Compression::default());
    deflater.write_all(tar).unwrap();
    let compressed = deflater.finish().unwrap();
    let flags = if extra.is_some() { 0x1c } else { 0 };
    let mut bytes = vec![0x1f, 0x8b, 8, flags];
    bytes.extend_from_slice(&mtime.to_le_bytes());
    bytes.extend_from_slice(&[0, 255]);
    if let Some(extra) = extra {
        bytes.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        bytes.extend_from_slice(extra);
        bytes.extend_from_slice(b"archive.tar\0");
        bytes.extend_from_slice(b"sealr\0");
    }
    bytes.extend_from_slice(&compressed);
    let mut crc = Crc::new();
    crc.update(tar);
    bytes.extend_from_slice(&crc.finalize().to_le_bytes());
    bytes.extend_from_slice(&(tar.len() as u32).to_le_bytes());
    bytes
}

fn options() -> ApplyOptions {
    ApplyOptions::new()
        .with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::PaxPortableV1)
}

fn inspect<'a>(bytes: &'a [u8], policy: &'a Policy, options: &ApplyOptions) -> sealr::Outcome {
    apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.pax.tar.gz"),
                data: bytes,
            },
            policy,
            dest: None,
        },
        options,
    )
}

fn decode_hex(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

#[test]
fn profile_and_public_selection_are_distinct_and_pinned() {
    let canonical = tar_gzip_pax_portable_v1_canonical_bytes();
    let profile: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    assert_eq!(profile["schema"], TAR_GZIP_PAX_PORTABLE_V1);
    assert_eq!(
        profile["inner_profile"],
        "sealr.profile.tar.pax-portable.v1"
    );
    assert_eq!(
        profile["inner_profile_sha256"],
        tar_pax_portable_v1_digest().as_str()
    );
    assert_eq!(
        tar_gzip_pax_portable_v1_digest(),
        "6cc91b2b8563b5b070b44bf357a5c62e5d9dda0aedc374d7a08cd80da9c5434f"
    );
    assert_eq!(options().archive_format(), ArchiveFormat::TarGzipPax);
    assert_eq!(
        options().tar_gzip_interpretation_profile(),
        Some(TarGzipInterpretationProfile::PaxPortableV1)
    );
    assert!(options().tar_pax_interpretation_profile().is_none());
    assert!(options().tar_interpretation_profile().is_none());
}

#[test]
fn inspect_retention_materialization_and_identities_bind_both_domains() {
    let path = "mission/deep/override-target.txt";
    let tar = local_path_and_size(path, b"effective payload");
    let extra = [b'S', b'L', 3, 0, b'x', b'y', b'z'];
    let first = gzip(&tar, 0, Some(&extra));
    let second = gzip(&tar, 1, Some(&extra));
    let policy = Policy::default_v7();
    let retained =
        options().with_retention(RetentionPlan::new(1024, 1024).with_path(path).unwrap());
    let outcome = inspect(&first, &policy, &retained);
    assert!(
        matches!(outcome.admission, AdmissionStatus::Admitted),
        "{:?}",
        outcome.view.findings
    );
    assert!(matches!(outcome.verification, VerificationStatus::Complete));
    let ir = outcome.archive_ir().unwrap();
    assert_eq!(ir.schema(), TAR_GZIP_PAX_ARCHIVE_IR_SCHEMA);
    assert_eq!(ir.format(), ArchiveFormat::TarGzipPax);
    let wrapper = ir.gzip_evidence().unwrap();
    assert_eq!(wrapper.derived_output_len, tar.len() as u64);
    assert_eq!(wrapper.derived_output_sha256, sealr::hex_sha256(&tar));
    let pax = ir.tar_pax_evidence().unwrap();
    assert_eq!(pax.extensions.len(), 1);
    assert_eq!(pax.extensions[0].records.len(), 2);
    let member = &ir.members()[0];
    assert_eq!(member.format(), ArchiveFormat::TarGzipPax);
    assert_eq!(member.canonical_path, path);
    let evidence = member.tar_pax_evidence().unwrap();
    assert_eq!(evidence.base_name_bytes, b"placeholder");
    assert!(matches!(
        evidence.path_source,
        PaxValueSource::Local {
            extension_index: 0,
            record_index: 0
        }
    ));
    assert!(matches!(
        evidence.size_source,
        PaxValueSource::Local {
            extension_index: 0,
            record_index: 1
        }
    ));
    assert!(matches!(
        outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV7 { .. }
    ));
    assert_eq!(
        format!(
            "{}:{}:{}",
            outcome.receipt.source.sha256().unwrap(),
            outcome.receipt.identities.layout.hex().unwrap(),
            outcome.receipt.identities.content.hex().unwrap()
        ),
        concat!(
            "62d1dde1b647fb5f4b31c13d1a74c28a1fc29b99d5520cb05dadb1ca93d76bd1:",
            "b0fc882599ce67342c87c6483c3bc7642dae71ab683c372949be38384ebfcce2:",
            "be2b60170c0d6f8a238d9097b7ee7bac1b53b94bac8e442f252202169d18cb43"
        )
    );
    let verified = outcome.verified_archive().unwrap();
    assert_eq!(
        verified.retained_member(path),
        Some(b"effective payload".as_slice())
    );
    assert_eq!(
        verified.read_member(path, 1024).unwrap(),
        b"effective payload"
    );

    let second_outcome = inspect(&second, &policy, &options());
    let raw = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.pax.tar"),
                data: &tar,
            },
            policy: &Policy::default_v5(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_pax_interpretation_profile(TarPaxInterpretationProfile::PortableV1),
    );
    assert!(matches!(raw.admission, AdmissionStatus::Admitted));
    assert_ne!(outcome.receipt.source, second_outcome.receipt.source);
    assert_ne!(
        outcome.receipt.identities.layout,
        second_outcome.receipt.identities.layout
    );
    assert_ne!(
        outcome.receipt.identities.layout,
        raw.receipt.identities.layout
    );
    assert_eq!(
        outcome.receipt.identities.interpretation.digest,
        second_outcome.receipt.identities.interpretation.digest
    );
    assert_eq!(
        outcome.receipt.identities.content,
        second_outcome.receipt.identities.content
    );
    assert_eq!(
        outcome.receipt.identities.content,
        raw.receipt.identities.content
    );

    let base = std::env::temp_dir().join(format!(
        "sealr-tar-gzip-pax-public-{}-{}",
        std::process::id(),
        &sealr::hex_sha256(&first)[..12]
    ));
    let dest: PathBuf = base.join("out");
    fs::create_dir(&base).unwrap();
    let materialized = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.pax.tar.gz"),
                data: &first,
            },
            policy: &policy,
            dest: Some(&dest),
        },
        &options(),
    );
    assert!(matches!(materialized.admission, AdmissionStatus::Admitted));
    assert_eq!(fs::read(dest.join(path)).unwrap(), b"effective payload");
    assert!(!dest.join("placeholder").exists());
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn wrapper_and_inner_language_fail_closed() {
    let tar = local_path_and_size("mission/file.txt", b"bounded payload");
    let member = gzip(&tar, 0, None);
    let policy = Policy::default_v7();

    let non_gzip = inspect(&tar, &policy, &options());
    assert!(matches!(
        non_gzip.interpretation,
        InterpretationStatus::Malformed
    ));
    assert_eq!(non_gzip.view.source.magic, "unknown");

    let mut trailing = member.clone();
    trailing.push(0x7f);
    assert!(matches!(
        inspect(&trailing, &policy, &options()).interpretation,
        InterpretationStatus::Malformed
    ));

    let concatenated = member.repeat(2);
    let concatenated = inspect(&concatenated, &policy, &options());
    assert!(matches!(
        concatenated.interpretation,
        InterpretationStatus::Unsupported
    ));
    assert!(concatenated
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::CodecDeflateTrailingInput));

    let unknown_keyword = {
        let payload = record("uid", "0");
        let mut bytes = Vec::new();
        append_record(
            &mut bytes,
            header(b"carrier", payload.len() as u64, b'x'),
            &payload,
        );
        append_record(&mut bytes, header(b"file.txt", 0, b'0'), b"");
        finish(bytes)
    };
    let unknown = inspect(&gzip(&unknown_keyword, 0, None), &policy, &options());
    assert!(matches!(
        unknown.interpretation,
        InterpretationStatus::Unsupported
    ));
    assert_eq!(unknown.view.source.magic, "gz");
    assert!(unknown
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::TarFeatureUnsupported));

    let mut derived_cap = Policy::default_v7();
    derived_cap.max_derived_archive_bytes = Some((tar.len() - 1) as u64);
    let denied = inspect(&member, &derived_cap, &options());
    assert!(matches!(
        denied.interpretation,
        InterpretationStatus::Interpreted
    ));
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaDerived));

    let mut ratio = Policy::default_v7();
    ratio.max_ratio = Some(1);
    let denied = inspect(&member, &ratio, &options());
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaRatio));

    let mut metadata = Policy::default_v7();
    metadata.max_metadata_bytes = 17;
    let denied = inspect(&member, &metadata, &options());
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaMetadata));
}

#[test]
fn policy_and_format_selection_do_not_alias_other_profiles() {
    let tar = local_path_and_size("mission/file.txt", b"content");
    let wrapped = gzip(&tar, 0, None);

    let older = inspect(&wrapped, &Policy::default_v6(), &options());
    assert!(!matches!(older.admission, AdmissionStatus::Admitted));
    assert!(older
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::PolicyUnsupported));

    let ustar_selection = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.pax.tar.gz"),
                data: &wrapped,
            },
            policy: &Policy::default_v7(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::UstarPortableV1),
    );
    assert!(!matches!(
        ustar_selection.admission,
        AdmissionStatus::Admitted
    ));

    let raw_selection = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.pax.tar.gz"),
                data: &wrapped,
            },
            policy: &Policy::default_v7(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_pax_interpretation_profile(TarPaxInterpretationProfile::PortableV1),
    );
    assert!(!matches!(
        raw_selection.admission,
        AdmissionStatus::Admitted
    ));
    assert!(raw_selection.archive_ir().is_none());

    let plain = plain_ustar("mission/plain.txt", b"identical bytes");
    let plain_wrapped = gzip(&plain, 0, None);
    let policy = Policy::default_v7();
    let as_pax = inspect(&plain_wrapped, &policy, &options());
    let as_ustar = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.gz"),
                data: &plain_wrapped,
            },
            policy: &policy,
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::UstarPortableV1),
    );
    assert!(matches!(as_pax.admission, AdmissionStatus::Admitted));
    assert!(matches!(as_ustar.admission, AdmissionStatus::Admitted));
    assert_eq!(as_pax.receipt.source, as_ustar.receipt.source);
    assert_ne!(
        as_pax.receipt.identities.interpretation.digest,
        as_ustar.receipt.identities.interpretation.digest
    );
    assert_ne!(
        as_pax.receipt.identities.layout,
        as_ustar.receipt.identities.layout
    );
    assert!(matches!(
        as_pax.receipt.identities.layout,
        TreeRoot::SealrTreeV7 { .. }
    ));
    assert!(matches!(
        as_ustar.receipt.identities.layout,
        TreeRoot::SealrTreeV4 { .. }
    ));
    assert_eq!(
        as_pax.receipt.identities.content,
        as_ustar.receipt.identities.content
    );
}

#[test]
fn committed_tree_v7_manifest_matches_the_public_production_path() {
    let manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-gzip-pax-identity-v1.json"))
            .unwrap();
    assert_eq!(
        manifest["schema"],
        "sealr.tar-gzip-pax-identity-conformance.v1"
    );
    assert_eq!(
        manifest["profile"]["digest"]["sha256"],
        tar_gzip_pax_portable_v1_digest()
    );
    assert_eq!(
        manifest["inner_profile"]["digest"]["sha256"],
        tar_pax_portable_v1_digest()
    );
    assert_eq!(manifest["layout_encoding"], "sealrTreeV7");
    assert_eq!(
        manifest["layout_label"],
        "sealr.tree.layout.tar-gzip-pax.v1"
    );

    let policy = Policy::default_v7();
    for case in manifest["cases"].as_array().unwrap() {
        let source = decode_hex(case["source_bytes_hex"].as_str().unwrap());
        let outcome = inspect(&source, &policy, &options());
        assert!(matches!(outcome.admission, AdmissionStatus::Admitted));
        assert!(matches!(outcome.verification, VerificationStatus::Complete));
        assert_eq!(
            serde_json::to_value(&outcome.receipt.source).unwrap(),
            case["source"]
        );
        assert_eq!(
            serde_json::to_value(&outcome.receipt.identities.layout).unwrap(),
            case["layout_root"]
        );
        assert_eq!(
            serde_json::to_value(&outcome.receipt.identities.content).unwrap(),
            case["content_root"]
        );

        let expected_ir = serde_json::json!({
            "schema": manifest["archive_ir_schema"].clone(),
            "profile": manifest["profile"]["id"].clone(),
            "profile_digest": manifest["profile"]["digest"]["sha256"].clone(),
            "source_digest": case["source"].clone(),
            "format": "tar-gzip-pax",
            "gzip": case["gzip"].clone(),
            "tar_covering": manifest["derived_tar"]["covering"].clone(),
            "pax_extensions": manifest["derived_tar"]["pax_extensions"].clone(),
            "members": manifest["derived_tar"]["members"].clone(),
        });
        assert_eq!(
            serde_json::to_value(outcome.archive_ir().unwrap()).unwrap(),
            expected_ir,
            "case {}",
            case["id"]
        );
    }

    let derived = decode_hex(manifest["derived_tar"]["bytes_hex"].as_str().unwrap());
    let raw = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.pax.tar"),
                data: &derived,
            },
            policy: &Policy::default_v5(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_pax_interpretation_profile(TarPaxInterpretationProfile::PortableV1),
    );
    assert!(matches!(raw.verification, VerificationStatus::Complete));
    assert_eq!(
        serde_json::to_value(&raw.receipt.identities.layout).unwrap(),
        manifest["derived_tar"]["raw_layout_root"]
    );
    assert_eq!(
        serde_json::to_value(&raw.receipt.identities.content).unwrap(),
        manifest["derived_tar"]["content_root"]
    );
}
