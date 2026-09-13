use std::fs;
use std::io::Write;
use std::path::PathBuf;

use crc32fast::Hasher as Crc;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use sealr::{
    apply_with_options, tar_gnu_longname_portable_v1_digest,
    tar_gzip_gnu_longname_portable_v1_canonical_bytes, tar_gzip_gnu_longname_portable_v1_digest,
    AdmissionStatus, ApplyOptions, ArchiveFormat, FindingCode, GnuLongNamePathSource,
    InterpretationStatus, Policy, Request, RetentionPlan, Source,
    TarGnuLongNameInterpretationProfile, TarGzipInterpretationProfile, TreeRoot,
    VerificationStatus, TAR_GZIP_GNU_LONGNAME_ARCHIVE_IR_SCHEMA, TAR_GZIP_GNU_LONGNAME_PORTABLE_V1,
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
    header[257..265].copy_from_slice(b"ustar  \0");
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
    header[154] = 0;
    header[155] = b' ';
    header
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

fn long_name_archive(carrier_name: &[u8], path: &str, base_name: &[u8], content: &[u8]) -> Vec<u8> {
    let mut payload = path.as_bytes().to_vec();
    payload.push(0);
    let mut bytes = Vec::new();
    append_record(
        &mut bytes,
        header(carrier_name, payload.len() as u64, b'L'),
        &payload,
    );
    append_record(
        &mut bytes,
        header(base_name, content.len() as u64, b'0'),
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
        .with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::GnuLongNamePortableV1)
}

fn inspect<'a>(bytes: &'a [u8], policy: &'a Policy, options: &ApplyOptions) -> sealr::Outcome {
    apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.gnu.tar.gz"),
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
    let canonical = tar_gzip_gnu_longname_portable_v1_canonical_bytes();
    let profile: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    assert_eq!(profile["schema"], TAR_GZIP_GNU_LONGNAME_PORTABLE_V1);
    assert_eq!(
        profile["inner_profile"],
        "sealr.profile.tar.gnu-longname-portable.v1"
    );
    assert_eq!(
        profile["inner_profile_sha256"],
        tar_gnu_longname_portable_v1_digest().as_str()
    );
    assert_eq!(
        tar_gzip_gnu_longname_portable_v1_digest(),
        "622943e9629c4acc7cfeb446eb9f2d16bb245db589c1a200e885a9d69a02295a"
    );
    assert_eq!(
        options().archive_format(),
        ArchiveFormat::TarGzipGnuLongName
    );
    assert_eq!(
        options().tar_gzip_interpretation_profile(),
        Some(TarGzipInterpretationProfile::GnuLongNamePortableV1)
    );
    assert!(options()
        .tar_gnu_longname_interpretation_profile()
        .is_none());
    assert!(options().tar_interpretation_profile().is_none());
}

#[test]
fn inspect_retention_materialization_and_identities_bind_both_domains() {
    let path = format!("mission/{}/status.txt", "segment".repeat(15));
    let tar = long_name_archive(b"././@LongLink", &path, b"opaque-base", b"nominal");
    let extra = [b'S', b'L', 3, 0, b'x', b'y', b'z'];
    let first = gzip(&tar, 0, Some(&extra));
    let second = gzip(&tar, 1, Some(&extra));
    let policy = Policy::default_v7();
    let retained =
        options().with_retention(RetentionPlan::new(1024, 1024).with_path(&path).unwrap());
    let outcome = inspect(&first, &policy, &retained);
    assert!(
        matches!(outcome.admission, AdmissionStatus::Admitted),
        "{:?}",
        outcome.view.findings
    );
    assert!(matches!(outcome.verification, VerificationStatus::Complete));
    let ir = outcome.archive_ir().unwrap();
    assert_eq!(ir.schema(), TAR_GZIP_GNU_LONGNAME_ARCHIVE_IR_SCHEMA);
    assert_eq!(ir.format(), ArchiveFormat::TarGzipGnuLongName);
    let wrapper = ir.gzip_evidence().unwrap();
    assert_eq!(wrapper.derived_output_len, tar.len() as u64);
    assert_eq!(wrapper.derived_output_sha256, sealr::hex_sha256(&tar));
    let gnu = ir.tar_gnu_longname_evidence().unwrap();
    assert_eq!(gnu.carriers.len(), 1);
    assert_eq!(gnu.carriers[0].path_bytes, path.as_bytes());
    let member = &ir.members()[0];
    assert_eq!(member.format(), ArchiveFormat::TarGzipGnuLongName);
    assert_eq!(member.canonical_path, path);
    let evidence = member.tar_gnu_longname_evidence().unwrap();
    assert_eq!(evidence.base_name_bytes, b"opaque-base");
    assert!(matches!(
        evidence.path_source,
        GnuLongNamePathSource::Carrier { carrier_index: 0 }
    ));
    assert!(matches!(
        outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV8 { .. }
    ));
    assert_eq!(
        format!(
            "{}:{}:{}",
            outcome.receipt.source.sha256().unwrap(),
            outcome.receipt.identities.layout.hex().unwrap(),
            outcome.receipt.identities.content.hex().unwrap()
        ),
        concat!(
            "0861c2f5c4dec85e1a058daa31b9e67f1666251e616c1d162782f207697bd5b2:",
            "d1c85e72f800e0c666a3a3bc11faa7edad10c69a0c40515fd69f8d8e8c5cc246:",
            "7d0746a82186263db1ab62a81d7ce54812778c05fe4df090359738cb634f4fee"
        )
    );
    let verified = outcome.verified_archive().unwrap();
    assert_eq!(verified.retained_member(&path), Some(b"nominal".as_slice()));
    assert_eq!(verified.read_member(&path, 1024).unwrap(), b"nominal");

    let second_outcome = inspect(&second, &policy, &options());
    let raw = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.gnu.tar"),
                data: &tar,
            },
            policy: &Policy::default_v6(),
            dest: None,
        },
        &ApplyOptions::new().with_tar_gnu_longname_interpretation_profile(
            TarGnuLongNameInterpretationProfile::PortableV1,
        ),
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
        "sealr-tar-gzip-gnu-public-{}-{}",
        std::process::id(),
        &sealr::hex_sha256(&first)[..12]
    ));
    let dest: PathBuf = base.join("out");
    fs::create_dir(&base).unwrap();
    let materialized = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.gnu.tar.gz"),
                data: &first,
            },
            policy: &policy,
            dest: Some(&dest),
        },
        &options(),
    );
    assert!(matches!(materialized.admission, AdmissionStatus::Admitted));
    assert_eq!(fs::read(dest.join(&path)).unwrap(), b"nominal");
    assert!(!dest.join("opaque-base").exists());
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn wrapper_and_inner_language_fail_closed() {
    let tar = long_name_archive(
        b"././@LongLink",
        "mission/long-name.txt",
        b"base",
        b"payload",
    );
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

    let long_link = {
        let mut payload = b"target-of-link".to_vec();
        payload.push(0);
        let mut bytes = Vec::new();
        append_record(
            &mut bytes,
            header(b"././@LongLink", payload.len() as u64, b'K'),
            &payload,
        );
        append_record(&mut bytes, header(b"link-name", 0, b'0'), b"");
        finish(bytes)
    };
    let unsupported = inspect(&gzip(&long_link, 0, None), &policy, &options());
    assert!(matches!(
        unsupported.interpretation,
        InterpretationStatus::Unsupported
    ));
    assert_eq!(unsupported.view.source.magic, "gz");
    assert!(unsupported
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::TarFeatureUnsupported));

    let orphan_carrier = {
        let mut payload = b"mission/orphan.txt".to_vec();
        payload.push(0);
        let mut bytes = Vec::new();
        append_record(
            &mut bytes,
            header(b"././@LongLink", payload.len() as u64, b'L'),
            &payload,
        );
        finish(bytes)
    };
    let orphan = inspect(&gzip(&orphan_carrier, 0, None), &policy, &options());
    assert!(!matches!(orphan.admission, AdmissionStatus::Admitted));

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
    let tar = long_name_archive(
        b"././@LongLink",
        "mission/long-name.txt",
        b"base",
        b"payload",
    );
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
                path: Some("mission.gnu.tar.gz"),
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

    let pax_selection = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.gnu.tar.gz"),
                data: &wrapped,
            },
            policy: &Policy::default_v7(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::PaxPortableV1),
    );
    assert!(!matches!(
        pax_selection.admission,
        AdmissionStatus::Admitted
    ));

    let raw_selection = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.gnu.tar.gz"),
                data: &wrapped,
            },
            policy: &Policy::default_v7(),
            dest: None,
        },
        &ApplyOptions::new().with_tar_gnu_longname_interpretation_profile(
            TarGnuLongNameInterpretationProfile::PortableV1,
        ),
    );
    assert!(!matches!(
        raw_selection.admission,
        AdmissionStatus::Admitted
    ));
    assert!(raw_selection.archive_ir().is_none());
}

#[test]
fn committed_tree_v8_manifest_matches_the_public_production_path() {
    let manifest: serde_json::Value = serde_json::from_slice(include_bytes!(
        "conformance/tar-gzip-gnu-longname-identity-v1.json"
    ))
    .unwrap();
    assert_eq!(
        manifest["schema"],
        "sealr.tar-gzip-gnu-longname-identity-conformance.v1"
    );
    assert_eq!(
        manifest["profile"]["digest"]["sha256"],
        tar_gzip_gnu_longname_portable_v1_digest()
    );
    assert_eq!(
        manifest["inner_profile"]["digest"]["sha256"],
        tar_gnu_longname_portable_v1_digest()
    );
    assert_eq!(manifest["layout_encoding"], "sealrTreeV8");
    assert_eq!(
        manifest["layout_label"],
        "sealr.tree.layout.tar-gzip-gnu-longname.v1"
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
            "format": "tar-gzip-gnu-longname",
            "gzip": case["gzip"].clone(),
            "tar_covering": manifest["derived_tar"]["covering"].clone(),
            "gnu_longname_carriers": manifest["derived_tar"]["gnu_longname_carriers"].clone(),
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
                path: Some("mission.gnu.tar"),
                data: &derived,
            },
            policy: &Policy::default_v6(),
            dest: None,
        },
        &ApplyOptions::new().with_tar_gnu_longname_interpretation_profile(
            TarGnuLongNameInterpretationProfile::PortableV1,
        ),
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
