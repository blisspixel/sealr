use std::fs;
use std::io::Write;
use std::path::PathBuf;

use crc32fast::Hasher as Crc;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use sealr::{
    apply_with_options, tar_gzip_ustar_portable_v1_canonical_bytes,
    tar_gzip_ustar_portable_v1_digest, AdmissionStatus, ApplyOptions, ArchiveFormat, FindingCode,
    InterpretationStatus, Policy, Request, RetentionPlan, Source, TarGzipInterpretationProfile,
    TarInterpretationProfile, TreeRoot, VerificationStatus, TAR_GZIP_ARCHIVE_IR_SCHEMA,
    TAR_GZIP_USTAR_PORTABLE_V1,
};

fn write_octal(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let octal = format!("{value:o}");
    let digits = field.len() - 1;
    field[digits - octal.len()..digits].copy_from_slice(octal.as_bytes());
    field[digits] = 0;
}

fn ustar(name: &str, body: &[u8]) -> Vec<u8> {
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], body.len() as u64);
    write_octal(&mut header[136..148], 1_788_000_000);
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[265..269].copy_from_slice(b"root");
    header[297..301].copy_from_slice(b"root");
    write_octal(&mut header[329..337], 0);
    write_octal(&mut header[337..345], 0);
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
    header[154] = 0;
    header[155] = b' ';

    let mut tar = header.to_vec();
    tar.extend_from_slice(body);
    tar.resize(tar.len().next_multiple_of(512), 0);
    tar.resize(tar.len() + 1024, 0);
    tar
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
        .with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::UstarPortableV1)
}

fn inspect<'a>(bytes: &'a [u8], policy: &'a Policy, options: &ApplyOptions) -> sealr::Outcome {
    apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.gz"),
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
    let canonical = tar_gzip_ustar_portable_v1_canonical_bytes();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&canonical).unwrap()["schema"],
        TAR_GZIP_USTAR_PORTABLE_V1
    );
    assert_eq!(
        tar_gzip_ustar_portable_v1_digest(),
        "914acdc0eab541483309a6838716fe837488ca80a1b7758383f28e47470925e1"
    );
    assert_eq!(options().archive_format(), ArchiveFormat::TarGzipUstar);
    assert_eq!(
        options().tar_gzip_interpretation_profile(),
        Some(TarGzipInterpretationProfile::UstarPortableV1)
    );
    assert!(options().tar_interpretation_profile().is_none());
}

#[test]
fn inspect_retention_materialization_and_identities_bind_both_domains() {
    let tar = ustar("mission/plan.txt", b"verify twice, decode once");
    let extra = [b'S', b'L', 3, 0, b'x', b'y', b'z'];
    let first = gzip(&tar, 0, Some(&extra));
    let second = gzip(&tar, 1, Some(&extra));
    let policy = Policy::default_v4();
    let retained = options().with_retention(
        RetentionPlan::new(1024, 1024)
            .with_path("mission/plan.txt")
            .unwrap(),
    );
    let outcome = inspect(&first, &policy, &retained);
    assert!(matches!(outcome.admission, AdmissionStatus::Admitted));
    assert!(matches!(outcome.verification, VerificationStatus::Complete));
    assert_eq!(
        outcome.receipt.source.sha256(),
        Some(sealr::hex_sha256(&first).as_str())
    );
    let ir = outcome.archive_ir().unwrap();
    assert_eq!(ir.schema(), TAR_GZIP_ARCHIVE_IR_SCHEMA);
    assert_eq!(ir.format(), ArchiveFormat::TarGzipUstar);
    assert_eq!(ir.source_digest(), &outcome.receipt.source);
    let wrapper = ir.gzip_evidence().unwrap();
    assert_eq!(wrapper.flags, 0x1c);
    assert_eq!(wrapper.extra_subfield_count, 1);
    assert_eq!(wrapper.extra.unwrap().offset, 10);
    assert_eq!(wrapper.extra.unwrap().len, 9);
    assert_eq!(wrapper.original_name.unwrap().offset, 19);
    assert_eq!(wrapper.comment.unwrap().offset, 31);
    assert_eq!(wrapper.derived_output_len, tar.len() as u64);
    assert_eq!(wrapper.derived_output_sha256, sealr::hex_sha256(&tar));
    assert!(ir.members().iter().all(|member| {
        member.format() == ArchiveFormat::TarGzipUstar && member.tar_evidence().is_some()
    }));
    assert!(matches!(
        outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV4 { .. }
    ));
    assert_eq!(
        format!(
            "{}:{}:{}",
            outcome.receipt.source.sha256().unwrap(),
            outcome.receipt.identities.layout.hex().unwrap(),
            outcome.receipt.identities.content.hex().unwrap()
        ),
        concat!(
            "dc051cdb4071e630f345c7cd18f5e4fb19941c2abecdf1eaeb317bb9b774f15a:",
            "76e2b9583adb9e72459c9aa44043c3b1e5a7fde3fc73adbd833ad788656eba4a:",
            "bc8f6d6f7870aeab647cff08db25471a729bd2a41e095d49d6254c49afc34278"
        )
    );
    let verified = outcome.verified_archive().unwrap();
    assert_eq!(
        verified.retained_member("mission/plan.txt"),
        Some(b"verify twice, decode once".as_slice())
    );
    assert_eq!(
        verified.read_member("mission/plan.txt", 1024).unwrap(),
        b"verify twice, decode once"
    );

    let second_outcome = inspect(&second, &policy, &options());
    let raw = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar"),
                data: &tar,
            },
            policy: &Policy::default_v2(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_interpretation_profile(TarInterpretationProfile::UstarPortableV1),
    );
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
        "sealr-tar-gzip-public-{}-{}",
        std::process::id(),
        sealr::hex_sha256(&first)[..12].to_owned()
    ));
    let dest: PathBuf = base.join("out");
    fs::create_dir(&base).unwrap();
    let materialized = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.gz"),
                data: &first,
            },
            policy: &policy,
            dest: Some(&dest),
        },
        &options(),
    );
    assert!(matches!(materialized.admission, AdmissionStatus::Admitted));
    assert_eq!(
        fs::read(dest.join("mission/plan.txt")).unwrap(),
        b"verify twice, decode once"
    );
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn wrapper_grammar_integrity_and_resource_axes_fail_closed() {
    let tar = ustar("file.txt", b"bounded derived content");
    let member = gzip(&tar, 0, None);
    let policy = Policy::default_v4();

    let non_gzip = inspect(&tar, &policy, &options());
    assert!(matches!(
        non_gzip.interpretation,
        InterpretationStatus::Malformed
    ));
    assert_eq!(non_gzip.view.source.magic, "unknown");

    let sub_header = inspect(&[0x1f], &policy, &options());
    assert!(matches!(
        sub_header.interpretation,
        InterpretationStatus::Malformed
    ));
    assert_eq!(sub_header.view.source.magic, "unknown");

    let mut method = member.clone();
    method[2] = 7;
    let method_outcome = inspect(&method, &policy, &options());
    assert!(matches!(
        method_outcome.interpretation,
        InterpretationStatus::Unsupported
    ));
    assert_eq!(method_outcome.view.source.magic, "gz");
    let mut reserved = member.clone();
    reserved[3] = 0x20;
    assert!(matches!(
        inspect(&reserved, &policy, &options()).interpretation,
        InterpretationStatus::Unsupported
    ));

    for count in [2, 3, 64] {
        let concatenated = member.repeat(count);
        let outcome = inspect(&concatenated, &policy, &options());
        assert!(matches!(
            outcome.interpretation,
            InterpretationStatus::Unsupported
        ));
        assert!(matches!(outcome.admission, AdmissionStatus::NotEvaluated));
        assert!(outcome
            .view
            .findings
            .iter()
            .any(|finding| { finding.code == FindingCode::CodecDeflateTrailingInput }));
    }
    let mut truncated_second = member.clone();
    truncated_second.extend_from_slice(&[0x1f, 0x8b]);
    let truncated_second = inspect(&truncated_second, &policy, &options());
    assert!(matches!(
        truncated_second.interpretation,
        InterpretationStatus::Malformed
    ));
    assert!(matches!(
        truncated_second.admission,
        AdmissionStatus::NotEvaluated
    ));

    let mut invalid_second = member.clone();
    let mut invalid_member = member.clone();
    invalid_member[2] = 0;
    invalid_second.extend_from_slice(&invalid_member);
    let invalid_second = inspect(&invalid_second, &policy, &options());
    assert!(matches!(
        invalid_second.interpretation,
        InterpretationStatus::Malformed
    ));
    assert!(matches!(
        invalid_second.admission,
        AdmissionStatus::NotEvaluated
    ));
    let mut trailing = member.clone();
    trailing.push(0x7f);
    assert!(matches!(
        inspect(&trailing, &policy, &options()).interpretation,
        InterpretationStatus::Malformed
    ));

    let invalid_inner = gzip(b"not a tar archive", 0, None);
    let invalid_inner_outcome = inspect(&invalid_inner, &policy, &options());
    assert!(matches!(
        invalid_inner_outcome.interpretation,
        InterpretationStatus::Malformed
    ));
    assert_eq!(invalid_inner_outcome.view.source.magic, "gz");

    let duplicate_extra = [b'S', b'L', 0, 0, b'S', b'L', 0, 0];
    let duplicate = gzip(&tar, 0, Some(&duplicate_extra));
    let duplicate_outcome = inspect(&duplicate, &policy, &options());
    assert!(matches!(
        duplicate_outcome.interpretation,
        InterpretationStatus::Malformed
    ));
    assert!(duplicate_outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::GzipExtra));

    let mut derived_cap = Policy::default_v4();
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

    let mut ratio = Policy::default_v4();
    ratio.max_ratio = Some(1);
    let denied = inspect(&member, &ratio, &options());
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaRatio));

    let mut source_cap = Policy::default_v4();
    source_cap.max_archive_bytes = (member.len() - 1) as u64;
    let denied = inspect(&member, &source_cap, &options());
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaArchive));

    let mut metadata = Policy::default_v4();
    metadata.max_metadata_bytes = 17;
    let denied = inspect(&member, &metadata, &options());
    assert!(matches!(
        denied.interpretation,
        InterpretationStatus::Interpreted
    ));
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaMetadata));

    let body_len = b"bounded derived content".len() as u64;
    let mut exact = Policy::default_v4();
    exact.max_archive_bytes = member.len() as u64;
    exact.max_derived_archive_bytes = Some(tar.len() as u64);
    exact.max_metadata_bytes = 18 + 512 + 1024;
    exact.max_files = 1;
    exact.max_member_bytes = body_len;
    exact.max_total_bytes = body_len;
    assert!(matches!(
        inspect(&member, &exact, &options()).admission,
        AdmissionStatus::Admitted
    ));

    let mut ratio_disabled = Policy::default_v4();
    ratio_disabled.max_ratio = None;
    assert!(matches!(
        inspect(&member, &ratio_disabled, &options()).admission,
        AdmissionStatus::Admitted
    ));

    let empty_tar = ustar("empty.txt", b"");
    let empty_member = gzip(&empty_tar, 0, None);
    let mut zero_denominator = Policy::default_v4();
    zero_denominator.max_ratio = Some(1_000);
    let empty_outcome = inspect(&empty_member, &zero_denominator, &options());
    assert!(matches!(empty_outcome.admission, AdmissionStatus::Admitted));
    assert!(empty_outcome
        .archive_ir()
        .unwrap()
        .members()
        .iter()
        .any(|member| member.declared_uncomp_size == 0));
}

#[test]
fn retained_reads_survive_caller_path_replacement_without_redecode() {
    let tar = ustar("mission/plan.txt", b"retained derived payload");
    let member = gzip(&tar, 0, None);
    let base = std::env::temp_dir().join(format!(
        "sealr-tar-gzip-replacement-{}-{}",
        std::process::id(),
        &sealr::hex_sha256(&member)[..12]
    ));
    fs::create_dir_all(&base).unwrap();
    let source = base.join("source.tar.gz");
    fs::write(&source, &member).unwrap();
    let policy = Policy::default_v4();
    let retained = options().with_retention(
        RetentionPlan::new(1024, 1024)
            .with_path("mission/plan.txt")
            .unwrap(),
    );
    let outcome = apply_with_options(
        Request {
            source: Source::Path(&source),
            policy: &policy,
            dest: None,
        },
        &retained,
    );
    assert!(matches!(outcome.admission, AdmissionStatus::Admitted));

    fs::write(&source, b"replacement bytes are not a gzip member").unwrap();
    let verified = outcome.verified_archive().unwrap();
    assert_eq!(
        verified.read_member("mission/plan.txt", 1024).unwrap(),
        b"retained derived payload"
    );
    assert_eq!(
        verified.retained_member("mission/plan.txt"),
        Some(b"retained derived payload".as_slice())
    );
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn policy_and_format_selection_do_not_alias_raw_tar_or_older_policies() {
    let tar = ustar("file.txt", b"content");
    let gzip = gzip(&tar, 0, None);
    let older = inspect(&gzip, &Policy::default_v3(), &options());
    assert!(!matches!(older.admission, AdmissionStatus::Admitted));
    assert!(older
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::PolicyUnsupported));

    let raw_selection = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("file.tar.gz"),
                data: &gzip,
            },
            policy: &Policy::default_v4(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_interpretation_profile(TarInterpretationProfile::UstarPortableV1),
    );
    assert!(!matches!(
        raw_selection.admission,
        AdmissionStatus::Admitted
    ));
    assert!(raw_selection.archive_ir().is_none());
}

#[test]
fn committed_tree_v4_manifest_matches_the_public_production_path() {
    let manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-gzip-identity-v1.json")).unwrap();
    assert_eq!(manifest["schema"], "sealr.tar-gzip-identity-conformance.v1");
    assert_eq!(
        manifest["profile"]["digest"]["sha256"],
        tar_gzip_ustar_portable_v1_digest()
    );

    let policy = Policy::default_v4();
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
            "format": "tar-gzip-ustar",
            "gzip": case["gzip"].clone(),
            "tar_covering": manifest["derived_tar"]["covering"].clone(),
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
                path: Some("mission.tar"),
                data: &derived,
            },
            policy: &Policy::default_v2(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_interpretation_profile(TarInterpretationProfile::UstarPortableV1),
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
