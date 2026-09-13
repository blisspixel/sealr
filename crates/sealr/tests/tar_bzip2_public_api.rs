use std::fs;
use std::path::PathBuf;

use sealr::{
    apply_with_options, tar_bzip2_ustar_portable_v1_canonical_bytes,
    tar_bzip2_ustar_portable_v1_digest, tar_ustar_portable_v1_digest, AdmissionStatus,
    ApplyOptions, ArchiveFormat, FindingCode, InterpretationStatus, Policy, Request, RetentionPlan,
    Source, TarBzip2InterpretationProfile, TarGzipInterpretationProfile, TarInterpretationProfile,
    TarXzInterpretationProfile, TarZstdInterpretationProfile, TreeRoot, VerificationStatus,
    TAR_BZIP2_ARCHIVE_IR_SCHEMA, TAR_BZIP2_USTAR_PORTABLE_V1,
};

/// CPython 3.12.10 `bz2.compress(tar, 9)` over the exact conformance derived
/// TAR (bundled libbz2 1.0.8; byte-identical to `bzip2 -9`): one block,
/// level digit '9'.
const BZ2_CLI_LEVEL9_HEX: &str = "425a68393141592653597b1dc2a70000447b91ca000040\
    4005ff0040006f27dfe0040000400008200074226a64f51a64d0340640c4d064a0d341a680034d001e65\
    87e2308c005913503e46a2880842162fc4d83544cc801bd752180f90d0c026e224716664838d467b58fb\
    fac1cf118147687b09c160a4ad2080f498e75a99561f215194f509f0637e2ee48a70a120f63b854e";

/// `bz2.compress(tar, 1)`: an identical compressed body under level digit '1'
/// because the input is far below every block size.
const BZ2_CLI_LEVEL1_HEX: &str = "425a68313141592653597b1dc2a70000447b91ca000040\
    4005ff0040006f27dfe0040000400008200074226a64f51a64d0340640c4d064a0d341a680034d001e65\
    87e2308c005913503e46a2880842162fc4d83544cc801bd752180f90d0c026e224716664838d467b58fb\
    fac1cf118147687b09c160a4ad2080f498e75a99561f215194f509f0637e2ee48a70a120f63b854e";

/// `bz2.compress(b"", 9)`: the legal 14-byte zero-block stream, denied at the
/// composition layer.
const BZ2_EMPTY_HEX: &str = "425a683917724538509000000000";

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

fn options() -> ApplyOptions {
    ApplyOptions::new()
        .with_tar_bzip2_interpretation_profile(TarBzip2InterpretationProfile::UstarPortableV1)
}

fn inspect<'a>(bytes: &'a [u8], policy: &'a Policy, options: &ApplyOptions) -> sealr::Outcome {
    apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.bz2"),
                data: bytes,
            },
            policy,
            dest: None,
        },
        options,
    )
}

fn decode_hex(value: &str) -> Vec<u8> {
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    let (pairs, remainder) = cleaned.as_bytes().as_chunks::<2>();
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
    let canonical = tar_bzip2_ustar_portable_v1_canonical_bytes();
    let profile: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    assert_eq!(profile["schema"], TAR_BZIP2_USTAR_PORTABLE_V1);
    assert_eq!(
        profile["wrapper_profile"],
        "sealr.transform.bzip2.bzip2fmt-single-stream.v1"
    );
    assert_eq!(
        profile["inner_profile"],
        "sealr.profile.tar.ustar-portable.v1"
    );
    assert_eq!(
        profile["inner_profile_sha256"],
        tar_ustar_portable_v1_digest().as_str()
    );
    assert_eq!(
        tar_bzip2_ustar_portable_v1_digest(),
        "f6711c0c98cff6e3a2c6b266d159413ef891c202b4898b4e1665081dce0f29ee"
    );
    assert_eq!(options().archive_format(), ArchiveFormat::TarBzip2Ustar);
    assert_eq!(
        options().tar_bzip2_interpretation_profile(),
        Some(TarBzip2InterpretationProfile::UstarPortableV1)
    );
    assert!(options().tar_interpretation_profile().is_none());
    assert!(options().tar_gzip_interpretation_profile().is_none());
    assert!(options().tar_zstd_interpretation_profile().is_none());
    assert!(options().tar_xz_interpretation_profile().is_none());
}

#[test]
fn inspect_retention_materialization_and_identities_bind_both_domains() {
    let tar = ustar("mission/plan.txt", b"verify twice, decode once");
    let first = decode_hex(BZ2_CLI_LEVEL9_HEX);
    let second = decode_hex(BZ2_CLI_LEVEL1_HEX);
    let policy = Policy::default_v10();
    let retained = options().with_retention(
        RetentionPlan::new(1024, 1024)
            .with_path("mission/plan.txt")
            .unwrap(),
    );
    let outcome = inspect(&first, &policy, &retained);
    assert!(
        matches!(outcome.admission, AdmissionStatus::Admitted),
        "{:?}",
        outcome.view.findings
    );
    assert!(matches!(outcome.verification, VerificationStatus::Complete));
    assert_eq!(outcome.view.source.magic, "bz2");
    let ir = outcome.archive_ir().unwrap();
    assert_eq!(ir.schema(), TAR_BZIP2_ARCHIVE_IR_SCHEMA);
    assert_eq!(ir.format(), ArchiveFormat::TarBzip2Ustar);
    let wrapper = ir.bzip2_evidence().unwrap();
    assert_eq!(wrapper.level, 9);
    assert_eq!(wrapper.header.offset, 0);
    assert_eq!(wrapper.header.len, 4);
    assert_eq!(wrapper.block_bit_offsets, vec![32]);
    assert_eq!(wrapper.block_crcs.len(), 1);
    assert_eq!(wrapper.combined_crc, wrapper.block_crcs[0]);
    assert_eq!(
        wrapper.payload_bits + u64::from(wrapper.padding_bits),
        first.len() as u64 * 8
    );
    assert_eq!(wrapper.derived_output_len, tar.len() as u64);
    assert_eq!(wrapper.derived_output_sha256, sealr::hex_sha256(&tar));
    assert!(ir.members().iter().all(|member| {
        member.format() == ArchiveFormat::TarBzip2Ustar && member.tar_evidence().is_some()
    }));
    assert!(matches!(
        outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV11 { .. }
    ));
    assert_eq!(
        format!(
            "{}:{}:{}",
            outcome.receipt.source.sha256().unwrap(),
            outcome.receipt.identities.layout.hex().unwrap(),
            outcome.receipt.identities.content.hex().unwrap()
        ),
        concat!(
            "6cf9b27f72fca2d3c665b7012e2ee8cfc24e7f1b7d5cc0f3aa8c239812ea5e87:",
            "6adec7927d150611af780ea135964e96cf1581d42a407f637ee752b63ac3894e:",
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
    assert!(matches!(
        second_outcome.admission,
        AdmissionStatus::Admitted
    ));
    assert_eq!(
        second_outcome
            .archive_ir()
            .unwrap()
            .bzip2_evidence()
            .unwrap()
            .level,
        1
    );
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
        "sealr-tar-bzip2-public-{}-{}",
        std::process::id(),
        &sealr::hex_sha256(&first)[..12]
    ));
    let dest: PathBuf = base.join("out");
    fs::create_dir(&base).unwrap();
    let materialized = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.bz2"),
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
fn wrapper_content_identity_is_shared_across_all_four_codec_encodings() {
    let bzip2_outcome = inspect(
        &decode_hex(BZ2_CLI_LEVEL9_HEX),
        &Policy::default_v10(),
        &options(),
    );
    assert!(matches!(bzip2_outcome.admission, AdmissionStatus::Admitted));

    let mut others = Vec::new();
    let gzip_manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-gzip-identity-v1.json")).unwrap();
    let gzip_source = decode_hex(
        gzip_manifest["cases"][0]["source_bytes_hex"]
            .as_str()
            .unwrap(),
    );
    others.push(apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.gz"),
                data: &gzip_source,
            },
            policy: &Policy::default_v4(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::UstarPortableV1),
    ));

    let zstd_manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-zstd-identity-v1.json")).unwrap();
    let zstd_source = decode_hex(
        zstd_manifest["cases"][0]["source_bytes_hex"]
            .as_str()
            .unwrap(),
    );
    others.push(apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.zst"),
                data: &zstd_source,
            },
            policy: &Policy::default_v8(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_zstd_interpretation_profile(TarZstdInterpretationProfile::UstarPortableV1),
    ));

    let xz_manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-xz-identity-v1.json")).unwrap();
    let xz_source = decode_hex(
        xz_manifest["cases"][0]["source_bytes_hex"]
            .as_str()
            .unwrap(),
    );
    others.push(apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.xz"),
                data: &xz_source,
            },
            policy: &Policy::default_v9(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_xz_interpretation_profile(TarXzInterpretationProfile::UstarPortableV1),
    ));

    for other in &others {
        assert!(matches!(other.admission, AdmissionStatus::Admitted));
        assert_ne!(
            bzip2_outcome.receipt.identities.interpretation.digest,
            other.receipt.identities.interpretation.digest
        );
        assert_ne!(
            bzip2_outcome.receipt.identities.layout,
            other.receipt.identities.layout
        );
        assert_eq!(
            bzip2_outcome.receipt.identities.content,
            other.receipt.identities.content
        );
    }
}

#[test]
fn wrapper_and_inner_language_fail_closed() {
    let tar = ustar("file.txt", b"bounded derived content");
    let member = decode_hex(BZ2_CLI_LEVEL9_HEX);
    let policy = Policy::default_v10();

    let non_bzip2 = inspect(&tar, &policy, &options());
    assert!(matches!(
        non_bzip2.interpretation,
        InterpretationStatus::Malformed
    ));
    assert_eq!(non_bzip2.view.source.magic, "unknown");

    let mut bzip1 = member.clone();
    bzip1[2] = b'0';
    let outcome = inspect(&bzip1, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Unsupported
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::FormatUnsupported));

    let mut level = member.clone();
    level[3] = b'0';
    assert!(matches!(
        inspect(&level, &policy, &options()).interpretation,
        InterpretationStatus::Unsupported
    ));

    let mut randomized = member.clone();
    randomized[14] |= 0x80;
    let outcome = inspect(&randomized, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Unsupported
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::FormatUnsupported));

    let empty = decode_hex(BZ2_EMPTY_HEX);
    let outcome = inspect(&empty, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Unsupported
    ));

    let mut truncated = member.clone();
    truncated.truncate(truncated.len() / 2);
    let outcome = inspect(&truncated, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Malformed
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::CodecBzip2InvalidStream));

    let mut corrupted = member.clone();
    let middle = corrupted.len() / 2;
    corrupted[middle] ^= 0x40;
    let outcome = inspect(&corrupted, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Malformed
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::CodecBzip2InvalidStream));
    assert_eq!(outcome.view.source.magic, "bz2");

    let mut trailing = member.clone();
    trailing.push(0x7F);
    let outcome = inspect(&trailing, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Malformed
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::CodecBzip2TrailingInput));

    let concatenated = [member.clone(), member.clone()].concat();
    let outcome = inspect(&concatenated, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Unsupported
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::CodecBzip2TrailingInput));

    let mut derived_cap = Policy::default_v10();
    derived_cap.max_derived_archive_bytes = Some(2047);
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

    let mut ratio = Policy::default_v10();
    ratio.max_ratio = Some(1);
    let denied = inspect(&member, &ratio, &options());
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaRatio));

    let mut source_cap = Policy::default_v10();
    source_cap.max_archive_bytes = (member.len() - 1) as u64;
    let denied = inspect(&member, &source_cap, &options());
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaArchive));

    let mut metadata = Policy::default_v10();
    metadata.max_metadata_bytes = 12;
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
    let member = decode_hex(BZ2_CLI_LEVEL9_HEX);

    let older = inspect(&member, &Policy::default_v9(), &options());
    assert!(!matches!(older.admission, AdmissionStatus::Admitted));
    assert!(older
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::PolicyUnsupported));

    let raw_selection = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.bz2"),
                data: &member,
            },
            policy: &Policy::default_v10(),
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

    let xz_selection = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.bz2"),
                data: &member,
            },
            policy: &Policy::default_v10(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_xz_interpretation_profile(TarXzInterpretationProfile::UstarPortableV1),
    );
    assert!(!matches!(xz_selection.admission, AdmissionStatus::Admitted));

    let gzip_manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-gzip-identity-v1.json")).unwrap();
    let gzip_source = decode_hex(
        gzip_manifest["cases"][0]["source_bytes_hex"]
            .as_str()
            .unwrap(),
    );
    let bzip2_over_gzip = inspect(&gzip_source, &Policy::default_v10(), &options());
    assert!(!matches!(
        bzip2_over_gzip.admission,
        AdmissionStatus::Admitted
    ));
}

#[test]
fn committed_tree_v11_manifest_matches_the_public_production_path() {
    let manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-bzip2-identity-v1.json")).unwrap();
    assert_eq!(
        manifest["schema"],
        "sealr.tar-bzip2-identity-conformance.v1"
    );
    assert_eq!(
        manifest["profile"]["digest"]["sha256"],
        tar_bzip2_ustar_portable_v1_digest()
    );
    assert_eq!(
        manifest["inner_profile"]["digest"]["sha256"],
        tar_ustar_portable_v1_digest()
    );
    assert_eq!(manifest["layout_encoding"], "sealrTreeV11");
    assert_eq!(
        manifest["layout_label"],
        "sealr.tree.layout.tar-bzip2-ustar.v1"
    );

    let policy = Policy::default_v10();
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
            "format": "tar-bzip2-ustar",
            "bzip2": case["bzip2"].clone(),
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

    // The multi-block section replays under its documented widened expansion
    // ratio; the identity roots it protects are policy-independent.
    let multiblock = &manifest["multiblock"];
    assert_eq!(
        multiblock["replay_policy"]["base"],
        "sealr:policy/default/v10"
    );
    let mut mpolicy = Policy::default_v10();
    mpolicy.max_ratio = Some(multiblock["replay_policy"]["max_ratio"].as_u64().unwrap());
    let msource = decode_hex(multiblock["source_bytes_hex"].as_str().unwrap());
    let moutcome = inspect(&msource, &mpolicy, &options());
    assert!(matches!(moutcome.admission, AdmissionStatus::Admitted));
    assert!(matches!(
        moutcome.verification,
        VerificationStatus::Complete
    ));
    assert_eq!(
        serde_json::to_value(&moutcome.receipt.source).unwrap(),
        multiblock["source"]
    );
    assert_eq!(
        serde_json::to_value(&moutcome.receipt.identities.layout).unwrap(),
        multiblock["layout_root"]
    );
    assert_eq!(
        serde_json::to_value(&moutcome.receipt.identities.content).unwrap(),
        multiblock["content_root"]
    );
    let expected_mir = serde_json::json!({
        "schema": manifest["archive_ir_schema"].clone(),
        "profile": manifest["profile"]["id"].clone(),
        "profile_digest": manifest["profile"]["digest"]["sha256"].clone(),
        "source_digest": multiblock["source"].clone(),
        "format": "tar-bzip2-ustar",
        "bzip2": multiblock["bzip2"].clone(),
        "tar_covering": multiblock["derived_tar"]["covering"].clone(),
        "members": multiblock["derived_tar"]["members"].clone(),
    });
    assert_eq!(
        serde_json::to_value(moutcome.archive_ir().unwrap()).unwrap(),
        expected_mir
    );
    assert_eq!(
        multiblock["bzip2"]["block_bit_offsets"]
            .as_array()
            .unwrap()
            .len(),
        3
    );

    let mderived = decode_hex(multiblock["derived_tar"]["bytes_hex"].as_str().unwrap());
    let mraw = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("telemetry.tar"),
                data: &mderived,
            },
            policy: &Policy::default_v2(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_interpretation_profile(TarInterpretationProfile::UstarPortableV1),
    );
    assert!(matches!(mraw.verification, VerificationStatus::Complete));
    assert_eq!(
        serde_json::to_value(&mraw.receipt.identities.layout).unwrap(),
        multiblock["derived_tar"]["raw_layout_root"]
    );
    assert_eq!(
        serde_json::to_value(&mraw.receipt.identities.content).unwrap(),
        multiblock["content_root"]
    );
}
