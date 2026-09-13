use core::hash::Hasher as _;
use std::fs;
use std::path::PathBuf;

use sealr::{
    apply_with_options, tar_ustar_portable_v1_digest, tar_zstd_ustar_portable_v1_canonical_bytes,
    tar_zstd_ustar_portable_v1_digest, AdmissionStatus, ApplyOptions, ArchiveFormat, FindingCode,
    InterpretationStatus, Policy, Request, RetentionPlan, Source, TarGzipInterpretationProfile,
    TarInterpretationProfile, TarZstdInterpretationProfile, TreeRoot, VerificationStatus,
    TAR_ZSTD_ARCHIVE_IR_SCHEMA, TAR_ZSTD_USTAR_PORTABLE_V1,
};

/// Zstandard CLI v1.5.7 default-level output for the exact conformance
/// derived TAR (single-segment frame, two-byte FCS, XXH64 checksum).
const ZSTD_CLI_DEFAULT_HEX: &str = "28b52ffd640007a5030062c5121880a96dc0ffd67f1bf321d16a06b6620b6d\
e647c162f422038a129f1e8cf43843d126fa1683558a6866f59b3abd0e3f43c424598ac944438c94ff7fa6e0ffad150d\
4887600824deb5b6100e004fc10f92c40c35149a94c11c58d301c0907b01a0133cf00e83dc50ab0238562e1326b004ca\
51b2db";

/// Zstandard CLI v1.5.7 `-19` output for the same derived TAR.
const ZSTD_CLI_LEVEL19_HEX: &str = "28b52ffd64000745030092451211907d50fa109d0fdd5d0a65adadfe5f69\
01c0b149836b94b916846370e3d01fb44e034ca9fd0776e19bc107608c41e5c13f3a2721645201e5fc3f40483dc01c8f\
b9622593c27ba10c0a20f036360e8ee71f9252061612030e14fe81d211d9830658982818ca51b2db";

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

fn xxh64_checksum(data: &[u8]) -> [u8; 4] {
    let mut hasher = twox_hash::XxHash64::with_seed(0);
    hasher.write(data);
    ((hasher.finish() & 0xFFFF_FFFF) as u32).to_le_bytes()
}

/// Handcrafted RFC 8878 frame carrying `content` as raw (uncompressed) blocks.
fn raw_block_frame(content: &[u8], checksum: bool) -> Vec<u8> {
    let mut bytes = 0xFD2F_B528_u32.to_le_bytes().to_vec();
    let mut descriptor = 0x20_u8;
    if checksum {
        descriptor |= 0x04;
    }
    descriptor |= 0b1000_0000;
    bytes.push(descriptor);
    bytes.extend_from_slice(&(content.len() as u32).to_le_bytes());
    let block_header = ((content.len() as u32) << 3) | 1;
    bytes.extend_from_slice(&block_header.to_le_bytes()[..3]);
    bytes.extend_from_slice(content);
    if checksum {
        bytes.extend_from_slice(&xxh64_checksum(content));
    }
    bytes
}

fn options() -> ApplyOptions {
    ApplyOptions::new()
        .with_tar_zstd_interpretation_profile(TarZstdInterpretationProfile::UstarPortableV1)
}

fn inspect<'a>(bytes: &'a [u8], policy: &'a Policy, options: &ApplyOptions) -> sealr::Outcome {
    apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.zst"),
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
    let canonical = tar_zstd_ustar_portable_v1_canonical_bytes();
    let profile: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    assert_eq!(profile["schema"], TAR_ZSTD_USTAR_PORTABLE_V1);
    assert_eq!(
        profile["wrapper_profile"],
        "sealr.transform.zstd.rfc8878-single-frame.v1"
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
        tar_zstd_ustar_portable_v1_digest(),
        "c7d2e708f2f5258eddfb99fbf13661bd2f671a2daa4a45bc1d9603d30d472ae7"
    );
    assert_eq!(options().archive_format(), ArchiveFormat::TarZstdUstar);
    assert_eq!(
        options().tar_zstd_interpretation_profile(),
        Some(TarZstdInterpretationProfile::UstarPortableV1)
    );
    assert!(options().tar_interpretation_profile().is_none());
    assert!(options().tar_gzip_interpretation_profile().is_none());
}

#[test]
fn inspect_retention_materialization_and_identities_bind_both_domains() {
    let tar = ustar("mission/plan.txt", b"verify twice, decode once");
    let first = decode_hex(ZSTD_CLI_DEFAULT_HEX);
    let second = decode_hex(ZSTD_CLI_LEVEL19_HEX);
    let policy = Policy::default_v8();
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
    assert_eq!(outcome.view.source.magic, "zst");
    let ir = outcome.archive_ir().unwrap();
    assert_eq!(ir.schema(), TAR_ZSTD_ARCHIVE_IR_SCHEMA);
    assert_eq!(ir.format(), ArchiveFormat::TarZstdUstar);
    let wrapper = ir.zstd_evidence().unwrap();
    assert!(wrapper.single_segment);
    assert!(wrapper.checksum_flag);
    assert_eq!(wrapper.window_descriptor, None);
    assert_eq!(wrapper.window_size, tar.len() as u64);
    assert_eq!(wrapper.frame_content_size, Some(tar.len() as u64));
    assert_eq!(wrapper.trailer.len, 4);
    assert_eq!(wrapper.trailer.end(), first.len() as u64);
    assert_eq!(
        wrapper.declared_checksum,
        Some(u32::from_le_bytes(xxh64_checksum(&tar)))
    );
    assert_eq!(wrapper.derived_output_len, tar.len() as u64);
    assert_eq!(wrapper.derived_output_sha256, sealr::hex_sha256(&tar));
    assert!(ir.members().iter().all(|member| {
        member.format() == ArchiveFormat::TarZstdUstar && member.tar_evidence().is_some()
    }));
    assert!(matches!(
        outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV9 { .. }
    ));
    assert_eq!(
        format!(
            "{}:{}:{}",
            outcome.receipt.source.sha256().unwrap(),
            outcome.receipt.identities.layout.hex().unwrap(),
            outcome.receipt.identities.content.hex().unwrap()
        ),
        concat!(
            "4a467796ef2cd9a9e1a6ed670fa1d1ef15174b95be29b087af7339c32b078dcb:",
            "8638eff6b2507614edc81eaccf4c3168e245febe0d1ee0eeb7651b018233fb63:",
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
        "sealr-tar-zstd-public-{}-{}",
        std::process::id(),
        &sealr::hex_sha256(&first)[..12]
    ));
    let dest: PathBuf = base.join("out");
    fs::create_dir(&base).unwrap();
    let materialized = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.zst"),
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
fn wrapper_content_identity_is_shared_across_gzip_and_zstd_encodings() {
    let zstd_outcome = inspect(
        &decode_hex(ZSTD_CLI_DEFAULT_HEX),
        &Policy::default_v8(),
        &options(),
    );
    assert!(matches!(zstd_outcome.admission, AdmissionStatus::Admitted));

    let gzip_manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-gzip-identity-v1.json")).unwrap();
    let gzip_source = decode_hex(
        gzip_manifest["cases"][0]["source_bytes_hex"]
            .as_str()
            .unwrap(),
    );
    let gzip_outcome = apply_with_options(
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
    );
    assert!(matches!(gzip_outcome.admission, AdmissionStatus::Admitted));
    assert_ne!(
        zstd_outcome.receipt.identities.interpretation.digest,
        gzip_outcome.receipt.identities.interpretation.digest
    );
    assert_ne!(
        zstd_outcome.receipt.identities.layout,
        gzip_outcome.receipt.identities.layout
    );
    assert_eq!(
        zstd_outcome.receipt.identities.content,
        gzip_outcome.receipt.identities.content
    );
}

#[test]
fn wrapper_and_inner_language_fail_closed() {
    let tar = ustar("file.txt", b"bounded derived content");
    let member = raw_block_frame(&tar, true);
    let policy = Policy::default_v8();

    let non_zstd = inspect(&tar, &policy, &options());
    assert!(matches!(
        non_zstd.interpretation,
        InterpretationStatus::Malformed
    ));
    assert_eq!(non_zstd.view.source.magic, "unknown");

    let mut skippable = 0x184D_2A50_u32.to_le_bytes().to_vec();
    skippable.extend_from_slice(&4_u32.to_le_bytes());
    skippable.extend_from_slice(b"skip");
    let outcome = inspect(&skippable, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Unsupported
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::FormatUnsupported));

    let mut dictionary = member.clone();
    dictionary[4] |= 0b0000_0001;
    assert!(matches!(
        inspect(&dictionary, &policy, &options()).interpretation,
        InterpretationStatus::Unsupported
    ));

    let mut reserved = member.clone();
    reserved[4] |= 0b0000_1000;
    assert!(matches!(
        inspect(&reserved, &policy, &options()).interpretation,
        InterpretationStatus::Unsupported
    ));

    let oversized_window = {
        let mut bytes = 0xFD2F_B528_u32.to_le_bytes().to_vec();
        bytes.push(0);
        bytes.push(0x70);
        let block_header = (4_u32 << 3) | 1;
        bytes.extend_from_slice(&block_header.to_le_bytes()[..3]);
        bytes.extend_from_slice(b"body");
        bytes
    };
    let outcome = inspect(&oversized_window, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Unsupported
    ));

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
        .any(|finding| finding.code == FindingCode::CodecZstdTrailingInput));

    let mut trailing = member.clone();
    trailing.push(0x7f);
    let outcome = inspect(&trailing, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Malformed
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::CodecZstdTrailingInput));

    let mut checksum_lie = member.clone();
    let last = checksum_lie.len() - 1;
    checksum_lie[last] ^= 0x01;
    let outcome = inspect(&checksum_lie, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Malformed
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::CrcMismatch));

    let invalid_inner = raw_block_frame(b"not a tar archive", false);
    let outcome = inspect(&invalid_inner, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Malformed
    ));
    assert_eq!(outcome.view.source.magic, "zst");

    let mut derived_cap = Policy::default_v8();
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

    let compressible = decode_hex(ZSTD_CLI_DEFAULT_HEX);
    let mut ratio = Policy::default_v8();
    ratio.max_ratio = Some(1);
    let denied = inspect(&compressible, &ratio, &options());
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaRatio));

    let mut source_cap = Policy::default_v8();
    source_cap.max_archive_bytes = (member.len() - 1) as u64;
    let denied = inspect(&member, &source_cap, &options());
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaArchive));

    let mut metadata = Policy::default_v8();
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
    let member = decode_hex(ZSTD_CLI_DEFAULT_HEX);

    let older = inspect(&member, &Policy::default_v7(), &options());
    assert!(!matches!(older.admission, AdmissionStatus::Admitted));
    assert!(older
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::PolicyUnsupported));

    let raw_selection = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.zst"),
                data: &member,
            },
            policy: &Policy::default_v8(),
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

    let gzip_selection = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.zst"),
                data: &member,
            },
            policy: &Policy::default_v8(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::UstarPortableV1),
    );
    assert!(!matches!(
        gzip_selection.admission,
        AdmissionStatus::Admitted
    ));

    let gzip_manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-gzip-identity-v1.json")).unwrap();
    let gzip_source = decode_hex(
        gzip_manifest["cases"][0]["source_bytes_hex"]
            .as_str()
            .unwrap(),
    );
    let zstd_over_gzip = inspect(&gzip_source, &Policy::default_v8(), &options());
    assert!(!matches!(
        zstd_over_gzip.admission,
        AdmissionStatus::Admitted
    ));
}

#[test]
fn committed_tree_v9_manifest_matches_the_public_production_path() {
    let manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-zstd-identity-v1.json")).unwrap();
    assert_eq!(manifest["schema"], "sealr.tar-zstd-identity-conformance.v1");
    assert_eq!(
        manifest["profile"]["digest"]["sha256"],
        tar_zstd_ustar_portable_v1_digest()
    );
    assert_eq!(
        manifest["inner_profile"]["digest"]["sha256"],
        tar_ustar_portable_v1_digest()
    );
    assert_eq!(manifest["layout_encoding"], "sealrTreeV9");
    assert_eq!(
        manifest["layout_label"],
        "sealr.tree.layout.tar-zstd-ustar.v1"
    );

    let policy = Policy::default_v8();
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
            "format": "tar-zstd-ustar",
            "zstd": case["zstd"].clone(),
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
