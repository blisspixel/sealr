use std::fs;
use std::path::PathBuf;

use sealr::{
    apply_with_options, tar_ustar_portable_v1_digest, tar_xz_ustar_portable_v1_canonical_bytes,
    tar_xz_ustar_portable_v1_digest, AdmissionStatus, ApplyOptions, ArchiveFormat, FindingCode,
    InterpretationStatus, Policy, Request, RetentionPlan, Source, TarGzipInterpretationProfile,
    TarInterpretationProfile, TarXzInterpretationProfile, TarZstdInterpretationProfile, TreeRoot,
    VerificationStatus, TAR_XZ_ARCHIVE_IR_SCHEMA, TAR_XZ_USTAR_PORTABLE_V1,
};

/// XZ Utils v5.8.1 `xz -6 -T1` output for the exact conformance derived TAR
/// (single stream, one block, LZMA2 with an 8 MiB dictionary, CRC64 check).
const XZ_CLI_CRC64_HEX: &str = "fd377a585a000004e6d6b4460200210116000000742fe5a3e007ff00705d\
    00369a4adff3ff4173689225555d5c3da569f20e0f1e46ed67823a5dcf0c5c5749d5f12bb878efa1897bcf\
    a2a38633f7d28fc607eaad183da7c2063caa76c99a73e3434b174e4fa5f5dd59582a4d6308d2ffca92620a\
    f736cdb6f7b1240ae87699d3cfb3eb7748f4ff4a5b315efe8cd37d00ec921496b86e87ef00018c01801000\
    00853c3866b1c467fb020000000004595a";

/// XZ Utils v5.8.1 `xz -6 -T1 -C sha256` output for the same derived TAR.
const XZ_CLI_SHA256_HEX: &str = "fd377a585a00000ae1fb0ca10200210116000000742fe5a3e007ff0070\
    5d00369a4adff3ff4173689225555d5c3da569f20e0f1e46ed67823a5dcf0c5c5749d5f12bb878efa1897b\
    cfa2a38633f7d28fc607eaad183da7c2063caa76c99a73e3434b174e4fa5f5dd59582a4d6308d2ffca9262\
    0af736cdb6f7b1240ae87699d3cfb3eb7748f4ff4a5b315efe8cd37d0036631c7b6055995f66c07c86f39b\
    baa386b893b177c693bb38a5f73aaa83837c0001a40180100000debbc78db6e9df1c02000000000a595a";

/// XZ Utils v5.8.1 `xz -6 -T1 -C none` output for the same derived TAR: the
/// profile denies streams that carry no integrity check.
const XZ_CLI_NONE_HEX: &str = "fd377a585a000000ff12d9410200210116000000742fe5a3e007ff00705d\
    00369a4adff3ff4173689225555d5c3da569f20e0f1e46ed67823a5dcf0c5c5749d5f12bb878efa1897bcf\
    a2a38633f7d28fc607eaad183da7c2063caa76c99a73e3434b174e4fa5f5dd59582a4d6308d2ffca92620a\
    f736cdb6f7b1240ae87699d3cfb3eb7748f4ff4a5b315efe8cd37d000001840180100000e8be6b8aa8000a\
    fc020000000000595a";

/// XZ Utils v5.8.1 `xz -9 -T1` output for the same derived TAR: a declared
/// 64 MiB dictionary exceeds the 8 MiB pre-allocation ceiling.
const XZ_CLI_DICT64M_HEX: &str = "fd377a585a000004e6d6b446020021011c00000010cf58cce007ff0070\
    5d00369a4adff3ff4173689225555d5c3da569f20e0f1e46ed67823a5dcf0c5c5749d5f12bb878efa1897b\
    cfa2a38633f7d28fc607eaad183da7c2063caa76c99a73e3434b174e4fa5f5dd59582a4d6308d2ffca9262\
    0af736cdb6f7b1240ae87699d3cfb3eb7748f4ff4a5b315efe8cd37d00ec921496b86e87ef00018c018010\
    0000853c3866b1c467fb020000000004595a";

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

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

/// Handcrafted single-block stream carrying `content` as uncompressed LZMA2
/// chunks with a CRC32 check, giving the tests full grammar control.
fn built_stream(content: &[u8]) -> Vec<u8> {
    let mut lzma2 = Vec::new();
    let mut first = true;
    for chunk in content.chunks(0xFFFF) {
        lzma2.push(if first { 0x01 } else { 0x02 });
        first = false;
        let size = (chunk.len() - 1) as u16;
        lzma2.extend_from_slice(&size.to_be_bytes());
        lzma2.extend_from_slice(chunk);
    }
    lzma2.push(0x00);

    let check_value = crc32(content).to_le_bytes();

    let mut header = vec![0_u8; 2];
    push_varint(&mut header, 0x21);
    push_varint(&mut header, 1);
    header.push(22);
    while !(header.len() + 4).is_multiple_of(4) {
        header.push(0);
    }
    header[0] = ((header.len() + 4) / 4 - 1) as u8;
    let header_crc = crc32(&header);
    header.extend_from_slice(&header_crc.to_le_bytes());

    let mut stream = vec![0xFD, b'7', b'z', b'X', b'Z', 0x00];
    stream.push(0);
    stream.push(0x01);
    stream.extend_from_slice(&crc32(&[0, 0x01]).to_le_bytes());

    let block_start = stream.len();
    stream.extend_from_slice(&header);
    stream.extend_from_slice(&lzma2);
    let unpadded = (stream.len() - block_start + check_value.len()) as u64;
    while (stream.len() - block_start) % 4 != 0 {
        stream.push(0);
    }
    stream.extend_from_slice(&check_value);

    let index_start = stream.len();
    stream.push(0);
    push_varint(&mut stream, 1);
    push_varint(&mut stream, unpadded);
    push_varint(&mut stream, content.len() as u64);
    while (stream.len() - index_start) % 4 != 0 {
        stream.push(0);
    }
    let index_crc = crc32(&stream[index_start..]);
    stream.extend_from_slice(&index_crc.to_le_bytes());
    let index_len = stream.len() - index_start;

    let backward = (index_len as u32 / 4) - 1;
    let mut footer_body = backward.to_le_bytes().to_vec();
    footer_body.push(0);
    footer_body.push(0x01);
    stream.extend_from_slice(&crc32(&footer_body).to_le_bytes());
    stream.extend_from_slice(&footer_body);
    stream.extend_from_slice(b"YZ");
    stream
}

fn options() -> ApplyOptions {
    ApplyOptions::new()
        .with_tar_xz_interpretation_profile(TarXzInterpretationProfile::UstarPortableV1)
}

fn inspect<'a>(bytes: &'a [u8], policy: &'a Policy, options: &ApplyOptions) -> sealr::Outcome {
    apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.xz"),
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
    let canonical = tar_xz_ustar_portable_v1_canonical_bytes();
    let profile: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    assert_eq!(profile["schema"], TAR_XZ_USTAR_PORTABLE_V1);
    assert_eq!(
        profile["wrapper_profile"],
        "sealr.transform.xz.xzfmt-single-stream.v1"
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
        tar_xz_ustar_portable_v1_digest(),
        "16ec815ab3b2c3c5f877ec04e592d1dd1a6ec41f2c7d843dd7aa2bc6b50cfd05"
    );
    assert_eq!(options().archive_format(), ArchiveFormat::TarXzUstar);
    assert_eq!(
        options().tar_xz_interpretation_profile(),
        Some(TarXzInterpretationProfile::UstarPortableV1)
    );
    assert!(options().tar_interpretation_profile().is_none());
    assert!(options().tar_gzip_interpretation_profile().is_none());
    assert!(options().tar_zstd_interpretation_profile().is_none());
}

#[test]
fn inspect_retention_materialization_and_identities_bind_both_domains() {
    let tar = ustar("mission/plan.txt", b"verify twice, decode once");
    let first = decode_hex(XZ_CLI_CRC64_HEX);
    let second = decode_hex(XZ_CLI_SHA256_HEX);
    let policy = Policy::default_v9();
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
    assert_eq!(outcome.view.source.magic, "xz");
    let ir = outcome.archive_ir().unwrap();
    assert_eq!(ir.schema(), TAR_XZ_ARCHIVE_IR_SCHEMA);
    assert_eq!(ir.format(), ArchiveFormat::TarXzUstar);
    let wrapper = ir.xz_evidence().unwrap();
    assert_eq!(wrapper.check_id, 0x04);
    assert_eq!(wrapper.header.offset, 0);
    assert_eq!(wrapper.header.len, 12);
    assert_eq!(wrapper.blocks.len(), 1);
    assert_eq!(wrapper.blocks[0].dict_size, 8 * 1024 * 1024);
    assert_eq!(wrapper.blocks[0].uncompressed_len, tar.len() as u64);
    assert_eq!(wrapper.blocks[0].check.len, 8);
    assert_eq!(wrapper.footer.len, 12);
    assert_eq!(wrapper.footer.end(), first.len() as u64);
    assert_eq!(wrapper.derived_output_len, tar.len() as u64);
    assert_eq!(wrapper.derived_output_sha256, sealr::hex_sha256(&tar));
    assert!(ir.members().iter().all(|member| {
        member.format() == ArchiveFormat::TarXzUstar && member.tar_evidence().is_some()
    }));
    assert!(matches!(
        outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV10 { .. }
    ));
    assert_eq!(
        format!(
            "{}:{}:{}",
            outcome.receipt.source.sha256().unwrap(),
            outcome.receipt.identities.layout.hex().unwrap(),
            outcome.receipt.identities.content.hex().unwrap()
        ),
        concat!(
            "54f88a8a4b418364e2c3f7747d9a40aecee3624d0d0880727e674a9cbc60a8ca:",
            "558d5f8e75966e1ab4b1892e71fcf871f9670f07b3e6ef47ae6e57b6a4e05f8d:",
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
            .xz_evidence()
            .unwrap()
            .check_id,
        0x0A
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
        "sealr-tar-xz-public-{}-{}",
        std::process::id(),
        &sealr::hex_sha256(&first)[..12]
    ));
    let dest: PathBuf = base.join("out");
    fs::create_dir(&base).unwrap();
    let materialized = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.xz"),
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
fn wrapper_content_identity_is_shared_across_gzip_zstd_and_xz_encodings() {
    let xz_outcome = inspect(
        &decode_hex(XZ_CLI_CRC64_HEX),
        &Policy::default_v9(),
        &options(),
    );
    assert!(matches!(xz_outcome.admission, AdmissionStatus::Admitted));

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

    let zstd_manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-zstd-identity-v1.json")).unwrap();
    let zstd_source = decode_hex(
        zstd_manifest["cases"][0]["source_bytes_hex"]
            .as_str()
            .unwrap(),
    );
    let zstd_outcome = apply_with_options(
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
    );
    assert!(matches!(zstd_outcome.admission, AdmissionStatus::Admitted));

    for other in [&gzip_outcome, &zstd_outcome] {
        assert_ne!(
            xz_outcome.receipt.identities.interpretation.digest,
            other.receipt.identities.interpretation.digest
        );
        assert_ne!(
            xz_outcome.receipt.identities.layout,
            other.receipt.identities.layout
        );
        assert_eq!(
            xz_outcome.receipt.identities.content,
            other.receipt.identities.content
        );
    }
}

#[test]
fn wrapper_and_inner_language_fail_closed() {
    let tar = ustar("file.txt", b"bounded derived content");
    let member = built_stream(&tar);
    let policy = Policy::default_v9();

    let non_xz = inspect(&tar, &policy, &options());
    assert!(matches!(
        non_xz.interpretation,
        InterpretationStatus::Malformed
    ));
    assert_eq!(non_xz.view.source.magic, "unknown");

    let check_none = decode_hex(XZ_CLI_NONE_HEX);
    let outcome = inspect(&check_none, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Unsupported
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::FormatUnsupported));

    let dict64m = decode_hex(XZ_CLI_DICT64M_HEX);
    let outcome = inspect(&dict64m, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Unsupported
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::FormatUnsupported));

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
        .any(|finding| finding.code == FindingCode::CodecXzTrailingInput));

    let mut padded = member.clone();
    padded.extend_from_slice(&[0, 0, 0, 0]);
    let outcome = inspect(&padded, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Unsupported
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::CodecXzTrailingInput));

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
        .any(|finding| finding.code == FindingCode::CodecXzTrailingInput));

    let mut check_lie = member.clone();
    let backward = u32::from_le_bytes([
        check_lie[check_lie.len() - 8],
        check_lie[check_lie.len() - 7],
        check_lie[check_lie.len() - 6],
        check_lie[check_lie.len() - 5],
    ]);
    let index_len = ((backward as usize) + 1) * 4;
    let check_end = check_lie.len() - 12 - index_len;
    check_lie[check_end - 1] ^= 0x01;
    let outcome = inspect(&check_lie, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Malformed
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::CrcMismatch));

    let invalid_inner = built_stream(b"not a tar archive at all");
    let outcome = inspect(&invalid_inner, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Malformed
    ));
    assert_eq!(outcome.view.source.magic, "xz");

    let mut derived_cap = Policy::default_v9();
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

    let compressible = decode_hex(XZ_CLI_CRC64_HEX);
    let mut ratio = Policy::default_v9();
    ratio.max_ratio = Some(1);
    let denied = inspect(&compressible, &ratio, &options());
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaRatio));

    let mut source_cap = Policy::default_v9();
    source_cap.max_archive_bytes = (member.len() - 1) as u64;
    let denied = inspect(&member, &source_cap, &options());
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaArchive));

    let mut metadata = Policy::default_v9();
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
    let member = decode_hex(XZ_CLI_CRC64_HEX);

    let older = inspect(&member, &Policy::default_v8(), &options());
    assert!(!matches!(older.admission, AdmissionStatus::Admitted));
    assert!(older
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::PolicyUnsupported));

    let raw_selection = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.xz"),
                data: &member,
            },
            policy: &Policy::default_v9(),
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

    let zstd_selection = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.xz"),
                data: &member,
            },
            policy: &Policy::default_v9(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_zstd_interpretation_profile(TarZstdInterpretationProfile::UstarPortableV1),
    );
    assert!(!matches!(
        zstd_selection.admission,
        AdmissionStatus::Admitted
    ));

    let gzip_manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-gzip-identity-v1.json")).unwrap();
    let gzip_source = decode_hex(
        gzip_manifest["cases"][0]["source_bytes_hex"]
            .as_str()
            .unwrap(),
    );
    let xz_over_gzip = inspect(&gzip_source, &Policy::default_v9(), &options());
    assert!(!matches!(xz_over_gzip.admission, AdmissionStatus::Admitted));

    let zstd_manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-zstd-identity-v1.json")).unwrap();
    let zstd_source = decode_hex(
        zstd_manifest["cases"][0]["source_bytes_hex"]
            .as_str()
            .unwrap(),
    );
    let xz_over_zstd = inspect(&zstd_source, &Policy::default_v9(), &options());
    assert!(!matches!(xz_over_zstd.admission, AdmissionStatus::Admitted));
}

#[test]
fn committed_tree_v10_manifest_matches_the_public_production_path() {
    let manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-xz-identity-v1.json")).unwrap();
    assert_eq!(manifest["schema"], "sealr.tar-xz-identity-conformance.v1");
    assert_eq!(
        manifest["profile"]["digest"]["sha256"],
        tar_xz_ustar_portable_v1_digest()
    );
    assert_eq!(
        manifest["inner_profile"]["digest"]["sha256"],
        tar_ustar_portable_v1_digest()
    );
    assert_eq!(manifest["layout_encoding"], "sealrTreeV10");
    assert_eq!(
        manifest["layout_label"],
        "sealr.tree.layout.tar-xz-ustar.v1"
    );

    let policy = Policy::default_v9();
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
            "format": "tar-xz-ustar",
            "xz": case["xz"].clone(),
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
