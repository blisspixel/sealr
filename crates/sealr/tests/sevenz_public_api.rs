use std::fs;
use std::path::PathBuf;

use sealr::{
    apply_with_options, sevenz_copy_portable_v1_canonical_bytes, sevenz_copy_portable_v1_digest,
    AdmissionStatus, ApplyOptions, ArchiveFormat, FindingCode, InterpretationStatus, MemberKind,
    Policy, Request, RetentionPlan, SevenZInterpretationProfile, Source, TarInterpretationProfile,
    TreeRoot, VerificationStatus, SEVENZ_COPY_ARCHIVE_IR_SCHEMA, SEVENZ_COPY_PORTABLE_V1,
};

/// 7-Zip 26.02 `7z a -m0=Copy -mhc=off` of exactly `mission/plan.txt` =
/// "verify twice, decode once" (mtime 1788000000): one Copy folder, raw
/// header, 147 bytes.
const SEVENZ_CLI_FILEONLY_HEX: &str = "377abcaf271c000435c12a4919000000000000\
    005a00000000000000eaaeb7e67665726966792074776963652c206465636f6465206f6e636501040600\
    01091900070b01000101000c1900080a0103b44165000005011123006d0069007300730069006f006e00\
    2f0070006c0061006e002e0074007800740000001900140a01000000d4bda237dd011506010020000000\
    0000";

/// The same producer over a directory, an empty file, and two payload files:
/// two Copy folders and the complete empty-stream/empty-file matrix.
const SEVENZ_CLI_MULTI_HEX: &str = "377abcaf271c000412338a09440000000000000\
    0ee00000000000000a70495047665726966792074776963652c206465636f6465206f6e63657468652062\
    6f756e64617279206f776e7320746865206d65616e696e67206f662065766572792062797465010406000\
    209192b00070b02000101000101000c192b00080a0103b44165443d37e6000005040e01c00f0140118083\
    006d0069007300730069006f006e0000006d0069007300730069006f006e002f0065006d0070007400790\
    02e0074007800740000006d0069007300730069006f006e002f0070006c0061006e002e00740078007400\
    00006d0069007300730069006f006e002f00740065006c0065006d0065007400720079002e006c006f006\
    70000001900142201000000d4bda237dd010000d4bda237dd010000d4bda237dd010000d4bda237dd0115\
    120100100000002000000020000000200000000000";

/// Stock `7z a -m0=Copy` (default): the next header is kEncodedHeader with an
/// LZMA1-coded header stream — the named unsupported shape.
const SEVENZ_CLI_ENCODED_HEADER_HEX: &str = "377abcaf271c0004f59452dd7800000000\
    00000021000000000000009db7c94a7665726966792074776963652c206465636f6465206f6e63650000\
    813307ae0fcf926e600febeb2d5cf9eaa7997e032f24bd2f25021d1de4439ce2744630c90a6dc37dde91\
    e412785742f539bd30d0c0918f644e5bb9f0713b9d5526658e27ebbf2feb0de156528f08f8308f33cf29\
    268f9c0a7af76e000017061901095f00070b01000123030101055d001000000c80860a01c515cbb70000";

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

/// Recompute the next-header CRC and then the start-header CRC that covers
/// it, so a mutated header fails only on the intended rule.
fn repair_header_crcs(source: &mut [u8], header_start: usize) {
    let next = crc32(&source[header_start..]);
    source[28..32].copy_from_slice(&next.to_le_bytes());
    let start = crc32(&source[12..32]);
    source[8..12].copy_from_slice(&start.to_le_bytes());
}

fn options() -> ApplyOptions {
    ApplyOptions::new()
        .with_sevenz_interpretation_profile(SevenZInterpretationProfile::CopyPortableV1)
}

fn inspect<'a>(bytes: &'a [u8], policy: &'a Policy, options: &ApplyOptions) -> sealr::Outcome {
    apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.7z"),
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
    let canonical = sevenz_copy_portable_v1_canonical_bytes();
    let profile: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    assert_eq!(profile["schema"], SEVENZ_COPY_PORTABLE_V1);
    assert_eq!(profile["format"], "7z-copy");
    assert_eq!(
        profile["header"],
        "exactly-one-raw-kheader-encoded-header-denied"
    );
    assert_eq!(
        sevenz_copy_portable_v1_digest(),
        "7b6604ad59b5aecf9ebdfa42d7d48d3df663813798992741dd6d74ea56f60b75"
    );
    assert_eq!(options().archive_format(), ArchiveFormat::SevenZCopy);
    assert_eq!(
        options().sevenz_interpretation_profile(),
        Some(SevenZInterpretationProfile::CopyPortableV1)
    );
    assert!(options().zip_interpretation_profile().is_none());
    assert!(options().tar_interpretation_profile().is_none());
    assert!(options().tar_bzip2_interpretation_profile().is_none());
}

#[test]
fn inspect_retention_materialization_and_identities_bind_the_container() {
    let source = decode_hex(SEVENZ_CLI_FILEONLY_HEX);
    let policy = Policy::default_v11();
    let retained = options().with_retention(
        RetentionPlan::new(1024, 1024)
            .with_path("mission/plan.txt")
            .unwrap(),
    );
    let outcome = inspect(&source, &policy, &retained);
    assert!(
        matches!(outcome.admission, AdmissionStatus::Admitted),
        "{:?}",
        outcome.view.findings
    );
    assert!(matches!(outcome.verification, VerificationStatus::Complete));
    assert_eq!(outcome.view.source.magic, "7z");
    let ir = outcome.archive_ir().unwrap();
    assert_eq!(ir.schema(), SEVENZ_COPY_ARCHIVE_IR_SCHEMA);
    assert_eq!(ir.format(), ArchiveFormat::SevenZCopy);
    let evidence = ir.sevenz_evidence().unwrap();
    assert_eq!(evidence.version_minor, 4);
    assert_eq!(evidence.pack_region.offset, 32);
    assert_eq!(evidence.pack_region.len, 25);
    assert_eq!(evidence.next_header.offset, 57);
    assert_eq!(evidence.next_header.len, 90);
    assert_eq!(evidence.folders.len(), 1);
    assert_eq!(evidence.folders[0].substreams.len(), 1);
    assert_eq!(
        evidence.folders[0].substreams[0].declared_crc,
        Some(0x6541_B403)
    );
    assert_eq!(ir.members().len(), 1);
    let member = &ir.members()[0];
    assert_eq!(member.canonical_path, "mission/plan.txt");
    assert_eq!(member.kind, MemberKind::File);
    assert_eq!(member.actual_crc, Some(0x6541_B403));
    assert!(matches!(
        outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV12 { .. }
    ));
    assert_eq!(
        format!(
            "{}:{}:{}",
            outcome.receipt.source.sha256().unwrap(),
            outcome.receipt.identities.layout.hex().unwrap(),
            outcome.receipt.identities.content.hex().unwrap()
        ),
        concat!(
            "ebefe20d0dfd944e29a0987e4b182c80595e2a7ec4d1efe3217123e22259c289:",
            "df4c1271279959b9fbd90e56078913779e134f52a69c52d959878ad76bff9a9d:",
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

    let base = std::env::temp_dir().join(format!(
        "sealr-sevenz-public-{}-{}",
        std::process::id(),
        &sealr::hex_sha256(&source)[..12]
    ));
    let dest: PathBuf = base.join("out");
    fs::create_dir(&base).unwrap();
    let materialized = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.7z"),
                data: &source,
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
fn content_identity_is_shared_across_containers_for_the_first_time() {
    // The 7z Copy archive and the raw TAR of the exact same member set must
    // share one format-neutral content root while every structural identity
    // differs — the first cross-CONTAINER parity, beyond the TAR wrappers.
    let sevenz_outcome = inspect(
        &decode_hex(SEVENZ_CLI_FILEONLY_HEX),
        &Policy::default_v11(),
        &options(),
    );
    assert!(matches!(
        sevenz_outcome.admission,
        AdmissionStatus::Admitted
    ));

    let tar = ustar("mission/plan.txt", b"verify twice, decode once");
    let tar_outcome = apply_with_options(
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
    assert!(matches!(tar_outcome.admission, AdmissionStatus::Admitted));

    assert_ne!(
        sevenz_outcome.receipt.identities.interpretation.digest,
        tar_outcome.receipt.identities.interpretation.digest
    );
    assert_ne!(
        sevenz_outcome.receipt.identities.layout,
        tar_outcome.receipt.identities.layout
    );
    assert_eq!(
        sevenz_outcome.receipt.identities.content,
        tar_outcome.receipt.identities.content
    );
}

#[test]
fn the_multi_archive_resolves_the_full_empty_matrix() {
    let source = decode_hex(SEVENZ_CLI_MULTI_HEX);
    let outcome = inspect(&source, &Policy::default_v11(), &options());
    assert!(
        matches!(outcome.admission, AdmissionStatus::Admitted),
        "{:?}",
        outcome.view.findings
    );
    let ir = outcome.archive_ir().unwrap();
    assert_eq!(ir.members().len(), 4);
    assert_eq!(ir.members()[0].canonical_path, "mission");
    assert_eq!(ir.members()[0].kind, MemberKind::Directory);
    assert_eq!(ir.members()[1].canonical_path, "mission/empty.txt");
    assert_eq!(ir.members()[1].kind, MemberKind::File);
    assert_eq!(ir.members()[1].actual_uncomp_size, Some(0));
    assert_eq!(ir.members()[2].canonical_path, "mission/plan.txt");
    assert_eq!(ir.members()[3].canonical_path, "mission/telemetry.log");
    assert_eq!(ir.members()[3].actual_uncomp_size, Some(43));
}

#[test]
fn container_and_language_fail_closed() {
    let member = decode_hex(SEVENZ_CLI_FILEONLY_HEX);
    let policy = Policy::default_v11();

    let non_sevenz = inspect(
        b"not a 7z archive at all, longer than a header",
        &policy,
        &options(),
    );
    assert!(matches!(
        non_sevenz.interpretation,
        InterpretationStatus::Malformed
    ));
    assert_eq!(non_sevenz.view.source.magic, "unknown");

    let encoded = decode_hex(SEVENZ_CLI_ENCODED_HEADER_HEX);
    let outcome = inspect(&encoded, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Unsupported
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::FormatUnsupported
            && finding.detail.contains("mhc=off")));

    let mut start_crc = member.clone();
    start_crc[8] ^= 0x01;
    let outcome = inspect(&start_crc, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Malformed
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::CrcMismatch));

    let mut trailing = member.clone();
    trailing.push(0x00);
    let outcome = inspect(&trailing, &policy, &options());
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Malformed
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::SevenZInvalidStructure));

    // A payload byte flip breaks the declared substream CRC at member
    // verification, after a structurally valid parse.
    let mut payload_lie = member.clone();
    payload_lie[32] ^= 0x01;
    let outcome = inspect(&payload_lie, &policy, &options());
    assert!(!matches!(outcome.admission, AdmissionStatus::Admitted));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::CrcMismatch));

    // A backslash smuggled into the UTF-16 name is rejected by the path jail.
    let mut backslash = member.clone();
    let name_offset = backslash
        .windows(4)
        .position(|window| window == b"\x2f\x00\x70\x00")
        .expect("the fixture name contains a forward slash");
    backslash[name_offset] = b'\\';
    repair_header_crcs(&mut backslash, 57);
    let outcome = inspect(&backslash, &policy, &options());
    assert!(!matches!(outcome.admission, AdmissionStatus::Admitted));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::PathInvalidChar));

    let mut files_cap = Policy::default_v11();
    files_cap.max_files = 0;
    let denied = inspect(&member, &files_cap, &options());
    assert!(matches!(
        denied.interpretation,
        InterpretationStatus::Interpreted
    ));
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaFiles));

    let mut metadata = Policy::default_v11();
    metadata.max_metadata_bytes = 40;
    let denied = inspect(&member, &metadata, &options());
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaMetadata));

    let mut member_cap = Policy::default_v11();
    member_cap.max_member_bytes = 24;
    let denied = inspect(&member, &member_cap, &options());
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaMember));

    let mut source_cap = Policy::default_v11();
    source_cap.max_archive_bytes = (member.len() - 1) as u64;
    let denied = inspect(&member, &source_cap, &options());
    assert!(matches!(denied.admission, AdmissionStatus::Denied));
    assert!(denied
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::QuotaArchive));
}

#[test]
fn policy_and_format_selection_do_not_alias_other_profiles() {
    let member = decode_hex(SEVENZ_CLI_FILEONLY_HEX);

    let older = inspect(&member, &Policy::default_v10(), &options());
    assert!(!matches!(older.admission, AdmissionStatus::Admitted));
    assert!(older
        .view
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::PolicyUnsupported));

    let zip_selection = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.7z"),
                data: &member,
            },
            policy: &Policy::default_v11(),
            dest: None,
        },
        &ApplyOptions::new(),
    );
    assert!(!matches!(
        zip_selection.admission,
        AdmissionStatus::Admitted
    ));

    let tar_selection = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.7z"),
                data: &member,
            },
            policy: &Policy::default_v11(),
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_interpretation_profile(TarInterpretationProfile::UstarPortableV1),
    );
    assert!(!matches!(
        tar_selection.admission,
        AdmissionStatus::Admitted
    ));

    let tar = ustar("mission/plan.txt", b"verify twice, decode once");
    let sevenz_over_tar = inspect(&tar, &Policy::default_v11(), &options());
    assert!(!matches!(
        sevenz_over_tar.admission,
        AdmissionStatus::Admitted
    ));
}

#[test]
fn committed_tree_v12_manifest_matches_the_public_production_path() {
    let manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/sevenz-copy-identity-v1.json")).unwrap();
    assert_eq!(manifest["schema"], "sealr.7z-copy-identity-conformance.v1");
    assert_eq!(
        manifest["profile"]["digest"]["sha256"],
        sevenz_copy_portable_v1_digest()
    );
    assert_eq!(manifest["layout_encoding"], "sealrTreeV12");
    assert_eq!(manifest["layout_label"], "sealr.tree.layout.7z-copy.v1");
    assert_eq!(
        manifest["cross_container_content_root"]["sealrTreeV1"],
        "bc8f6d6f7870aeab647cff08db25471a729bd2a41e095d49d6254c49afc34278"
    );

    let policy = Policy::default_v11();
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
        assert_eq!(
            serde_json::to_value(outcome.archive_ir().unwrap()).unwrap(),
            case["archive_ir"],
            "case {}",
            case["id"]
        );
    }
}
