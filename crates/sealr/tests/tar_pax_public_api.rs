use std::path::PathBuf;

use sealr::{
    apply, apply_with_options, encode_tar_layout, encode_tar_pax_layout,
    tar_pax_portable_v1_digest, tar_ustar_portable_v1_digest, AdmissionStatus, ApplyOptions,
    ArchiveFormat, ByteRange, EffectStatus, FindingCode, InterpretationStatus, PaxExtensionKind,
    PaxKeyword, PaxValueSource, Policy, Request, RetentionPlan, Source, TarInterpretationProfile,
    TarPaxInterpretationProfile, TreeRoot, VerificationStatus, TAR_ARCHIVE_IR_SCHEMA,
    TAR_PAX_ARCHIVE_IR_SCHEMA, TAR_PAX_PORTABLE_V1, TAR_USTAR_PORTABLE_V1,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PaxProducerManifest {
    schema: String,
    fixtures: Vec<PaxProducerFixture>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PaxProducerFixture {
    id: String,
    producer: String,
    command: String,
    member_path: String,
    member_content_hex: String,
    base_name_hex: String,
    carrier_name_hex: String,
    records: Vec<PaxProducerRecord>,
    size_source: String,
    len: usize,
    source_sha256: String,
    layout_sha256: String,
    content_sha256: String,
    spans: Vec<PaxProducerSpan>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PaxProducerRecord {
    keyword: String,
    value: String,
    parsed_size: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PaxProducerSpan {
    offset: usize,
    hex: String,
}

fn reconstruct_pax_fixture(fixture: &PaxProducerFixture) -> Vec<u8> {
    let mut source = vec![0_u8; fixture.len];
    let mut previous_end = 0;
    for span in &fixture.spans {
        let bytes = decode_hex(&span.hex);
        let end = span.offset.checked_add(bytes.len()).unwrap();
        assert!(span.offset >= previous_end, "fixture spans must be ordered");
        assert!(end <= source.len(), "fixture span exceeds source length");
        assert!(
            bytes.iter().all(|byte| *byte != 0),
            "sparse fixture spans may contain only nonzero bytes"
        );
        source[span.offset..end].copy_from_slice(&bytes);
        previous_end = end;
    }
    source
}

fn write_octal(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let octal = format!("{value:o}");
    let digits = field.len() - 1;
    field[digits - octal.len()..digits].copy_from_slice(octal.as_bytes());
    field[digits] = 0;
}

fn header(name: &[u8], size: u64, typeflag: u8) -> [u8; 512] {
    assert!(name.len() <= 100);
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

fn decode_hex(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(
        remainder.is_empty(),
        "hex input must contain complete byte pairs"
    );
    pairs
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
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

fn ordinary_ustar(name: &str, content: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_record(
        &mut bytes,
        header(name.as_bytes(), content.len() as u64, b'0'),
        content,
    );
    finish(bytes)
}

fn local_path_and_size(path: &str, base_size: u64, content: &[u8]) -> Vec<u8> {
    let payload = [
        record("path", path),
        record("size", &content.len().to_string()),
    ]
    .concat();
    let mut bytes = Vec::new();
    append_record(
        &mut bytes,
        header(b"../../metadata-only-carrier", payload.len() as u64, b'x'),
        &payload,
    );
    append_record(&mut bytes, header(b"placeholder", base_size, b'0'), content);
    finish(bytes)
}

fn pax_options() -> ApplyOptions {
    ApplyOptions::new().with_tar_pax_interpretation_profile(TarPaxInterpretationProfile::PortableV1)
}

fn apply_pax<'a>(bytes: &'a [u8], policy: &'a Policy) -> sealr::Outcome {
    apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("fixture.pax.tar"),
                data: bytes,
            },
            policy,
            dest: None,
        },
        &pax_options(),
    )
}

#[test]
fn controlled_major_producers_share_the_restricted_pax_meaning() {
    let manifest: PaxProducerManifest =
        serde_json::from_slice(include_bytes!("conformance/tar-pax-producers-v1.json")).unwrap();
    assert_eq!(manifest.schema, "sealr.tar-pax-producer-fixtures.v1");
    assert_eq!(
        manifest
            .fixtures
            .iter()
            .map(|fixture| fixture.id.as_str())
            .collect::<Vec<_>>(),
        [
            "gnu-tar-1.35",
            "libarchive-paxr-3.8.4",
            "python-tarfile-3.12.10"
        ]
    );

    let policy = Policy::default_v5();
    for fixture in &manifest.fixtures {
        assert!(!fixture.producer.is_empty());
        assert!(!fixture.command.is_empty());
        assert!(!fixture.records.is_empty());
        let source = reconstruct_pax_fixture(fixture);
        assert_eq!(sealr::hex_sha256(&source), fixture.source_sha256);

        let outcome = apply_pax(&source, &policy);
        assert!(
            matches!(outcome.admission, AdmissionStatus::Admitted),
            "{}: {:?}",
            fixture.id,
            outcome.view.findings
        );
        assert!(matches!(outcome.verification, VerificationStatus::Complete));
        assert_eq!(
            outcome.receipt.identities.layout.hex(),
            Some(fixture.layout_sha256.as_str())
        );
        assert_eq!(
            outcome.receipt.identities.content.hex(),
            Some(fixture.content_sha256.as_str())
        );

        let ir = outcome.archive_ir().unwrap();
        let extensions = ir.pax_extensions().unwrap();
        assert_eq!(extensions.len(), 1, "{}", fixture.id);
        let extension = &extensions[0];
        assert_eq!(extension.kind, PaxExtensionKind::Local);
        assert_eq!(
            extension.raw_name_bytes,
            decode_hex(&fixture.carrier_name_hex)
        );
        assert_eq!(extension.records.len(), fixture.records.len());
        for (actual, expected) in extension.records.iter().zip(&fixture.records) {
            assert_eq!(
                actual.keyword,
                match expected.keyword.as_str() {
                    "path" => PaxKeyword::Path,
                    "size" => PaxKeyword::Size,
                    keyword => panic!("unexpected fixture keyword {keyword}"),
                }
            );
            assert_eq!(actual.raw_value_bytes, expected.value.as_bytes());
            assert_eq!(actual.parsed_size, expected.parsed_size);
            assert_eq!(
                &source[actual.value.offset as usize
                    ..(actual.value.offset + actual.value.len) as usize],
                expected.value.as_bytes()
            );
        }

        let member = &ir.members()[0];
        assert_eq!(member.canonical_path, fixture.member_path);
        let evidence = member.tar_pax_evidence().unwrap();
        assert_eq!(evidence.base_name_bytes, decode_hex(&fixture.base_name_hex));
        assert_eq!(
            evidence.path_source,
            PaxValueSource::Local {
                extension_index: 0,
                record_index: 0,
            }
        );
        assert_eq!(
            evidence.size_source,
            match fixture.size_source.as_str() {
                "ustar" => PaxValueSource::Ustar,
                "local:0:1" => PaxValueSource::Local {
                    extension_index: 0,
                    record_index: 1,
                },
                source => panic!("unexpected fixture size source {source}"),
            }
        );
        assert_eq!(
            member.declared_uncomp_size,
            decode_hex(&fixture.member_content_hex).len() as u64
        );
        assert_eq!(
            outcome
                .verified_archive()
                .unwrap()
                .read_member(&fixture.member_path, fixture.len as u64)
                .unwrap(),
            decode_hex(&fixture.member_content_hex)
        );
    }
}

#[test]
fn explicit_pax_selection_exposes_exact_local_override_evidence_and_verified_reads() {
    let path_record = record("path", "mission/on-mars.txt");
    let size_record = record("size", "4");
    let extension_payload_len = path_record.len() + size_record.len();
    let bytes = local_path_and_size("mission/on-mars.txt", 9, b"mars");
    let retention = RetentionPlan::new(1024, 1024)
        .with_path("mission/on-mars.txt")
        .unwrap();
    let options = pax_options().with_retention(retention);
    assert_eq!(options.archive_format(), ArchiveFormat::TarPax);
    assert_eq!(
        options.tar_pax_interpretation_profile(),
        Some(TarPaxInterpretationProfile::PortableV1)
    );
    assert!(options.tar_interpretation_profile().is_none());
    assert!(options.zip_interpretation_profile().is_none());

    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.pax.tar"),
                data: &bytes,
            },
            policy: &Policy::default_v5(),
            dest: None,
        },
        &options,
    );

    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Interpreted
    ));
    assert!(matches!(outcome.admission, AdmissionStatus::Admitted));
    assert!(matches!(outcome.verification, VerificationStatus::Complete));
    assert!(matches!(outcome.effect, EffectStatus::NotRequested));
    assert!(matches!(
        outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV5 { .. }
    ));
    assert!(matches!(
        outcome.receipt.identities.content,
        TreeRoot::SealrTreeV1 { .. }
    ));

    let ir = outcome.archive_ir().unwrap();
    assert_eq!(ir.schema(), TAR_PAX_ARCHIVE_IR_SCHEMA);
    assert_eq!(ir.profile(), TAR_PAX_PORTABLE_V1);
    assert_eq!(ir.profile_digest(), tar_pax_portable_v1_digest());
    assert_eq!(ir.format(), ArchiveFormat::TarPax);
    assert!(ir.zip_covering().is_none());
    assert!(ir.gzip_evidence().is_none());
    assert!(encode_tar_layout(ir).is_none());
    assert!(encode_tar_pax_layout(ir).is_some());

    let covering = ir.tar_covering().unwrap();
    assert_eq!(
        covering.member_records,
        ByteRange {
            offset: 0,
            len: 2048
        }
    );
    assert_eq!(
        covering.terminator,
        ByteRange {
            offset: 2048,
            len: 1024
        }
    );
    assert_eq!(
        covering.trailing_zeros,
        ByteRange {
            offset: 3072,
            len: 0
        }
    );

    let extensions = ir.pax_extensions().unwrap();
    assert_eq!(extensions.len(), 1);
    let extension = &extensions[0];
    assert_eq!(extension.kind, PaxExtensionKind::Local);
    assert_eq!(extension.raw_name_bytes, b"../../metadata-only-carrier");
    assert_eq!(
        extension.header,
        ByteRange {
            offset: 0,
            len: 512
        }
    );
    assert_eq!(
        extension.payload,
        ByteRange {
            offset: 512,
            len: extension_payload_len as u64,
        }
    );
    assert_eq!(
        extension.padding,
        ByteRange {
            offset: 512 + extension_payload_len as u64,
            len: 512 - extension_payload_len as u64,
        }
    );
    assert_eq!(extension.records.len(), 2);
    assert_eq!(extension.records[0].keyword, PaxKeyword::Path);
    assert_eq!(extension.records[0].raw_value_bytes, b"mission/on-mars.txt");
    assert_eq!(
        extension.records[0].record,
        ByteRange {
            offset: 512,
            len: path_record.len() as u64,
        }
    );
    let path_value_offset = path_record
        .windows(b"mission/on-mars.txt".len())
        .position(|window| window == b"mission/on-mars.txt")
        .unwrap();
    assert_eq!(
        extension.records[0].value,
        ByteRange {
            offset: 512 + path_value_offset as u64,
            len: b"mission/on-mars.txt".len() as u64,
        }
    );
    assert_eq!(extension.records[0].parsed_size, None);
    assert_eq!(extension.records[1].keyword, PaxKeyword::Size);
    assert_eq!(extension.records[1].raw_value_bytes, b"4");
    assert_eq!(extension.records[1].parsed_size, Some(4));
    assert_eq!(
        extension.records[1].record,
        ByteRange {
            offset: 512 + path_record.len() as u64,
            len: size_record.len() as u64,
        }
    );

    let member = &ir.members()[0];
    assert_eq!(member.canonical_path, "mission/on-mars.txt");
    assert_eq!(member.raw_name_bytes, b"mission/on-mars.txt");
    assert_eq!(member.declared_uncomp_size, 4);
    assert_eq!(member.format(), ArchiveFormat::TarPax);
    assert!(member.zip_evidence().is_none());
    let evidence = member.tar_pax_evidence().unwrap();
    assert_eq!(evidence.base_name_bytes, b"placeholder");
    assert_eq!(evidence.base_size, 9);
    assert_eq!(
        evidence.path_source,
        PaxValueSource::Local {
            extension_index: 0,
            record_index: 0,
        }
    );
    assert_eq!(
        evidence.size_source,
        PaxValueSource::Local {
            extension_index: 0,
            record_index: 1,
        }
    );
    assert_eq!(
        evidence.tar.header,
        ByteRange {
            offset: 1024,
            len: 512
        }
    );
    assert_eq!(
        evidence.tar.payload,
        ByteRange {
            offset: 1536,
            len: 4
        }
    );
    assert_eq!(
        evidence.tar.padding,
        ByteRange {
            offset: 1540,
            len: 508
        }
    );

    let verified = outcome.verified_archive().unwrap();
    assert_eq!(
        verified.retained_member("mission/on-mars.txt"),
        Some(b"mars".as_slice())
    );
    assert_eq!(
        verified.read_member("mission/on-mars.txt", 4).unwrap(),
        b"mars"
    );
}

#[test]
fn global_values_persist_while_local_path_wins_for_exactly_one_member() {
    let global = [record("path", "global.txt"), record("size", "1")].concat();
    let local = record("path", "local.txt");
    let mut bytes = Vec::new();
    append_record(
        &mut bytes,
        header(b"global-carrier", global.len() as u64, b'g'),
        &global,
    );
    append_record(
        &mut bytes,
        header(b"local-carrier", local.len() as u64, b'x'),
        &local,
    );
    append_record(&mut bytes, header(b"first-base", 9, b'0'), b"a");
    append_record(&mut bytes, header(b"second-base", 9, b'0'), b"b");
    let bytes = finish(bytes);

    let policy = Policy::default_v5();
    let outcome = apply_pax(&bytes, &policy);
    assert!(matches!(outcome.admission, AdmissionStatus::Admitted));
    let ir = outcome.archive_ir().unwrap();
    assert_eq!(ir.members().len(), 2);
    assert_eq!(ir.pax_extensions().unwrap().len(), 2);

    let local_member = &ir.members()[0];
    assert_eq!(local_member.canonical_path, "local.txt");
    let local_evidence = local_member.tar_pax_evidence().unwrap();
    assert_eq!(
        local_evidence.path_source,
        PaxValueSource::Local {
            extension_index: 1,
            record_index: 0,
        }
    );
    assert_eq!(
        local_evidence.size_source,
        PaxValueSource::Global {
            extension_index: 0,
            record_index: 1,
        }
    );
    assert_eq!(local_evidence.base_name_bytes, b"first-base");
    assert_eq!(local_evidence.base_size, 9);

    let global_member = &ir.members()[1];
    assert_eq!(global_member.canonical_path, "global.txt");
    let global_evidence = global_member.tar_pax_evidence().unwrap();
    assert_eq!(
        global_evidence.path_source,
        PaxValueSource::Global {
            extension_index: 0,
            record_index: 0,
        }
    );
    assert_eq!(
        global_evidence.size_source,
        PaxValueSource::Global {
            extension_index: 0,
            record_index: 1,
        }
    );
    let verified = outcome.verified_archive().unwrap();
    assert_eq!(verified.read_member("local.txt", 1).unwrap(), b"a");
    assert_eq!(verified.read_member("global.txt", 1).unwrap(), b"b");
}

#[test]
fn no_extension_ustar_subset_keeps_content_identity_but_not_profile_or_layout_identity() {
    let bytes = ordinary_ustar("subset.txt", b"same semantic file");
    let policy = Policy::default_v5();
    let pax = apply_pax(&bytes, &policy);
    let ustar = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("subset.tar"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        },
        &ApplyOptions::new()
            .with_tar_interpretation_profile(TarInterpretationProfile::UstarPortableV1),
    );
    assert!(matches!(pax.admission, AdmissionStatus::Admitted));
    assert!(matches!(ustar.admission, AdmissionStatus::Admitted));

    let pax_ir = pax.archive_ir().unwrap();
    let ustar_ir = ustar.archive_ir().unwrap();
    assert_eq!(pax_ir.schema(), TAR_PAX_ARCHIVE_IR_SCHEMA);
    assert_eq!(pax_ir.profile(), TAR_PAX_PORTABLE_V1);
    assert_eq!(pax_ir.format(), ArchiveFormat::TarPax);
    assert!(pax_ir.pax_extensions().unwrap().is_empty());
    assert_eq!(ustar_ir.schema(), TAR_ARCHIVE_IR_SCHEMA);
    assert_eq!(ustar_ir.profile(), TAR_USTAR_PORTABLE_V1);
    assert_eq!(ustar_ir.format(), ArchiveFormat::TarUstar);
    assert_ne!(tar_pax_portable_v1_digest(), tar_ustar_portable_v1_digest());
    assert_ne!(pax_ir.profile_digest(), ustar_ir.profile_digest());
    assert!(matches!(
        pax_ir.members()[0].tar_pax_evidence().unwrap().path_source,
        PaxValueSource::Ustar
    ));
    assert!(matches!(
        pax_ir.members()[0].tar_pax_evidence().unwrap().size_source,
        PaxValueSource::Ustar
    ));
    assert!(matches!(
        pax.receipt.identities.layout,
        TreeRoot::SealrTreeV5 { .. }
    ));
    assert!(matches!(
        ustar.receipt.identities.layout,
        TreeRoot::SealrTreeV2 { .. }
    ));
    assert_ne!(
        pax.receipt.identities.layout.hex(),
        ustar.receipt.identities.layout.hex()
    );
    assert_eq!(
        pax.receipt.identities.content,
        ustar.receipt.identities.content
    );
    assert!(matches!(
        pax.receipt.identities.content,
        TreeRoot::SealrTreeV1 { .. }
    ));
    assert!(encode_tar_pax_layout(pax_ir).is_some());
    assert!(encode_tar_layout(pax_ir).is_none());
    assert!(encode_tar_layout(ustar_ir).is_some());
    assert!(encode_tar_pax_layout(ustar_ir).is_none());
}

#[test]
fn committed_tree_v5_manifest_matches_the_public_production_path() {
    let manifest: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-pax-identity-v1.json")).unwrap();
    assert_eq!(manifest["schema"], "sealr.tar-pax-identity-conformance.v1");
    assert_eq!(manifest["archive_ir_schema"], TAR_PAX_ARCHIVE_IR_SCHEMA);
    assert_eq!(manifest["layout_encoding"], "sealrTreeV5");
    assert_eq!(manifest["layout_label"], "sealr.tree.layout.tar-pax.v1");
    assert_eq!(manifest["content_encoding"], "sealrTreeV1");
    assert_eq!(manifest["content_label"], "sealr.tree.content.v1");
    assert_eq!(manifest["profile"]["id"], TAR_PAX_PORTABLE_V1);
    assert_eq!(
        manifest["profile"]["digest"]["sha256"],
        tar_pax_portable_v1_digest()
    );

    let cases = manifest["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    assert_eq!(cases[0]["id"], "local-path-size");
    assert_eq!(cases[1]["id"], "global-local-precedence");
    for case in cases {
        let source = decode_hex(case["source_bytes_hex"].as_str().unwrap());
        assert_eq!(sealr::hex_sha256(&source), case["source"]["sha256"]);
        let outcome = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some(case["id"].as_str().unwrap()),
                    data: &source,
                },
                policy: &Policy::default_v5(),
                dest: None,
            },
            &pax_options(),
        );
        assert!(
            matches!(outcome.admission, AdmissionStatus::Admitted),
            "{}: {:?}",
            case["id"],
            outcome.view.findings
        );
        assert!(matches!(outcome.verification, VerificationStatus::Complete));
        assert_eq!(
            serde_json::to_value(outcome.archive_ir().unwrap()).unwrap(),
            case["archive_ir"]
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
            sealr::encode_tar_pax_layout(outcome.archive_ir().unwrap()).map(|bytes| bytes
                .into_iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()),
            Some(case["layout_preimage_hex"].as_str().unwrap().to_owned())
        );
    }
}

#[test]
fn policy_v4_refuses_pax_before_attempting_source_ingestion() {
    let missing = unique_temp("pax-policy-before-source").join("missing.tar");
    let outcome = apply_with_options(
        Request {
            source: Source::Path(&missing),
            policy: &Policy::default_v4(),
            dest: None,
        },
        &pax_options(),
    );
    assert_eq!(outcome.view.findings.len(), 1);
    assert_eq!(
        outcome.view.findings[0].code,
        FindingCode::PolicyUnsupported
    );
    assert!(outcome.receipt.source.sha256().is_none());
    assert!(outcome.archive_ir().is_none());
}

#[test]
fn malformed_unknown_and_orphan_pax_state_fail_closed_with_specific_findings() {
    let cases = [
        (
            b"013 path=a\n".to_vec(),
            FindingCode::TarPaxRecord,
            InterpretationStatus::Malformed,
        ),
        (
            record("mtime", "0"),
            FindingCode::TarFeatureUnsupported,
            InterpretationStatus::Unsupported,
        ),
    ];
    let policy = Policy::default_v5();
    for (payload, code, interpretation) in cases {
        let mut bytes = Vec::new();
        append_record(
            &mut bytes,
            header(b"local-carrier", payload.len() as u64, b'x'),
            &payload,
        );
        append_record(&mut bytes, header(b"ordinary", 0, b'0'), b"");
        let outcome = apply_pax(&finish(bytes), &policy);
        assert_eq!(outcome.view.findings[0].code, code);
        assert_eq!(outcome.interpretation, interpretation);
        assert!(outcome.archive_ir().is_none());
        assert!(outcome.verified_archive().is_none());
    }

    let orphan = record("path", "orphan.txt");
    let mut bytes = Vec::new();
    append_record(
        &mut bytes,
        header(b"local-carrier", orphan.len() as u64, b'x'),
        &orphan,
    );
    let outcome = apply_pax(&finish(bytes), &policy);
    assert_eq!(outcome.view.findings[0].code, FindingCode::TarPaxState);
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Malformed
    ));
    assert!(outcome.archive_ir().is_none());
}

#[test]
fn archive_selection_never_guesses_or_falls_back_between_pax_and_zip() {
    let bytes = local_path_and_size("selected.txt", 0, b"");
    let policy = Policy::default_v5();
    let zip_selected = apply(Request {
        source: Source::Bytes {
            path: Some("selected.pax.tar"),
            data: &bytes,
        },
        policy: &policy,
        dest: None,
    });
    assert!(!matches!(zip_selected.admission, AdmissionStatus::Admitted));
    assert!(zip_selected.archive_ir().is_none());

    let not_tar = b"PK\x03\x04this is deliberately not a pax archive";
    let pax_selected = apply_pax(not_tar, &policy);
    assert!(!matches!(pax_selected.admission, AdmissionStatus::Admitted));
    assert!(pax_selected.archive_ir().is_none());
    assert!(pax_selected.verified_archive().is_none());
}

#[cfg(any(windows, target_os = "linux"))]
#[test]
fn pax_materializes_effective_paths_through_the_portable_atomic_core() {
    let bytes = local_path_and_size("mission/status.txt", 99, b"nominal");
    let root = unique_temp("pax-materialize");
    std::fs::create_dir(&root).unwrap();
    let destination = root.join("result");
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.pax.tar"),
                data: &bytes,
            },
            policy: &Policy::default_v5(),
            dest: Some(&destination),
        },
        &pax_options(),
    );
    assert!(matches!(outcome.effect, EffectStatus::Committed));
    assert!(outcome.wrote());
    assert_eq!(
        std::fs::read(destination.join("mission/status.txt")).unwrap(),
        b"nominal"
    );
    assert_eq!(
        outcome.archive_ir().unwrap().members()[0]
            .tar_pax_evidence()
            .unwrap()
            .base_name_bytes,
        b"placeholder"
    );
    std::fs::remove_dir_all(root).unwrap();
}

fn unique_temp(label: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("sealr-{label}-{}-{nonce}", std::process::id()))
}
