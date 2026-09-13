use std::fs;
use std::path::PathBuf;

use sealr::{
    apply, apply_with_options, tar_ustar_portable_v1_canonical_bytes, tar_ustar_portable_v1_digest,
    AdmissionStatus, ApplyOptions, ArchiveFormat, FindingCode, InterpretationStatus, MemberKind,
    Policy, Request, RetentionPlan, Source, TarInterpretationProfile, TreeRoot, VerificationStatus,
    TAR_ARCHIVE_IR_SCHEMA, TAR_USTAR_PORTABLE_V1,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerManifest {
    schema: String,
    fixtures: Vec<ProducerFixture>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerFixture {
    id: String,
    producer: String,
    command: String,
    member_path: String,
    member_content_hex: String,
    len: usize,
    source_sha256: String,
    layout_sha256: String,
    content_sha256: String,
    spans: Vec<ProducerSpan>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerSpan {
    offset: usize,
    hex: String,
}

fn decode_hex(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "hex input must have an even length");
    pairs
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn reconstruct_fixture(fixture: &ProducerFixture) -> Vec<u8> {
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

struct Entry<'a> {
    name: &'a str,
    body: &'a [u8],
    typeflag: u8,
}

fn write_octal(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let octal = format!("{value:o}");
    let digits = field.len() - 1;
    field[digits - octal.len()..digits].copy_from_slice(octal.as_bytes());
    field[digits] = 0;
}

fn header(entry: &Entry<'_>) -> [u8; 512] {
    let mut header = [0_u8; 512];
    header[..entry.name.len()].copy_from_slice(entry.name.as_bytes());
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], entry.body.len() as u64);
    write_octal(&mut header[136..148], 1_788_000_000);
    header[148..156].fill(b' ');
    header[156] = entry.typeflag;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[265..269].copy_from_slice(b"root");
    header[297..301].copy_from_slice(b"root");
    write_octal(&mut header[329..337], 0);
    write_octal(&mut header[337..345], 0);
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    let encoded = format!("{checksum:06o}");
    header[148..154].copy_from_slice(encoded.as_bytes());
    header[154] = 0;
    header[155] = b' ';
    header
}

fn ustar(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend_from_slice(&header(entry));
        bytes.extend_from_slice(entry.body);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
    }
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

fn options() -> ApplyOptions {
    ApplyOptions::new().with_tar_interpretation_profile(TarInterpretationProfile::UstarPortableV1)
}

#[test]
fn portable_ustar_profile_identity_is_pinned() {
    let bytes = tar_ustar_portable_v1_canonical_bytes();
    let vector = include_bytes!("conformance/tar-ustar-portable-v1.json");
    assert_eq!(&bytes, &vector[..vector.len() - 1]);
    assert_eq!(
        tar_ustar_portable_v1_digest(),
        "3c87c5ec4c1ad5377eb60ebb308e9e394aaf7a4133dddf5587829b4510af1700"
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["schema"],
        TAR_USTAR_PORTABLE_V1
    );
}

#[test]
fn independent_major_producers_share_the_portable_ustar_meaning() {
    let manifest: ProducerManifest =
        serde_json::from_slice(include_bytes!("conformance/tar-producers-v1.json")).unwrap();
    assert_eq!(manifest.schema, "sealr.tar-producer-fixtures.v1");
    assert_eq!(
        manifest
            .fixtures
            .iter()
            .map(|fixture| fixture.id.as_str())
            .collect::<Vec<_>>(),
        ["gnu-tar-1.35", "bsdtar-3.8.4", "python-tarfile-3.12.10"]
    );

    let policy = Policy::default_v2();
    for fixture in &manifest.fixtures {
        assert!(!fixture.producer.is_empty());
        assert!(!fixture.command.is_empty());
        let source = reconstruct_fixture(fixture);
        assert_eq!(sealr::hex_sha256(&source), fixture.source_sha256);
        let outcome = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some(&fixture.id),
                    data: &source,
                },
                policy: &policy,
                dest: None,
            },
            &options(),
        );

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
        assert_eq!(
            outcome
                .verified_archive()
                .unwrap()
                .read_member(&fixture.member_path, fixture.len.try_into().unwrap())
                .unwrap(),
            decode_hex(&fixture.member_content_hex)
        );
    }
}

#[test]
fn explicit_tar_profile_inspects_retains_and_rereads_without_a_second_parser() {
    let bytes = ustar(&[
        Entry {
            name: "mission/",
            body: b"",
            typeflag: b'5',
        },
        Entry {
            name: "mission/plan.txt",
            body: b"verify twice, interpret once",
            typeflag: b'0',
        },
        Entry {
            name: "mission/telemetry.bin",
            body: b"1234",
            typeflag: b'0',
        },
    ]);
    let policy = Policy::default_v2();
    let retention = RetentionPlan::new(1024, 1024)
        .with_path("mission/plan.txt")
        .unwrap();
    let options = options().with_retention(retention);
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        },
        &options,
    );

    assert!(matches!(outcome.admission, AdmissionStatus::Admitted));
    assert!(matches!(outcome.verification, VerificationStatus::Complete));
    let ir = outcome.archive_ir().unwrap();
    assert_eq!(ir.schema(), TAR_ARCHIVE_IR_SCHEMA);
    assert_eq!(ir.profile(), TAR_USTAR_PORTABLE_V1);
    assert_eq!(ir.format(), ArchiveFormat::TarUstar);
    assert!(ir.zip_covering().is_none());
    assert_eq!(ir.members().len(), 3);
    assert!(ir.tar_covering().is_some());
    assert!(ir.members().iter().all(|member| {
        member.tar_evidence().is_some()
            && member.zip_evidence().is_none()
            && member.container_facts().is_none()
    }));
    assert!(matches!(
        outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV2 { .. }
    ));
    assert_eq!(
        outcome.receipt.source.sha256(),
        Some("b148fa5258ac850f4dfe50276104aaa7112b2f0fbb6017488d24335bf33a7c49")
    );
    assert_eq!(
        outcome.receipt.identities.layout.hex(),
        Some("9802357e809cbd54eb0424d716ee1f16830e4b4d75ec6c45fbed3c17758eb70d")
    );
    assert_eq!(
        outcome.receipt.identities.content.hex(),
        Some("49cce4ddb7c115bb182269a766dbe8942686303a39a57b4208120eb91104857c")
    );
    let vector: serde_json::Value =
        serde_json::from_slice(include_bytes!("conformance/tar-layout-v2.json")).unwrap();
    let serialized_ir = serde_json::to_value(ir).unwrap();
    assert!(serialized_ir.get("covering").is_none());
    assert_eq!(serialized_ir["tar_covering"], vector["covering"]);
    assert_eq!(
        vector["source"]["sha256"],
        outcome.receipt.source.sha256().unwrap()
    );
    assert_eq!(
        vector["layout_root"]["sealrTreeV2"],
        outcome.receipt.identities.layout.hex().unwrap()
    );
    assert_eq!(
        vector["content_root"]["sealrTreeV1"],
        outcome.receipt.identities.content.hex().unwrap()
    );
    for (actual, expected) in serialized_ir["members"]
        .as_array()
        .unwrap()
        .iter()
        .zip(vector["members"].as_array().unwrap())
    {
        for field in [
            "canonical_path",
            "kind",
            "raw_name_bytes",
            "declared_uncomp_size",
            "actual_uncomp_size",
            "content_sha256",
            "normalization_actions",
        ] {
            assert_eq!(actual[field], expected[field], "member field {field}");
        }
        for field in [
            "header",
            "payload",
            "padding",
            "mode",
            "mtime",
            "header_checksum",
            "header_sha256",
        ] {
            assert_eq!(actual["tar"][field], expected[field], "TAR field {field}");
        }
        for zip_field in [
            "method",
            "flags",
            "declared_crc",
            "declared_comp_size",
            "source_ranges",
            "extra_fields",
        ] {
            assert!(
                actual.get(zip_field).is_none(),
                "TAR member exposed ZIP field {zip_field}"
            );
        }
    }
    assert!(ir
        .members()
        .iter()
        .all(|member| member.format() == ArchiveFormat::TarUstar));

    let verified = outcome.verified_archive().unwrap();
    assert_eq!(
        verified.retained_member("mission/plan.txt"),
        Some(b"verify twice, interpret once".as_slice())
    );
    assert_eq!(
        verified.read_member("mission/plan.txt", 1024).unwrap(),
        b"verify twice, interpret once"
    );
    assert_eq!(
        verified.read_member("mission/telemetry.bin", 4).unwrap(),
        b"1234"
    );
}

#[test]
fn default_zip_profile_does_not_guess_tar() {
    let bytes = ustar(&[Entry {
        name: "file.txt",
        body: b"content",
        typeflag: b'0',
    }]);
    let policy = Policy::default_v1();
    let outcome = apply(Request {
        source: Source::Bytes {
            path: Some("file.tar"),
            data: &bytes,
        },
        policy: &policy,
        dest: None,
    });
    assert!(!matches!(outcome.admission, AdmissionStatus::Admitted));
    assert!(outcome.archive_ir().is_none());
}

#[test]
fn portable_tar_requires_an_authorizing_policy_before_source_ingestion() {
    let missing = unique_temp("policy-before-source").join("missing.tar");
    let policy = Policy::default_v1();
    let outcome = apply_with_options(
        Request {
            source: Source::Path(&missing),
            policy: &policy,
            dest: None,
        },
        &options(),
    );
    assert_eq!(outcome.view.findings.len(), 1);
    assert_eq!(
        outcome.view.findings[0].code,
        FindingCode::PolicyUnsupported
    );
    assert!(outcome.receipt.source.sha256().is_none());
}

#[test]
fn selected_tar_does_not_claim_unrecognized_bytes_as_observed_tar() {
    let bytes = vec![b'x'; 1024];
    let policy = Policy::default_v2();
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("not-tar.bin"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        },
        &options(),
    );
    assert_eq!(outcome.view.findings[0].code, FindingCode::TarDialect);
    assert_eq!(outcome.view.source.magic, "unknown");
}

#[test]
fn recognized_but_unsupported_tar_feature_is_not_reported_as_malformed() {
    let bytes = ustar(&[Entry {
        name: "pax-header",
        body: b"",
        typeflag: b'x',
    }]);
    let policy = Policy::default_v2();
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("pax.tar"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        },
        &options(),
    );
    assert_eq!(
        outcome.view.findings[0].code,
        FindingCode::TarFeatureUnsupported
    );
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Unsupported
    ));
    assert_eq!(outcome.view.source.magic, "tar");
}

#[test]
fn unknown_typeflags_are_malformed_not_supported_extensions() {
    for typeflag in [b'Z', 0xff] {
        let bytes = ustar(&[Entry {
            name: "unknown",
            body: b"",
            typeflag,
        }]);
        let policy = Policy::default_v2();
        let outcome = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("unknown-type.tar"),
                    data: &bytes,
                },
                policy: &policy,
                dest: None,
            },
            &options(),
        );
        assert!(matches!(
            outcome.interpretation,
            InterpretationStatus::Malformed
        ));
        assert!(matches!(outcome.admission, AdmissionStatus::NotEvaluated));
        assert_eq!(outcome.view.findings[0].code, FindingCode::TarType);
    }
}

#[test]
fn malformed_header_precedes_quota_denial_on_the_public_surface() {
    let mut bytes = ustar(&[Entry {
        name: "file",
        body: b"",
        typeflag: b'0',
    }]);
    bytes[257] = b'X';
    bytes[148..156].fill(b' ');
    let checksum: u32 = bytes[..512].iter().map(|byte| u32::from(*byte)).sum();
    bytes[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
    bytes[154] = 0;
    bytes[155] = b' ';

    for mutate in [
        |policy: &mut Policy| policy.max_files = 0,
        |policy: &mut Policy| policy.max_metadata_bytes = 511,
    ] {
        let mut policy = Policy::default_v2();
        mutate(&mut policy);
        let outcome = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("malformed-before-quota.tar"),
                    data: &bytes,
                },
                policy: &policy,
                dest: None,
            },
            &options(),
        );
        assert!(matches!(
            outcome.interpretation,
            InterpretationStatus::Malformed
        ));
        assert!(matches!(outcome.admission, AdmissionStatus::NotEvaluated));
        assert_eq!(outcome.view.findings[0].code, FindingCode::TarDialect);
    }
}

#[test]
fn portable_tar_profile_denies_traversal_before_verification() {
    let bytes = ustar(&[Entry {
        name: "../escape",
        body: b"denied",
        typeflag: b'0',
    }]);
    let policy = Policy::default_v2();
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: None,
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        },
        &options(),
    );
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code == sealr::FindingCode::PathDotDot));
    assert!(outcome.verified_archive().is_none());
}

#[test]
fn portable_tar_materializes_through_the_shared_atomic_core() {
    let bytes = ustar(&[
        Entry {
            name: "mission/",
            body: b"",
            typeflag: b'5',
        },
        Entry {
            name: "mission/status.txt",
            body: b"nominal",
            typeflag: b'0',
        },
    ]);
    let policy = Policy::default_v2();
    let root = unique_temp("tar-materialize");
    fs::create_dir(&root).unwrap();
    let destination = root.join("result");
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar"),
                data: &bytes,
            },
            policy: &policy,
            dest: Some(&destination),
        },
        &options(),
    );
    assert_eq!(
        fs::read(destination.join("mission/status.txt")).unwrap(),
        b"nominal"
    );
    assert!(matches!(
        outcome.archive_ir().unwrap().members()[0].kind,
        MemberKind::Directory
    ));
    fs::remove_dir_all(root).unwrap();
}

fn unique_temp(label: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("sealr-{label}-{}-{nonce}", std::process::id()))
}
