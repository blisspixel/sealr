use sealr::{
    apply, apply_with_options, AdmissionStatus, ApplyOptions, ArchiveEvidence, ArchiveFormat,
    EffectStatus, FindingCode, InterpretationStatus, MemberEvidence, Policy, Request,
    RetentionPlan, Source, TreeRoot, VerificationStatus, Zip64DataDescriptorWidth,
    Zip64LocalValueShape, ZipInterpretationProfile, ZIP64_ARCHIVE_IR_SCHEMA, ZIP64_STRICT_ASCII_V1,
};

const CPYTHON_SEEK_HEX: &str = concat!(
    "504b03042d0000000800000021000b5704bbffffffffffffffff01001400",
    "6101001000100000000000000005000000000000007374440500504b0102",
    "2d002d0000000800000021000b5704bb0500000010000000010000000000",
    "00000000000080010000000061504b050600000000010001002f00000038",
    "0000000000",
);

const EMPTY_GLOBAL_ZIP64_HEX: &str = "504b06062c000000000000002d002d0000000000000000000000000000000000000000000000000000000000000000000000000000000000504b060700000000000000000000000001000000504b05060000000000000000ffffffff000000000000";

fn decode_hex(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn options() -> ApplyOptions {
    ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::Zip64StrictAsciiV1)
}

#[test]
fn strict_zip64_profile_identity_is_pinned() {
    let bytes = sealr::zip64_strict_ascii_v1_canonical_bytes();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["schema"],
        ZIP64_STRICT_ASCII_V1
    );
    assert_eq!(
        sealr::zip64_strict_ascii_v1_digest(),
        "167a6d226bbe74e88189ec61c61df10ae5ed35c0294ad0cf3b5194d2f0bc23e2"
    );
}

#[test]
fn zip64_identity_conformance_manifest_matches_production() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("conformance/zip64-identity-v1.json")).unwrap();
    assert_eq!(manifest["schema"], "sealr.zip64-identity-conformance.v1");
    assert_eq!(manifest["profile"]["id"], ZIP64_STRICT_ASCII_V1);
    assert_eq!(
        manifest["profile"]["digest"]["sha256"],
        sealr::zip64_strict_ascii_v1_digest()
    );
    assert_eq!(manifest["layout_encoding"], "sealrTreeV3");
    assert_eq!(manifest["layout_label"], "sealr.tree.layout.zip64.v1");

    for case in manifest["cases"].as_array().unwrap() {
        let source = decode_hex(case["source_bytes_hex"].as_str().unwrap());
        let outcome = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: case["id"].as_str(),
                    data: &source,
                },
                policy: &Policy::default_v3(),
                dest: None,
            },
            &options(),
        );
        assert!(
            !outcome.rejected(),
            "{}: {:?}",
            case["id"],
            outcome.view.findings
        );
        let ir = outcome.archive_ir().unwrap();
        assert_eq!(serde_json::to_value(ir).unwrap(), case["archive_ir"]);
        assert_eq!(
            encode_hex(&sealr::encode_zip64_layout(ir).unwrap()),
            case["layout_preimage_hex"].as_str().unwrap()
        );
        assert_eq!(
            serde_json::to_value(&outcome.receipt.identities.layout).unwrap(),
            case["layout_root"]
        );
        assert_eq!(
            serde_json::to_value(&outcome.receipt.identities.content).unwrap(),
            case["content_root"]
        );
    }
}

#[test]
fn strict_zip64_inspects_retains_and_exposes_native_evidence() {
    let source = decode_hex(CPYTHON_SEEK_HEX);
    let retention = RetentionPlan::new(64, 64).with_path("a").unwrap();
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("cpython-seek.zip"),
                data: &source,
            },
            policy: &Policy::default_v3(),
            dest: None,
        },
        &options().with_retention(retention),
    );

    assert!(
        matches!(outcome.admission, AdmissionStatus::Admitted),
        "{:?}",
        outcome.view.findings
    );
    assert!(matches!(outcome.verification, VerificationStatus::Complete));
    let ir = outcome.archive_ir().unwrap();
    assert_eq!(
        encode_hex(&sealr::encode_zip64_layout(ir).unwrap()),
        concat!(
            "7365616c722e747265652e6c61796f75742e7a697036342e76312032303300",
            "0000000000000000380000000000000038000000000000002f0000000000",
            "00000000670000000000000016000000000000007d000000000000000000",
            "000000000000010000000100000061010100000061080000000500000000",
            "00000010000000000000000b5704bb000000000000000033000000000000",
            "00330000000000000005000000000000000038000000000000002f000000",
            "00000000010000000101000223000000000000001000000000002d002d00",
            "0000030101230000000000000010000000000000000000",
        )
    );
    assert_eq!(ir.schema(), ZIP64_ARCHIVE_IR_SCHEMA);
    assert_eq!(ir.profile(), ZIP64_STRICT_ASCII_V1);
    assert_eq!(ir.format(), ArchiveFormat::Zip64);
    assert!(matches!(ir.evidence(), ArchiveEvidence::Zip64(_)));
    assert!(ir.covering().is_none());
    assert!(ir.zip64_covering().is_some());
    assert!(matches!(
        outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV3 { .. }
    ));
    assert!(matches!(
        outcome.receipt.identities.content,
        TreeRoot::SealrTreeV1 { .. }
    ));
    assert_eq!(
        outcome.receipt.identities.layout.hex(),
        Some("c074e18efe379d4c1544380e734fbf09a9185805942e20ad96f72cfe6460e95f")
    );
    assert_eq!(
        outcome.receipt.identities.content.hex(),
        Some("9b878b8f52b46ababb846c3796dbb4cdd3de990a828d5affd183e91f2639ddbd")
    );
    let member = &ir.members()[0];
    assert_eq!(member.format(), ArchiveFormat::Zip64);
    assert!(matches!(member.evidence, MemberEvidence::Zip64(_)));
    let evidence = member.zip64_evidence().unwrap();
    assert_eq!(evidence.local_value_shape, Zip64LocalValueShape::Exact);
    assert_eq!(evidence.central_presence_mask, 0);
    assert_eq!(evidence.descriptor_width, None);
    assert!(evidence.local_zip64_extra.is_some());
    assert!(evidence.central_zip64_extra.is_none());
    assert_eq!(
        outcome
            .verified_archive()
            .unwrap()
            .read_member("a", 16)
            .unwrap(),
        b"AAAAAAAAAAAAAAAA"
    );
}

#[test]
fn zip_and_zip64_selections_do_not_alias() {
    let zip64 = decode_hex(CPYTHON_SEEK_HEX);
    let default_outcome = apply(Request {
        source: Source::Bytes {
            path: None,
            data: &zip64,
        },
        policy: &Policy::default_v1(),
        dest: None,
    });
    assert!(default_outcome.rejected());

    let plain_zip = decode_hex("504b0506000000000000000000000000000000000000");
    let zip64_outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: None,
                data: &plain_zip,
            },
            policy: &Policy::default_v3(),
            dest: None,
        },
        &options(),
    );
    assert!(zip64_outcome.rejected());
    assert!(matches!(
        zip64_outcome.interpretation,
        InterpretationStatus::Unsupported
    ));

    let unauthorized = apply_with_options(
        Request {
            source: Source::Bytes {
                path: None,
                data: &zip64,
            },
            policy: &Policy::default_v2(),
            dest: None,
        },
        &options(),
    );
    assert!(unauthorized.rejected());
    assert!(unauthorized.archive_ir().is_none());
}

#[test]
fn descriptor_width_enum_remains_explicit() {
    assert_ne!(
        Zip64DataDescriptorWidth::Zip32,
        Zip64DataDescriptorWidth::Zip64
    );
}

#[test]
fn empty_global_zip64_magic_is_exact_and_profile_scoped() {
    let source = decode_hex(EMPTY_GLOBAL_ZIP64_HEX);
    let selected = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("empty-global.zip"),
                data: &source,
            },
            policy: &Policy::default_v3(),
            dest: None,
        },
        &options(),
    );
    assert!(!selected.rejected(), "{:?}", selected.view.findings);
    assert!(selected.archive_ir().unwrap().members().is_empty());
    assert_eq!(
        encode_hex(&sealr::encode_zip64_layout(selected.archive_ir().unwrap()).unwrap()),
        "7365616c722e747265652e6c61796f75742e7a697036342e763120313032000000000000000000000000000000000000000000000000000000000000000000010000000000000000380000000000000001380000000000000014000000000000004c0000000000000016000000000000006200000000000000000000000000000000000000"
    );
    assert!(selected
        .archive_ir()
        .unwrap()
        .zip64_covering()
        .unwrap()
        .zip64_eocd
        .is_some());
    assert_eq!(
        selected.receipt.identities.layout.hex(),
        Some("02d0757e59980e22c32a65aafbc9d0bac0facfd439c36db07e31872c14ccc93e")
    );
    assert_eq!(
        selected.receipt.identities.content.hex(),
        Some("6d2beb70163bbde616d1693f7621d175fe40340e1fc2f38afa6c994c9920e407")
    );

    let compatibility_default = apply(Request {
        source: Source::Bytes {
            path: Some("empty-global.zip"),
            data: &source,
        },
        policy: &Policy::default_v1(),
        dest: None,
    });
    assert!(compatibility_default.rejected());
    assert!(compatibility_default.archive_ir().is_none());

    let near_signature = decode_hex("504b060500000000");
    let near = apply_with_options(
        Request {
            source: Source::Bytes {
                path: None,
                data: &near_signature,
            },
            policy: &Policy::default_v3(),
            dest: None,
        },
        &options(),
    );
    assert!(near.rejected());
    assert!(near.archive_ir().is_none());
}

#[test]
fn malformed_zip64_c5_is_malformed_in_every_public_axis() {
    let mut source = decode_hex(EMPTY_GLOBAL_ZIP64_HEX);
    source[4] = 45;
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("malformed-extensible-sector.zip"),
                data: &source,
            },
            policy: &Policy::default_v3(),
            dest: None,
        },
        &options(),
    );

    assert!(outcome.rejected());
    assert_eq!(outcome.cli_exit_code(), 2);
    assert_eq!(outcome.interpretation, InterpretationStatus::Malformed);
    assert_eq!(outcome.view.interpretation, InterpretationStatus::Malformed);
    assert_eq!(
        outcome.receipt.interpretation,
        InterpretationStatus::Malformed
    );
    assert_eq!(outcome.admission, AdmissionStatus::NotEvaluated);
    assert_eq!(outcome.verification, VerificationStatus::StructureOnly);
    assert_eq!(outcome.effect, EffectStatus::NotRequested);
    assert!(outcome.archive_ir().is_none());
    assert!(outcome.verified_archive().is_none());
    assert_eq!(outcome.view.findings[0].code, FindingCode::ZipDiffC5Zip64);
    assert_eq!(
        outcome.view.findings[0].detail,
        "ZIP64 EOCD extensible sector is denied"
    );
}

#[test]
fn zip32_under_zip64_remains_unsupported_in_every_public_axis() {
    let source = decode_hex("504b0506000000000000000000000000000000000000");
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("plain-zip32.zip"),
                data: &source,
            },
            policy: &Policy::default_v3(),
            dest: None,
        },
        &options(),
    );

    assert!(outcome.rejected());
    assert_eq!(outcome.cli_exit_code(), 2);
    assert_eq!(outcome.interpretation, InterpretationStatus::Unsupported);
    assert_eq!(
        outcome.view.interpretation,
        InterpretationStatus::Unsupported
    );
    assert_eq!(
        outcome.receipt.interpretation,
        InterpretationStatus::Unsupported
    );
    assert_eq!(outcome.view.findings[0].code, FindingCode::ZipDiffC5Zip64);
    assert_eq!(
        outcome.view.findings[0].detail,
        "archive contains no ZIP64 construct"
    );
}
