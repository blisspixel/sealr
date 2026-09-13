use sealr::{
    apply, apply_with_options, encode_tar_gnu_longname_layout, tar_gnu_longname_portable_v1_digest,
    AdmissionStatus, ApplyOptions, ArchiveFormat, ByteRange, EffectStatus, FindingCode,
    GnuLongNamePathSource, InterpretationStatus, Policy, Request, RetentionPlan, Source,
    TarGnuLongNameInterpretationProfile, TreeRoot, VerificationStatus,
    TAR_GNU_LONGNAME_ARCHIVE_IR_SCHEMA, TAR_GNU_LONGNAME_PORTABLE_V1,
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

fn options() -> ApplyOptions {
    ApplyOptions::new().with_tar_gnu_longname_interpretation_profile(
        TarGnuLongNameInterpretationProfile::PortableV1,
    )
}

fn apply_gnu<'a>(bytes: &'a [u8], policy: &'a Policy) -> sealr::Outcome {
    apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("fixture.gnu.tar"),
                data: bytes,
            },
            policy,
            dest: None,
        },
        &options(),
    )
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn explicit_gnu_selection_binds_carrier_state_and_verified_reads() {
    let path = format!("mission/{}/status.txt", "segment".repeat(15));
    let bytes = long_name_archive(b"././@LongLink", &path, b"opaque-base", b"nominal");
    let retention = RetentionPlan::new(1024, 1024).with_path(&path).unwrap();
    let selected = options().with_retention(retention);
    assert_eq!(selected.archive_format(), ArchiveFormat::TarGnuLongName);
    assert_eq!(
        selected.tar_gnu_longname_interpretation_profile(),
        Some(TarGnuLongNameInterpretationProfile::PortableV1)
    );
    assert!(selected.zip_interpretation_profile().is_none());

    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.gnu.tar"),
                data: &bytes,
            },
            policy: &Policy::default_v6(),
            dest: None,
        },
        &selected,
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
        TreeRoot::SealrTreeV6 { .. }
    ));
    assert!(matches!(
        outcome.receipt.identities.content,
        TreeRoot::SealrTreeV1 { .. }
    ));

    let ir = outcome.archive_ir().unwrap();
    assert_eq!(ir.schema(), TAR_GNU_LONGNAME_ARCHIVE_IR_SCHEMA);
    assert_eq!(ir.profile(), TAR_GNU_LONGNAME_PORTABLE_V1);
    assert_eq!(ir.profile_digest(), tar_gnu_longname_portable_v1_digest());
    assert_eq!(ir.format(), ArchiveFormat::TarGnuLongName);
    assert!(encode_tar_gnu_longname_layout(ir).is_some());
    let carrier = &ir.gnu_longname_carriers().unwrap()[0];
    assert_eq!(carrier.raw_name_bytes, b"././@LongLink");
    assert_eq!(carrier.path_bytes, path.as_bytes());
    assert_eq!(
        carrier.payload,
        ByteRange {
            offset: 512,
            len: path.len() as u64 + 1
        }
    );
    assert_eq!(
        carrier.path,
        ByteRange {
            offset: 512,
            len: path.len() as u64
        }
    );
    let member = &ir.members()[0];
    assert_eq!(member.canonical_path, path);
    let evidence = member.tar_gnu_longname_evidence().unwrap();
    assert_eq!(evidence.base_name_bytes, b"opaque-base");
    assert_eq!(
        evidence.path_source,
        GnuLongNamePathSource::Carrier { carrier_index: 0 }
    );
    let verified = outcome.verified_archive().unwrap();
    assert_eq!(verified.retained_member(&path), Some(b"nominal".as_slice()));
    assert_eq!(verified.read_member(&path, 7).unwrap(), b"nominal");
}

#[test]
fn carrier_names_and_redundant_short_overrides_remain_bound_evidence() {
    for carrier_name in [
        b"././@LongLink".as_slice(),
        b"././@LongName".as_slice(),
        b"producer-metadata".as_slice(),
    ] {
        let bytes = long_name_archive(carrier_name, "short.txt", b"base", b"x");
        let outcome = apply_gnu(&bytes, &Policy::default_v6());
        assert!(
            matches!(outcome.admission, AdmissionStatus::Admitted),
            "{carrier_name:?}: {:?}",
            outcome.view.findings
        );
        assert_eq!(
            outcome
                .archive_ir()
                .unwrap()
                .gnu_longname_carriers()
                .unwrap()[0]
                .raw_name_bytes,
            carrier_name
        );
    }
}

#[test]
fn committed_tree_v6_manifest_matches_the_public_production_path() {
    let manifest: serde_json::Value = serde_json::from_slice(include_bytes!(
        "conformance/tar-gnu-longname-identity-v1.json"
    ))
    .unwrap();
    assert_eq!(
        manifest["schema"],
        "sealr.tar-gnu-longname-identity-conformance.v1"
    );
    assert_eq!(
        manifest["archive_ir_schema"],
        TAR_GNU_LONGNAME_ARCHIVE_IR_SCHEMA
    );
    assert_eq!(manifest["layout_encoding"], "sealrTreeV6");
    assert_eq!(
        manifest["layout_label"],
        "sealr.tree.layout.tar-gnu-longname.v1"
    );
    assert_eq!(manifest["content_encoding"], "sealrTreeV1");
    assert_eq!(manifest["content_label"], "sealr.tree.content.v1");
    assert_eq!(manifest["profile"]["id"], TAR_GNU_LONGNAME_PORTABLE_V1);
    assert_eq!(
        manifest["profile"]["digest"]["sha256"],
        tar_gnu_longname_portable_v1_digest()
    );

    let cases = manifest["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    assert_eq!(cases[0]["id"], "long-file");
    assert_eq!(cases[1]["id"], "arbitrary-carrier-directory-and-header");
    for case in cases {
        let source = decode_hex(case["source_bytes_hex"].as_str().unwrap());
        assert_eq!(sealr::hex_sha256(&source), case["source"]["sha256"]);
        let outcome = apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some(case["id"].as_str().unwrap()),
                    data: &source,
                },
                policy: &Policy::default_v6(),
                dest: None,
            },
            &options(),
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
            encode_tar_gnu_longname_layout(outcome.archive_ir().unwrap()).map(|bytes| bytes
                .into_iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()),
            Some(case["layout_preimage_hex"].as_str().unwrap().to_owned())
        );
    }
}

#[test]
fn pax_gnu_mixed_state_is_rejected_before_any_carrier_state() {
    let mut bytes = Vec::new();
    append_record(&mut bytes, header(b"pax", 0, b'x'), b"");
    let outcome = apply_gnu(&finish(bytes), &Policy::default_v6());
    assert_eq!(
        outcome.view.findings[0].code,
        FindingCode::TarFeatureUnsupported
    );
    assert!(matches!(
        outcome.interpretation,
        InterpretationStatus::Unsupported
    ));
    assert!(outcome.archive_ir().is_none());
}

#[test]
fn oversized_carrier_is_denied_before_payload_allocation_or_range_reads() {
    let bytes = finish(header(b"././@LongLink", 8193, b'L').to_vec());
    let outcome = apply_gnu(&bytes, &Policy::default_v6());
    assert_eq!(outcome.view.findings[0].code, FindingCode::QuotaMetadata);
    assert!(outcome.archive_ir().is_none());
}

#[test]
fn policy_and_selection_never_guess_or_fall_back() {
    let bytes = long_name_archive(b"././@LongLink", "selected.txt", b"base", b"");
    let zip_selected = apply(Request {
        source: Source::Bytes {
            path: Some("selected.gnu.tar"),
            data: &bytes,
        },
        policy: &Policy::default_v6(),
        dest: None,
    });
    assert!(!matches!(zip_selected.admission, AdmissionStatus::Admitted));
    assert!(zip_selected.archive_ir().is_none());

    let missing = std::env::temp_dir().join("sealr-definitely-missing-gnu-policy.tar");
    let denied = apply_with_options(
        Request {
            source: Source::Path(&missing),
            policy: &Policy::default_v5(),
            dest: None,
        },
        &options(),
    );
    assert_eq!(denied.view.findings[0].code, FindingCode::PolicyUnsupported);
    assert!(denied.receipt.source.sha256().is_none());
}
