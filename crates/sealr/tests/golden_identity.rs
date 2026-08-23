//! Cross-platform golden vectors for `sealrTreeV1`.
//!
//! These pin the walkthrough fixtures and empty-tree encodings so Linux, macOS,
//! and Windows cannot silently diverge. A digest of the ZIP is not a digest of
//! the tree; both are recorded.

use std::fs;

use sealr::{
    apply, apply_with_options, hex_sha256, zip_strict_ascii_v1_canonical_bytes,
    zip_strict_ascii_v1_digest, zip_strict_ascii_v2_canonical_bytes, zip_strict_ascii_v2_digest,
    AdmissionStatus, ApplyOptions, EffectStatus, InterpretationStatus, Policy, Request, Source,
    VerificationStatus, ZipInterpretationProfile, ZIP_STRICT_ASCII_V1, ZIP_STRICT_ASCII_V2,
};

#[path = "../../../scripts/walkthrough_fixtures.rs"]
mod walkthrough_fixtures;

const IDENTITY_VECTORS: &str = include_str!("conformance/identity-v1.json");

const ALLOWED_SOURCE: &str = "580606f3b53229ab60ff1d786bac90c91f75c054269c11142cd971f380d3fc25";
const REJECTED_SOURCE: &str = "5039cccff40a5df0d0b61a2734b5dafeb8224f914603cae870f1638990f58140";
const PROFILE_DIGEST: &str = "da3a2145d48decf8f8995ea01f1ddd0adb587f7f3544d4642bb8bb07b8f039f5";

const EMPTY_ZIP: &[u8] = &[
    0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// SHA-256 of the layout preimage for the canonical 22-byte empty ZIP.
const EMPTY_LAYOUT: &str = "33415b1ed680a15e8c8b9e4794392736c8d998ca30200fe99b207b1cff279091";
/// SHA-256 of `sealr.tree.content.v1 4\0` plus four zero bytes.
const EMPTY_CONTENT: &str = "6d2beb70163bbde616d1693f7621d175fe40340e1fc2f38afa6c994c9920e407";

const ALLOWED_LAYOUT: &str = "9986381ec4a61fd34452fb759ccaf44b82ee58c8147ee032f077722c1ccac3a3";
const ALLOWED_CONTENT: &str = "ccae362a7daa3508aace90d589c4538c27f13ff517a82a049e47005724073f38";

fn pin(label: &str, actual: Option<&str>, expected: &str) {
    let actual = actual.expect(label);
    assert_eq!(actual, expected, "{label} changed; new value:\n{actual}");
}

fn apply_bytes(bytes: &[u8], dest: Option<&std::path::Path>) -> sealr::Outcome {
    let policy = Policy::default_v1();
    apply(Request {
        source: Source::Bytes {
            path: Some("golden.zip"),
            data: bytes,
        },
        policy: &policy,
        dest,
    })
}

fn decode_hex(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "vector hex has even length");
    pairs
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("vector hex is ASCII");
            u8::from_str_radix(text, 16).expect("vector hex is valid")
        })
        .collect()
}

fn feature_complete_identity_zip() -> Vec<u8> {
    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn local_header(
        bytes: &mut Vec<u8>,
        name: &[u8],
        flags: u16,
        crc: u32,
        size: u32,
        extra: &[u8],
    ) {
        push_u32(bytes, 0x0403_4b50);
        push_u16(bytes, 20);
        push_u16(bytes, flags);
        push_u16(bytes, 0);
        push_u16(bytes, 0);
        push_u16(bytes, 0x0021);
        push_u32(bytes, crc);
        push_u32(bytes, size);
        push_u32(bytes, size);
        push_u16(bytes, name.len() as u16);
        push_u16(bytes, extra.len() as u16);
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(extra);
    }

    struct Central<'a> {
        name: &'a [u8],
        flags: u16,
        crc: u32,
        size: u32,
        extra: &'a [u8],
        external_attributes: u32,
        local_offset: u32,
    }

    fn central_header(bytes: &mut Vec<u8>, entry: &Central<'_>) {
        push_u32(bytes, 0x0201_4b50);
        push_u16(bytes, 0x0314);
        push_u16(bytes, 20);
        push_u16(bytes, entry.flags);
        push_u16(bytes, 0);
        push_u16(bytes, 0);
        push_u16(bytes, 0x0021);
        push_u32(bytes, entry.crc);
        push_u32(bytes, entry.size);
        push_u32(bytes, entry.size);
        push_u16(bytes, entry.name.len() as u16);
        push_u16(bytes, entry.extra.len() as u16);
        push_u16(bytes, 0);
        push_u16(bytes, 0);
        push_u16(bytes, 0);
        push_u32(bytes, entry.external_attributes);
        push_u32(bytes, entry.local_offset);
        bytes.extend_from_slice(entry.name);
        bytes.extend_from_slice(entry.extra);
    }

    const DIRECTORY_NAME: &[u8] = b"pkg/";
    const FILE_NAME: &[u8] = b"./pkg/data.txt";
    const DATA: &[u8] = b"abc";
    const CRC32_ABC: u32 = 0x3524_41c2;
    const EXTRA: &[u8] = &[0x55, 0x78, 0, 0];

    let mut archive = Vec::new();
    local_header(&mut archive, DIRECTORY_NAME, 0, 0, 0, EXTRA);
    let file_offset = archive.len() as u32;
    local_header(&mut archive, FILE_NAME, 0x0008, 0, 0, EXTRA);
    archive.extend_from_slice(DATA);
    push_u32(&mut archive, 0x0807_4b50);
    push_u32(&mut archive, CRC32_ABC);
    push_u32(&mut archive, DATA.len() as u32);
    push_u32(&mut archive, DATA.len() as u32);

    let central_offset = archive.len() as u32;
    central_header(
        &mut archive,
        &Central {
            name: DIRECTORY_NAME,
            flags: 0,
            crc: 0,
            size: 0,
            extra: EXTRA,
            external_attributes: (0o040755_u32 << 16) | 0x10,
            local_offset: 0,
        },
    );
    central_header(
        &mut archive,
        &Central {
            name: FILE_NAME,
            flags: 0x0008,
            crc: CRC32_ABC,
            size: DATA.len() as u32,
            extra: EXTRA,
            external_attributes: 0o100644_u32 << 16,
            local_offset: file_offset,
        },
    );
    let central_size = archive.len() as u32 - central_offset;
    push_u32(&mut archive, 0x0605_4b50);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, 2);
    push_u16(&mut archive, 2);
    push_u32(&mut archive, central_size);
    push_u32(&mut archive, central_offset);
    push_u16(&mut archive, 0);
    archive
}

#[test]
fn identity_conformance_manifest_matches_production_evidence() {
    let manifest: serde_json::Value =
        serde_json::from_str(IDENTITY_VECTORS).expect("identity vectors are JSON");
    let cases = manifest["cases"]
        .as_array()
        .expect("identity vectors contain cases");
    assert!(!cases.is_empty());

    let profiles = manifest["profiles"]
        .as_array()
        .expect("identity vectors contain profiles");
    assert_eq!(profiles.len(), 2);
    for profile in profiles {
        let id = profile["id"].as_str().expect("profile id");
        let (canonical, digest) = match id {
            ZIP_STRICT_ASCII_V1 => (
                zip_strict_ascii_v1_canonical_bytes(),
                zip_strict_ascii_v1_digest(),
            ),
            ZIP_STRICT_ASCII_V2 => (
                zip_strict_ascii_v2_canonical_bytes(),
                zip_strict_ascii_v2_digest(),
            ),
            _ => panic!("unexpected profile vector {id}"),
        };
        assert_eq!(
            decode_hex(profile["canonical_bytes_hex"].as_str().unwrap()),
            canonical,
            "{id} canonical profile bytes"
        );
        assert_eq!(profile["digest"]["sha256"], digest, "{id} digest");
    }

    for case in cases {
        let id = case["id"].as_str().expect("case id");
        let bytes = decode_hex(
            case["source_bytes_hex"]
                .as_str()
                .expect("case source bytes"),
        );
        if id == "layout-features" {
            assert_eq!(
                bytes,
                feature_complete_identity_zip(),
                "{id} source construction"
            );
        }
        let out = apply_bytes(&bytes, None);
        let actual_axes = serde_json::json!({
            "interpretation": &out.interpretation,
            "admission": &out.admission,
            "verification": &out.verification,
            "effect": &out.effect,
            "view_completeness": &out.view_completeness,
        });

        assert_eq!(
            serde_json::to_value(&out.receipt.source).unwrap(),
            case["source"],
            "{id} source identity"
        );
        assert_eq!(
            serde_json::to_value(&out.receipt.identities.interpretation).unwrap(),
            case["interpretation"],
            "{id} interpretation identity"
        );
        assert_eq!(actual_axes, case["axes"], "{id} semantic axes");
        assert_eq!(
            serde_json::to_value(&out.view.findings).unwrap(),
            case["findings"],
            "{id} findings"
        );
        assert_eq!(
            serde_json::to_value(out.archive_ir()).unwrap(),
            case["archive_ir"],
            "{id} ArchiveIR"
        );
        assert_eq!(
            serde_json::to_value(&out.receipt.identities.layout).unwrap(),
            case["layout_root"],
            "{id} layout root"
        );
        assert_eq!(
            serde_json::to_value(&out.receipt.identities.content).unwrap(),
            case["content_root"],
            "{id} content root"
        );
    }
}

#[test]
fn strict_v2_empty_tree_identity_is_cross_platform_pinned() {
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::StrictAsciiV2);
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("strict-v2-empty.zip"),
                data: EMPTY_ZIP,
            },
            policy: &policy,
            dest: None,
        },
        &options,
    );

    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
    assert_eq!(outcome.archive_ir().unwrap().profile(), ZIP_STRICT_ASCII_V2);
    assert_eq!(
        outcome.receipt.identities.interpretation.digest.sha256,
        "384dceb8623a2b32d430034fefda2a9498439927285952c10a60c9f6caa51d45"
    );
    pin(
        "strict v2 empty layout",
        outcome.receipt.identities.layout.hex(),
        EMPTY_LAYOUT,
    );
    pin(
        "strict v2 empty content",
        outcome.receipt.identities.content.hex(),
        EMPTY_CONTENT,
    );
}

#[test]
fn empty_tree_preimages_are_pinned() {
    let inspect = apply_bytes(EMPTY_ZIP, None);
    assert!(!inspect.rejected(), "{:?}", inspect.view.findings);
    assert_eq!(inspect.admission, AdmissionStatus::Admitted);
    assert_eq!(inspect.verification, VerificationStatus::Complete);
    let ir = inspect.archive_ir().expect("empty ZIP has an IR");
    assert_eq!(ir.schema(), "sealr.archive-ir.v1");
    assert_eq!(ir.profile(), ZIP_STRICT_ASCII_V1);
    assert_eq!(ir.profile_digest(), PROFILE_DIGEST);
    assert!(ir.source_digest().is_available());
    assert!(ir.members().is_empty());
    assert_eq!(ir.covering().eocd.offset, 0);
    assert_eq!(ir.covering().eocd.len, 22);
    pin(
        "empty layout",
        inspect.receipt.identities.layout.hex(),
        EMPTY_LAYOUT,
    );
    pin(
        "empty content",
        inspect.receipt.identities.content.hex(),
        EMPTY_CONTENT,
    );
    assert_ne!(EMPTY_LAYOUT, EMPTY_CONTENT);
}

#[test]
fn walkthrough_allowed_fixture_has_pinned_roots() {
    let dir = std::env::temp_dir().join(format!("sealr-golden-allowed-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let fixtures = walkthrough_fixtures::generate(&dir).expect("walkthrough fixtures");
    let bytes = fs::read(&fixtures.allowed).expect("allowed.zip");
    assert_eq!(hex_sha256(&bytes), ALLOWED_SOURCE);

    let inspect = apply_bytes(&bytes, None);
    assert!(!inspect.rejected(), "{:?}", inspect.view.findings);
    assert_eq!(inspect.interpretation, InterpretationStatus::Interpreted);
    assert_eq!(inspect.admission, AdmissionStatus::Admitted);
    assert_eq!(inspect.verification, VerificationStatus::Complete);
    assert_eq!(inspect.effect, EffectStatus::NotRequested);
    assert_eq!(
        inspect.receipt.identities.interpretation.id,
        ZIP_STRICT_ASCII_V1
    );
    assert_eq!(
        inspect.receipt.identities.interpretation.digest.sha256,
        PROFILE_DIGEST
    );
    pin(
        "allowed layout",
        inspect.receipt.identities.layout.hex(),
        ALLOWED_LAYOUT,
    );
    pin(
        "allowed content",
        inspect.receipt.identities.content.hex(),
        ALLOWED_CONTENT,
    );
    assert_ne!(
        inspect.receipt.view_digest.sha256, ALLOWED_LAYOUT,
        "view_digest must not be the layout root"
    );
    assert_ne!(ALLOWED_SOURCE, ALLOWED_LAYOUT);
    assert_ne!(ALLOWED_LAYOUT, ALLOWED_CONTENT);

    let dest = dir.join("materialized");
    let materialize = apply_bytes(&bytes, Some(&dest));
    assert!(materialize.wrote(), "{:?}", materialize.view.findings);
    pin(
        "materialize layout",
        materialize.receipt.identities.layout.hex(),
        ALLOWED_LAYOUT,
    );
    pin(
        "materialize content",
        materialize.receipt.identities.content.hex(),
        ALLOWED_CONTENT,
    );
    assert_ne!(
        inspect.receipt.view_digest.sha256,
        materialize.receipt.view_digest.sha256
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn walkthrough_rejected_fixture_has_no_tree_roots() {
    let dir = std::env::temp_dir().join(format!("sealr-golden-rejected-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let fixtures = walkthrough_fixtures::generate(&dir).expect("walkthrough fixtures");
    let bytes = fs::read(&fixtures.rejected).expect("rejected.zip");
    assert_eq!(hex_sha256(&bytes), REJECTED_SOURCE);

    let out = apply_bytes(&bytes, None);
    assert!(out.rejected());
    assert_eq!(out.interpretation, InterpretationStatus::Interpreted);
    assert_eq!(out.admission, AdmissionStatus::Denied);
    assert!(
        out.receipt.identities.layout.hex().is_none(),
        "denied archives have no layout root"
    );
    assert!(out.receipt.identities.content.hex().is_none());
    assert_eq!(out.receipt.source.sha256(), Some(REJECTED_SOURCE));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn failed_destination_keeps_layout_and_omits_content() {
    let dir = std::env::temp_dir().join(format!("sealr-golden-effect-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let fixtures = walkthrough_fixtures::generate(&dir).expect("walkthrough fixtures");
    let bytes = fs::read(&fixtures.allowed).expect("allowed.zip");
    let missing = dir.join("missing").join("out");

    let out = apply_bytes(&bytes, Some(&missing));
    assert!(out.rejected());
    assert_eq!(out.admission, AdmissionStatus::Admitted);
    assert_eq!(out.effect, EffectStatus::Failed);
    assert_eq!(out.verification, VerificationStatus::StructureOnly);
    pin(
        "failed-dest layout",
        out.receipt.identities.layout.hex(),
        ALLOWED_LAYOUT,
    );
    assert!(
        out.receipt.identities.content.hex().is_none(),
        "content root requires complete verification"
    );

    let _ = fs::remove_dir_all(&dir);
}
