//! Cross-platform golden vectors for `sealrTreeV1`.
//!
//! These pin the walkthrough fixtures and empty-tree encodings so Linux, macOS,
//! and Windows cannot silently diverge. A digest of the ZIP is not a digest of
//! the tree; both are recorded.

use std::fs;

use sealr::{
    apply, hex_sha256, AdmissionStatus, EffectStatus, InterpretationStatus, Policy, Request,
    Source, VerificationStatus, ZIP_STRICT_ASCII_V1,
};

#[path = "../../../scripts/walkthrough_fixtures.rs"]
mod walkthrough_fixtures;

const ALLOWED_SOURCE: &str = "580606f3b53229ab60ff1d786bac90c91f75c054269c11142cd971f380d3fc25";
const REJECTED_SOURCE: &str = "5039cccff40a5df0d0b61a2734b5dafeb8224f914603cae870f1638990f58140";
const PROFILE_DIGEST: &str = "da3a2145d48decf8f8995ea01f1ddd0adb587f7f3544d4642bb8bb07b8f039f5";

/// SHA-256 of `sealr.tree.layout.v1 4\0` plus four zero bytes.
const EMPTY_LAYOUT: &str = "71a337a4992b91092a55201b7cda79eb3ccc03b22af4d2289ff22d9ba97fa9f1";
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

#[test]
fn empty_tree_preimages_are_pinned() {
    use sealr::{content_root, layout_root, ArchiveIR, SourceDigest};

    let ir = ArchiveIR::new(SourceDigest::available("abc"), Vec::new());
    pin("empty layout", layout_root(&ir).hex(), EMPTY_LAYOUT);
    pin("empty content", content_root(&ir).hex(), EMPTY_CONTENT);
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
