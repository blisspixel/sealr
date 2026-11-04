use sealr::{Durability, Policy, PolicyDocument, PolicyDocumentV12};

fn legacy_literal() -> PolicyDocument {
    let p = Policy::default_v12();
    PolicyDocument {
        schema: p.schema.into(),
        id: p.id,
        formats: p.formats,
        max_archive_bytes: p.max_archive_bytes,
        max_derived_archive_bytes: p.max_derived_archive_bytes,
        max_files: p.max_files,
        max_member_bytes: p.max_member_bytes,
        max_total_bytes: p.max_total_bytes,
        max_ratio: p.max_ratio,
        max_path_depth: p.max_path_depth,
        max_metadata_bytes: p.max_metadata_bytes,
        max_dict_bytes: p.max_dict_bytes,
        symlinks: p.symlinks.into(),
        hardlinks: p.hardlinks.into(),
        overwrite: p.overwrite.into(),
        setuid: p.setuid.into(),
        nested_depth: p.nested_depth,
        ambiguity: p.ambiguity.into(),
        case_fold_collision: p.case_fold_collision.into(),
        magic_vs_extension: p.magic_vs_extension.into(),
        encrypted: p.encrypted.into(),
        atomic: p.atomic,
    }
}

#[test]
fn original_exhaustive_construction_and_member_modes_remain_supported() {
    let doc = legacy_literal().with_durability(Durability::MemberSync);
    assert_eq!(doc.durability(), Durability::MemberSync);
    assert_eq!(
        doc.validate().unwrap().policy().durability(),
        Durability::MemberSync
    );
}

#[test]
fn explicit_upgrade_preserves_directory_sync_and_canonical_identity() {
    let doc = PolicyDocumentV12::from(legacy_literal()).with_durability(Durability::DirectorySync);
    assert_eq!(doc.durability(), Durability::DirectorySync);
    let expected = Policy::default_v12().with_durability(Durability::DirectorySync);
    let validated = doc.validate().unwrap();
    assert_eq!(validated.policy(), &expected);
    assert_eq!(validated.digest_hex(), expected.digest_hex());
    let json = serde_json::to_vec(&expected).unwrap();
    assert!(serde_json::from_slice::<PolicyDocument>(&json).is_err());
    let decoded: PolicyDocumentV12 = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded.validate().unwrap().policy(), &expected);
}

#[test]
#[should_panic(expected = "DirectorySync requires PolicyDocumentV12")]
fn legacy_setter_never_silently_downgrades_directory_sync() {
    legacy_literal().set_durability(Durability::DirectorySync);
}
