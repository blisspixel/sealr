use sealr::{Durability, Policy, PolicyDocument, PolicyDocumentV12};

fn legacy_literal() -> PolicyDocument {
    let policy = Policy::default_v12();
    PolicyDocument {
        schema: policy.schema.into(),
        id: policy.id,
        formats: policy.formats,
        max_archive_bytes: policy.max_archive_bytes,
        max_derived_archive_bytes: policy.max_derived_archive_bytes,
        max_files: policy.max_files,
        max_member_bytes: policy.max_member_bytes,
        max_total_bytes: policy.max_total_bytes,
        max_ratio: policy.max_ratio,
        max_path_depth: policy.max_path_depth,
        max_metadata_bytes: policy.max_metadata_bytes,
        max_dict_bytes: policy.max_dict_bytes,
        symlinks: policy.symlinks.into(),
        hardlinks: policy.hardlinks.into(),
        overwrite: policy.overwrite.into(),
        setuid: policy.setuid.into(),
        nested_depth: policy.nested_depth,
        ambiguity: policy.ambiguity.into(),
        case_fold_collision: policy.case_fold_collision.into(),
        magic_vs_extension: policy.magic_vs_extension.into(),
        encrypted: policy.encrypted.into(),
        atomic: policy.atomic,
    }
}

#[test]
fn original_exhaustive_construction_and_member_modes_remain_supported() {
    let document = legacy_literal().with_durability(Durability::MemberSync);
    assert_eq!(document.durability(), Durability::MemberSync);
    assert_eq!(
        document.validate().unwrap().policy().durability(),
        Durability::MemberSync
    );
}

#[test]
fn explicit_upgrade_preserves_directory_sync_and_canonical_identity() {
    let document =
        PolicyDocumentV12::from(legacy_literal()).with_durability(Durability::DirectorySync);
    assert_eq!(document.durability(), Durability::DirectorySync);
    let expected = Policy::default_v12().with_durability(Durability::DirectorySync);
    let validated = document.validate().unwrap();
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
