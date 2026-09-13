//! Named durability selection preserves historical policy and effect contracts.

use sealr::{Durability, FindingCode, Policy, PolicyDocument, ValidatedPolicy};

fn policies() -> [Policy; 11] {
    [
        Policy::default_v1(),
        Policy::default_v2(),
        Policy::default_v3(),
        Policy::default_v4(),
        Policy::default_v5(),
        Policy::default_v6(),
        Policy::default_v7(),
        Policy::default_v8(),
        Policy::default_v9(),
        Policy::default_v10(),
        Policy::default_v11(),
    ]
}

const MODES: [(Durability, bool); 2] = [
    (Durability::FlushOnly, false),
    (Durability::MemberSync, true),
];

#[test]
fn named_policy_durability_preserves_every_legacy_encoding() {
    for original in policies() {
        let default_bytes = serde_json::to_vec(&original).unwrap();
        assert_eq!(original.durability(), Durability::FlushOnly);
        for (durability, atomic) in MODES {
            let mut legacy = original.clone();
            legacy.atomic = atomic;
            let mut named = original.clone().with_durability(durability);

            assert_eq!(named.durability(), durability);
            assert_eq!(named, legacy);
            assert_eq!(
                serde_json::to_vec(&named).unwrap(),
                serde_json::to_vec(&legacy).unwrap()
            );
            assert_eq!(named.digest_hex(), legacy.digest_hex());
            assert_eq!(named.compile().unwrap(), legacy.compile().unwrap());
            assert_eq!(named.compile().unwrap().effect.member_sync, atomic);
            let json = serde_json::to_value(&named).unwrap();
            assert_eq!(json["atomic"], atomic);
            assert!(json.get("durability").is_none());

            if atomic {
                assert_ne!(named.digest_hex(), original.digest_hex());
            }
            named.set_durability(Durability::FlushOnly);
            assert_eq!(serde_json::to_vec(&named).unwrap(), default_bytes);
            named.set_durability(Durability::MemberSync);
            assert!(named.atomic);
            named.atomic = false;
            assert_eq!(named.durability(), Durability::FlushOnly);
        }
    }
}

#[test]
fn document_selection_keeps_validation_and_memoized_identity_consistent() {
    for original in policies() {
        for (durability, atomic) in MODES {
            let document: PolicyDocument =
                serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
            let named = document.clone().with_durability(durability);
            let mut selected = document;
            selected.set_durability(durability);
            assert_eq!(selected, named);
            assert_eq!(selected.durability(), durability);
            assert_eq!(selected.atomic, atomic);

            let validated = selected.validate().unwrap();
            let policy = original.clone().with_durability(durability);
            assert_eq!(validated.policy(), &policy);
            assert_eq!(validated.policy().durability(), durability);
            assert_eq!(validated.digest_hex(), policy.digest_hex());
            assert_eq!(
                validated.policy().compile().unwrap(),
                policy.compile().unwrap()
            );
            assert_eq!(
                serde_json::to_vec(validated.policy()).unwrap(),
                serde_json::to_vec(&policy).unwrap()
            );

            let opposite = if atomic {
                Durability::FlushOnly
            } else {
                Durability::MemberSync
            };
            let changed =
                ValidatedPolicy::new(validated.clone().into_policy().with_durability(opposite))
                    .unwrap();
            assert_ne!(changed.digest_hex(), validated.digest_hex());
            assert_eq!(validated.digest_hex(), policy.digest_hex());
            assert_eq!(validated.policy().durability(), durability);

            let mut invalid = named;
            invalid.symlinks = "allow".to_owned();
            assert_eq!(
                invalid.validate().unwrap_err().code,
                FindingCode::PolicyUnsupported
            );
        }
    }
}

#[test]
fn named_rust_controls_do_not_create_a_second_json_policy_language() {
    for mode in ["flush-only", "member-sync"] {
        for keep_atomic in [false, true] {
            let mut value = serde_json::to_value(Policy::default_v1()).unwrap();
            let object = value.as_object_mut().unwrap();
            if !keep_atomic {
                object.remove("atomic");
            }
            object.insert("durability".to_owned(), serde_json::json!(mode));
            let error = serde_json::from_value::<PolicyDocument>(value).unwrap_err();
            assert!(error.to_string().contains("unknown field"), "{error}");
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod materialization {
    use super::*;
    use sealr::{apply, hex_sha256, AdmissionStatus, EffectStatus, Request, Source};
    use std::fs;
    use std::io::{Cursor, Write};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "sealr-durability-migration-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn archive() -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                "nested/member.txt",
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(b"verified member content").unwrap();
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn both_modes_materialize_and_preserve_existing_destinations() {
        let bytes = archive();
        let source_digest = hex_sha256(&bytes);
        for (mode, atomic) in MODES {
            let root = TempRoot::new();
            let destination = root.0.join("result");
            let neighbor = root.0.join("unrelated.txt");
            fs::write(&neighbor, b"unrelated caller file").unwrap();
            let policy = Policy::default_v1().with_durability(mode);
            let mut legacy = Policy::default_v1();
            legacy.atomic = atomic;
            let inspect = apply(Request {
                source: Source::Bytes {
                    path: Some("members.zip"),
                    data: &bytes,
                },
                policy: &policy,
                dest: None,
            });
            assert_eq!(inspect.admission, AdmissionStatus::Admitted);
            assert_eq!(inspect.effect, EffectStatus::NotRequested);
            assert_eq!(inspect.receipt.materialization.durability, "none");

            let materialized = apply(Request {
                source: Source::Bytes {
                    path: Some("members.zip"),
                    data: &bytes,
                },
                policy: &policy,
                dest: Some(&destination),
            });
            assert_eq!(
                materialized.effect,
                EffectStatus::Committed,
                "{:?}",
                materialized.view.findings
            );
            assert_eq!(
                fs::read(destination.join("nested/member.txt")).unwrap(),
                b"verified member content"
            );
            assert_eq!(
                materialized.receipt.source.sha256(),
                Some(source_digest.as_str())
            );
            assert_eq!(
                materialized.receipt.policy.digest.sha256,
                legacy.digest_hex()
            );
            assert_eq!(materialized.receipt.source, inspect.receipt.source);
            assert_eq!(
                serde_json::to_vec(&materialized.receipt.identities).unwrap(),
                serde_json::to_vec(&inspect.receipt.identities).unwrap()
            );
            assert_eq!(
                materialized.receipt.materialization.durability,
                if atomic { "member-sync" } else { "flush-only" }
            );
            assert_ne!(
                materialized.receipt.materialization.publication_primitive,
                "none"
            );
            assert_eq!(materialized.receipt.materialization.outcome, "committed");

            fs::write(destination.join("nested/member.txt"), b"caller replacement").unwrap();
            fs::write(destination.join("sentinel.txt"), b"caller sentinel").unwrap();
            let refused = apply(Request {
                source: Source::Bytes {
                    path: Some("members.zip"),
                    data: &bytes,
                },
                policy: &policy,
                dest: Some(&destination),
            });
            assert_eq!(refused.effect, EffectStatus::Failed);
            assert_eq!(refused.receipt.materialization.outcome, "setup-failed");
            assert_eq!(refused.receipt.materialization.cleanup, "not-created");
            assert_eq!(
                refused.receipt.materialization.durability,
                materialized.receipt.materialization.durability
            );
            assert_eq!(
                refused.receipt.materialization.publication_primitive,
                materialized.receipt.materialization.publication_primitive
            );
            assert_eq!(
                fs::read(destination.join("nested/member.txt")).unwrap(),
                b"caller replacement"
            );
            assert_eq!(
                fs::read(destination.join("sentinel.txt")).unwrap(),
                b"caller sentinel"
            );
            assert_eq!(fs::read(&neighbor).unwrap(), b"unrelated caller file");
            assert_eq!(fs::read_dir(&root.0).unwrap().count(), 2);
        }
    }
}
