//! The disagreement lesson as a sealr artifact: one archive digest, three
//! consumer outcomes, the source file gone before any evaluation.
//!
//! ```text
//! cargo run --locked -p sealr --example same_digest_different_tree
//! ```
//!
//! The 2025 ZipDiff study and the uv/pip advisories share one shape: the same
//! archive bytes are made to mean different installed trees by different
//! parsers. sealr inverts that. The bytes admit through exactly one
//! interpretation, so the source digest and the archive-tree identity are
//! properties of the bytes alone and never move. Any consumer-level difference
//! is forced into an explicit, filename-bound artifact identity, or into a
//! typed refusal — never a second silent tree.
//!
//! This demonstration admits one wheel, DELETES the file, and then evaluates
//! the retained capability under three outer filenames a caller might present:
//!
//! 1. the canonical name — admitted;
//! 2. a benign alternate spelling that normalizes identically — also admitted,
//!    with the identical source and archive-tree identity and the identical
//!    installed target set, but DIFFERENT artifact and install-plan identities,
//!    because both commit to the exact filename the caller claimed;
//! 3. a name whose distribution disagrees with the embedded metadata — DENIED
//!    with a typed finding, the same bytes yielding no tree at all.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Write as _};

use sealr::wheel::{evaluate_wheel, WheelEvaluation, WheelIdentities, WheelLimits};
use sealr::{
    apply_with_options, ApplyOptions, Policy, Request, Source, VerifiedArchive,
    ZipInterpretationProfile,
};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, System, ZipWriter};

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(ALPHABET[((value >> 18) & 63) as usize] as char);
        output.push(ALPHABET[((value >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[((value >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(value & 63) as usize] as char);
        }
    }
    output
}

/// One small, valid wheel whose distribution is `demo` and version `1.0`.
fn wheel_bytes() -> Vec<u8> {
    let mut files = BTreeMap::new();
    files.insert(
        "demo/greet.py".to_owned(),
        b"def greet():\n    return \"sealed\"\n".to_vec(),
    );
    files.insert(
        "demo-1.0.dist-info/WHEEL".to_owned(),
        b"Wheel-Version: 1.0\nGenerator: sealr-demo\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
            .to_vec(),
    );
    files.insert(
        "demo-1.0.dist-info/METADATA".to_owned(),
        b"Metadata-Version: 2.6\nName: demo\nVersion: 1.0\n\n".to_vec(),
    );

    let mut record = String::new();
    for (path, bytes) in &files {
        record.push_str(path);
        record.push_str(",sha256=");
        record.push_str(&base64url(&Sha256::digest(bytes)));
        record.push(',');
        record.push_str(&bytes.len().to_string());
        record.push('\n');
    }
    record.push_str("demo-1.0.dist-info/RECORD,,\n");
    files.insert("demo-1.0.dist-info/RECORD".to_owned(), record.into_bytes());

    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .compression_level(Some(6))
            .last_modified_time(DateTime::DEFAULT)
            .unix_permissions(0o644)
            .system(System::Unix);
        for (path, bytes) in files {
            writer
                .start_file(path, options)
                .expect("start wheel member");
            writer.write_all(&bytes).expect("write wheel member");
        }
        writer.finish().expect("finish wheel");
    }
    cursor.into_inner()
}

fn admit(bytes: &[u8]) -> VerifiedArchive {
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("demo-1.0-py3-none-any.whl"),
                data: bytes,
            },
            policy: &policy,
            dest: None,
        },
        &options,
    );
    outcome
        .verified_archive()
        .expect("the demo wheel container is well-formed")
        .clone()
}

fn evaluate(archive: &VerifiedArchive, outer_filename: &str) -> WheelEvaluation {
    evaluate_wheel(outer_filename, archive, WheelLimits::default())
}

fn report_identities(label: &str, identities: &WheelIdentities) {
    println!("   [{label}] admitted");
    println!("      source_sha256        {}", identities.source_sha256);
    println!(
        "      archive_tree_sha256  {}",
        identities.archive_tree_sha256
    );
    println!("      artifact_sha256      {}", identities.artifact_sha256);
    println!(
        "      install_plan_sha256  {}",
        identities.install_plan_sha256
    );
}

fn main() {
    let bytes = wheel_bytes();
    let source_digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    // Admit once from a temporary file, then delete the file. Everything below
    // reads only the retained capability.
    let temp = std::env::temp_dir().join(format!(
        "sealr-same-digest-{}-{}.whl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    fs::write(&temp, &bytes).expect("write demo wheel");
    let archive = admit(&fs::read(&temp).expect("read demo wheel"));
    fs::remove_file(&temp).expect("delete demo wheel");

    println!("One archive, three consumer outcomes, source already deleted.");
    println!("   raw ZIP sha256:          {source_digest}");
    println!("   source file exists:      {}", temp.exists());

    // 1. The canonical outer name.
    println!("== 1. demo-1.0-py3-none-any.whl (canonical) ==");
    let WheelEvaluation::Admitted {
        identities: canonical,
        plan: canonical_plan,
        ..
    } = evaluate(&archive, "demo-1.0-py3-none-any.whl")
    else {
        panic!("the canonical filename must admit");
    };
    report_identities("canonical", &canonical);

    // 2. A benign alternate spelling: uppercase distribution normalizes to the
    //    identical `demo`, so admission succeeds and the source, archive-tree,
    //    and install-plan identities are byte-for-byte identical — but the
    //    artifact identity differs, because it commits to the exact filename.
    println!("== 2. Demo-1.0-py3-none-any.whl (benign alternate spelling) ==");
    let WheelEvaluation::Admitted {
        identities: alternate,
        plan: alternate_plan,
        ..
    } = evaluate(&archive, "Demo-1.0-py3-none-any.whl")
    else {
        panic!("a spelling that normalizes identically must admit");
    };
    report_identities("alternate", &alternate);

    let realized_tree = |plan: &sealr::wheel::WheelInstallPlan| {
        plan.entries()
            .iter()
            .map(|entry| {
                (
                    format!("{:?}", entry.scheme),
                    entry.relative_path.clone(),
                    entry.sha256.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        canonical.source_sha256, alternate.source_sha256,
        "the source digest is a property of the bytes"
    );
    assert_eq!(
        canonical.archive_tree_sha256, alternate.archive_tree_sha256,
        "the archive-tree identity is a property of the bytes"
    );
    assert_eq!(
        realized_tree(&canonical_plan),
        realized_tree(&alternate_plan),
        "the installed target set — every scheme, path, and content hash — is identical"
    );
    assert_ne!(
        canonical.artifact_sha256, alternate.artifact_sha256,
        "the artifact identity commits to the exact filename claim"
    );
    assert_ne!(
        canonical.install_plan_sha256, alternate.install_plan_sha256,
        "the plan identity binds the artifact identity, so it too names the claim"
    );
    println!("   same source, same archive tree, same installed target set;");
    println!("   the artifact and plan identities bind the exact filename claim.");

    // 3. A filename whose distribution disagrees with the embedded metadata.
    //    The same bytes yield no tree at all — a typed refusal, never a second
    //    silent tree.
    println!("== 3. other-1.0-py3-none-any.whl (distribution disagreement) ==");
    match evaluate(&archive, "other-1.0-py3-none-any.whl") {
        WheelEvaluation::Denied { findings } => {
            for finding in findings {
                println!("   denied: {} ({})", finding.code, finding.detail);
            }
        }
        other => panic!("a disagreeing filename must be denied, got {other:?}"),
    }

    println!("== Same digest is not same tree. One meaning, or nothing. ==");
}
