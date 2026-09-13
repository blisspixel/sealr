//! Executable public-consumer rule: sealr.verdict-consumer-migration.v1.
//!
//! Every case obtains an actual outcome. Linux main supplies the authenticated
//! worker; cargo test uses the in-process API and also runs on Windows.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sealr::{
    apply_supervised, apply_with_options, AdmissionStatus, ApplyOptions, EffectStatus,
    InterpretationStatus, LinuxWorker, Outcome, Policy, Request, Source, VerificationStatus,
    VerifiedArchive, ZipInterpretationProfile,
};

fn verified_archive(outcome: &Outcome) -> Result<&VerifiedArchive, &'static str> {
    if !matches!(outcome.admission, AdmissionStatus::Admitted)
        || !matches!(outcome.verification, VerificationStatus::Complete)
    {
        return Err("archive-not-verified");
    }
    outcome.verified_archive().ok_or("capability-unavailable")
}

fn require_effect(outcome: &Outcome, materialization_requested: bool) -> Result<(), &'static str> {
    match (materialization_requested, &outcome.effect) {
        (false, EffectStatus::NotRequested) | (true, EffectStatus::Committed) => Ok(()),
        _ => Err("requested-effect-not-satisfied"),
    }
}

pub fn inspection_archive(outcome: &Outcome) -> Result<&VerifiedArchive, &'static str> {
    require_effect(outcome, false)?;
    verified_archive(outcome)
}

fn apply(source: Source<'_>, dest: Option<&Path>, worker: Option<&LinuxWorker>) -> Outcome {
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::StrictAsciiV2);
    let request = Request {
        source,
        policy: &policy,
        dest,
    };
    match worker {
        Some(worker) => apply_supervised(request, &options, worker)
            .expect("migration case must complete through the supervised boundary"),
        None => apply_with_options(request, &options),
    }
}

fn bytes(data: &[u8]) -> Source<'_> {
    Source::Bytes {
        path: Some("hello.zip"),
        data,
    }
}

fn inspected_capability(worker: Option<&LinuxWorker>) {
    let outcome = apply(bytes(super::HELLO_ZIP), None, worker);
    let archive = inspection_archive(&outcome).unwrap();
    assert_eq!(archive.read_member("hello.txt", 5).unwrap(), b"hello");
    assert_eq!(
        require_effect(&outcome, true),
        Err("requested-effect-not-satisfied")
    );
    assert_eq!(outcome.cli_exit_code(), 0);
    assert!(!outcome.wrote());
    let owned = outcome.into_verified_archive().expect("owned capability");
    assert_eq!(owned.read_member("hello.txt", 5).unwrap(), b"hello");
}

fn committed_materialization(worker: Option<&LinuxWorker>) {
    let temp = TempRoot::new();
    let dest = temp.0.join("committed");
    let outcome = apply(bytes(super::HELLO_ZIP), Some(&dest), worker);
    require_effect(&outcome, true).unwrap();
    assert!(inspection_archive(&outcome).is_err());
    let archive = verified_archive(&outcome).unwrap();
    assert_eq!(archive.read_member("hello.txt", 5).unwrap(), b"hello");
    assert_eq!(fs::read(dest.join("hello.txt")).unwrap(), b"hello");
    assert_eq!(outcome.cli_exit_code(), 0);
    assert!(outcome.wrote());
    let owned = outcome.into_verified_archive().expect("owned capability");
    assert_eq!(owned.read_member("hello.txt", 5).unwrap(), b"hello");
}

fn structural_denial(worker: Option<&LinuxWorker>) {
    let mut malformed = super::HELLO_ZIP.to_vec();
    // Keep the ZIP envelope, but break its central-directory header signature.
    malformed[44] ^= 1;
    let outcome = apply(bytes(&malformed), None, worker);
    assert_eq!(outcome.interpretation, InterpretationStatus::Malformed);
    assert_eq!(outcome.admission, AdmissionStatus::NotEvaluated);
    assert_eq!(outcome.verification, VerificationStatus::StructureOnly);
    assert_refused(&outcome);
}

fn crc_denial(worker: Option<&LinuxWorker>) {
    let mut corrupt = super::HELLO_ZIP.to_vec();
    // The field-grouped fixture's member payload follows its 30-byte header
    // and 9-byte filename. Preserve the claimed CRC and corrupt actual content.
    corrupt[39] ^= 1;
    let outcome = apply(bytes(&corrupt), None, worker);
    assert_eq!(outcome.admission, AdmissionStatus::Denied);
    assert!(matches!(
        outcome.verification,
        VerificationStatus::Partial { .. }
    ));
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code.as_str() == "crc.mismatch"));
    assert_refused(&outcome);
}

fn effect_setup_failure(worker: Option<&LinuxWorker>) {
    let temp = TempRoot::new();
    let sentinel = temp.0.join("keep.txt");
    fs::write(&sentinel, b"keep").unwrap();
    let outcome = apply(bytes(super::HELLO_ZIP), Some(&temp.0), worker);
    assert_eq!(outcome.admission, AdmissionStatus::Admitted);
    assert_eq!(outcome.verification, VerificationStatus::StructureOnly);
    assert_eq!(outcome.effect, EffectStatus::Failed);
    assert!(verified_archive(&outcome).is_err());
    assert!(outcome.verified_archive().is_none());
    assert_eq!(
        require_effect(&outcome, true),
        Err("requested-effect-not-satisfied")
    );
    assert_eq!(outcome.cli_exit_code(), 3);
    assert!(outcome.rejected());
    assert!(!outcome.wrote());
    assert_eq!(fs::read(sentinel).unwrap(), b"keep");
    assert!(!temp.0.join("hello.txt").exists());
}

fn source_unavailable(worker: Option<&LinuxWorker>) {
    let temp = TempRoot::new();
    let absent = temp.0.join("missing.zip");
    let outcome = apply(Source::Path(&absent), None, worker);
    assert_eq!(outcome.interpretation, InterpretationStatus::Indeterminate);
    assert_eq!(outcome.admission, AdmissionStatus::NotEvaluated);
    assert_eq!(outcome.verification, VerificationStatus::StructureOnly);
    assert!(outcome
        .view
        .findings
        .iter()
        .any(|finding| finding.code.as_str() == "source.io"));
    assert_refused(&outcome);
    assert!(!absent.exists());
}

fn assert_refused(outcome: &Outcome) {
    assert!(inspection_archive(outcome).is_err());
    assert!(outcome.verified_archive().is_none());
    assert_eq!(outcome.effect, EffectStatus::NotRequested);
    assert_eq!(outcome.cli_exit_code(), 2);
    assert!(outcome.rejected());
    assert!(!outcome.wrote());
}

pub fn run(worker: Option<&LinuxWorker>) {
    // BEGIN sealr.verdict-consumer-migration.v1
    let cases: &[(&str, fn(Option<&LinuxWorker>))] = &[
        ("inspected-capability", inspected_capability),
        ("committed-materialization", committed_materialization),
        ("structural-denial", structural_denial),
        ("crc-denial", crc_denial),
        ("effect-setup-failure", effect_setup_failure),
        ("source-unavailable", source_unavailable),
    ];
    // END sealr.verdict-consumer-migration.v1
    for (name, case) in cases {
        case(worker);
        println!("Verdict consumer migration passed: {name}");
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "sealr-outcome-migration-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn public_outcome_migration_matrix() {
        super::run(None);
    }
}
