//! Downstream-facing compile and behavior fixture for the intended public API.

use std::io::{Cursor, Write};

use sealr::{
    apply, apply_with_options, ApplyOptions, EnvMeta, MaterializationMeta, MemberContainerFacts,
    MemberEvidence, MemberReadErrorKind, Outcome, OutcomeIdentities, Policy, PolicyMeta, Receipt,
    Request, RetentionPlan, RetentionStatus, SnapshotKind, Source, SourceMeta, ToolMeta,
    VerifiedArchive, View, ZipInterpretationProfile, ZipMemberEvidence, ZIP_PORTABLE_UTF8_V1,
    ZIP_STRICT_ASCII_V2, ZIP_WHEEL_UTF8_V1,
};
#[cfg(not(target_os = "linux"))]
use sealr::{LinuxWorker, SupervisionErrorKind};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const EMPTY_ZIP: &[u8] = &[
    0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn assert_public_output_types(outcome: &Outcome) {
    let _: &View = &outcome.view;
    let _: &Receipt = &outcome.receipt;
    let _: &SourceMeta = &outcome.view.source;
    let _: &PolicyMeta = &outcome.view.policy;
    let _: &ToolMeta = &outcome.receipt.tool;
    let _: &EnvMeta = &outcome.receipt.environment;
    let _: &MaterializationMeta = &outcome.receipt.materialization;
    let _: &OutcomeIdentities = &outcome.receipt.identities;
    let _: SnapshotKind = outcome.receipt.source_snapshot;
}

#[cfg(not(target_os = "linux"))]
#[test]
fn supervised_worker_loading_fails_closed_off_linux() {
    let error = LinuxWorker::load(std::path::Path::new("/sealr-worker"), 1, &"00".repeat(32))
        .expect_err("non-Linux worker activation must fail closed");
    assert_eq!(error.kind(), SupervisionErrorKind::IsolationUnavailable);
    let manifest_error =
        LinuxWorker::load_from_manifest(std::path::Path::new("/sealr-worker.manifest"))
            .expect_err("non-Linux manifest activation must fail closed");
    assert_eq!(
        manifest_error.kind(),
        SupervisionErrorKind::IsolationUnavailable
    );
}

fn member_zip() -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        writer.start_file("METADATA", options).unwrap();
        writer.write_all(b"Name: example\n").unwrap();
        writer.finish().unwrap();
    }
    cursor.into_inner()
}

#[test]
fn intended_receipt_and_view_types_are_nameable_downstream() {
    let policy = Policy::default_v1();
    let outcome = apply(Request {
        source: Source::Bytes {
            path: Some("empty.zip"),
            data: EMPTY_ZIP,
        },
        policy: &policy,
        dest: None,
    });

    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
    assert_public_output_types(&outcome);
}

#[test]
fn downstream_callers_can_select_the_closed_strict_profile() {
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::StrictAsciiV2);
    assert_eq!(
        options.interpretation_profile(),
        ZipInterpretationProfile::StrictAsciiV2
    );
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("empty.zip"),
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
        outcome.receipt.identities.interpretation.id,
        ZIP_STRICT_ASCII_V2
    );
}

#[test]
fn downstream_callers_can_select_the_portable_utf8_profile() {
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
    assert_eq!(
        options.interpretation_profile(),
        ZipInterpretationProfile::PortableUtf8V1
    );
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("empty.zip"),
                data: EMPTY_ZIP,
            },
            policy: &policy,
            dest: None,
        },
        &options,
    );

    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
    assert_eq!(
        outcome.archive_ir().unwrap().profile(),
        ZIP_PORTABLE_UTF8_V1
    );
    assert_eq!(
        outcome.receipt.identities.interpretation.id,
        ZIP_PORTABLE_UTF8_V1
    );
}

#[test]
fn downstream_callers_can_name_research_wheel_container_facts() {
    let bytes = member_zip();
    let policy = Policy::default_v1();
    let options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::WheelUtf8V1);
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("example.whl"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        },
        &options,
    );

    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
    assert_eq!(outcome.archive_ir().unwrap().profile(), ZIP_WHEEL_UTF8_V1);
    let member = &outcome.archive_ir().unwrap().members()[0];
    assert!(matches!(&member.evidence, MemberEvidence::Zip(_)));
    let zip: &ZipMemberEvidence = member.zip_evidence().expect("ZIP evidence");
    let _: u16 = zip.method;
    let _: u16 = zip.flags;
    let _: u32 = zip.declared_crc;
    let _: u64 = zip.declared_comp_size;
    let _ = &zip.source_ranges;
    let _ = &zip.extra_fields;
    assert!(member.tar_evidence().is_none());
    let facts: MemberContainerFacts = member.container_facts().expect("ZIP container facts");
    let _: u8 = facts.creator_system;
    let _: u32 = facts.external_attributes;
    let _: Option<u16> = facts.unix_mode();
    let _: bool = facts.pypa_installer_0_7_executable();
}

#[test]
fn verified_capability_is_nameable_and_reads_without_reopening_the_source() {
    let mut bytes = member_zip();
    let policy = Policy::default_v1();
    let outcome = apply(Request {
        source: Source::Bytes {
            path: Some("example.whl"),
            data: &bytes,
        },
        policy: &policy,
        dest: None,
    });
    bytes.fill(0);

    let archive: &VerifiedArchive = outcome.verified_archive().expect("verified capability");
    assert_eq!(
        archive.read_member("METADATA", 14).unwrap(),
        b"Name: example\n"
    );
    assert_eq!(
        archive.read_member("METADATA", 13).unwrap_err().kind(),
        MemberReadErrorKind::LimitExceeded
    );
}

#[test]
fn bounded_retention_is_available_to_downstream_consumers() {
    let bytes = member_zip();
    let policy = Policy::default_v1();
    let plan = RetentionPlan::new(14, 14).with_path("METADATA").unwrap();
    let options = ApplyOptions::new().with_retention(plan);
    let outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("example.whl"),
                data: &bytes,
            },
            policy: &policy,
            dest: None,
        },
        &options,
    );

    let archive = outcome.verified_archive().expect("verified capability");
    assert_eq!(
        archive.retention_status("METADATA"),
        RetentionStatus::Retained
    );
    assert_eq!(
        archive.retained_member("METADATA"),
        Some(b"Name: example\n".as_slice())
    );
}
