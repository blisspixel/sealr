use std::collections::BTreeMap;
use std::io::{Cursor, Write};

use sealr::wheel::{evaluate_wheel, WheelEvaluation, WheelLimits, CONSUMER_PROFILE_ID};
use sealr::{
    apply_supervised, apply_with_options, AdmissionStatus, ApplyOptions, ArchiveFormat,
    LinuxWorker, MemberReadErrorKind, Policy, Request, RetentionPlan, RetentionStatus,
    SevenZInterpretationProfile, Source, TarBzip2InterpretationProfile,
    TarGnuLongNameInterpretationProfile, TarGzipInterpretationProfile, TarInterpretationProfile,
    TarPaxInterpretationProfile, TarXzInterpretationProfile, TarZstdInterpretationProfile,
    TreeRoot, VerificationStatus, VerifiedArchive, ZipInterpretationProfile,
    SEVENZ_COPY_PORTABLE_V1, TAR_BZIP2_USTAR_PORTABLE_V1, TAR_GNU_LONGNAME_PORTABLE_V1,
    TAR_GZIP_GNU_LONGNAME_PORTABLE_V1, TAR_GZIP_PAX_PORTABLE_V1, TAR_PAX_PORTABLE_V1,
    TAR_USTAR_PORTABLE_V1, TAR_XZ_USTAR_PORTABLE_V1, TAR_ZSTD_USTAR_PORTABLE_V1,
    ZIP_STRICT_ASCII_V2,
};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

// A canonical ZIP32 archive containing stored `hello.txt` with bytes `hello`.
const HELLO_ZIP: &[u8] = &[
    // Local file header.
    0x50, 0x4b, 0x03, 0x04, // signature
    0x14, 0x00, // version needed
    0x00, 0x00, // flags
    0x00, 0x00, // Store
    0x00, 0x00, 0x00, 0x00, // time and date
    0x86, 0xa6, 0x10, 0x36, // CRC32
    0x05, 0x00, 0x00, 0x00, // compressed size
    0x05, 0x00, 0x00, 0x00, // uncompressed size
    0x09, 0x00, // filename length
    0x00, 0x00, // extra length
    b'h', b'e', b'l', b'l', b'o', b'.', b't', b'x', b't', // hello.txt
    b'h', b'e', b'l', b'l', b'o', // payload
    // Central directory header.
    0x50, 0x4b, 0x01, 0x02, // signature
    0x14, 0x00, // version made by
    0x14, 0x00, // version needed
    0x00, 0x00, // flags
    0x00, 0x00, // Store
    0x00, 0x00, 0x00, 0x00, // time and date
    0x86, 0xa6, 0x10, 0x36, // CRC32
    0x05, 0x00, 0x00, 0x00, // compressed size
    0x05, 0x00, 0x00, 0x00, // uncompressed size
    0x09, 0x00, // filename length
    0x00, 0x00, // extra length
    0x00, 0x00, // comment length
    0x00, 0x00, // disk start
    0x00, 0x00, // internal attributes
    0x00, 0x00, 0x00, 0x00, // external attributes
    0x00, 0x00, 0x00, 0x00, // local-header offset
    b'h', b'e', b'l', b'l', b'o', b'.', b't', b'x', b't', // hello.txt
    // End of central directory.
    0x50, 0x4b, 0x05, 0x06, // signature
    0x00, 0x00, 0x00, 0x00, // disk numbers
    0x01, 0x00, 0x01, 0x00, // entry counts
    0x37, 0x00, 0x00, 0x00, // central-directory size: 55
    0x2c, 0x00, 0x00, 0x00, // central-directory offset: 44
    0x00, 0x00, // comment length
];

fn main() {
    let mut args = std::env::args_os().skip(1);
    assert_eq!(
        args.next().as_deref(),
        Some(std::ffi::OsStr::new("--worker-manifest")),
        "usage: sealr-packaged-consumer --worker-manifest <absolute-path>"
    );
    let manifest = args
        .next()
        .expect("worker manifest path is required for the packaged consumer");
    assert!(
        args.next().is_none(),
        "packaged consumer rejects unexpected arguments"
    );
    let worker = LinuxWorker::load_from_manifest(std::path::Path::new(&manifest))
        .expect("packaged crate must authenticate the selected production helper");
    let policy = Policy::default_v1();
    let retention = RetentionPlan::new(5, 5)
        .with_path("hello.txt")
        .expect("canonical bounded path");
    let options = ApplyOptions::new()
        .with_interpretation_profile(ZipInterpretationProfile::StrictAsciiV2)
        .with_retention(retention);
    let outcome = apply_supervised(
        Request {
            source: Source::Bytes {
                path: Some("hello.zip"),
                data: HELLO_ZIP,
            },
            policy: &policy,
            dest: None,
        },
        &options,
        &worker,
    )
    .expect("packaged crate must complete through the supervised boundary");

    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
    assert_eq!(outcome.archive_ir().unwrap().profile(), ZIP_STRICT_ASCII_V2);
    let archive: &VerifiedArchive = outcome
        .verified_archive()
        .expect("admitted archive must expose verified authority");
    assert_eq!(
        archive.retention_status("hello.txt"),
        RetentionStatus::Retained
    );
    assert_eq!(
        archive.retained_member("hello.txt"),
        Some(b"hello".as_slice())
    );
    assert_eq!(archive.read_member("hello.txt", 5).unwrap(), b"hello");
    assert_eq!(
        archive.read_member("hello.txt", 4).unwrap_err().kind(),
        MemberReadErrorKind::LimitExceeded
    );

    let retained: VerifiedArchive = outcome
        .into_verified_archive()
        .expect("capability remains available when taken from the outcome");
    assert_eq!(retained.member("hello.txt").unwrap().canonical_path, "hello.txt");

    let wheel_bytes = wheel_bytes();
    let wheel_options =
        ApplyOptions::new().with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
    let wheel_outcome = apply_supervised(
        Request {
            source: Source::Bytes {
                path: Some("demo-1.0-py3-none-any.whl"),
                data: &wheel_bytes,
            },
            policy: &policy,
            dest: None,
        },
        &wheel_options,
        &worker,
    )
    .expect("packaged crate must verify the portable wheel through the supervisor");
    assert!(!wheel_outcome.rejected(), "{:?}", wheel_outcome.view.findings);
    let evaluation = evaluate_wheel(
        "demo-1.0-py3-none-any.whl",
        wheel_outcome
            .verified_archive()
            .expect("verified wheel authority"),
        WheelLimits::default(),
    );
    let WheelEvaluation::Admitted {
        artifact,
        plan,
        identities,
        ..
    } = evaluation
    else {
        panic!("packaged wheel evaluator did not admit its canonical fixture");
    };
    assert_eq!(artifact.consumer_profile, CONSUMER_PROFILE_ID);
    assert!(artifact
        .record
        .iter()
        .any(|binding| binding.path == "demo/caf\u{e9}.py"));
    assert_eq!(plan.artifact_sha256(), identities.artifact_sha256);

    let tar_policy = Policy::default_v2();
    let tar_options = ApplyOptions::new()
        .with_tar_interpretation_profile(TarInterpretationProfile::UstarPortableV1)
        .with_retention(
            RetentionPlan::new(8, 8)
                .with_path("retained.txt")
                .expect("canonical TAR retention path"),
        );
    let tar_outcome = {
        let tar_bytes = portable_tar();
        apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("portable.tar"),
                    data: &tar_bytes,
                },
                policy: &tar_policy,
                dest: None,
            },
            &tar_options,
        )
    };
    assert!(!tar_outcome.rejected(), "{:?}", tar_outcome.view.findings);
    let tar_ir = tar_outcome.archive_ir().expect("portable TAR IR");
    assert_eq!(tar_ir.format(), ArchiveFormat::TarUstar);
    assert_eq!(tar_ir.profile(), TAR_USTAR_PORTABLE_V1);
    assert!(matches!(
        tar_outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV2 { .. }
    ));
    let tar_archive = tar_outcome
        .into_verified_archive()
        .expect("portable TAR must expose verified authority");
    assert_eq!(
        tar_archive.retention_status("retained.txt"),
        RetentionStatus::Retained
    );
    assert_eq!(
        tar_archive.retained_member("retained.txt"),
        Some(b"retained".as_slice())
    );
    assert_eq!(tar_archive.read_member("later.txt", 5).unwrap(), b"later");

    let pax_policy = Policy::default_v5();
    let pax_options = ApplyOptions::new()
        .with_tar_pax_interpretation_profile(TarPaxInterpretationProfile::PortableV1)
        .with_retention(
            RetentionPlan::new(4, 4)
                .with_path("mars/retained.txt")
                .expect("canonical PAX retention path"),
        );
    let pax_outcome = {
        let pax_bytes = portable_pax();
        apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("portable-pax.tar"),
                    data: &pax_bytes,
                },
                policy: &pax_policy,
                dest: None,
            },
            &pax_options,
        )
    };
    assert!(!pax_outcome.rejected(), "{:?}", pax_outcome.view.findings);
    let pax_ir = pax_outcome.archive_ir().expect("portable PAX IR");
    assert_eq!(pax_ir.format(), ArchiveFormat::TarPax);
    assert_eq!(pax_ir.profile(), TAR_PAX_PORTABLE_V1);
    assert_eq!(pax_ir.pax_extensions().expect("PAX extension evidence").len(), 1);
    assert!(matches!(
        pax_outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV5 { .. }
    ));
    let pax_archive = pax_outcome
        .into_verified_archive()
        .expect("portable PAX must expose verified authority");
    assert_eq!(
        pax_archive.retention_status("mars/retained.txt"),
        RetentionStatus::Retained
    );
    assert_eq!(
        pax_archive.retained_member("mars/retained.txt"),
        Some(b"mars".as_slice())
    );
    assert_eq!(
        pax_archive.read_member("mars/retained.txt", 4).unwrap(),
        b"mars"
    );

    let gnu_path = format!("mission/{}/status.txt", "segment".repeat(15));
    let gnu_policy = Policy::default_v6();
    let gnu_options = ApplyOptions::new()
        .with_tar_gnu_longname_interpretation_profile(
            TarGnuLongNameInterpretationProfile::PortableV1,
        )
        .with_retention(
            RetentionPlan::new(7, 7)
                .with_path(&gnu_path)
                .expect("canonical GNU long-name retention path"),
        );
    let gnu_outcome = {
        let gnu_bytes = portable_gnu_longname(&gnu_path);
        apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("portable-gnu.tar"),
                    data: &gnu_bytes,
                },
                policy: &gnu_policy,
                dest: None,
            },
            &gnu_options,
        )
    };
    assert!(!gnu_outcome.rejected(), "{:?}", gnu_outcome.view.findings);
    let gnu_ir = gnu_outcome.archive_ir().expect("portable GNU long-name IR");
    assert_eq!(gnu_ir.format(), ArchiveFormat::TarGnuLongName);
    assert_eq!(gnu_ir.profile(), TAR_GNU_LONGNAME_PORTABLE_V1);
    assert_eq!(
        gnu_ir
            .gnu_longname_carriers()
            .expect("GNU carrier evidence")
            .len(),
        1
    );
    assert!(matches!(
        gnu_outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV6 { .. }
    ));
    let gnu_archive = gnu_outcome
        .into_verified_archive()
        .expect("portable GNU long-name TAR must expose verified authority");
    assert_eq!(
        gnu_archive.retention_status(&gnu_path),
        RetentionStatus::Retained
    );
    assert_eq!(
        gnu_archive.retained_member(&gnu_path),
        Some(b"nominal".as_slice())
    );
    assert_eq!(gnu_archive.read_member(&gnu_path, 7).unwrap(), b"nominal");

    let gzip_pax_policy = Policy::default_v7();
    let gzip_pax_options = ApplyOptions::new()
        .with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::PaxPortableV1)
        .with_retention(
            RetentionPlan::new(4, 4)
                .with_path("mars/retained.txt")
                .expect("canonical gzip-wrapped PAX retention path"),
        );
    let gzip_pax_tar = portable_pax();
    let gzip_pax_outcome = {
        let gzip_pax_bytes = gzip_wrapped(&gzip_pax_tar);
        apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("portable-pax.tar.gz"),
                    data: &gzip_pax_bytes,
                },
                policy: &gzip_pax_policy,
                dest: None,
            },
            &gzip_pax_options,
        )
    };
    assert!(
        !gzip_pax_outcome.rejected(),
        "{:?}",
        gzip_pax_outcome.view.findings
    );
    let gzip_pax_ir = gzip_pax_outcome.archive_ir().expect("gzip-wrapped PAX IR");
    assert_eq!(gzip_pax_ir.format(), ArchiveFormat::TarGzipPax);
    assert_eq!(gzip_pax_ir.profile(), TAR_GZIP_PAX_PORTABLE_V1);
    let gzip_pax_wrapper = gzip_pax_ir
        .gzip_evidence()
        .expect("gzip-wrapped PAX wrapper evidence");
    assert_eq!(gzip_pax_wrapper.derived_output_len, gzip_pax_tar.len() as u64);
    assert_eq!(
        gzip_pax_ir
            .tar_pax_evidence()
            .expect("gzip-wrapped PAX extension evidence")
            .extensions
            .len(),
        1
    );
    assert!(matches!(
        gzip_pax_outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV7 { .. }
    ));
    let gzip_pax_archive = gzip_pax_outcome
        .into_verified_archive()
        .expect("gzip-wrapped PAX must expose verified authority");
    assert_eq!(
        gzip_pax_archive.retention_status("mars/retained.txt"),
        RetentionStatus::Retained
    );
    assert_eq!(
        gzip_pax_archive.retained_member("mars/retained.txt"),
        Some(b"mars".as_slice())
    );
    assert_eq!(
        gzip_pax_archive.read_member("mars/retained.txt", 4).unwrap(),
        b"mars"
    );

    let gzip_gnu_policy = Policy::default_v7();
    let gzip_gnu_options = ApplyOptions::new()
        .with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::GnuLongNamePortableV1)
        .with_retention(
            RetentionPlan::new(7, 7)
                .with_path(&gnu_path)
                .expect("canonical gzip-wrapped GNU long-name retention path"),
        );
    let gzip_gnu_tar = portable_gnu_longname(&gnu_path);
    let gzip_gnu_outcome = {
        let gzip_gnu_bytes = gzip_wrapped(&gzip_gnu_tar);
        apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("portable-gnu.tar.gz"),
                    data: &gzip_gnu_bytes,
                },
                policy: &gzip_gnu_policy,
                dest: None,
            },
            &gzip_gnu_options,
        )
    };
    assert!(
        !gzip_gnu_outcome.rejected(),
        "{:?}",
        gzip_gnu_outcome.view.findings
    );
    let gzip_gnu_ir = gzip_gnu_outcome
        .archive_ir()
        .expect("gzip-wrapped GNU long-name IR");
    assert_eq!(gzip_gnu_ir.format(), ArchiveFormat::TarGzipGnuLongName);
    assert_eq!(gzip_gnu_ir.profile(), TAR_GZIP_GNU_LONGNAME_PORTABLE_V1);
    let gzip_gnu_wrapper = gzip_gnu_ir
        .gzip_evidence()
        .expect("gzip-wrapped GNU long-name wrapper evidence");
    assert_eq!(gzip_gnu_wrapper.derived_output_len, gzip_gnu_tar.len() as u64);
    assert_eq!(
        gzip_gnu_ir
            .tar_gnu_longname_evidence()
            .expect("gzip-wrapped GNU carrier evidence")
            .carriers
            .len(),
        1
    );
    assert!(matches!(
        gzip_gnu_outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV8 { .. }
    ));
    let gzip_gnu_archive = gzip_gnu_outcome
        .into_verified_archive()
        .expect("gzip-wrapped GNU long-name TAR must expose verified authority");
    assert_eq!(
        gzip_gnu_archive.retention_status(&gnu_path),
        RetentionStatus::Retained
    );
    assert_eq!(
        gzip_gnu_archive.retained_member(&gnu_path),
        Some(b"nominal".as_slice())
    );
    assert_eq!(gzip_gnu_archive.read_member(&gnu_path, 7).unwrap(), b"nominal");

    let zstd_policy = Policy::default_v8();
    let zstd_options = ApplyOptions::new()
        .with_tar_zstd_interpretation_profile(TarZstdInterpretationProfile::UstarPortableV1)
        .with_retention(
            RetentionPlan::new(8, 8)
                .with_path("retained.txt")
                .expect("canonical zstd-wrapped TAR retention path"),
        );
    let zstd_tar = portable_tar();
    let zstd_outcome = {
        let zstd_bytes = zstd_wrapped(&zstd_tar);
        apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("portable.tar.zst"),
                    data: &zstd_bytes,
                },
                policy: &zstd_policy,
                dest: None,
            },
            &zstd_options,
        )
    };
    assert!(
        matches!(zstd_outcome.admission, AdmissionStatus::Admitted),
        "{:?}",
        zstd_outcome.view.findings
    );
    assert!(matches!(
        zstd_outcome.verification,
        VerificationStatus::Complete
    ));
    let zstd_ir = zstd_outcome.archive_ir().expect("zstd-wrapped ustar IR");
    assert_eq!(zstd_ir.format(), ArchiveFormat::TarZstdUstar);
    assert_eq!(zstd_ir.profile(), TAR_ZSTD_USTAR_PORTABLE_V1);
    let zstd_wrapper = zstd_ir
        .zstd_evidence()
        .expect("zstd-wrapped ustar wrapper evidence");
    assert_eq!(zstd_wrapper.derived_output_len, zstd_tar.len() as u64);
    assert!(matches!(
        zstd_outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV9 { .. }
    ));
    let zstd_archive = zstd_outcome
        .into_verified_archive()
        .expect("zstd-wrapped portable ustar must expose verified authority");
    assert_eq!(
        zstd_archive.retention_status("retained.txt"),
        RetentionStatus::Retained
    );
    assert_eq!(
        zstd_archive.retained_member("retained.txt"),
        Some(b"retained".as_slice())
    );
    assert_eq!(zstd_archive.read_member("later.txt", 5).unwrap(), b"later");
    assert_eq!(
        zstd_archive.read_member("later.txt", 4).unwrap_err().kind(),
        MemberReadErrorKind::LimitExceeded
    );

    let xz_policy = Policy::default_v9();
    let xz_options = ApplyOptions::new()
        .with_tar_xz_interpretation_profile(TarXzInterpretationProfile::UstarPortableV1)
        .with_retention(
            RetentionPlan::new(8, 8)
                .with_path("retained.txt")
                .expect("canonical xz-wrapped TAR retention path"),
        );
    let xz_tar = portable_tar();
    let xz_outcome = {
        let xz_bytes = xz_wrapped(&xz_tar);
        apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("portable.tar.xz"),
                    data: &xz_bytes,
                },
                policy: &xz_policy,
                dest: None,
            },
            &xz_options,
        )
    };
    assert!(
        matches!(xz_outcome.admission, AdmissionStatus::Admitted),
        "{:?}",
        xz_outcome.view.findings
    );
    assert!(matches!(
        xz_outcome.verification,
        VerificationStatus::Complete
    ));
    let xz_ir = xz_outcome.archive_ir().expect("xz-wrapped ustar IR");
    assert_eq!(xz_ir.format(), ArchiveFormat::TarXzUstar);
    assert_eq!(xz_ir.profile(), TAR_XZ_USTAR_PORTABLE_V1);
    let xz_wrapper = xz_ir.xz_evidence().expect("xz-wrapped ustar wrapper evidence");
    assert_eq!(xz_wrapper.derived_output_len, xz_tar.len() as u64);
    assert_eq!(xz_wrapper.blocks.len(), 1);
    assert!(matches!(
        xz_outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV10 { .. }
    ));
    let xz_archive = xz_outcome
        .into_verified_archive()
        .expect("xz-wrapped portable ustar must expose verified authority");
    assert_eq!(
        xz_archive.retention_status("retained.txt"),
        RetentionStatus::Retained
    );
    assert_eq!(
        xz_archive.retained_member("retained.txt"),
        Some(b"retained".as_slice())
    );
    assert_eq!(xz_archive.read_member("later.txt", 5).unwrap(), b"later");
    assert_eq!(
        xz_archive.read_member("later.txt", 4).unwrap_err().kind(),
        MemberReadErrorKind::LimitExceeded
    );

    // The bzip2 format has no stored mode, so the packaged consumer replays
    // pinned producer bytes (CPython 3.12.10 `bz2.compress(tar, 9)` over the
    // conformance TAR carrying `mission/plan.txt`).
    let bzip2_policy = Policy::default_v10();
    let bzip2_options = ApplyOptions::new()
        .with_tar_bzip2_interpretation_profile(TarBzip2InterpretationProfile::UstarPortableV1)
        .with_retention(
            RetentionPlan::new(32, 32)
                .with_path("mission/plan.txt")
                .expect("canonical bzip2-wrapped TAR retention path"),
        );
    let bzip2_bytes = decode_hex(TAR_BZIP2_LEVEL9_FIXTURE_HEX);
    let bzip2_outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.tar.bz2"),
                data: &bzip2_bytes,
            },
            policy: &bzip2_policy,
            dest: None,
        },
        &bzip2_options,
    );
    assert!(
        matches!(bzip2_outcome.admission, AdmissionStatus::Admitted),
        "{:?}",
        bzip2_outcome.view.findings
    );
    assert!(matches!(
        bzip2_outcome.verification,
        VerificationStatus::Complete
    ));
    let bzip2_ir = bzip2_outcome.archive_ir().expect("bzip2-wrapped ustar IR");
    assert_eq!(bzip2_ir.format(), ArchiveFormat::TarBzip2Ustar);
    assert_eq!(bzip2_ir.profile(), TAR_BZIP2_USTAR_PORTABLE_V1);
    let bzip2_wrapper = bzip2_ir
        .bzip2_evidence()
        .expect("bzip2-wrapped ustar wrapper evidence");
    assert_eq!(bzip2_wrapper.level, 9);
    assert_eq!(bzip2_wrapper.block_crcs.len(), 1);
    assert_eq!(bzip2_wrapper.derived_output_len, 2048);
    assert!(matches!(
        bzip2_outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV11 { .. }
    ));
    let bzip2_archive = bzip2_outcome
        .into_verified_archive()
        .expect("bzip2-wrapped portable ustar must expose verified authority");
    assert_eq!(
        bzip2_archive.retention_status("mission/plan.txt"),
        RetentionStatus::Retained
    );
    assert_eq!(
        bzip2_archive.retained_member("mission/plan.txt"),
        Some(b"verify twice, decode once".as_slice())
    );
    assert_eq!(
        bzip2_archive.read_member("mission/plan.txt", 25).unwrap(),
        b"verify twice, decode once"
    );
    assert_eq!(
        bzip2_archive
            .read_member("mission/plan.txt", 24)
            .unwrap_err()
            .kind(),
        MemberReadErrorKind::LimitExceeded
    );

    // The restricted Copy 7z container replays pinned 7-Zip 26.02
    // `7z a -m0=Copy -mhc=off` bytes carrying `mission/plan.txt` — the first
    // container profile beyond ZIP, with zero new dependencies.
    let sevenz_policy = Policy::default_v11();
    let sevenz_options = ApplyOptions::new()
        .with_sevenz_interpretation_profile(SevenZInterpretationProfile::CopyPortableV1)
        .with_retention(
            RetentionPlan::new(32, 32)
                .with_path("mission/plan.txt")
                .expect("canonical 7z retention path"),
        );
    let sevenz_bytes = decode_hex(SEVENZ_COPY_FILEONLY_FIXTURE_HEX);
    let sevenz_outcome = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("mission.7z"),
                data: &sevenz_bytes,
            },
            policy: &sevenz_policy,
            dest: None,
        },
        &sevenz_options,
    );
    assert!(
        matches!(sevenz_outcome.admission, AdmissionStatus::Admitted),
        "{:?}",
        sevenz_outcome.view.findings
    );
    assert!(matches!(
        sevenz_outcome.verification,
        VerificationStatus::Complete
    ));
    let sevenz_ir = sevenz_outcome.archive_ir().expect("7z Copy IR");
    assert_eq!(sevenz_ir.format(), ArchiveFormat::SevenZCopy);
    assert_eq!(sevenz_ir.profile(), SEVENZ_COPY_PORTABLE_V1);
    let sevenz_evidence = sevenz_ir
        .sevenz_evidence()
        .expect("7z Copy container evidence");
    assert_eq!(sevenz_evidence.version_minor, 4);
    assert_eq!(sevenz_evidence.folders.len(), 1);
    assert_eq!(
        sevenz_evidence.folders[0].substreams[0].declared_crc,
        Some(0x6541_B403)
    );
    assert!(matches!(
        sevenz_outcome.receipt.identities.layout,
        TreeRoot::SealrTreeV12 { .. }
    ));
    let sevenz_archive = sevenz_outcome
        .into_verified_archive()
        .expect("7z Copy container must expose verified authority");
    assert_eq!(
        sevenz_archive.retention_status("mission/plan.txt"),
        RetentionStatus::Retained
    );
    assert_eq!(
        sevenz_archive.retained_member("mission/plan.txt"),
        Some(b"verify twice, decode once".as_slice())
    );
    assert_eq!(
        sevenz_archive.read_member("mission/plan.txt", 25).unwrap(),
        b"verify twice, decode once"
    );
    assert_eq!(
        sevenz_archive
            .read_member("mission/plan.txt", 24)
            .unwrap_err()
            .kind(),
        MemberReadErrorKind::LimitExceeded
    );
}

/// 7-Zip 26.02 `7z a -m0=Copy -mhc=off` output holding exactly
/// `mission/plan.txt` with `verify twice, decode once`.
const SEVENZ_COPY_FILEONLY_FIXTURE_HEX: &str =
    "377abcaf271c000435c12a4919000000000000005a00000000000000eaaeb7e6766572696679207477696365\n     2c206465636f6465206f6e63650104060001091900070b01000101000c1900080a0103b44165000005011123\n     006d0069007300730069006f006e002f0070006c0061006e002e0074007800740000001900140a01000000d4\n     bda237dd0115060100200000000000";

/// CPython 3.12.10 `bz2.compress(tar, 9)` over the conformance derived TAR
/// (bundled libbz2 1.0.8; byte-identical to `bzip2 -9`).
const TAR_BZIP2_LEVEL9_FIXTURE_HEX: &str =
    "425a68393141592653597b1dc2a70000447b91ca0000404005ff0040006f27dfe004000040000820007422\
     6a64f51a64d0340640c4d064a0d341a680034d001e6587e2308c005913503e46a2880842162fc4d83544cc\
     801bd752180f90d0c026e224716664838d467b58fbfac1cf118147687b09c160a4ad2080f498e75a99561f\
     215194f509f0637e2ee48a70a120f63b854e";

fn decode_hex(value: &str) -> Vec<u8> {
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(cleaned.len() % 2 == 0);
    (0..cleaned.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&cleaned[index..index + 2], 16).expect("fixture hex is valid")
        })
        .collect()
}

fn portable_tar() -> Vec<u8> {
    let mut bytes = Vec::new();
    for (name, body) in [
        ("retained.txt", b"retained".as_slice()),
        ("later.txt", b"later".as_slice()),
    ] {
        bytes.extend_from_slice(&ustar_header(name, body.len()));
        bytes.extend_from_slice(body);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
    }
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

fn portable_pax() -> Vec<u8> {
    let payload = [pax_record("path", "mars/retained.txt"), pax_record("size", "4")].concat();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&ustar_header_with_type("PaxHeaders/entry", payload.len(), b'x'));
    bytes.extend_from_slice(&payload);
    bytes.resize(bytes.len().next_multiple_of(512), 0);
    bytes.extend_from_slice(&ustar_header_with_type("placeholder", 99, b'0'));
    bytes.extend_from_slice(b"mars");
    bytes.resize(bytes.len().next_multiple_of(512), 0);
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

fn portable_gnu_longname(path: &str) -> Vec<u8> {
    let mut carrier_payload = path.as_bytes().to_vec();
    carrier_payload.push(0);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&old_gnu_header(
        "producer-carrier",
        carrier_payload.len(),
        b'L',
    ));
    bytes.extend_from_slice(&carrier_payload);
    bytes.resize(bytes.len().next_multiple_of(512), 0);
    bytes.extend_from_slice(&old_gnu_header("opaque-base", 7, b'0'));
    bytes.extend_from_slice(b"nominal");
    bytes.resize(bytes.len().next_multiple_of(512), 0);
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

// A deterministic gzip member holding one stored (uncompressed) Deflate block,
// so the exact wrapper bytes remain reviewable without a compression dependency.
fn gzip_wrapped(tar: &[u8]) -> Vec<u8> {
    let len =
        u16::try_from(tar.len()).expect("consumer TAR fixture fits one stored Deflate block");
    let mut bytes = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255, 0x01];
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(&(!len).to_le_bytes());
    bytes.extend_from_slice(tar);
    bytes.extend_from_slice(&crc32(tar).to_le_bytes());
    bytes.extend_from_slice(&(tar.len() as u32).to_le_bytes());
    bytes
}

// A handcrafted RFC 8878 zstd frame carrying its derived TAR as one raw
// (uncompressed) block with no content checksum, so the exact wrapper bytes
// remain reviewable without a compression dependency.
fn zstd_wrapped(tar: &[u8]) -> Vec<u8> {
    let mut bytes = 0xFD2F_B528_u32.to_le_bytes().to_vec();
    bytes.push(0x00);
    bytes.push(0x08);
    let block_header = ((tar.len() as u32) << 3) | 1;
    bytes.extend_from_slice(&block_header.to_le_bytes()[..3]);
    bytes.extend_from_slice(tar);
    bytes
}

// A handcrafted single-stream XZ container carrying its derived TAR as
// uncompressed LZMA2 chunks with a CRC32 check, so the exact wrapper bytes
// remain reviewable without a compression dependency.
fn xz_wrapped(tar: &[u8]) -> Vec<u8> {
    fn push_varint(out: &mut Vec<u8>, mut value: u64) {
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    }

    let mut lzma2 = Vec::new();
    let mut first = true;
    for chunk in tar.chunks(0xFFFF) {
        lzma2.push(if first { 0x01 } else { 0x02 });
        first = false;
        let size = (chunk.len() - 1) as u16;
        lzma2.extend_from_slice(&size.to_be_bytes());
        lzma2.extend_from_slice(chunk);
    }
    lzma2.push(0x00);

    let check_value = crc32(tar).to_le_bytes();

    let mut header = vec![0_u8; 2];
    push_varint(&mut header, 0x21);
    push_varint(&mut header, 1);
    header.push(22);
    while (header.len() + 4) % 4 != 0 {
        header.push(0);
    }
    header[0] = ((header.len() + 4) / 4 - 1) as u8;
    let header_crc = crc32(&header);
    header.extend_from_slice(&header_crc.to_le_bytes());

    let mut stream = vec![0xFD, b'7', b'z', b'X', b'Z', 0x00];
    stream.push(0);
    stream.push(0x01);
    stream.extend_from_slice(&crc32(&[0, 0x01]).to_le_bytes());

    let block_start = stream.len();
    stream.extend_from_slice(&header);
    stream.extend_from_slice(&lzma2);
    let unpadded = (stream.len() - block_start + check_value.len()) as u64;
    while (stream.len() - block_start) % 4 != 0 {
        stream.push(0);
    }
    stream.extend_from_slice(&check_value);

    let index_start = stream.len();
    stream.push(0);
    push_varint(&mut stream, 1);
    push_varint(&mut stream, unpadded);
    push_varint(&mut stream, tar.len() as u64);
    while (stream.len() - index_start) % 4 != 0 {
        stream.push(0);
    }
    let index_crc = crc32(&stream[index_start..]);
    stream.extend_from_slice(&index_crc.to_le_bytes());
    let index_len = stream.len() - index_start;

    let backward = (index_len as u32 / 4) - 1;
    let mut footer_body = backward.to_le_bytes().to_vec();
    footer_body.push(0);
    footer_body.push(0x01);
    stream.extend_from_slice(&crc32(&footer_body).to_le_bytes());
    stream.extend_from_slice(&footer_body);
    stream.extend_from_slice(b"YZ");
    stream
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let body = format!(" {key}={value}\n");
    let mut digits = 1_usize;
    loop {
        let length = digits + body.len();
        let next_digits = length.to_string().len();
        if digits == next_digits {
            return format!("{length}{body}").into_bytes();
        }
        digits = next_digits;
    }
}

fn ustar_header(name: &str, body_len: usize) -> [u8; 512] {
    ustar_header_with_type(name, body_len, b'0')
}

fn ustar_header_with_type(name: &str, body_len: usize, typeflag: u8) -> [u8; 512] {
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    write_ustar_octal(&mut header[100..108], 0o644);
    write_ustar_octal(&mut header[108..116], 0);
    write_ustar_octal(&mut header[116..124], 0);
    write_ustar_octal(&mut header[124..136], body_len as u64);
    write_ustar_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = typeflag;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
    header[154] = 0;
    header[155] = b' ';
    header
}

fn old_gnu_header(name: &str, body_len: usize, typeflag: u8) -> [u8; 512] {
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    write_ustar_octal(&mut header[100..108], 0o644);
    write_ustar_octal(&mut header[108..116], 0);
    write_ustar_octal(&mut header[116..124], 0);
    write_ustar_octal(&mut header[124..136], body_len as u64);
    write_ustar_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = typeflag;
    header[257..265].copy_from_slice(b"ustar  \0");
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
    header[154] = 0;
    header[155] = b' ';
    header
}

fn write_ustar_octal(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let octal = format!("{value:o}");
    let digit_len = field.len() - 1;
    field[digit_len - octal.len()..digit_len].copy_from_slice(octal.as_bytes());
    field[digit_len] = 0;
}

fn wheel_bytes() -> Vec<u8> {
    let mut files = BTreeMap::new();
    files.insert("demo/__init__.py".to_owned(), b"VALUE = 1\n".to_vec());
    files.insert(
        "demo/caf\u{e9}.py".to_owned(),
        b"VALUE = 'unicode'\n".to_vec(),
    );
    files.insert(
        "demo-1.0.dist-info/WHEEL".to_owned(),
        b"Wheel-Version: 1.0\nGenerator: packaged-consumer\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n".to_vec(),
    );
    files.insert(
        "demo-1.0.dist-info/METADATA".to_owned(),
        b"Metadata-Version: 2.4\nName: demo\nVersion: 1.0\n\n".to_vec(),
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
        let options =
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (path, bytes) in files {
            writer.start_file(path, options).expect("start wheel member");
            writer.write_all(&bytes).expect("write wheel member");
        }
        writer.finish().expect("finish wheel");
    }
    cursor.into_inner()
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
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
