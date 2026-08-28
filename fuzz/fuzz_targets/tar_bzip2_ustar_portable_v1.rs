#![no_main]

use libfuzzer_sys::fuzz_target;
use sealr::{
    apply_with_options, ApplyOptions, ArchiveFormat, EffectStatus, Policy, Request, Source,
    TarBzip2InterpretationProfile,
};

const MAX_INPUT_BYTES: usize = 262_144;

fuzz_target!(|input: &[u8]| {
    if input.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut policy = Policy::default_v10();
    policy.max_archive_bytes = MAX_INPUT_BYTES as u64;
    policy.max_derived_archive_bytes = Some(131_072);
    policy.max_metadata_bytes = 32_768;
    policy.max_files = 64;
    policy.max_member_bytes = 32_768;
    policy.max_total_bytes = 65_536;
    policy.max_path_depth = 16;
    policy.max_ratio = Some(32);
    let options = ApplyOptions::new()
        .with_tar_bzip2_interpretation_profile(TarBzip2InterpretationProfile::UstarPortableV1);

    let inspect = || {
        apply_with_options(
            Request {
                source: Source::Bytes {
                    path: Some("fuzz.tar.bz2"),
                    data: input,
                },
                policy: &policy,
                dest: None,
            },
            &options,
        )
    };
    let first = inspect();
    let second = inspect();

    assert_eq!(first.interpretation, second.interpretation);
    assert_eq!(first.admission, second.admission);
    assert_eq!(first.verification, second.verification);
    assert_eq!(first.effect, EffectStatus::NotRequested);
    assert_eq!(first.effect, second.effect);
    assert_eq!(first.view_completeness, second.view_completeness);
    assert_eq!(first.rejected(), second.rejected());
    assert!(!first.wrote());
    assert!(!second.wrote());
    assert_eq!(first.view.findings, second.view.findings);
    assert_eq!(first.receipt.findings, second.receipt.findings);
    assert_eq!(first.receipt.source, second.receipt.source);
    assert_eq!(first.receipt.policy.digest, second.receipt.policy.digest);
    assert_eq!(first.receipt.view_digest, second.receipt.view_digest);
    assert_eq!(
        format!("{:?}", first.receipt.identities),
        format!("{:?}", second.receipt.identities)
    );
    assert_eq!(
        format!("{:?}", first.view.members),
        format!("{:?}", second.view.members)
    );
    assert_eq!(
        format!("{:?}", first.archive_ir()),
        format!("{:?}", second.archive_ir())
    );

    assert_eq!(
        first.receipt.identities.interpretation.id,
        "sealr.profile.tar-bzip2.ustar-portable.v1"
    );
    assert_ne!(
        first.receipt.identities.interpretation.id,
        "sealr.profile.tar.ustar-portable.v1"
    );
    if let Some(ir) = first.archive_ir() {
        assert_eq!(ir.format(), ArchiveFormat::TarBzip2Ustar);
        assert_eq!(ir.source_digest(), &first.receipt.source);
    }
});
