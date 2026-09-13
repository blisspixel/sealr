#![no_main]

use libfuzzer_sys::fuzz_target;
use sealr::{apply_with_options, ApplyOptions, Policy, Request, Source, ZipInterpretationProfile};

fuzz_target!(|input: &[u8]| {
    let mut policy = Policy::default_v3();
    policy.max_archive_bytes = 1_048_576;
    policy.max_files = 256;
    policy.max_member_bytes = 65_536;
    policy.max_total_bytes = 262_144;
    policy.max_metadata_bytes = 262_144;
    let options = ApplyOptions::new()
        .with_interpretation_profile(ZipInterpretationProfile::Zip64StrictAsciiV1);
    let _ = apply_with_options(
        Request {
            source: Source::Bytes {
                path: Some("fuzz.zip"),
                data: input,
            },
            policy: &policy,
            dest: None,
        },
        &options,
    );
});
