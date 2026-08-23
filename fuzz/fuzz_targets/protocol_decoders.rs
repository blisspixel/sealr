#![no_main]

use libfuzzer_sys::fuzz_target;
use sealr_worker_protocol::{
    decode_result, decode_start, encode_result, encode_start, ExecutionMode, FindingSeverity,
    InterpretationProfile, ManifestEntry, ManifestKind, ProtocolFinding, ResourceLimits,
    StartRequest, WorkerResult, WorkerStatus,
};

const OPERATION_ID: [u8; 16] = [0x42; 16];

fn sample_start() -> Vec<u8> {
    encode_start(&StartRequest {
        operation_id: OPERATION_ID,
        mode: ExecutionMode::Materialize,
        interpretation_profile: InterpretationProfile::StrictAsciiV2,
        member_sync: true,
        capability_count: 2,
        source_capability: 0,
        stage_capability: Some(1),
        source_len: 1_024,
        source_sha256: [0x11; 32],
        interpretation_profile_sha256: [0x22; 32],
        policy_sha256: [0x33; 32],
        limits: ResourceLimits {
            max_archive_bytes: 2_048,
            max_files: 100,
            max_member_bytes: 4_096,
            max_total_bytes: 16_384,
            max_ratio: Some(100),
            max_path_depth: 16,
            max_metadata_bytes: 512,
        },
    })
    .expect("constant start request is valid")
}

fn sample_result() -> Vec<u8> {
    encode_result(&WorkerResult {
        operation_id: OPERATION_ID,
        status: WorkerStatus::Complete,
        interpretation_profile_sha256: [0x22; 32],
        layout_root: Some([0x44; 32]),
        content_root: Some([0x55; 32]),
        manifest: vec![
            ManifestEntry {
                path: "pkg".into(),
                kind: ManifestKind::Directory,
                size: 0,
                sha256: [0; 32],
            },
            ManifestEntry {
                path: "pkg/data.txt".into(),
                kind: ManifestKind::File,
                size: 7,
                sha256: [0x66; 32],
            },
        ],
        findings: vec![ProtocolFinding {
            severity: FindingSeverity::Warning,
            code: "archive.note".into(),
            detail: "bounded warning".into(),
            member_path: Some("pkg/data.txt".into()),
        }],
    })
    .expect("constant result is valid")
}

fn exercise_start(input: &[u8]) {
    for received_capabilities in 0..=3 {
        if let Ok(decoded) = decode_start(input, received_capabilities) {
            let canonical = encode_start(&decoded).expect("decoded start must encode");
            assert_eq!(canonical, input);
            assert_eq!(
                decode_start(&canonical, received_capabilities).unwrap(),
                decoded
            );
        }
    }
}

fn exercise_result(input: &[u8]) {
    let mut expected_operation_id = OPERATION_ID;
    if let Some(bytes) = input.get(16..32) {
        expected_operation_id.copy_from_slice(bytes);
    }
    if let Ok(decoded) = decode_result(input, expected_operation_id, 0) {
        let canonical = encode_result(&decoded).expect("decoded result must encode");
        assert_eq!(canonical, input);
        assert_eq!(
            decode_result(&canonical, expected_operation_id, 0).unwrap(),
            decoded
        );
    }
}

fn mutate(seed: &mut [u8], input: &[u8]) {
    for mutation in input.chunks_exact(3).take(64) {
        let index = usize::from(u16::from_le_bytes([mutation[0], mutation[1]])) % seed.len();
        seed[index] = mutation[2];
    }
}

fuzz_target!(|input: &[u8]| {
    exercise_start(input);
    exercise_result(input);

    let mut start = sample_start();
    mutate(&mut start, input);
    exercise_start(&start);

    let mut result = sample_result();
    mutate(&mut result, input);
    exercise_result(&result);
});
