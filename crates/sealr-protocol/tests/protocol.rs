use sealr_worker_protocol::{
    decode_result, decode_result_for_request, decode_start, encode_result, encode_start,
    validate_result_for_request, ExecutionMode, FindingSeverity, InterpretationProfile,
    ManifestEntry, ManifestKind, ProtocolErrorKind, ProtocolFinding, ResourceLimits, StartRequest,
    WorkerResult, WorkerStatus, FRAME_HEADER_BYTES, FRAME_MAGIC, MAX_FINDINGS, MAX_FRAME_BYTES,
    MAX_MANIFEST_MEMBERS, PROTOCOL_VERSION, START_FRAME_BYTES,
};

const OPERATION_ID: [u8; 16] = [0x42; 16];

fn start_request(mode: ExecutionMode) -> StartRequest {
    let (capability_count, stage_capability) = match mode {
        ExecutionMode::Inspect => (1, None),
        ExecutionMode::Materialize => (2, Some(1)),
    };
    StartRequest {
        operation_id: OPERATION_ID,
        mode,
        interpretation_profile: InterpretationProfile::StrictAsciiV2,
        member_sync: true,
        capability_count,
        source_capability: 0,
        stage_capability,
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
    }
}

fn complete_result() -> WorkerResult {
    WorkerResult {
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
    }
}

fn rejected_result() -> WorkerResult {
    WorkerResult {
        operation_id: OPERATION_ID,
        status: WorkerStatus::Rejected,
        interpretation_profile_sha256: [0x22; 32],
        layout_root: Some([0x44; 32]),
        content_root: None,
        manifest: Vec::new(),
        findings: vec![ProtocolFinding {
            severity: FindingSeverity::Error,
            code: "archive.rejected".into(),
            detail: "policy denied the archive".into(),
            member_path: None,
        }],
    }
}

fn error_kind<T: std::fmt::Debug>(
    result: Result<T, sealr_worker_protocol::ProtocolError>,
) -> ProtocolErrorKind {
    result.expect_err("frame must be rejected").kind
}

fn replace_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn replace_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn replace_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("test fixture contains marker")
}

#[test]
fn start_roundtrips_both_modes() {
    for mode in [ExecutionMode::Inspect, ExecutionMode::Materialize] {
        let request = start_request(mode);
        let encoded = encode_start(&request).expect("valid request encodes");
        assert_eq!(encoded.len(), START_FRAME_BYTES);
        assert_eq!(&encoded[..8], &FRAME_MAGIC);
        assert_eq!(&encoded[8..10], &PROTOCOL_VERSION.to_le_bytes());
        let decoded = decode_start(&encoded, request.capability_count).expect("frame decodes");
        assert_eq!(decoded, request);
    }
}

#[test]
fn result_roundtrips_complete_and_rejected_states() {
    for result in [complete_result(), rejected_result()] {
        let encoded = encode_result(&result).expect("valid result encodes");
        let decoded = decode_result(&encoded, OPERATION_ID, 0).expect("frame decodes");
        assert_eq!(decoded, result);
    }
}

#[test]
fn every_truncation_of_valid_frames_is_rejected() {
    let start = encode_start(&start_request(ExecutionMode::Materialize)).unwrap();
    for cut in 0..start.len() {
        assert!(decode_start(&start[..cut], 2).is_err(), "start cut {cut}");
    }

    let result = encode_result(&complete_result()).unwrap();
    for cut in 0..result.len() {
        assert!(
            decode_result(&result[..cut], OPERATION_ID, 0).is_err(),
            "result cut {cut}"
        );
    }
}

#[test]
fn header_rejects_wrong_identity_length_and_trailing_bytes() {
    let valid = encode_start(&start_request(ExecutionMode::Inspect)).unwrap();

    let mut frame = valid.clone();
    frame[0] ^= 1;
    assert_eq!(
        error_kind(decode_start(&frame, 1)),
        ProtocolErrorKind::InvalidMagic
    );

    let mut frame = valid.clone();
    replace_u16(&mut frame, 8, PROTOCOL_VERSION + 1);
    assert_eq!(
        error_kind(decode_start(&frame, 1)),
        ProtocolErrorKind::UnsupportedVersion
    );

    let mut frame = valid.clone();
    frame[10] = 2;
    assert_eq!(
        error_kind(decode_start(&frame, 1)),
        ProtocolErrorKind::UnexpectedFrameKind
    );

    let mut frame = valid.clone();
    frame[11] = 1;
    assert_eq!(
        error_kind(decode_start(&frame, 1)),
        ProtocolErrorKind::ReservedNonZero
    );

    let mut frame = valid.clone();
    replace_u32(&mut frame, 12, u32::try_from(valid.len()).unwrap());
    assert_eq!(
        error_kind(decode_start(&frame, 1)),
        ProtocolErrorKind::Truncated
    );

    let mut frame = valid;
    frame.push(0);
    assert_eq!(
        error_kind(decode_start(&frame, 1)),
        ProtocolErrorKind::TrailingBytes
    );
}

#[test]
fn oversized_frame_is_rejected_before_header_processing() {
    let frame = vec![0; MAX_FRAME_BYTES + 1];
    assert_eq!(
        error_kind(decode_start(&frame, 0)),
        ProtocolErrorKind::FrameTooLarge
    );
    assert_eq!(
        error_kind(decode_result(&frame, OPERATION_ID, 0)),
        ProtocolErrorKind::FrameTooLarge
    );
}

#[test]
fn start_rejects_invalid_fields_and_capability_sets() {
    let valid = encode_start(&start_request(ExecutionMode::Materialize)).unwrap();

    let mut frame = valid.clone();
    frame[16..32].fill(0);
    assert_eq!(
        error_kind(decode_start(&frame, 2)),
        ProtocolErrorKind::InvalidSemanticState
    );

    for (offset, value) in [(32, 9), (33, 9), (34, 2)] {
        let mut frame = valid.clone();
        frame[offset] = value;
        assert_eq!(
            error_kind(decode_start(&frame, 2)),
            ProtocolErrorKind::InvalidEnum
        );
    }

    for offset in [35, 42, 181, 200] {
        let mut frame = valid.clone();
        frame[offset] = 1;
        assert_eq!(
            error_kind(decode_start(&frame, 2)),
            ProtocolErrorKind::ReservedNonZero,
            "reserved offset {offset}"
        );
    }

    assert_eq!(
        error_kind(decode_start(&valid, 1)),
        ProtocolErrorKind::CapabilityMismatch
    );

    let mut frame = valid.clone();
    replace_u16(&mut frame, 36, 3);
    assert_eq!(
        error_kind(decode_start(&frame, 3)),
        ProtocolErrorKind::CapabilityMismatch
    );

    let mut frame = valid.clone();
    replace_u16(&mut frame, 38, 2);
    assert_eq!(
        error_kind(decode_start(&frame, 2)),
        ProtocolErrorKind::CapabilityMismatch
    );

    let mut frame = valid.clone();
    replace_u16(&mut frame, 40, 0);
    assert_eq!(
        error_kind(decode_start(&frame, 2)),
        ProtocolErrorKind::CapabilityMismatch
    );

    let mut frame = valid.clone();
    frame[32] = 0;
    assert_eq!(
        error_kind(decode_start(&frame, 2)),
        ProtocolErrorKind::CapabilityMismatch
    );

    let mut frame = valid.clone();
    replace_u64(&mut frame, 44, 2_049);
    assert_eq!(
        error_kind(decode_start(&frame, 2)),
        ProtocolErrorKind::InvalidSemanticState
    );

    let mut frame = valid;
    frame[180] = 0;
    assert_eq!(
        error_kind(decode_start(&frame, 2)),
        ProtocolErrorKind::InvalidSemanticState
    );
}

#[test]
fn result_rejects_capability_and_correlation_confusion() {
    let frame = encode_result(&complete_result()).unwrap();
    assert_eq!(
        error_kind(decode_result(&frame, OPERATION_ID, 1)),
        ProtocolErrorKind::CapabilityMismatch
    );
    assert_eq!(
        error_kind(decode_result(&frame, [0x99; 16], 0)),
        ProtocolErrorKind::CorrelationMismatch
    );
}

#[test]
fn result_counts_are_bounded_and_consistent_before_reservation() {
    let valid = encode_result(&complete_result()).unwrap();

    let mut frame = valid.clone();
    replace_u32(&mut frame, 36, MAX_MANIFEST_MEMBERS + 1);
    assert_eq!(
        error_kind(decode_result(&frame, OPERATION_ID, 0)),
        ProtocolErrorKind::LimitExceeded
    );

    let mut frame = valid.clone();
    replace_u32(&mut frame, 40, MAX_FINDINGS + 1);
    assert_eq!(
        error_kind(decode_result(&frame, OPERATION_ID, 0)),
        ProtocolErrorKind::LimitExceeded
    );

    let mut frame = valid.clone();
    replace_u32(&mut frame, 36, MAX_MANIFEST_MEMBERS);
    assert_eq!(
        error_kind(decode_result(&frame, OPERATION_ID, 0)),
        ProtocolErrorKind::CountInconsistent
    );

    let rejected = encode_result(&rejected_result()).unwrap();
    let mut frame = rejected;
    replace_u32(&mut frame, 40, MAX_FINDINGS);
    assert_eq!(
        error_kind(decode_result(&frame, OPERATION_ID, 0)),
        ProtocolErrorKind::CountInconsistent
    );
}

#[test]
fn result_rejects_reserved_root_and_state_confusion() {
    let valid = encode_result(&complete_result()).unwrap();

    for (offset, value) in [(32, 9), (33, 4), (34, 1)] {
        let mut frame = valid.clone();
        frame[offset] = value;
        let expected = if offset == 32 {
            ProtocolErrorKind::InvalidEnum
        } else {
            ProtocolErrorKind::ReservedNonZero
        };
        assert_eq!(error_kind(decode_result(&frame, OPERATION_ID, 0)), expected);
    }

    let mut frame = valid.clone();
    frame[33] &= !1;
    assert_eq!(
        error_kind(decode_result(&frame, OPERATION_ID, 0)),
        ProtocolErrorKind::InvalidSemanticState
    );

    let mut frame = valid.clone();
    frame[32] = 2;
    assert_eq!(
        error_kind(decode_result(&frame, OPERATION_ID, 0)),
        ProtocolErrorKind::InvalidSemanticState
    );

    let mut frame = valid;
    let warning = find_bytes(&frame, b"archive.note");
    frame[warning - 2] = 2;
    assert_eq!(
        error_kind(decode_result(&frame, OPERATION_ID, 0)),
        ProtocolErrorKind::InvalidSemanticState
    );
}

#[test]
fn manifest_rejects_invalid_strings_order_and_directory_content() {
    let valid = encode_result(&complete_result()).unwrap();
    let first_path = find_bytes(&valid, b"pkg");
    let second_path = find_bytes(&valid, b"pkg/data.txt");

    let mut frame = valid.clone();
    frame[first_path] = 0xff;
    assert_eq!(
        error_kind(decode_result(&frame, OPERATION_ID, 0)),
        ProtocolErrorKind::InvalidUtf8
    );

    let mut frame = valid.clone();
    frame[second_path + 3] = b'\\';
    assert_eq!(
        error_kind(decode_result(&frame, OPERATION_ID, 0)),
        ProtocolErrorKind::InvalidString
    );

    let mut frame = valid.clone();
    frame[second_path..second_path + 3].copy_from_slice(b"aaa");
    assert_eq!(
        error_kind(decode_result(&frame, OPERATION_ID, 0)),
        ProtocolErrorKind::NonCanonicalOrder
    );

    let mut frame = valid;
    replace_u64(&mut frame, first_path - 40, 1);
    assert_eq!(
        error_kind(decode_result(&frame, OPERATION_ID, 0)),
        ProtocolErrorKind::InvalidSemanticState
    );
}

#[test]
fn manifest_rejects_a_file_that_is_an_ancestor_of_another_entry() {
    let mut result = complete_result();
    result.manifest = vec![
        ManifestEntry {
            path: "a".into(),
            kind: ManifestKind::File,
            size: 1,
            sha256: [0x10; 32],
        },
        ManifestEntry {
            path: "a-b".into(),
            kind: ManifestKind::File,
            size: 1,
            sha256: [0x20; 32],
        },
        ManifestEntry {
            path: "a/child".into(),
            kind: ManifestKind::File,
            size: 1,
            sha256: [0x30; 32],
        },
    ];

    assert_eq!(
        error_kind(encode_result(&result)),
        ProtocolErrorKind::InvalidSemanticState
    );
}

#[test]
fn request_bound_result_validation_enforces_profile_and_resource_limits() {
    let result = complete_result();
    let frame = encode_result(&result).unwrap();
    let request = start_request(ExecutionMode::Inspect);
    assert_eq!(
        decode_result_for_request(&frame, &request, 0).unwrap(),
        result
    );
    validate_result_for_request(&result, &request).unwrap();

    let mut mismatched = request.clone();
    mismatched.interpretation_profile_sha256 = [0x99; 32];
    assert_eq!(
        error_kind(decode_result_for_request(&frame, &mismatched, 0)),
        ProtocolErrorKind::RequestMismatch
    );

    let mut mismatched = request.clone();
    mismatched.limits.max_files = 1;
    assert_eq!(
        error_kind(validate_result_for_request(&result, &mismatched)),
        ProtocolErrorKind::RequestMismatch
    );

    let mut mismatched = request.clone();
    mismatched.limits.max_member_bytes = 6;
    assert_eq!(
        error_kind(validate_result_for_request(&result, &mismatched)),
        ProtocolErrorKind::RequestMismatch
    );

    let mut mismatched = request.clone();
    mismatched.limits.max_total_bytes = 6;
    assert_eq!(
        error_kind(validate_result_for_request(&result, &mismatched)),
        ProtocolErrorKind::RequestMismatch
    );

    let mut mismatched = request.clone();
    mismatched.limits.max_path_depth = 1;
    assert_eq!(
        error_kind(validate_result_for_request(&result, &mismatched)),
        ProtocolErrorKind::RequestMismatch
    );

    let mut mismatched = request;
    mismatched.operation_id = [0x77; 16];
    assert_eq!(
        error_kind(decode_result_for_request(&frame, &mismatched, 0)),
        ProtocolErrorKind::CorrelationMismatch
    );

    let mut overflowing = complete_result();
    overflowing.manifest = vec![
        ManifestEntry {
            path: "a".into(),
            kind: ManifestKind::File,
            size: u64::MAX,
            sha256: [0x10; 32],
        },
        ManifestEntry {
            path: "b".into(),
            kind: ManifestKind::File,
            size: 1,
            sha256: [0x20; 32],
        },
    ];
    let mut permissive = start_request(ExecutionMode::Inspect);
    permissive.limits.max_member_bytes = u64::MAX;
    permissive.limits.max_total_bytes = u64::MAX;
    assert_eq!(
        error_kind(validate_result_for_request(&overflowing, &permissive)),
        ProtocolErrorKind::IntegerOverflow
    );
}

#[test]
fn encode_rejects_semantically_invalid_values() {
    let mut request = start_request(ExecutionMode::Inspect);
    request.operation_id = [0; 16];
    assert_eq!(
        error_kind(encode_start(&request)),
        ProtocolErrorKind::InvalidSemanticState
    );

    let mut request = start_request(ExecutionMode::Materialize);
    request.stage_capability = Some(0);
    assert_eq!(
        error_kind(encode_start(&request)),
        ProtocolErrorKind::CapabilityMismatch
    );

    let mut result = complete_result();
    result.manifest.swap(0, 1);
    assert_eq!(
        error_kind(encode_result(&result)),
        ProtocolErrorKind::NonCanonicalOrder
    );

    let mut result = rejected_result();
    result.findings.clear();
    assert_eq!(
        error_kind(encode_result(&result)),
        ProtocolErrorKind::InvalidSemanticState
    );

    for path in [
        "café.txt",
        "safe.txt:hidden",
        "NUL.txt",
        "trailing.",
        "bad<name",
    ] {
        let mut result = complete_result();
        result.manifest[1].path = path.into();
        assert_eq!(
            error_kind(encode_result(&result)),
            ProtocolErrorKind::InvalidString,
            "invalid path {path}"
        );
    }
}

#[test]
fn deterministic_mutations_never_escape_roundtrip_validation() {
    let start = encode_start(&start_request(ExecutionMode::Materialize)).unwrap();
    for index in 0..start.len() {
        for mask in [1, 0x5a, 0xff] {
            let mut mutated = start.clone();
            mutated[index] ^= mask;
            if let Ok(decoded) = decode_start(&mutated, 2) {
                let canonical = encode_start(&decoded).expect("decoded start must re-encode");
                assert_eq!(decode_start(&canonical, 2).unwrap(), decoded);
            }
        }
    }

    let result = encode_result(&complete_result()).unwrap();
    for index in 0..result.len() {
        for mask in [1, 0x5a, 0xff] {
            let mut mutated = result.clone();
            mutated[index] ^= mask;
            if let Ok(decoded) = decode_result(&mutated, OPERATION_ID, 0) {
                let canonical = encode_result(&decoded).expect("decoded result must re-encode");
                assert_eq!(decode_result(&canonical, OPERATION_ID, 0).unwrap(), decoded);
            }
        }
    }
}

#[test]
fn decoders_do_not_accept_one_frame_as_the_other() {
    let start = encode_start(&start_request(ExecutionMode::Inspect)).unwrap();
    let result = encode_result(&complete_result()).unwrap();
    assert_eq!(
        error_kind(decode_result(&start, OPERATION_ID, 0)),
        ProtocolErrorKind::UnexpectedFrameKind
    );
    assert_eq!(
        error_kind(decode_start(&result, 1)),
        ProtocolErrorKind::UnexpectedFrameKind
    );
    assert_eq!(FRAME_HEADER_BYTES, 16);
}
