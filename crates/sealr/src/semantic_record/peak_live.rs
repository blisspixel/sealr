use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use sha2::{Digest, Sha256};

use super::*;
use crate::apply::{
    apply_with_options, plan_source, ApplyOptions, PlanDecision, PlanningContext, Request, Source,
};
use crate::policy::Policy;

const CHILD_MODE: &str = "SEALR_SEMANTIC_PEAK_LIVE_MODE";
const SAMPLE_MARKER: &str = "SEALR_SEMANTIC_PEAK_LIVE_SAMPLE=";
const MEMBER_COUNT: usize = 349;
const MEMBER_NAME_BYTES: usize = 64_000;
const EXPECTED_PLAN_BYTES: usize = 67_042_849;
const EXPECTED_PLAN_SHA256: &str =
    "acdcfb9a5282f559716f2673f1cc8a8e682488a9e5a8ae7a34d318332ed2e3ec";
const ACCEPTED_TRANSIENT_BYTES: usize = 1024 * 1024;
const ACCEPTED_RETAINED_SLOP_BYTES: usize = 256 * 1024;
const STALE_TRANSIENT_BYTES: usize = 64 * 1024;
const LATE_INVALID_TRANSIENT_BYTES: usize = 1024 * 1024;

struct LiveAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);
static MEASURING: AtomicBool = AtomicBool::new(false);

fn record_increase(bytes: usize) {
    if bytes == 0 {
        return;
    }
    let live = LIVE_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
    if MEASURING.load(Ordering::Relaxed) {
        let mut peak = PEAK_BYTES.load(Ordering::Relaxed);
        while live > peak {
            match PEAK_BYTES.compare_exchange_weak(peak, live, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(observed) => peak = observed,
            }
        }
    }
}

fn record_decrease(bytes: usize) {
    if bytes == 0 {
        return;
    }
    let mut live = LIVE_BYTES.load(Ordering::Relaxed);
    loop {
        let Some(next) = live.checked_sub(bytes) else {
            std::process::abort();
        };
        match LIVE_BYTES.compare_exchange_weak(live, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => live = observed,
        }
    }
}

// Safety: every operation delegates to System with the original pointer and
// layout. The atomics observe requested live bytes and never affect allocation.
unsafe impl GlobalAlloc for LiveAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Safety: GlobalAlloc supplies a valid layout.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_increase(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // Safety: GlobalAlloc supplies a valid layout.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_increase(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record_decrease(layout.size());
        // Safety: GlobalAlloc supplies the pointer and its original layout.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Safety: GlobalAlloc supplies a live allocation, its layout, and the
        // replacement size.
        let replacement = unsafe { System.realloc(pointer, layout, new_size) };
        if !replacement.is_null() {
            if new_size >= layout.size() {
                record_increase(new_size - layout.size());
            } else {
                record_decrease(layout.size() - new_size);
            }
        }
        replacement
    }
}

#[global_allocator]
static ALLOCATOR: LiveAllocator = LiveAllocator;

struct Measurement {
    baseline: usize,
}

#[derive(Clone, Copy, Debug)]
struct Sample {
    peak_delta: usize,
    final_live_delta: usize,
}

impl Measurement {
    fn begin() -> Self {
        assert!(
            !MEASURING.swap(true, Ordering::SeqCst),
            "peak-live measurement cannot be nested"
        );
        let baseline = LIVE_BYTES.load(Ordering::SeqCst);
        PEAK_BYTES.store(baseline, Ordering::SeqCst);
        Self { baseline }
    }

    fn finish(self) -> Sample {
        let peak = PEAK_BYTES.load(Ordering::SeqCst);
        let final_live = LIVE_BYTES.load(Ordering::SeqCst);
        MEASURING.store(false, Ordering::SeqCst);
        Sample {
            peak_delta: peak
                .checked_sub(self.baseline)
                .expect("peak live bytes cannot precede the baseline"),
            final_live_delta: final_live
                .checked_sub(self.baseline)
                .expect("measured code unexpectedly freed baseline allocations"),
        }
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        MEASURING.store(false, Ordering::SeqCst);
    }
}

struct PreparedCase {
    planning: ValidatedPlanningRecord,
    completion: Vec<u8>,
    logical_reconstruction_bytes: usize,
    plan_sha256: String,
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn member_name(index: usize) -> Vec<u8> {
    let prefix = format!("member-{index:03}-");
    assert!(prefix.len() < MEMBER_NAME_BYTES);
    let mut name = vec![b'a'; MEMBER_NAME_BYTES];
    name[..prefix.len()].copy_from_slice(prefix.as_bytes());
    name
}

fn near_limit_zip() -> Vec<u8> {
    let source_bytes =
        MEMBER_COUNT * (30 + MEMBER_NAME_BYTES + 1) + MEMBER_COUNT * (46 + MEMBER_NAME_BYTES) + 22;
    let mut output = Vec::with_capacity(source_bytes);
    let payload = [0_u8];
    let crc = crc32fast::hash(&payload);
    let mut local_offsets = Vec::with_capacity(MEMBER_COUNT);

    for index in 0..MEMBER_COUNT {
        local_offsets.push(u32::try_from(output.len()).unwrap());
        let name = member_name(index);
        push_u32(&mut output, 0x0403_4b50);
        push_u16(&mut output, 20);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u32(&mut output, crc);
        push_u32(&mut output, 1);
        push_u32(&mut output, 1);
        push_u16(&mut output, MEMBER_NAME_BYTES as u16);
        push_u16(&mut output, 0);
        output.extend_from_slice(&name);
        output.extend_from_slice(&payload);
    }

    let central_offset = u32::try_from(output.len()).unwrap();
    for (index, local_offset) in local_offsets.into_iter().enumerate() {
        let name = member_name(index);
        push_u32(&mut output, 0x0201_4b50);
        push_u16(&mut output, 20);
        push_u16(&mut output, 20);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u32(&mut output, crc);
        push_u32(&mut output, 1);
        push_u32(&mut output, 1);
        push_u16(&mut output, MEMBER_NAME_BYTES as u16);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u32(&mut output, 0);
        push_u32(&mut output, local_offset);
        output.extend_from_slice(&name);
    }
    let central_size = u32::try_from(output.len()).unwrap() - central_offset;

    push_u32(&mut output, 0x0605_4b50);
    push_u16(&mut output, 0);
    push_u16(&mut output, 0);
    push_u16(&mut output, MEMBER_COUNT as u16);
    push_u16(&mut output, MEMBER_COUNT as u16);
    push_u32(&mut output, central_size);
    push_u32(&mut output, central_offset);
    push_u16(&mut output, 0);
    assert_eq!(output.len(), source_bytes);
    output
}

fn prepare_case(mode: &str) -> PreparedCase {
    let source = near_limit_zip();
    let profile = ZipInterpretationProfile::StrictAsciiV2;
    let mut policy = Policy::default_v1();
    policy.max_metadata_bytes = MAX_RECORD_BYTES as u64;
    let controls = policy.compile().unwrap();
    let options = ApplyOptions::new().with_interpretation_profile(profile);
    let operation_source = Source::Bytes {
        path: Some("semantic-peak-live.zip"),
        data: &source,
    };
    let planning_context = PlanningContext::compile(&policy, profile).unwrap();
    let ready = match plan_source(&operation_source, planning_context).unwrap() {
        PlanDecision::Ready(ready) => ready,
        PlanDecision::Terminal(terminal) => {
            panic!("near-limit fixture reached terminal planning: {terminal:?}")
        }
    };
    let (snapshot, pending, _payloads, planning_findings, planning_context) = ready.into_parts();
    assert!(planning_findings.is_empty());
    assert_eq!(planning_context.controls(), controls);
    assert_eq!(planning_context.profile(), profile);
    let outcome = apply_with_options(
        Request {
            source: operation_source,
            policy: &policy,
            dest: None,
        },
        &options,
    );
    assert_eq!(outcome.admission, AdmissionStatus::Admitted);
    assert_eq!(outcome.verification, VerificationStatus::Complete);
    let mut members: Vec<_> = outcome
        .archive_ir()
        .unwrap()
        .members
        .iter()
        .map(|member| MemberCompletion::Verified {
            actual_uncomp_size: member.actual_uncomp_size.unwrap(),
            actual_crc: member.actual_crc.unwrap(),
            content_sha256: parse_hex_32(member.content_sha256.as_deref().unwrap()).unwrap(),
        })
        .collect();
    drop(outcome);

    let binding = InvocationBinding {
        operation_id: [0x41; 16],
        source_len: snapshot.len(),
        source_sha256: parse_hex_32(snapshot.digest().sha256().unwrap()).unwrap(),
        profile: planning_context.profile(),
        profile_sha256: parse_hex_32(&planning_context.profile().digest()).unwrap(),
        policy_id: planning_context.policy_id().to_owned(),
        policy_sha256: parse_hex_32(planning_context.policy_sha256()).unwrap(),
        budget: planning_context.controls().budget,
        target: planning_context.controls().target,
        consumer: planning_context.controls().consumer,
        requested_effect: RequestedEffect::Inspect,
        target_sha256: None,
        member_sync: planning_context.controls().effect.member_sync,
        retention: RetentionBinding::None,
    };
    let plan = PlanningRecord {
        binding: binding.clone(),
        disposition: PlanningDisposition::ReadyForVerification,
        ir: Some(pending),
        findings: Vec::new(),
    };
    let plan_bytes = encode_planning(&plan).unwrap();
    let plan_sha256 = hex_32(&Sha256::digest(&plan_bytes).into());
    eprintln!(
        "near-limit semantic plan: bytes={}, sha256={plan_sha256}",
        plan_bytes.len()
    );
    assert_eq!(plan_bytes.len(), EXPECTED_PLAN_BYTES);
    assert_eq!(plan_sha256, EXPECTED_PLAN_SHA256);
    assert!(MAX_RECORD_BYTES - plan_bytes.len() < 128 * 1024);
    drop(plan);

    let planning = decode_planning(&plan_bytes, &binding, &snapshot).unwrap();
    let (disposition, findings) = match mode {
        "stopped" => {
            *members.last_mut().unwrap() = MemberCompletion::Failed {
                cause: FindingCode::CrcMismatch,
            };
            (
                CompletionDisposition::Stopped {
                    verified_members: (MEMBER_COUNT - 1) as u64,
                    pending_members: 1,
                },
                vec![Finding::error(
                    FindingCode::CrcMismatch,
                    "d".repeat(MAX_FINDING_DETAIL_BYTES),
                )
                .on("m".repeat(MAX_NAME_BYTES))],
            )
        }
        "late-invalid" => {
            *members.last_mut().unwrap() = MemberCompletion::Pending;
            (CompletionDisposition::Complete, Vec::new())
        }
        _ => (CompletionDisposition::Complete, Vec::new()),
    };
    let completion_record = CompletionRecord {
        operation_id: planning.record.binding.operation_id,
        request_id: planning.request_id,
        plan_id: planning.plan_id,
        disposition,
        members,
        findings,
    };
    let mut completion = encode_completion_validated(&completion_record).unwrap();
    if mode == "stale" {
        completion[HEADER_BYTES + 16 + 32] ^= 1;
    }
    drop(completion_record);
    drop(snapshot);
    drop(plan_bytes);
    drop(binding);
    drop(source);

    let logical_reconstruction_bytes = if matches!(mode, "accepted" | "stopped") {
        COMPLETION_ALLOCATION_BUDGET.with(|budget| budget.set(Some(usize::MAX)));
        let warm = decode_completion(&completion, &planning).unwrap();
        black_box(&warm.ir);
        drop(warm);
        let remaining = COMPLETION_ALLOCATION_BUDGET
            .with(|budget| budget.replace(None))
            .unwrap();
        usize::MAX - remaining
    } else {
        0
    };
    COMPLETION_IR_MATERIALIZATIONS.with(|count| count.set(0));

    PreparedCase {
        planning,
        completion,
        logical_reconstruction_bytes,
        plan_sha256,
    }
}

fn run_child(mode: &str) {
    let prepared = prepare_case(mode);
    let measurement = Measurement::begin();
    let result = decode_completion(&prepared.completion, &prepared.planning);
    let sample = measurement.finish();
    let materializations = COMPLETION_IR_MATERIALIZATIONS.with(std::cell::Cell::get);

    match mode {
        "accepted" => {
            let completion = result.expect("near-limit completion must reconstruct");
            black_box(&completion.ir);
            let logical = prepared.logical_reconstruction_bytes;
            assert_eq!(materializations, 1);
            assert!(sample.peak_delta >= logical);
            assert!(sample.peak_delta <= logical + ACCEPTED_TRANSIENT_BYTES);
            assert!(sample.final_live_delta >= logical);
            assert!(sample.final_live_delta <= logical + ACCEPTED_RETAINED_SLOP_BYTES);
            assert!(sample.peak_delta < logical * 2);
            println!(
                "{SAMPLE_MARKER}accepted,plan_bytes={EXPECTED_PLAN_BYTES},plan_sha256={},logical_bytes={logical},peak_delta={},final_live_delta={},materializations={materializations}",
                prepared.plan_sha256, sample.peak_delta, sample.final_live_delta
            );
            drop(completion);
        }
        "stopped" => {
            let completion = result.expect("near-limit stopped completion must reconstruct");
            black_box(&completion.ir);
            assert_eq!(
                completion.verification,
                VerificationStatus::Partial {
                    verified_members: (MEMBER_COUNT - 1) as u64,
                    pending_members: 1,
                }
            );
            let logical = prepared.logical_reconstruction_bytes;
            assert_eq!(materializations, 1);
            assert!(sample.peak_delta >= logical);
            assert!(sample.peak_delta <= logical + ACCEPTED_TRANSIENT_BYTES);
            assert!(sample.final_live_delta >= logical);
            assert!(sample.final_live_delta <= logical + ACCEPTED_RETAINED_SLOP_BYTES);
            assert!(sample.peak_delta < logical * 2);
            println!(
                "{SAMPLE_MARKER}stopped,plan_bytes={EXPECTED_PLAN_BYTES},plan_sha256={},logical_bytes={logical},peak_delta={},final_live_delta={},materializations={materializations}",
                prepared.plan_sha256, sample.peak_delta, sample.final_live_delta
            );
            drop(completion);
        }
        "stale" => {
            assert_eq!(result.unwrap_err().kind, RecordErrorKind::BindingMismatch);
            assert_eq!(materializations, 0);
            assert!(sample.peak_delta <= STALE_TRANSIENT_BYTES);
            assert_eq!(sample.final_live_delta, 0);
            println!(
                "{SAMPLE_MARKER}stale,peak_delta={},final_live_delta={},materializations={materializations}",
                sample.peak_delta, sample.final_live_delta
            );
        }
        "late-invalid" => {
            assert_eq!(
                result.unwrap_err().kind,
                RecordErrorKind::InvalidSemanticState
            );
            assert_eq!(materializations, 0);
            assert!(sample.peak_delta <= LATE_INVALID_TRANSIENT_BYTES);
            assert_eq!(sample.final_live_delta, 0);
            println!(
                "{SAMPLE_MARKER}late-invalid,peak_delta={},final_live_delta={},materializations={materializations}",
                sample.peak_delta, sample.final_live_delta
            );
        }
        _ => panic!("unknown peak-live child mode: {mode}"),
    }
}

fn invoke_child(mode: &str) -> String {
    let output = Command::new(std::env::current_exe().unwrap())
        .arg("semantic_record::peak_live::completion_reconstruction_peak_live_child")
        .arg("--exact")
        .arg("--ignored")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(CHILD_MODE, mode)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "peak-live {mode} child failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let marker = stdout
        .lines()
        .find_map(|line| line.find(SAMPLE_MARKER).map(|offset| &line[offset..]))
        .unwrap_or_else(|| panic!("peak-live {mode} child emitted no sample: {stdout}"));
    marker.to_owned()
}

#[test]
#[ignore = "required CI runs the isolated near-limit heap probe explicitly"]
fn completion_reconstruction_peak_live_is_bounded() {
    for mode in ["accepted", "stopped", "stale", "late-invalid"] {
        println!("{}", invoke_child(mode));
    }
}

#[test]
#[ignore = "invoked only in an isolated child by the required peak-live driver"]
fn completion_reconstruction_peak_live_child() {
    let mode = std::env::var(CHILD_MODE).expect("peak-live child mode is required");
    run_child(&mode);
}
