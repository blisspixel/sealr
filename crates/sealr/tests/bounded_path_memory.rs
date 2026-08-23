use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::{self, File};
use std::hint::black_box;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use sealr::{apply, Policy, Request, SnapshotKind, Source};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

struct CountingAllocator;

static TRACKING: AtomicBool = AtomicBool::new(false);
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

fn record_allocation(bytes: usize) {
    if TRACKING.load(Ordering::Relaxed) {
        ALLOCATED.fetch_add(bytes, Ordering::Relaxed);
    }
}

// Safety: every operation delegates to the process System allocator with the
// original pointer and layout. The counters do not affect allocator behavior.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Safety: the caller supplies the layout required by GlobalAlloc.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // Safety: the caller supplies the layout required by GlobalAlloc.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // Safety: the caller supplies the pointer and layout paired with the
        // original allocation.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Safety: the caller supplies the allocation and requested new size
        // required by GlobalAlloc.
        let replacement = unsafe { System.realloc(pointer, layout, new_size) };
        if !replacement.is_null() {
            record_allocation(new_size.saturating_sub(layout.size()));
        }
        replacement
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct TrackingGuard;

impl TrackingGuard {
    fn begin() -> Self {
        ALLOCATED.store(0, Ordering::SeqCst);
        TRACKING.store(true, Ordering::SeqCst);
        Self
    }

    fn allocated(&self) -> usize {
        ALLOCATED.load(Ordering::SeqCst)
    }
}

impl Drop for TrackingGuard {
    fn drop(&mut self) {
        TRACKING.store(false, Ordering::SeqCst);
    }
}

fn temp_directory() -> PathBuf {
    let mut random = [0_u8; 12];
    getrandom::fill(&mut random).unwrap();
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    std::env::temp_dir().join(format!("sealr-bounded-memory-{suffix}"))
}

fn write_stored_archive(path: &Path, payload_bytes: usize) {
    let file = File::create(path).unwrap();
    let mut archive = ZipWriter::new(file);
    archive
        .start_file(
            "large.bin",
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
    let block = [0x5a_u8; 64 * 1024];
    let mut remaining = payload_bytes;
    while remaining != 0 {
        let count = remaining.min(block.len());
        archive.write_all(&block[..count]).unwrap();
        remaining -= count;
    }
    archive.finish().unwrap();
}

fn measured_apply(path: &Path) -> usize {
    let policy = Policy::default_v1();
    let tracking = TrackingGuard::begin();
    let outcome = apply(Request {
        source: Source::Path(path),
        policy: &policy,
        dest: None,
    });
    let allocated = tracking.allocated();
    drop(tracking);

    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
    assert_eq!(outcome.receipt.source_snapshot, SnapshotKind::PrivateFile);
    assert_eq!(outcome.view.members.len(), 1);
    let _ = black_box(outcome);
    allocated
}

#[test]
fn path_snapshot_heap_allocation_is_bounded_independently_of_archive_bytes() {
    const SMALL_BYTES: usize = 1024 * 1024;
    const LARGE_BYTES: usize = 32 * 1024 * 1024;
    const MAX_MEASURED_ALLOCATION: usize = 8 * 1024 * 1024;
    const MAX_SCALE_DELTA: usize = 1024 * 1024;

    let directory = temp_directory();
    fs::create_dir(&directory).unwrap();
    let small = directory.join("small.zip");
    let large = directory.join("large.zip");
    write_stored_archive(&small, SMALL_BYTES);
    write_stored_archive(&large, LARGE_BYTES);

    let small_allocated = measured_apply(&small);
    let large_allocated = measured_apply(&large);
    eprintln!(
        "tracked heap allocation: 1 MiB archive={small_allocated} bytes, 32 MiB archive={large_allocated} bytes"
    );

    assert!(
        large_allocated <= MAX_MEASURED_ALLOCATION,
        "32 MiB path input allocated {large_allocated} tracked heap bytes"
    );
    assert!(
        large_allocated <= small_allocated.saturating_add(MAX_SCALE_DELTA),
        "tracked allocation scaled with archive bytes: small={small_allocated}, large={large_allocated}"
    );

    fs::remove_dir_all(directory).unwrap();
}
