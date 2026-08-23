use std::alloc::{GlobalAlloc, Layout, System};
use std::env;
use std::fs::{self, File};
use std::hint::black_box;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use sealr::{apply, Policy, Request, SnapshotKind, Source};

const RESOURCE_PROBE_PATH: &str = "SEALR_RESOURCE_PROBE_PATH";
const PEAK_RSS_MARKER: &str = "SEALR_PEAK_RSS_BYTES=";

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

fn zero_crc32(payload_bytes: u64) -> u32 {
    let mut crc = crc32fast::Hasher::new();
    let block = [0_u8; 64 * 1024];
    let mut remaining = payload_bytes;
    while remaining != 0 {
        let count = remaining.min(block.len() as u64) as usize;
        crc.update(&block[..count]);
        remaining -= count as u64;
    }
    crc.finalize()
}

fn write_u16(file: &mut File, value: u16) {
    file.write_all(&value.to_le_bytes()).unwrap();
}

fn write_u32(file: &mut File, value: u32) {
    file.write_all(&value.to_le_bytes()).unwrap();
}

#[cfg(windows)]
fn mark_sparse(file: &File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let mut returned = 0_u32;
    // Safety: the file handle remains live for the call, this control code has
    // no input or output buffer, and bytes-returned points to valid storage.
    let status = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(status, 0, "FSCTL_SET_SPARSE failed");
}

#[cfg(not(windows))]
fn mark_sparse(_file: &File) {}

#[cfg(unix)]
fn allocated_file_bytes(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;

    fs::metadata(path).unwrap().blocks().saturating_mul(512)
}

#[cfg(windows)]
fn allocated_file_bytes(path: &Path) -> u64 {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{GetLastError, SetLastError, ERROR_SUCCESS};
    use windows_sys::Win32::Storage::FileSystem::{GetCompressedFileSizeW, INVALID_FILE_SIZE};

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let mut high = 0_u32;
    // Safety: wide is NUL-terminated and high points to valid writable storage.
    let low = unsafe {
        SetLastError(ERROR_SUCCESS);
        GetCompressedFileSizeW(wide.as_ptr(), &mut high)
    };
    if low == INVALID_FILE_SIZE {
        // Safety: GetLastError has no preconditions and is read immediately
        // after the API whose ambiguous sentinel it disambiguates.
        let error = unsafe { GetLastError() };
        assert_eq!(
            error,
            ERROR_SUCCESS,
            "GetCompressedFileSizeW failed: {}",
            std::io::Error::from_raw_os_error(error as i32)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

#[cfg(not(any(unix, windows)))]
fn allocated_file_bytes(path: &Path) -> u64 {
    fs::metadata(path).unwrap().len()
}

/// Write one valid ZIP32 Stored member whose zero payload is a filesystem hole.
/// The central directory remains below 4 GiB for every fixture used here.
fn write_sparse_stored_archive(path: &Path, payload_bytes: u64) {
    const NAME: &[u8] = b"large.bin";

    let payload_size = u32::try_from(payload_bytes).unwrap();
    let crc = zero_crc32(payload_bytes);
    let mut file = File::create(path).unwrap();
    mark_sparse(&file);

    write_u32(&mut file, 0x0403_4b50);
    write_u16(&mut file, 20);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u32(&mut file, crc);
    write_u32(&mut file, payload_size);
    write_u32(&mut file, payload_size);
    write_u16(&mut file, NAME.len() as u16);
    write_u16(&mut file, 0);
    file.write_all(NAME).unwrap();

    let payload_offset = file.stream_position().unwrap();
    file.seek(SeekFrom::Start(payload_offset + payload_bytes))
        .unwrap();
    let central_directory_offset = file.stream_position().unwrap();

    write_u32(&mut file, 0x0201_4b50);
    write_u16(&mut file, 20);
    write_u16(&mut file, 20);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u32(&mut file, crc);
    write_u32(&mut file, payload_size);
    write_u32(&mut file, payload_size);
    write_u16(&mut file, NAME.len() as u16);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u32(&mut file, 0);
    write_u32(&mut file, 0);
    file.write_all(NAME).unwrap();

    let central_directory_end = file.stream_position().unwrap();
    write_u32(&mut file, 0x0605_4b50);
    write_u16(&mut file, 0);
    write_u16(&mut file, 0);
    write_u16(&mut file, 1);
    write_u16(&mut file, 1);
    write_u32(
        &mut file,
        u32::try_from(central_directory_end - central_directory_offset).unwrap(),
    );
    write_u32(&mut file, u32::try_from(central_directory_offset).unwrap());
    write_u16(&mut file, 0);
    file.flush().unwrap();
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

#[cfg(unix)]
fn peak_resident_bytes() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // Safety: getrusage initializes the provided rusage object for this process.
    let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    assert_eq!(status, 0, "getrusage failed");
    // Safety: a successful getrusage call initialized the object.
    let usage = unsafe { usage.assume_init() };
    let raw = u64::try_from(usage.ru_maxrss).unwrap();
    if cfg!(target_os = "macos") {
        raw
    } else {
        raw.saturating_mul(1024)
    }
}

#[cfg(windows)]
fn peak_resident_bytes() -> u64 {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let mut counters = std::mem::MaybeUninit::<PROCESS_MEMORY_COUNTERS>::zeroed();
    let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>();
    // Safety: the buffer has the size reported to GetProcessMemoryInfo and the
    // pseudo-handle returned by GetCurrentProcess is always valid here.
    let status = unsafe {
        let pointer = counters.as_mut_ptr();
        (*pointer).cb = u32::try_from(size).unwrap();
        GetProcessMemoryInfo(GetCurrentProcess(), pointer, u32::try_from(size).unwrap())
    };
    assert_ne!(status, 0, "GetProcessMemoryInfo failed");
    // Safety: a successful GetProcessMemoryInfo call initialized the object.
    let counters = unsafe { counters.assume_init() };
    u64::try_from(counters.PeakWorkingSetSize).unwrap()
}

#[cfg(not(any(unix, windows)))]
fn peak_resident_bytes() -> u64 {
    panic!("peak resident memory measurement is unsupported on this target")
}

#[test]
#[ignore = "invoked in an isolated child by the required resource test"]
fn peak_resident_memory_probe_child() {
    let Ok(path) = env::var(RESOURCE_PROBE_PATH) else {
        return;
    };
    let policy = Policy::default_v1();
    let outcome = apply(Request {
        source: Source::Path(Path::new(&path)),
        policy: &policy,
        dest: None,
    });
    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
    assert_eq!(outcome.receipt.source_snapshot, SnapshotKind::PrivateFile);
    assert_eq!(outcome.view.members.len(), 1);
    println!("{PEAK_RSS_MARKER}{}", peak_resident_bytes());
    let _ = black_box(outcome);
}

fn measured_peak_resident_bytes(path: &Path) -> u64 {
    let output = Command::new(env::current_exe().unwrap())
        .args([
            "--exact",
            "peak_resident_memory_probe_child",
            "--ignored",
            "--nocapture",
        ])
        .env(RESOURCE_PROBE_PATH, path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "resource child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix(PEAK_RSS_MARKER))
        .expect("resource child did not report peak resident memory")
        .parse()
        .unwrap()
}

#[test]
fn path_snapshot_resources_are_bounded_independently_of_archive_bytes() {
    const SMALL_BYTES: usize = 1024 * 1024;
    const LARGE_BYTES: usize = 128 * 1024 * 1024;
    const MAX_MEASURED_ALLOCATION: usize = 8 * 1024 * 1024;
    const MAX_SCALE_DELTA: usize = 1024 * 1024;
    const MAX_PEAK_RESIDENT_BYTES: u64 = 256 * 1024 * 1024;
    const MAX_PEAK_RESIDENT_DELTA: u64 = 64 * 1024 * 1024;

    let directory = temp_directory();
    fs::create_dir(&directory).unwrap();
    let small = directory.join("small.zip");
    let large = directory.join("large.zip");
    write_sparse_stored_archive(&small, SMALL_BYTES as u64);
    write_sparse_stored_archive(&large, LARGE_BYTES as u64);
    let large_allocated_file_bytes = allocated_file_bytes(&large);
    assert!(
        large_allocated_file_bytes <= 2 * 1024 * 1024,
        "128 MiB fixture is not sparse: allocated {large_allocated_file_bytes} bytes"
    );

    let small_allocated = measured_apply(&small);
    let large_allocated = measured_apply(&large);
    let small_peak_resident = measured_peak_resident_bytes(&small);
    let large_peak_resident = measured_peak_resident_bytes(&large);
    eprintln!(
        "resource evidence: 1 MiB archive={small_allocated} allocated/{small_peak_resident} peak resident bytes, 128 MiB sparse archive={large_allocated} allocated/{large_peak_resident} peak resident bytes"
    );

    assert!(
        large_allocated <= MAX_MEASURED_ALLOCATION,
        "128 MiB sparse path input allocated {large_allocated} tracked heap bytes"
    );
    assert!(
        large_allocated <= small_allocated.saturating_add(MAX_SCALE_DELTA),
        "tracked allocation scaled with archive bytes: small={small_allocated}, large={large_allocated}"
    );
    assert!(
        large_peak_resident <= MAX_PEAK_RESIDENT_BYTES,
        "128 MiB sparse path input reached {large_peak_resident} peak resident bytes"
    );
    assert!(
        large_peak_resident <= small_peak_resident.saturating_add(MAX_PEAK_RESIDENT_DELTA),
        "peak resident memory scaled with archive bytes: small={small_peak_resident}, large={large_peak_resident}"
    );

    fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "scheduled 3 GiB sparse gate requires several GiB of temporary storage"]
fn multigigabyte_sparse_path_input_stays_within_the_heap_budget() {
    const PAYLOAD_BYTES: u64 = 3 * 1024 * 1024 * 1024;
    const MAX_MEASURED_ALLOCATION: usize = 8 * 1024 * 1024;

    let directory = temp_directory();
    fs::create_dir(&directory).unwrap();
    let archive = directory.join("three-gibibytes.zip");
    write_sparse_stored_archive(&archive, PAYLOAD_BYTES);
    let allocated_file_bytes = allocated_file_bytes(&archive);
    assert!(
        allocated_file_bytes <= 2 * 1024 * 1024,
        "3 GiB fixture is not sparse: allocated {allocated_file_bytes} bytes"
    );

    let mut policy = Policy::default_v1();
    policy.max_archive_bytes = PAYLOAD_BYTES + 1024 * 1024;
    policy.max_member_bytes = PAYLOAD_BYTES;
    policy.max_total_bytes = PAYLOAD_BYTES;
    let tracking = TrackingGuard::begin();
    let outcome = apply(Request {
        source: Source::Path(&archive),
        policy: &policy,
        dest: None,
    });
    let allocated = tracking.allocated();
    drop(tracking);

    assert!(!outcome.rejected(), "{:?}", outcome.view.findings);
    assert_eq!(outcome.view.members[0].uncomp_bytes, PAYLOAD_BYTES);
    assert!(
        allocated <= MAX_MEASURED_ALLOCATION,
        "3 GiB sparse path input allocated {allocated} tracked heap bytes"
    );
    eprintln!(
        "3 GiB sparse evidence: {allocated_file_bytes} source bytes allocated on disk, {allocated} tracked heap bytes"
    );
    drop(outcome);
    fs::remove_dir_all(directory).unwrap();
}
