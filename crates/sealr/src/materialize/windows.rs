use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr;

use cap_std::fs::Dir as CapDir;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FileRenameInformation, NtCreateFile, NtSetInformationFile, FILE_CREATE, FILE_DIRECTORY_FILE,
    FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    RtlNtStatusToDosError, HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

pub(super) const STAGE_CREATION_PRIMITIVE: &str =
    "ntcreatefile-parent-handle-create-directory-nofollow";
pub(super) const PUBLICATION_PRIMITIVE: &str =
    "ntsetinformationfile-retained-source-parent-noreplace";

pub(super) fn create_stage(parent: &CapDir, name: &Path) -> io::Result<CapDir> {
    let mut name: Vec<u16> = name.as_os_str().encode_wide().collect();
    let name_bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "stage name is too long"))?;
    let name_length = u16::try_from(name_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "stage name is too long"))?;
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stage name is empty",
        ));
    }

    let unicode_name = UNICODE_STRING {
        Length: name_length,
        MaximumLength: name_length,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>()).expect("structure size fits u32"),
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &unicode_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut handle: HANDLE = INVALID_HANDLE_VALUE;
    let mut status_block = MaybeUninit::<IO_STATUS_BLOCK>::zeroed();

    // Safety: every pointer refers to initialized storage for the duration of the call.
    // FILE_CREATE makes creation exclusive, and the returned handle is owned exactly once.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
            &attributes,
            status_block.as_mut_ptr(),
            ptr::null(),
            FILE_ATTRIBUTE_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(ntstatus_error(status));
    }
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::other(
            "NtCreateFile succeeded without a valid staging handle",
        ));
    }

    // Safety: NtCreateFile returned a new owned handle, and File assumes sole ownership.
    let file = unsafe { File::from_raw_handle(handle) };
    Ok(CapDir::from_std_file(file))
}

pub(super) fn rename_noreplace(parent: &CapDir, root: &CapDir, to: &Path) -> io::Result<()> {
    let name: Vec<u16> = to.as_os_str().encode_wide().collect();
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination name is empty",
        ));
    }
    let name_bytes = name.len().checked_mul(size_of::<u16>()).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination name is too long")
    })?;
    let buffer_bytes = size_of::<FILE_RENAME_INFORMATION>()
        .checked_add(name_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename buffer is too large"))?;
    let word_count = buffer_bytes.div_ceil(size_of::<usize>());
    let mut buffer = vec![0_usize; word_count];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();

    // Safety: the buffer is aligned, zero-initialized, large enough for the generated
    // structure plus UTF-16 name, and remains live until the synchronous call returns.
    unsafe {
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = parent.as_raw_handle();
        (*info).FileNameLength = u32::try_from(name_bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "destination name is too long")
        })?;
        ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());

        let mut status_block = IO_STATUS_BLOCK::default();
        let status = NtSetInformationFile(
            root.as_raw_handle(),
            &mut status_block,
            info.cast::<c_void>(),
            u32::try_from(buffer_bytes).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "rename buffer is too large")
            })?,
            FileRenameInformation,
        );
        if status < 0 {
            return Err(ntstatus_error(status));
        }
    }
    Ok(())
}

fn ntstatus_error(status: i32) -> io::Error {
    let code = unsafe { RtlNtStatusToDosError(status) };
    match i32::try_from(code) {
        Ok(code) => io::Error::from_raw_os_error(code),
        Err(_) => io::Error::other(format!("Windows NTSTATUS 0x{status:08x}")),
    }
}
