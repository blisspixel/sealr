use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

use cap_std::fs::Dir as CapDir;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FileFsDeviceInformation, FileRenameInformation, NtCreateFile, NtQueryVolumeInformationFile,
    NtSetInformationFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT,
    FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Wdk::System::SystemServices::{FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE};
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, RtlNtStatusToDosError, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN,
    HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
#[cfg(test)]
use windows_sys::Win32::Security::INHERITED_ACE;
use windows_sys::Win32::Security::{
    AclSizeInformation, AddAccessAllowedAceEx, CopySid, EqualSid, GetAce, GetAclInformation,
    GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl,
    InitializeSecurityDescriptor, IsValidSid, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TokenUser, ACCESS_ALLOWED_ACE, ACL,
    ACL_REVISION, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
    INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_DESCRIPTOR, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetVolumeInformationByHandleW, DELETE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    READ_CONTROL, SYNCHRONIZE,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, FILE_PERSISTENT_ACLS, FILE_READ_ONLY_VOLUME,
    SECURITY_DESCRIPTOR_REVISION,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

#[cfg(test)]
std::thread_local! {
    static INJECT_STAGE_SECURITY_FAILURE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
pub(super) struct StageSecurityFailureGuard;

#[cfg(test)]
impl Drop for StageSecurityFailureGuard {
    fn drop(&mut self) {
        INJECT_STAGE_SECURITY_FAILURE.with(|inject| inject.set(false));
    }
}

#[cfg(test)]
pub(super) fn inject_stage_security_failure() -> StageSecurityFailureGuard {
    INJECT_STAGE_SECURITY_FAILURE.with(|inject| inject.set(true));
    StageSecurityFailureGuard
}
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

pub(super) const STORAGE_POLICY: &str = "windows-local-ntfs-v1";
pub(super) const STAGE_ACL_POLICY: &str = "windows-protected-token-user-v1";
pub(super) const STAGE_CREATION_PRIMITIVE: &str =
    "ntcreatefile-parent-handle-create-directory-explicit-dacl-nofollow";
pub(super) const PUBLICATION_PRIMITIVE: &str =
    "ntsetinformationfile-retained-source-parent-noreplace";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StorageObservation {
    pub(super) filesystem: Option<String>,
    pub(super) device_scope: &'static str,
    pub(super) persistent_acls: Option<bool>,
    pub(super) read_only: Option<bool>,
}

impl StorageObservation {
    pub(super) fn not_observed() -> Self {
        Self {
            filesystem: None,
            device_scope: "not-observed",
            persistent_acls: None,
            read_only: None,
        }
    }
}

#[derive(Debug)]
pub(super) struct StorageProbeError {
    pub(super) observation: StorageObservation,
    pub(super) error: io::Error,
}

pub(super) fn probe_supported_parent(
    parent: &CapDir,
) -> Result<StorageObservation, StorageProbeError> {
    let mut observation = StorageObservation {
        filesystem: None,
        device_scope: "unknown",
        persistent_acls: None,
        read_only: None,
    };
    let mut device = FILE_FS_DEVICE_INFORMATION::default();
    let mut status_block = IO_STATUS_BLOCK::default();

    // Safety: the parent handle is retained, the output buffers are initialized and sized for
    // the requested information class, and the call is synchronous for this directory handle.
    let status = unsafe {
        NtQueryVolumeInformationFile(
            parent.as_raw_handle(),
            &mut status_block,
            (&mut device as *mut FILE_FS_DEVICE_INFORMATION).cast::<c_void>(),
            u32::try_from(size_of::<FILE_FS_DEVICE_INFORMATION>())
                .expect("volume information structure size fits u32"),
            FileFsDeviceInformation,
        )
    };
    if status != 0 {
        return Err(StorageProbeError {
            observation,
            error: ntstatus_error(status),
        });
    }
    if device.Characteristics & FILE_REMOTE_DEVICE != 0 {
        observation.device_scope = "remote";
        return Err(StorageProbeError {
            observation,
            error: io::Error::new(
                io::ErrorKind::Unsupported,
                "remote Windows filesystems are outside the materialization support boundary",
            ),
        });
    }
    observation.device_scope = "local";

    let mut filesystem_flags = 0_u32;
    let mut filesystem_name = [0_u16; 32];
    // Safety: the retained directory handle is valid and each optional output is either null or
    // points to initialized writable storage with its exact element count.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            parent.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut filesystem_flags,
            filesystem_name.as_mut_ptr(),
            u32::try_from(filesystem_name.len()).expect("filesystem buffer length fits u32"),
        )
    };
    if ok == 0 {
        return Err(StorageProbeError {
            observation,
            error: last_os_error(),
        });
    }
    let Some(nul) = filesystem_name.iter().position(|unit| *unit == 0) else {
        return Err(StorageProbeError {
            observation,
            error: io::Error::new(
                io::ErrorKind::InvalidData,
                "filesystem name was not NUL terminated",
            ),
        });
    };
    let filesystem =
        String::from_utf16(&filesystem_name[..nul]).map_err(|error| StorageProbeError {
            observation: observation.clone(),
            error: io::Error::new(
                io::ErrorKind::InvalidData,
                format!("filesystem name is not valid UTF-16: {error}"),
            ),
        })?;
    observation.filesystem = Some(filesystem);
    observation.persistent_acls = Some(filesystem_flags & FILE_PERSISTENT_ACLS != 0);
    observation.read_only = Some(filesystem_flags & FILE_READ_ONLY_VOLUME != 0);

    if let Some(reason) = unsupported_storage_reason(&observation) {
        return Err(StorageProbeError {
            observation,
            error: io::Error::new(io::ErrorKind::Unsupported, reason),
        });
    }
    Ok(observation)
}

fn unsupported_storage_reason(observation: &StorageObservation) -> Option<&'static str> {
    if observation.device_scope != "local" {
        return Some("the Windows filesystem is not proven local");
    }
    if observation
        .filesystem
        .as_deref()
        .is_none_or(|name| !name.eq_ignore_ascii_case("NTFS"))
    {
        return Some("only local NTFS is supported for Windows materialization");
    }
    if observation.persistent_acls != Some(true) {
        return Some("the Windows filesystem does not report persistent ACL support");
    }
    if observation.read_only != Some(false) {
        return Some("the Windows filesystem is read-only or its writeability is unknown");
    }
    None
}

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

    let mut security = PrivateStageSecurity::for_effective_user()?;
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
        SecurityDescriptor: security.descriptor_ptr(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut handle: HANDLE = INVALID_HANDLE_VALUE;
    let mut status_block = MaybeUninit::<IO_STATUS_BLOCK>::zeroed();

    // Safety: every pointer refers to initialized storage for the duration of the synchronous
    // call. FILE_CREATE makes creation exclusive, and the returned handle is owned exactly once.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            DELETE
                | READ_CONTROL
                | FILE_LIST_DIRECTORY
                | FILE_READ_ATTRIBUTES
                | FILE_TRAVERSE
                | SYNCHRONIZE,
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

pub(super) fn ensure_private_stage_security(root: &CapDir) -> io::Result<()> {
    #[cfg(test)]
    if INJECT_STAGE_SECURITY_FAILURE.with(|inject| inject.replace(false)) {
        return Err(io::Error::other(
            "injected stage security verification failure",
        ));
    }
    let expected_sid = effective_user_sid()?;
    validate_private_security(
        root.as_raw_handle(),
        expected_sid.as_ptr(),
        SecurityKind::StageRoot,
    )
}

#[cfg(test)]
pub(super) fn ensure_private_descendant_security(
    handle: HANDLE,
    is_directory: bool,
) -> io::Result<()> {
    let expected_sid = effective_user_sid()?;
    validate_private_security(
        handle,
        expected_sid.as_ptr(),
        if is_directory {
            SecurityKind::ChildDirectory
        } else {
            SecurityKind::ChildFile
        },
    )
}

#[derive(Clone, Copy)]
enum SecurityKind {
    StageRoot,
    #[cfg(test)]
    ChildDirectory,
    #[cfg(test)]
    ChildFile,
}

fn validate_private_security(
    handle: HANDLE,
    expected_sid: PSID,
    kind: SecurityKind,
) -> io::Result<()> {
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // Safety: output pointers remain valid until the returned descriptor is released with
    // LocalFree. The retained stage handle has READ_CONTROL access.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(win32_error(status));
    }
    if descriptor.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stage security query returned no descriptor",
        ));
    }
    let _descriptor = LocalDescriptor(descriptor);

    // Safety: owner and dacl point inside the live descriptor, and expected_sid is owned by the
    // caller for this validation call.
    if owner.is_null() || unsafe { EqualSid(owner, expected_sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stage owner is not the effective token user",
        ));
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // Safety: descriptor is live and both scalar outputs are writable.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(last_os_error());
    }
    if matches!(kind, SecurityKind::StageRoot) && control & SE_DACL_PROTECTED == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stage DACL is not protected from parent inheritance",
        ));
    }
    if dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stage DACL is absent or null",
        ));
    }

    let mut acl_info = ACL_SIZE_INFORMATION::default();
    // Safety: dacl points inside the live descriptor and acl_info has the required size.
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).expect("ACL info size fits u32"),
            AclSizeInformation,
        )
    } == 0
    {
        return Err(last_os_error());
    }
    if acl_info.AceCount != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stage DACL does not contain exactly one ACE",
        ));
    }

    let mut ace_ptr: *mut c_void = ptr::null_mut();
    // Safety: the validated ACL reports one ACE, and the output pointer is writable.
    if unsafe { GetAce(dacl, 0, &mut ace_ptr) } == 0 {
        return Err(last_os_error());
    }
    if ace_ptr.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stage DACL returned a null ACE",
        ));
    }
    // Safety: GetAce returned a pointer whose leading field is ACE_HEADER. The full
    // ACCESS_ALLOWED_ACE fields are used only after confirming the ACE type.
    let ace = unsafe { &*ace_ptr.cast::<ACCESS_ALLOWED_ACE>() };
    if u32::from(ace.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stage DACL contains a non-allow ACE",
        ));
    }
    let expected_flags = match kind {
        SecurityKind::StageRoot => OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        #[cfg(test)]
        SecurityKind::ChildDirectory => OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERITED_ACE,
        #[cfg(test)]
        SecurityKind::ChildFile => INHERITED_ACE,
    };
    if u32::from(ace.Header.AceFlags) != expected_flags
        || ace.Header.AceFlags
            & u8::try_from(INHERIT_ONLY_ACE).expect("inherit-only ACE flag fits u8")
            != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stage allow ACE has unexpected inheritance flags",
        ));
    }
    if ace.Mask != FILE_ALL_ACCESS {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stage allow ACE does not grant the exact file access mask",
        ));
    }
    let ace_sid = ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
    // Safety: an ACCESS_ALLOWED_ACE stores its SID beginning at SidStart.
    if unsafe { IsValidSid(ace_sid) } == 0 || unsafe { EqualSid(ace_sid, expected_sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stage allow ACE principal is not the effective token user",
        ));
    }
    Ok(())
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

    // Safety: the buffer is aligned, zero-initialized, large enough for the generated structure
    // plus UTF-16 name, and remains live until the synchronous call returns.
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

struct OwnedSid {
    words: Vec<usize>,
}

impl OwnedSid {
    fn as_ptr(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast::<c_void>()
    }
}

struct PrivateStageSecurity {
    sid: OwnedSid,
    acl_words: Vec<usize>,
    descriptor: SECURITY_DESCRIPTOR,
}

impl PrivateStageSecurity {
    fn for_effective_user() -> io::Result<Self> {
        let sid = effective_user_sid()?;
        // Safety: effective_user_sid returns a validated SID in owned aligned storage.
        let sid_length = usize::try_from(unsafe { GetLengthSid(sid.as_ptr()) })
            .map_err(|_| io::Error::other("effective user SID length does not fit usize"))?;
        let acl_bytes = size_of::<ACL>()
            .checked_add(size_of::<ACCESS_ALLOWED_ACE>())
            .and_then(|size| size.checked_sub(size_of::<u32>()))
            .and_then(|size| size.checked_add(sid_length))
            .and_then(|size| size.checked_add(size_of::<u32>() - 1))
            .map(|size| size & !(size_of::<u32>() - 1))
            .ok_or_else(|| io::Error::other("stage ACL size overflow"))?;
        let mut acl_words = vec![0_usize; acl_bytes.div_ceil(size_of::<usize>())];
        let acl = acl_words.as_mut_ptr().cast::<ACL>();

        // Safety: the ACL buffer is aligned, zeroed, and has the checked size supplied here.
        if unsafe {
            InitializeAcl(
                acl,
                u32::try_from(acl_bytes).map_err(|_| io::Error::other("stage ACL is too large"))?,
                ACL_REVISION,
            )
        } == 0
        {
            return Err(last_os_error());
        }
        // Safety: the ACL is initialized and has enough space for exactly this allow ACE and SID.
        if unsafe {
            AddAccessAllowedAceEx(
                acl,
                ACL_REVISION,
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                FILE_ALL_ACCESS,
                sid.as_ptr(),
            )
        } == 0
        {
            return Err(last_os_error());
        }

        let mut descriptor = SECURITY_DESCRIPTOR::default();
        let descriptor_ptr = (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast::<c_void>();
        // Safety: descriptor is writable absolute-descriptor storage; the SID and ACL live in
        // heap allocations that remain stable while the containing structure moves.
        if unsafe { InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION) }
            == 0
            || unsafe { SetSecurityDescriptorOwner(descriptor_ptr, sid.as_ptr(), 0) } == 0
            || unsafe { SetSecurityDescriptorDacl(descriptor_ptr, 1, acl, 0) } == 0
            || unsafe {
                SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
            } == 0
        {
            return Err(last_os_error());
        }
        Ok(Self {
            sid,
            acl_words,
            descriptor,
        })
    }

    fn descriptor_ptr(&mut self) -> *const SECURITY_DESCRIPTOR {
        let _keep_alive = (&self.sid, &self.acl_words);
        &self.descriptor
    }
}

fn effective_user_sid() -> io::Result<OwnedSid> {
    let token = effective_token()?;
    let mut required = 0_u32;
    // Safety: the first call intentionally supplies no buffer to obtain the required size.
    let first = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut required,
        )
    };
    if first != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || required == 0 {
        return Err(last_os_error());
    }
    let required_usize = usize::try_from(required)
        .map_err(|_| io::Error::other("token user buffer length does not fit usize"))?;
    let mut token_words = vec![0_usize; required_usize.div_ceil(size_of::<usize>())];
    // Safety: token_words is aligned and at least the required byte length.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            token_words.as_mut_ptr().cast::<c_void>(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(last_os_error());
    }
    // Safety: a successful TokenUser query initializes TOKEN_USER at the start of the buffer.
    let sid = unsafe { (*token_words.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // Safety: sid is supplied by the kernel inside the live token buffer.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "effective token returned an invalid user SID",
        ));
    }
    // Safety: the SID is validated and remains live while its length is queried and copied.
    let sid_length = unsafe { GetLengthSid(sid) };
    if sid_length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "effective token returned an empty user SID",
        ));
    }
    let sid_bytes = usize::try_from(sid_length)
        .map_err(|_| io::Error::other("effective user SID length does not fit usize"))?;
    let mut words = vec![0_usize; sid_bytes.div_ceil(size_of::<usize>())];
    // Safety: destination storage is aligned and at least sid_length bytes; source is validated.
    if unsafe { CopySid(sid_length, words.as_mut_ptr().cast::<c_void>(), sid) } == 0 {
        return Err(last_os_error());
    }
    Ok(OwnedSid { words })
}

fn effective_token() -> io::Result<OwnedHandle> {
    let mut token: HANDLE = ptr::null_mut();
    // Safety: GetCurrentThread returns a pseudo-handle valid for this call and token is writable.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
        let error = unsafe { GetLastError() };
        if error != ERROR_NO_TOKEN {
            return Err(win32_error(error));
        }
        // Safety: GetCurrentProcess returns a pseudo-handle valid for this call and token is
        // writable. The resulting token handle is owned by the caller.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(last_os_error());
        }
    }
    if token.is_null() || token == INVALID_HANDLE_VALUE {
        return Err(io::Error::other(
            "token query succeeded without a valid token handle",
        ));
    }
    // Safety: OpenThreadToken or OpenProcessToken returned a new owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

struct LocalDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        // Safety: GetSecurityInfo allocated this descriptor with LocalAlloc-compatible storage.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn ntstatus_error(status: i32) -> io::Error {
    // Safety: RtlNtStatusToDosError has no pointer arguments and accepts every NTSTATUS value.
    let code = unsafe { RtlNtStatusToDosError(status) };
    win32_error(code)
}

fn last_os_error() -> io::Error {
    io::Error::last_os_error()
}

fn win32_error(code: u32) -> io::Error {
    match i32::try_from(code) {
        Ok(code) => io::Error::from_raw_os_error(code),
        Err(_) => io::Error::other(format!("Windows error 0x{code:08x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(
        filesystem: Option<&str>,
        device_scope: &'static str,
        persistent_acls: Option<bool>,
        read_only: Option<bool>,
    ) -> StorageObservation {
        StorageObservation {
            filesystem: filesystem.map(str::to_owned),
            device_scope,
            persistent_acls,
            read_only,
        }
    }

    #[test]
    fn storage_allowlist_accepts_only_local_writable_ntfs_with_acls() {
        assert_eq!(
            unsupported_storage_reason(&observation(
                Some("NTFS"),
                "local",
                Some(true),
                Some(false)
            )),
            None
        );
        assert_eq!(
            unsupported_storage_reason(&observation(
                Some("ntfs"),
                "local",
                Some(true),
                Some(false)
            )),
            None
        );

        for rejected in [
            observation(Some("ReFS"), "local", Some(true), Some(false)),
            observation(Some("NTFS"), "remote", Some(true), Some(false)),
            observation(Some("exFAT"), "local", Some(false), Some(false)),
            observation(Some("NTFS"), "local", Some(false), Some(false)),
            observation(Some("NTFS"), "local", Some(true), Some(true)),
            observation(None, "unknown", None, None),
        ] {
            assert!(unsupported_storage_reason(&rejected).is_some());
        }
    }

    #[test]
    fn private_stage_descriptor_round_trips_exactly() {
        let security = PrivateStageSecurity::for_effective_user().unwrap();
        let expected_sid = security.sid.as_ptr();
        let descriptor = (&security.descriptor as *const SECURITY_DESCRIPTOR)
            .cast_mut()
            .cast::<c_void>();
        let mut control = 0_u16;
        let mut revision = 0_u32;
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) },
            0
        );
        assert_ne!(control & SE_DACL_PROTECTED, 0);
        assert_eq!(security.descriptor.Owner, expected_sid);
        assert!(!security.descriptor.Dacl.is_null());
    }
}
