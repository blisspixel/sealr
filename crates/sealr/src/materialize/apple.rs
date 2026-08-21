use std::ffi::{c_int, c_void};
use std::io;
use std::os::fd::AsRawFd;

use cap_std::fs::Dir as CapDir;

const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;

unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
    fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_free(object: *mut c_void) -> c_int;
}

pub(super) fn has_extended_acl(dir: &CapDir) -> io::Result<bool> {
    // Safety: dir owns a live file descriptor, and ACL_TYPE_EXTENDED is the Apple ACL kind.
    let acl = unsafe { acl_get_fd_np(dir.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(error)
        };
    }

    let mut entry = std::ptr::null_mut();
    // Safety: acl is live and owned by this function, and entry points to writable storage.
    let entry_result = unsafe { acl_get_entry(acl, 0, &mut entry) };
    let entry_error = (entry_result == -1).then(io::Error::last_os_error);

    // Safety: acl_get_fd_np returned an allocated ACL object owned by this function.
    let free_result = unsafe { acl_free(acl) };
    if let Some(error) = entry_error {
        return Err(error);
    }
    if free_result != 0 {
        return Err(io::Error::last_os_error());
    }
    match entry_result {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(io::Error::other(format!(
            "acl_get_entry returned unexpected status {value}"
        ))),
    }
}
