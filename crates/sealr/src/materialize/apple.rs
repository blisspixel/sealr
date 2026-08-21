use std::ffi::{c_int, c_void};
use std::io;
use std::os::fd::AsRawFd;

use cap_std::fs::Dir as CapDir;

const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;

unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
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

    // Safety: acl_get_fd_np returned an allocated ACL object owned by this function.
    let free_result = unsafe { acl_free(acl) };
    if free_result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std::ambient_authority;
    use std::fs;
    use std::process::Command;

    #[test]
    fn retained_descriptor_distinguishes_absent_and_present_extended_acl() {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("sealr-apple-acl-{suffix}"));
        fs::create_dir(&path).unwrap();
        let dir = CapDir::open_ambient_dir(&path, ambient_authority()).unwrap();

        assert!(!has_extended_acl(&dir).unwrap());

        let output = Command::new("chmod")
            .args([
                "+a",
                "everyone allow add_file,add_subdirectory,delete_child",
            ])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "add test ACL: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(has_extended_acl(&dir).unwrap());

        drop(dir);
        let output = Command::new("chmod").arg("-N").arg(&path).output().unwrap();
        assert!(output.status.success());
        fs::remove_dir(path).unwrap();
    }
}
