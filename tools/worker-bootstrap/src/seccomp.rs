#[cfg(target_arch = "x86_64")]
use rustix::fd::AsRawFd;
use rustix::fd::BorrowedFd;
use std::io;
use thiserror::Error;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const SECCOMP_MODE_FILTER: libc::c_int = 2;

#[cfg(target_arch = "x86_64")]
const DENIED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_ioctl,
    libc::SYS_clone,
    libc::SYS_fork,
    libc::SYS_vfork,
    libc::SYS_execve,
    libc::SYS_chmod,
    libc::SYS_fchmod,
    libc::SYS_chown,
    libc::SYS_fchown,
    libc::SYS_lchown,
    libc::SYS_setxattr,
    libc::SYS_lsetxattr,
    libc::SYS_fsetxattr,
    libc::SYS_removexattr,
    libc::SYS_lremovexattr,
    libc::SYS_fremovexattr,
    libc::SYS_fchownat,
    libc::SYS_fchmodat,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_execveat,
    libc::SYS_clone3,
    libc::SYS_fchmodat2,
    libc::SYS_link,
    libc::SYS_linkat,
    libc::SYS_unlink,
    libc::SYS_unlinkat,
    libc::SYS_rename,
    libc::SYS_renameat,
    libc::SYS_renameat2,
    libc::SYS_symlink,
    libc::SYS_symlinkat,
    libc::SYS_mknod,
    libc::SYS_mknodat,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_truncate,
    libc::SYS_ftruncate,
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
];

pub(crate) fn install_and_verify(stage: Option<BorrowedFd<'_>>) -> Result<(), SeccompError> {
    install_filter()?;
    verify_filter_mode()?;
    verify_denied_syscalls(stage)?;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn install_filter() -> Result<(), SeccompError> {
    let mut filter = build_filter()?;
    let len = u16::try_from(filter.len()).map_err(|_| SeccompError::FilterTooLarge)?;
    let program = libc::sock_fprog {
        len,
        filter: filter.as_mut_ptr(),
    };

    // SAFETY: the BPF program is fully initialized, remains alive for the
    // syscall, checks the x86_64 audit architecture before the syscall number,
    // and contains only forward jumps within its own instruction array.
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            std::ptr::from_ref(&program),
        )
    };
    if result == 0 {
        return Ok(());
    }
    if result == -1 {
        return Err(SeccompError::Install(io::Error::last_os_error()));
    }
    Err(SeccompError::ThreadSync(result))
}

#[cfg(not(target_arch = "x86_64"))]
fn install_filter() -> Result<(), SeccompError> {
    Err(SeccompError::UnsupportedArchitecture)
}

#[cfg(target_arch = "x86_64")]
fn build_filter() -> Result<Vec<libc::sock_filter>, SeccompError> {
    const LOAD_WORD_ABSOLUTE: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const JUMP_EQUAL_CONSTANT: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    const JUMP_GREATER_EQUAL_CONSTANT: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
    const RETURN_CONSTANT: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
    const ARCH_OFFSET: u32 = std::mem::offset_of!(libc::seccomp_data, arch) as u32;
    const NUMBER_OFFSET: u32 = std::mem::offset_of!(libc::seccomp_data, nr) as u32;
    const DENY: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;

    let mut filter = Vec::with_capacity(7 + DENIED_SYSCALLS.len() * 2);
    filter.push(statement(LOAD_WORD_ABSOLUTE, ARCH_OFFSET));
    filter.push(jump(JUMP_EQUAL_CONSTANT, AUDIT_ARCH_X86_64, 1, 0));
    filter.push(statement(RETURN_CONSTANT, libc::SECCOMP_RET_KILL_PROCESS));
    filter.push(statement(LOAD_WORD_ABSOLUTE, NUMBER_OFFSET));
    filter.push(jump(JUMP_GREATER_EQUAL_CONSTANT, X32_SYSCALL_BIT, 0, 1));
    filter.push(statement(RETURN_CONSTANT, libc::SECCOMP_RET_KILL_PROCESS));
    for syscall in DENIED_SYSCALLS {
        let syscall =
            u32::try_from(*syscall).map_err(|_| SeccompError::InvalidSyscall(*syscall))?;
        filter.push(jump(JUMP_EQUAL_CONSTANT, syscall, 0, 1));
        filter.push(statement(RETURN_CONSTANT, DENY));
    }
    filter.push(statement(RETURN_CONSTANT, libc::SECCOMP_RET_ALLOW));
    Ok(filter)
}

#[cfg(target_arch = "x86_64")]
const fn statement(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

#[cfg(target_arch = "x86_64")]
const fn jump(code: u16, value: u32, on_true: u8, on_false: u8) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: on_true,
        jf: on_false,
        k: value,
    }
}

fn verify_filter_mode() -> Result<(), SeccompError> {
    // SAFETY: PR_GET_SECCOMP reads no userspace pointers and ignores the
    // trailing zero arguments.
    let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    if mode == SECCOMP_MODE_FILTER {
        Ok(())
    } else if mode == -1 {
        Err(SeccompError::ReadMode(io::Error::last_os_error()))
    } else {
        Err(SeccompError::WrongMode(mode))
    }
}

#[cfg(target_arch = "x86_64")]
fn verify_denied_syscalls(stage: Option<BorrowedFd<'_>>) -> Result<(), SeccompError> {
    // Each probe has invalid or inert arguments, so a filter regression cannot
    // create a child, replace the process, or join a namespace while still
    // making the expected EPERM distinguishable from the kernel's normal
    // EINVAL, EFAULT, or EBADF result.
    // SAFETY: syscall is variadic; every call supplies the arguments required
    // by its x86_64 ABI, and all userspace pointers are deliberately null.
    unsafe {
        expect_permission_denied(
            "clone3",
            libc::syscall(libc::SYS_clone3, std::ptr::null::<libc::c_void>(), 0_usize),
        )?;
        expect_permission_denied(
            "clone",
            libc::syscall(
                libc::SYS_clone,
                usize::MAX,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
                0_usize,
            ),
        )?;
        expect_permission_denied(
            "execve",
            libc::syscall(
                libc::SYS_execve,
                std::ptr::null::<libc::c_char>(),
                std::ptr::null::<*const libc::c_char>(),
                std::ptr::null::<*const libc::c_char>(),
            ),
        )?;
        expect_permission_denied("setns", libc::syscall(libc::SYS_setns, -1_i32, 0_i32))?;
        expect_permission_denied("unshare", libc::syscall(libc::SYS_unshare, 0_i32))?;
        expect_permission_denied("ioctl", libc::syscall(libc::SYS_ioctl, -1_i32, 0_u64))?;
        expect_permission_denied(
            "renameat2",
            libc::syscall(
                libc::SYS_renameat2,
                -1_i32,
                std::ptr::null::<libc::c_char>(),
                -1_i32,
                std::ptr::null::<libc::c_char>(),
                0_u32,
            ),
        )?;
        expect_permission_denied(
            "unlinkat",
            libc::syscall(
                libc::SYS_unlinkat,
                -1_i32,
                std::ptr::null::<libc::c_char>(),
                0_i32,
            ),
        )?;
        expect_permission_denied(
            "linkat",
            libc::syscall(
                libc::SYS_linkat,
                -1_i32,
                std::ptr::null::<libc::c_char>(),
                -1_i32,
                std::ptr::null::<libc::c_char>(),
                0_i32,
            ),
        )?;
        expect_permission_denied(
            "mount",
            libc::syscall(
                libc::SYS_mount,
                std::ptr::null::<libc::c_char>(),
                std::ptr::null::<libc::c_char>(),
                std::ptr::null::<libc::c_char>(),
                0_u64,
                std::ptr::null::<libc::c_void>(),
            ),
        )?;
        expect_permission_denied(
            "socket",
            libc::syscall(libc::SYS_socket, -1_i32, libc::SOCK_STREAM, 0_i32),
        )?;
        expect_permission_denied(
            "connect",
            libc::syscall(
                libc::SYS_connect,
                -1_i32,
                std::ptr::null::<libc::sockaddr>(),
                0_u32,
            ),
        )?;
    }

    if let Some(stage) = stage {
        let descriptor = stage.as_raw_fd();
        // SAFETY: descriptor is borrowed for each call. The static xattr name
        // is NUL-terminated and the one-byte value is valid for its length.
        unsafe {
            expect_permission_denied(
                "fchmod",
                libc::c_long::from(libc::fchmod(descriptor, 0o777)),
            )?;
            expect_permission_denied(
                "fchown",
                libc::c_long::from(libc::fchown(descriptor, libc::uid_t::MAX, libc::gid_t::MAX)),
            )?;
            let name = b"user.sealr-seccomp-probe\0";
            let value = [1_u8];
            expect_permission_denied(
                "fsetxattr",
                libc::fsetxattr(
                    descriptor,
                    name.as_ptr().cast(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                ) as libc::c_long,
            )?;
        }
    }

    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
fn verify_denied_syscalls(_stage: Option<BorrowedFd<'_>>) -> Result<(), SeccompError> {
    Err(SeccompError::UnsupportedArchitecture)
}

#[cfg(target_arch = "x86_64")]
fn expect_permission_denied(
    operation: &'static str,
    result: libc::c_long,
) -> Result<(), SeccompError> {
    let error = io::Error::last_os_error();
    if result == -1 && error.raw_os_error() == Some(libc::EPERM) {
        Ok(())
    } else {
        Err(SeccompError::Probe {
            operation,
            result,
            error,
        })
    }
}

#[derive(Debug, Error)]
pub(crate) enum SeccompError {
    #[cfg(not(target_arch = "x86_64"))]
    #[error("seccomp filter currently supports only x86_64 Linux")]
    UnsupportedArchitecture,
    #[cfg(target_arch = "x86_64")]
    #[error("seccomp filter exceeds the kernel instruction-count representation")]
    FilterTooLarge,
    #[cfg(target_arch = "x86_64")]
    #[error("seccomp filter contains invalid syscall number {0}")]
    InvalidSyscall(libc::c_long),
    #[cfg(target_arch = "x86_64")]
    #[error("installing seccomp filter failed: {0}")]
    Install(io::Error),
    #[cfg(target_arch = "x86_64")]
    #[error("seccomp thread synchronization failed at thread ID {0}")]
    ThreadSync(libc::c_long),
    #[error("reading seccomp mode failed: {0}")]
    ReadMode(io::Error),
    #[error("seccomp mode is {0}; expected filter mode 2")]
    WrongMode(libc::c_int),
    #[cfg(target_arch = "x86_64")]
    #[error("seccomp probe {operation} returned {result} with {error}; expected EPERM")]
    Probe {
        operation: &'static str,
        result: libc::c_long,
        error: io::Error,
    },
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn denied_syscalls_are_unique_and_filter_is_forward_only() {
        assert_eq!(
            DENIED_SYSCALLS
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            DENIED_SYSCALLS.len()
        );
        let filter = build_filter().expect("x86_64 seccomp filter builds");
        assert_eq!(filter.len(), 7 + DENIED_SYSCALLS.len() * 2);
        assert_eq!(
            filter[0].k,
            std::mem::offset_of!(libc::seccomp_data, arch) as u32
        );
        assert_eq!(filter[1].k, AUDIT_ARCH_X86_64);
        assert_eq!(filter[2].k, libc::SECCOMP_RET_KILL_PROCESS);
        assert_eq!(
            filter[3].k,
            std::mem::offset_of!(libc::seccomp_data, nr) as u32
        );
        assert_eq!(filter[4].k, X32_SYSCALL_BIT);
        assert_eq!(filter[5].k, libc::SECCOMP_RET_KILL_PROCESS);
        for (index, syscall) in DENIED_SYSCALLS.iter().enumerate() {
            let jump = &filter[6 + index * 2];
            let deny = &filter[7 + index * 2];
            assert_eq!(jump.k, u32::try_from(*syscall).expect("syscall is valid"));
            assert_eq!(deny.k, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32);
        }
        assert_eq!(
            filter.last().expect("allow tail").k,
            libc::SECCOMP_RET_ALLOW
        );
    }
}
