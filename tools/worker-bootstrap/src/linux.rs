use crate::frame::{Frame, FrameError, FRAME_LEN};
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::io::FdFlags;
use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};
use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use thiserror::Error;

pub(crate) const FLAG_STAGE: u8 = 1 << 0;
pub(crate) const FLAG_NO_NEW_PRIVS: u8 = 1 << 1;
pub(crate) const FLAG_CLOSE_RANGE: u8 = 1 << 2;
pub(crate) const FLAG_LANDLOCK_ENFORCED: u8 = 1 << 3;
pub(crate) const READY_FLAGS: u8 = FLAG_NO_NEW_PRIVS | FLAG_CLOSE_RANGE | FLAG_LANDLOCK_ENFORCED;
pub(crate) const PROTOCOL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) const ERROR_PROTOCOL: u64 = 1;
pub(crate) const ERROR_DESCRIPTOR: u64 = 2;
pub(crate) const ERROR_AUTHORITY_CLOSE: u64 = 3;
pub(crate) const ERROR_RESTRICTION: u64 = 4;
pub(crate) const ERROR_PROBE: u64 = 5;
pub(crate) const DETAIL_DATA_TRUNCATED: u64 = 1 << 0;
pub(crate) const DETAIL_CONTROL_TRUNCATED: u64 = 1 << 1;
pub(crate) const DETAIL_SHORT_FRAME: u64 = 1 << 2;

pub(crate) fn configure_timeout<Fd: AsFd>(socket: Fd) -> Result<(), TransportError> {
    rustix::net::sockopt::set_socket_timeout(
        socket.as_fd(),
        rustix::net::sockopt::Timeout::Recv,
        Some(PROTOCOL_TIMEOUT),
    )?;
    rustix::net::sockopt::set_socket_timeout(
        socket.as_fd(),
        rustix::net::sockopt::Timeout::Send,
        Some(PROTOCOL_TIMEOUT),
    )?;
    Ok(())
}

pub(crate) fn send_packet<Fd: AsFd>(
    socket: Fd,
    frame: Frame,
    descriptors: &[BorrowedFd<'_>],
) -> Result<(), TransportError> {
    if descriptors.len() > 2 {
        return Err(TransportError::DescriptorCount {
            expected: 2,
            actual: descriptors.len(),
        });
    }

    let encoded = frame.encode();
    let iov = [IoSlice::new(&encoded)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !descriptors.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(descriptors)) {
        return Err(TransportError::AncillaryCapacity);
    }
    let written = sendmsg(socket.as_fd(), &iov, &mut ancillary, SendFlags::NOSIGNAL)?;
    if written != FRAME_LEN {
        return Err(TransportError::ShortSend(written));
    }
    Ok(())
}

pub(crate) fn send_raw_conformance_packet<Fd: AsFd>(
    socket: Fd,
    bytes: &[u8],
    descriptors: &[BorrowedFd<'_>],
) -> Result<usize, TransportError> {
    if descriptors.len() > 5 {
        return Err(TransportError::DescriptorCount {
            expected: 5,
            actual: descriptors.len(),
        });
    }

    let iov = [IoSlice::new(bytes)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(5))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !descriptors.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(descriptors)) {
        return Err(TransportError::AncillaryCapacity);
    }
    Ok(sendmsg(
        socket.as_fd(),
        &iov,
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )?)
}

pub(crate) fn receive_packet<Fd: AsFd>(
    socket: Fd,
    expected_descriptors: Option<usize>,
) -> Result<(Frame, Vec<OwnedFd>), TransportError> {
    let mut encoded = [0_u8; FRAME_LEN];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message = {
        let mut iov = [IoSliceMut::new(&mut encoded)];
        recvmsg(
            socket.as_fd(),
            &mut iov,
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC,
        )?
    };

    let data_truncated = message.flags.contains(ReturnFlags::TRUNC);
    let control_truncated = message.flags.contains(ReturnFlags::CTRUNC);
    if data_truncated || control_truncated {
        return Err(TransportError::Truncated {
            data: data_truncated,
            control: control_truncated,
        });
    }
    if message.bytes != FRAME_LEN {
        return Err(TransportError::Frame(FrameError::Length(message.bytes)));
    }

    let mut rights_messages = 0_usize;
    let mut unexpected_ancillary = false;
    let mut descriptors = Vec::with_capacity(expected_descriptors.unwrap_or(2).min(2));
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(rights) => {
                rights_messages += 1;
                descriptors.extend(rights);
            }
            _ => unexpected_ancillary = true,
        }
    }

    let expected_messages = usize::from(!descriptors.is_empty());
    if unexpected_ancillary || rights_messages != expected_messages {
        return Err(TransportError::UnexpectedAncillary);
    }
    if let Some(expected) = expected_descriptors {
        if descriptors.len() != expected {
            return Err(TransportError::DescriptorCount {
                expected,
                actual: descriptors.len(),
            });
        }
    }
    for descriptor in &descriptors {
        let flags = rustix::io::fcntl_getfd(descriptor)?;
        if !flags.contains(FdFlags::CLOEXEC) {
            return Err(TransportError::DescriptorNotCloseOnExec);
        }
    }

    Ok((Frame::decode(&encoded)?, descriptors))
}

pub(crate) fn close_inherited_authority<Fd: AsFd>(control: Fd) -> Result<(), TransportError> {
    use std::os::fd::IntoRawFd;

    let probe = rustix::io::fcntl_dupfd_cloexec(control.as_fd(), 3)?.into_raw_fd();
    // SAFETY: close_range is invoked before the single-threaded child receives
    // any capabilities. Fds 0, 1, and 2 are intentionally outside the range:
    // fd 0 is the control socket and fds 1 and 2 are inert /dev/null streams.
    // Keeping the null streams open prevents received capabilities from being
    // assigned conventional standard-stream numbers.
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_UNSHARE,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        // SAFETY: the probe is an owned raw descriptor until close_range
        // succeeds. This error path must close it explicitly.
        unsafe { libc::close(probe) };
        return Err(TransportError::System(error));
    }

    // No descriptor can be opened between close_range and this check in the
    // single-threaded child, so the raw number cannot have been reused.
    // SAFETY: fcntl accepts an integer descriptor and reports EBADF for the
    // expected closed probe.
    let probe_status = unsafe { libc::fcntl(probe, libc::F_GETFD) };
    if probe_status != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
        if probe_status != -1 {
            // SAFETY: a nonnegative fcntl result proves the probe is still open.
            unsafe { libc::close(probe) };
        }
        return Err(TransportError::AuthorityProbeSurvived);
    }

    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum TransportError {
    #[error(transparent)]
    Errno(#[from] rustix::io::Errno),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error(transparent)]
    System(#[from] std::io::Error),
    #[error("bootstrap ancillary buffer was too small")]
    AncillaryCapacity,
    #[error("bootstrap packet sent only {0} bytes")]
    ShortSend(usize),
    #[error("bootstrap packet truncation flags are data={data}, control={control}")]
    Truncated { data: bool, control: bool },
    #[error("bootstrap packet carried an unexpected ancillary message layout")]
    UnexpectedAncillary,
    #[error("bootstrap packet carried {actual} descriptors; expected {expected}")]
    DescriptorCount { expected: usize, actual: usize },
    #[error("received bootstrap descriptor is not close-on-exec")]
    DescriptorNotCloseOnExec,
    #[error("post-exec descriptor survived child-entry authority closure")]
    AuthorityProbeSurvived,
}

impl TransportError {
    pub(crate) fn protocol_detail(&self) -> u64 {
        match self {
            Self::Truncated { data, control } => {
                (u64::from(*data) * DETAIL_DATA_TRUNCATED)
                    | (u64::from(*control) * DETAIL_CONTROL_TRUNCATED)
            }
            Self::Frame(FrameError::Length(length)) if *length < FRAME_LEN => DETAIL_SHORT_FRAME,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_detail_preserves_each_process_boundary_condition() {
        assert_eq!(
            TransportError::Truncated {
                data: true,
                control: false,
            }
            .protocol_detail(),
            DETAIL_DATA_TRUNCATED
        );
        assert_eq!(
            TransportError::Truncated {
                data: false,
                control: true,
            }
            .protocol_detail(),
            DETAIL_CONTROL_TRUNCATED
        );
        assert_eq!(
            TransportError::Truncated {
                data: true,
                control: true,
            }
            .protocol_detail(),
            DETAIL_DATA_TRUNCATED | DETAIL_CONTROL_TRUNCATED
        );
        assert_eq!(
            TransportError::Frame(FrameError::Length(FRAME_LEN - 1)).protocol_detail(),
            DETAIL_SHORT_FRAME
        );
        assert_eq!(
            TransportError::Frame(FrameError::Magic).protocol_detail(),
            0
        );
    }
}
