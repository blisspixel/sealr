use crate::frame::{Frame, FrameError, FRAME_LEN};
use rustix::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use rustix::io::FdFlags;
use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::FromRawFd;
use std::slice;
use thiserror::Error;

pub(crate) const FLAG_STAGE: u8 = 1 << 0;
pub(crate) const FLAG_NO_NEW_PRIVS: u8 = 1 << 1;
pub(crate) const FLAG_CLOSE_RANGE: u8 = 1 << 2;
pub(crate) const FLAG_LANDLOCK_ENFORCED: u8 = 1 << 3;
pub(crate) const FLAG_SECCOMP_ENFORCED: u8 = 1 << 4;
pub(crate) const FLAG_MEMBER_READ: u8 = 1 << 5;
pub(crate) const FLAG_MATERIALIZE: u8 = 1 << 6;
pub(crate) const READY_FLAGS: u8 =
    FLAG_NO_NEW_PRIVS | FLAG_CLOSE_RANGE | FLAG_LANDLOCK_ENFORCED | FLAG_SECCOMP_ENFORCED;
pub(crate) const PROTOCOL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) const ERROR_PROTOCOL: u64 = 1;
pub(crate) const ERROR_DESCRIPTOR: u64 = 2;
pub(crate) const ERROR_AUTHORITY_CLOSE: u64 = 3;
pub(crate) const ERROR_RESTRICTION: u64 = 4;
pub(crate) const ERROR_PROBE: u64 = 5;
pub(crate) const DETAIL_DATA_TRUNCATED: u64 = 1 << 0;
pub(crate) const DETAIL_CONTROL_TRUNCATED: u64 = 1 << 1;
pub(crate) const DETAIL_SHORT_FRAME: u64 = 1 << 2;
pub(crate) const DETAIL_ANCILLARY_MALFORMED: u64 = 1 << 3;
pub(crate) const DETAIL_ANCILLARY_UNKNOWN: u64 = 1 << 4;
pub(crate) const DETAIL_ANCILLARY_MULTIPLE_RIGHTS: u64 = 1 << 5;

const RECEIVE_CONTROL_BYTES: usize = 64;
const RECEIVE_CONTROL_WORDS: usize = RECEIVE_CONTROL_BYTES / std::mem::size_of::<usize>();
// Linux CMSG_ALIGN rounds to sizeof(size_t). This differs from Rust's
// cmsghdr alignment under musl, where the public length field is narrower.
const ANCILLARY_ALIGNMENT: usize = std::mem::size_of::<libc::size_t>();
const ANCILLARY_HEADER_LEN: usize = align_up(std::mem::size_of::<libc::cmsghdr>());

const fn align_up(length: usize) -> usize {
    (length + ANCILLARY_ALIGNMENT - 1) & !(ANCILLARY_ALIGNMENT - 1)
}

fn checked_convert<From, To>(value: From) -> Option<To>
where
    To: TryFrom<From>,
{
    To::try_from(value).ok()
}

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

#[cfg(feature = "lab")]
pub(crate) fn send_raw_conformance_packet<Fd: AsFd>(
    socket: Fd,
    bytes: &[u8],
    descriptors: &[BorrowedFd<'_>],
) -> Result<usize, TransportError> {
    if descriptors.len() > 20 {
        return Err(TransportError::DescriptorCount {
            expected: 20,
            actual: descriptors.len(),
        });
    }

    let iov = [IoSlice::new(bytes)];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(20))];
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
    let mut control = [0_usize; RECEIVE_CONTROL_WORDS];
    let mut iov = libc::iovec {
        iov_base: encoded.as_mut_ptr().cast(),
        iov_len: encoded.len(),
    };
    // SAFETY: an all-zero msghdr is a valid starting state. The initialized
    // data and aligned control buffers remain live and exclusively borrowed
    // for the syscall, and their exact capacities are supplied to the kernel.
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = std::ptr::from_mut(&mut iov);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = checked_convert(std::mem::size_of_val(&control)).ok_or(
        TransportError::MalformedAncillary("control capacity is unrepresentable"),
    )?;
    // SAFETY: every pointer in message references the live buffers above.
    // MSG_CMSG_CLOEXEC makes every installed descriptor close-on-exec before
    // it becomes visible to userspace.
    let received = unsafe {
        libc::recvmsg(
            socket.as_fd().as_raw_fd(),
            std::ptr::from_mut(&mut message),
            libc::MSG_CMSG_CLOEXEC,
        )
    };
    if received < 0 {
        return Err(TransportError::System(std::io::Error::last_os_error()));
    }

    let control_len = checked_convert(message.msg_controllen).ok_or(
        TransportError::MalformedAncillary("reported control length is unrepresentable"),
    )?;
    if control_len > std::mem::size_of_val(&control) {
        return Err(TransportError::MalformedAncillary(
            "reported control length exceeds its buffer",
        ));
    }
    // SAFETY: the control array was initialized before recvmsg, and the kernel
    // returned a length within that live array. The parser performs checked,
    // unaligned reads and immediately owns every received SCM_RIGHTS fd.
    let control = unsafe { slice::from_raw_parts(control.as_ptr().cast::<u8>(), control_len) };
    let parsed_descriptors = parse_ancillary(control);

    // Parse before reporting framing errors so every kernel-installed fd is
    // owned and dropped on all rejection paths, including MSG_CTRUNC. Framing
    // remains the externally reported error because it is the first property
    // the transport promises to validate for these packets.
    let data_truncated = message.msg_flags & libc::MSG_TRUNC != 0;
    let control_truncated = message.msg_flags & libc::MSG_CTRUNC != 0;
    if data_truncated || control_truncated {
        return Err(TransportError::Truncated {
            data: data_truncated,
            control: control_truncated,
        });
    }
    let received = usize::try_from(received)
        .map_err(|_| TransportError::Frame(FrameError::Length(usize::MAX)))?;
    if received != FRAME_LEN {
        return Err(TransportError::Frame(FrameError::Length(received)));
    }
    let descriptors = parsed_descriptors?;
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

fn parse_ancillary(control: &[u8]) -> Result<Vec<OwnedFd>, TransportError> {
    let mut offset = 0_usize;
    let mut rights_messages = 0_usize;
    let mut unexpected = None;
    let mut descriptors = Vec::with_capacity(2);

    while offset < control.len() {
        let remaining = control.len() - offset;
        if remaining < ANCILLARY_HEADER_LEN {
            if offset != 0
                && remaining < ANCILLARY_ALIGNMENT
                && control[offset..].iter().all(|byte| *byte == 0)
            {
                break;
            }
            return Err(TransportError::MalformedAncillary(
                "trailing control bytes do not contain a header",
            ));
        }
        // SAFETY: the checked remaining length covers a complete cmsghdr.
        // read_unaligned avoids relying on the byte-slice alignment.
        let header = unsafe {
            control
                .as_ptr()
                .add(offset)
                .cast::<libc::cmsghdr>()
                .read_unaligned()
        };
        let message_len = checked_convert(header.cmsg_len).ok_or(
            TransportError::MalformedAncillary("ancillary message length is unrepresentable"),
        )?;
        if message_len < ANCILLARY_HEADER_LEN || message_len > remaining {
            return Err(TransportError::MalformedAncillary(
                "ancillary message length is outside the remaining control bytes",
            ));
        }
        let payload_start = offset + ANCILLARY_HEADER_LEN;
        let payload_end = offset + message_len;
        let payload = &control[payload_start..payload_end];

        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            if payload.is_empty() {
                return Err(TransportError::MalformedAncillary(
                    "SCM_RIGHTS payload is empty",
                ));
            }
            rights_messages += 1;
            let (encoded_fds, remainder) =
                payload.as_chunks::<{ std::mem::size_of::<libc::c_int>() }>();
            for encoded_fd in encoded_fds {
                let raw_fd = libc::c_int::from_ne_bytes(*encoded_fd);
                if raw_fd < 0 {
                    return Err(TransportError::MalformedAncillary(
                        "SCM_RIGHTS payload contains a negative descriptor",
                    ));
                }
                // SAFETY: ownership of an fd delivered through SCM_RIGHTS is
                // transferred to the receiving process exactly once.
                descriptors.push(unsafe { OwnedFd::from_raw_fd(raw_fd) });
            }
            if !remainder.is_empty() {
                return Err(TransportError::MalformedAncillary(
                    "SCM_RIGHTS payload contains a partial descriptor",
                ));
            }
        } else if unexpected.is_none() {
            unexpected = Some((header.cmsg_level, header.cmsg_type));
        }

        let aligned_len = align_up(message_len);
        let consumed = if aligned_len <= remaining {
            aligned_len
        } else if message_len == remaining {
            message_len
        } else {
            return Err(TransportError::MalformedAncillary(
                "ancillary alignment exceeds the remaining control bytes",
            ));
        };
        offset += consumed;
    }

    if let Some((level, kind)) = unexpected {
        return Err(TransportError::UnexpectedAncillary { level, kind });
    }
    if rights_messages > 1 {
        return Err(TransportError::MultipleRightsMessages);
    }
    Ok(descriptors)
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
    #[error("bootstrap packet carried a malformed ancillary message layout: {0}")]
    MalformedAncillary(&'static str),
    #[error("bootstrap packet carried unexpected ancillary level {level}, type {kind}")]
    UnexpectedAncillary {
        level: libc::c_int,
        kind: libc::c_int,
    },
    #[error("bootstrap packet carried multiple SCM_RIGHTS messages")]
    MultipleRightsMessages,
    #[error("bootstrap packet carried {actual} descriptors; expected {expected}")]
    DescriptorCount { expected: usize, actual: usize },
    #[error("received bootstrap descriptor is not close-on-exec")]
    DescriptorNotCloseOnExec,
    #[error("post-exec descriptor survived child-entry authority closure")]
    AuthorityProbeSurvived,
}

impl TransportError {
    #[cfg(feature = "lab")]
    pub(crate) fn is_would_block(&self) -> bool {
        match self {
            Self::Errno(error) => *error == rustix::io::Errno::AGAIN,
            Self::System(error) => error.kind() == std::io::ErrorKind::WouldBlock,
            _ => false,
        }
    }

    pub(crate) fn protocol_detail(&self) -> u64 {
        match self {
            Self::Truncated { data, control } => {
                (u64::from(*data) * DETAIL_DATA_TRUNCATED)
                    | (u64::from(*control) * DETAIL_CONTROL_TRUNCATED)
            }
            Self::Frame(FrameError::Length(length)) if *length < FRAME_LEN => DETAIL_SHORT_FRAME,
            Self::MalformedAncillary(_) => DETAIL_ANCILLARY_MALFORMED,
            Self::UnexpectedAncillary { .. } => DETAIL_ANCILLARY_UNKNOWN,
            Self::MultipleRightsMessages => DETAIL_ANCILLARY_MULTIPLE_RIGHTS,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Kind;
    use rustix::net::{AddressFamily, SocketFlags, SocketType};
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;

    fn append_control_message(
        control: &mut Vec<u8>,
        level: libc::c_int,
        kind: libc::c_int,
        payload: &[u8],
    ) {
        let message_len = ANCILLARY_HEADER_LEN + payload.len();
        let record_len = align_up(message_len);
        let offset = control.len();
        control.resize(offset + record_len, 0);
        // SAFETY: cmsghdr is an integer-only C layout and zero is valid for
        // its platform-specific padding fields. The public fields are then
        // assigned their complete record values.
        let mut header = unsafe { std::mem::zeroed::<libc::cmsghdr>() };
        header.cmsg_len = checked_convert(message_len).expect("representable cmsg length");
        header.cmsg_level = level;
        header.cmsg_type = kind;
        // SAFETY: the destination covers one complete, possibly unaligned
        // cmsghdr inside the resized byte vector.
        unsafe {
            control
                .as_mut_ptr()
                .add(offset)
                .cast::<libc::cmsghdr>()
                .write_unaligned(header);
        }
        control[offset + ANCILLARY_HEADER_LEN..offset + message_len].copy_from_slice(payload);
    }

    fn assert_peer_eof(mut peer: UnixStream) {
        peer.set_nonblocking(true).expect("set peer nonblocking");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("read peer EOF"), 0);
    }

    #[test]
    fn raw_receiver_accepts_the_kernel_rights_layout() {
        let (sender, receiver) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair");
        let descriptor = File::open("/dev/null").expect("open descriptor");
        let frame = Frame::new(Kind::Source, [7; 16]);
        send_packet(&sender, frame, &[descriptor.as_fd()]).expect("send rights frame");
        let (decoded, descriptors) = receive_packet(&receiver, Some(1))
            .unwrap_or_else(|error| panic!("receive rights frame: {error}"));
        assert_eq!(decoded, frame);
        assert_eq!(descriptors.len(), 1);
    }

    #[test]
    fn kernel_unknown_ancillary_is_rejected_and_received_rights_are_closed() {
        let (sender, receiver) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair");
        let enabled: libc::c_int = 1;
        // SAFETY: the option value is a live c_int of the supplied length.
        let configured = unsafe {
            libc::setsockopt(
                receiver.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMP,
                std::ptr::from_ref(&enabled).cast(),
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        };
        assert_eq!(
            configured,
            0,
            "enable timestamp: {}",
            std::io::Error::last_os_error()
        );

        let (peer, passed) = UnixStream::pair().expect("probe socketpair");
        let frame = Frame::new(Kind::Source, [11; 16]);
        send_packet(&sender, frame, &[passed.as_fd()]).expect("send timestamped frame");
        drop(passed);
        let error = receive_packet(&receiver, Some(1)).expect_err("reject unknown ancillary");
        assert!(matches!(
            error,
            TransportError::UnexpectedAncillary {
                level: libc::SOL_SOCKET,
                kind: libc::SO_TIMESTAMP,
            }
        ));
        assert_peer_eof(peer);
    }

    #[test]
    fn short_frame_rejection_closes_received_rights() {
        let (sender, receiver) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair");
        let (peer, passed) = UnixStream::pair().expect("probe socketpair");
        let written =
            send_raw_conformance_packet(&sender, &[0_u8; FRAME_LEN - 1], &[passed.as_fd()])
                .expect("send short frame");
        assert_eq!(written, FRAME_LEN - 1);
        drop(passed);
        assert!(matches!(
            receive_packet(&receiver, Some(1)),
            Err(TransportError::Frame(FrameError::Length(length))) if length == FRAME_LEN - 1
        ));
        assert_peer_eof(peer);
    }

    #[test]
    fn control_truncation_closes_every_installed_right() {
        let (sender, receiver) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair");
        let (peer, passed) = UnixStream::pair().expect("probe socketpair");
        let descriptors = vec![passed.as_fd(); 20];
        let written = send_raw_conformance_packet(&sender, &[0_u8; FRAME_LEN], &descriptors)
            .expect("send oversized control");
        assert_eq!(written, FRAME_LEN);
        drop(passed);
        assert!(matches!(
            receive_packet(&receiver, None),
            Err(TransportError::Truncated {
                data: false,
                control: true,
            })
        ));
        assert_peer_eof(peer);
    }

    #[test]
    fn unknown_record_before_rights_still_closes_the_descriptor() {
        let (peer, passed) = UnixStream::pair().expect("probe socketpair");
        let raw = passed.into_raw_fd();
        let mut control = Vec::new();
        append_control_message(&mut control, libc::SOL_SOCKET, libc::SO_TIMESTAMP, &[0; 8]);
        append_control_message(
            &mut control,
            libc::SOL_SOCKET,
            libc::SCM_RIGHTS,
            &raw.to_ne_bytes(),
        );

        assert!(matches!(
            parse_ancillary(&control),
            Err(TransportError::UnexpectedAncillary {
                level: libc::SOL_SOCKET,
                kind: libc::SO_TIMESTAMP,
            })
        ));
        assert_peer_eof(peer);
    }

    #[test]
    fn multiple_rights_records_close_every_descriptor() {
        let (first_peer, first_passed) = UnixStream::pair().expect("first probe socketpair");
        let (second_peer, second_passed) = UnixStream::pair().expect("second probe socketpair");
        let first_raw = first_passed.into_raw_fd();
        let second_raw = second_passed.into_raw_fd();
        let mut control = Vec::new();
        append_control_message(
            &mut control,
            libc::SOL_SOCKET,
            libc::SCM_RIGHTS,
            &first_raw.to_ne_bytes(),
        );
        append_control_message(
            &mut control,
            libc::SOL_SOCKET,
            libc::SCM_RIGHTS,
            &second_raw.to_ne_bytes(),
        );

        assert!(matches!(
            parse_ancillary(&control),
            Err(TransportError::MultipleRightsMessages)
        ));
        assert_peer_eof(first_peer);
        assert_peer_eof(second_peer);
    }

    #[test]
    fn malformed_rights_record_closes_each_complete_descriptor() {
        let (peer, passed) = UnixStream::pair().expect("probe socketpair");
        let raw = passed.into_raw_fd();
        let mut payload = raw.to_ne_bytes().to_vec();
        payload.push(0);
        let mut control = Vec::new();
        append_control_message(&mut control, libc::SOL_SOCKET, libc::SCM_RIGHTS, &payload);

        assert!(matches!(
            parse_ancillary(&control),
            Err(TransportError::MalformedAncillary(
                "SCM_RIGHTS payload contains a partial descriptor"
            ))
        ));
        assert_peer_eof(peer);
    }

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
        assert!(TransportError::Errno(rustix::io::Errno::AGAIN).is_would_block());
        assert!(
            TransportError::System(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                .is_would_block()
        );
        assert!(!TransportError::Frame(FrameError::Magic).is_would_block());
    }
}
