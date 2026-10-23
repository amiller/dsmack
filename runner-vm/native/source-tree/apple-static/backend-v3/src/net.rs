//! v3 native NIC integration: a BOUNDED, ALLOWLISTED generic virtio-net option.
//!
//! The v2 control profile has NO NetDevice and `build_vm` rejects an arbitrary
//! caller-supplied `device_manager` (returning profiles own their device set).
//! v3 adds exactly ONE network option, and only this one:
//!
//!   * a single generic virtio-net device whose backend is the EXISTING
//!     upstream fd-based transport (`VirtioNetBackend::UnixstreamFd(RawFd)` in
//!     devices/src/virtio/net/device.rs). The caller hands over ONE connected
//!     SOCK_STREAM descriptor whose far end is a NAT/transport helper running
//!     OUTSIDE the app (see NATIVE-V3-NETWORK.md). No tap, no unix path, no
//!     host device, no host share, no arbitrary device_manager — those are all
//!     refused. The guest sees one NIC; the host policy lives in the helper.
//!
//! This module owns the FD lifecycle and the refusal policy. The libkrun wiring
//! (teaching `control_profile` to append this one net device to its fixed
//! device set) is the `source-changes/vmm_builder-net-option.md` proposal; the
//! ownership/validation primitive is proven here on host Linux with real fds.

use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

/// The guest's EXPECTED static network configuration (the common slirp/passt
/// NAT convention). The backend configures NONE of this: it is the guest
/// contract the external NAT helper must satisfy, recorded for the app/operator
/// and documented in NATIVE-V3-NETWORK.md. Any guest adaptation is a reviewed
/// guest-image change, never an app/backend network-global edit.
pub const GUEST_STATIC_IP: &str = "10.0.2.15";
pub const GUEST_GATEWAY: &str = "10.0.2.2";
pub const GUEST_DNS: &str = "10.0.2.3";

/// Fixed locally-administered unicast MAC for the single generic NIC. Fixed
/// (not random, not caller-chosen) so the device identity is part of the
/// bounded option, not an arbitrary caller input. LAA bit set, multicast clear.
pub const GENERIC_NIC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x15];

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    #[error("net fd {fd} fstat failed: errno {errno}")]
    Fstat { fd: RawFd, errno: i32 },
    #[error("net fd {fd} must be a connected stream SOCKET, not a {kind} \
             (no tap/path/host device/share is permitted in this profile)")]
    NotSocket { fd: RawFd, kind: &'static str },
    #[error("net fd {fd} must be SOCK_STREAM (got socket type {sotype})")]
    NotStream { fd: RawFd, sotype: i32 },
    #[error("net fd {fd} is not connected (getpeername errno {errno})")]
    NotConnected { fd: RawFd, errno: i32 },
}

fn file_kind(mode: libc::mode_t) -> &'static str {
    match mode & libc::S_IFMT {
        libc::S_IFREG => "regular file",
        libc::S_IFDIR => "directory",
        libc::S_IFCHR => "character device",
        libc::S_IFBLK => "block device",
        libc::S_IFIFO => "pipe",
        libc::S_IFLNK => "symlink",
        _ => "non-socket",
    }
}

/// The validated, owned generic-NIC transport. Holds the OwnedFd so its
/// lifetime is unambiguous: dropped (closed exactly once) on refusal, kept here
/// and closed exactly once at teardown on success. We never re-derive the fd
/// via F_GETFD or re-open it — ownership is the `OwnedFd`, period.
#[derive(Debug)]
pub struct NetTransport {
    fd: OwnedFd,
    mac: [u8; 6],
}

impl NetTransport {
    /// Validate a caller-handed fd as the allowlisted generic virtio-net
    /// transport and TAKE OWNERSHIP of it. The fd MUST be a connected
    /// SOCK_STREAM socket (the far end is the external NAT helper). Anything
    /// else — a tap fd, a unix path, a host regular file/device, an
    /// unconnected socket — is refused, and ownership of `fd` is consumed
    /// (dropped/closed exactly once) on every path.
    pub fn own_validated(fd: OwnedFd) -> Result<Self, (NetError, OwnedFd)> {
        let raw = fd.as_raw_fd();
        // SAFETY: fstat on an owned valid fd; writes into a zeroed stat.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(raw, &mut st) } != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err((NetError::Fstat { fd: raw, errno }, fd));
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            return Err((
                NetError::NotSocket {
                    fd: raw,
                    kind: file_kind(st.st_mode),
                },
                fd,
            ));
        }
        // Must be SOCK_STREAM (the fd-based unixstream transport).
        let mut sotype: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt writes an int into sotype with matching len.
        let rc = unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                &mut sotype as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 || sotype != libc::SOCK_STREAM {
            return Err((NetError::NotStream { fd: raw, sotype }, fd));
        }
        // Must be CONNECTED (far end = the NAT helper); a listening/unbound
        // socket is refused so the option can never become a host ingress.
        let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut plen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        // SAFETY: getpeername writes up to plen bytes into peer.
        let rc = unsafe {
            libc::getpeername(raw, &mut peer as *mut _ as *mut libc::sockaddr, &mut plen)
        };
        if rc != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err((NetError::NotConnected { fd: raw, errno }, fd));
        }
        Ok(NetTransport {
            fd,
            mac: GENERIC_NIC_MAC,
        })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Consume the transport, returning the raw fd for the libkrun
    /// `VirtioNetBackend::UnixstreamFd(RawFd)` wiring. After this the NET
    /// device owns the fd; the transport no longer closes it (ownership moves
    /// to the device, closed exactly once there — no double-close).
    pub fn into_unixstream_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

/// Construct an `OwnedFd` from a caller-supplied raw fd at the FFI boundary,
/// taking ownership (never a borrow). A negative fd means "no network" and
/// yields `None` with nothing claimed or closed.
///
/// # Safety
/// `fd`, when non-negative, must be an open descriptor the caller is handing
/// over unconditionally; it must not be used or closed by the caller again.
pub unsafe fn own_raw(fd: RawFd) -> Option<OwnedFd> {
    if fd < 0 {
        None
    } else {
        // SAFETY: caller contract — `fd` is a live owned descriptor.
        Some(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}
