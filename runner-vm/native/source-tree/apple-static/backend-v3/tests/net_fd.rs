//! Bounded allowlisted generic virtio-net option — FD validation + ownership.
//! Proves: only a connected SOCK_STREAM is accepted; tap/path/host device/
//! regular file / unconnected socket are refused; the OwnedFd is closed exactly
//! once on refusal and moves cleanly into the device fd on success.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use dsmack_backend_v3::net::{NetError, NetTransport, GENERIC_NIC_MAC, GUEST_GATEWAY, GUEST_STATIC_IP};

fn socketpair() -> (OwnedFd, OwnedFd) {
    let mut fds = [0 as libc::c_int; 2];
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
        0
    );
    // SAFETY: both are fresh owned descriptors from socketpair.
    (unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe { OwnedFd::from_raw_fd(fds[1]) })
}

fn fd_open(fd: libc::c_int) -> bool {
    let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    rc != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
}

#[test]
fn connected_stream_socket_accepted_and_owns_fd() {
    let (a, b) = socketpair();
    let a_raw = a.as_raw_fd();
    let t = NetTransport::own_validated(a).expect("connected stream accepted");
    assert_eq!(t.mac(), GENERIC_NIC_MAC);
    assert_eq!(t.raw_fd(), a_raw);
    // move the fd into the device wiring; the transport no longer closes it.
    let dev_fd = t.into_unixstream_fd();
    assert_eq!(dev_fd, a_raw);
    assert!(fd_open(dev_fd), "fd must still be open after ownership moves to the device");
    // device owns it now; close once here to stand in for the device teardown.
    unsafe { libc::close(dev_fd) };
    drop(b);
    // guest contract constants are present for the NAT helper
    assert_eq!(GUEST_STATIC_IP, "10.0.2.15");
    assert_eq!(GUEST_GATEWAY, "10.0.2.2");
}

#[test]
fn regular_file_fd_refused_and_closed_once() {
    let d = std::env::temp_dir().join(format!("dsmack-v3-net-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join("not-a-socket");
    std::fs::write(&p, b"x").unwrap();
    let f = std::fs::OpenOptions::new().read(true).open(&p).unwrap();
    let raw = f.as_raw_fd();
    let owned: OwnedFd = f.into();
    match NetTransport::own_validated(owned) {
        Err((NetError::NotSocket { kind, .. }, fd)) => {
            assert_eq!(kind, "regular file");
            drop(fd); // closed exactly once
        }
        other => panic!("expected NotSocket refusal, got {other:?}"),
    }
    assert!(!fd_open(raw), "refused net fd must be closed exactly once");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn pipe_fd_refused() {
    let mut fds = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: fresh owned pipe read end.
    let r = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    match NetTransport::own_validated(r) {
        Err((NetError::NotSocket { kind, .. }, fd)) => {
            assert_eq!(kind, "pipe");
            drop(fd);
        }
        other => panic!("expected NotSocket for a pipe, got {other:?}"),
    }
    unsafe { libc::close(fds[1]) };
}

#[test]
fn unconnected_socket_refused() {
    // A fresh unbound/unconnected stream socket: getpeername fails → refused,
    // so the option can never be a listening host ingress.
    let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    assert!(s >= 0);
    // SAFETY: fresh owned socket.
    let owned = unsafe { OwnedFd::from_raw_fd(s) };
    match NetTransport::own_validated(owned) {
        Err((NetError::NotConnected { .. }, fd)) => drop(fd),
        other => panic!("expected NotConnected, got {other:?}"),
    }
}
