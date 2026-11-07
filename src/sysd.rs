//! Dependency-free systemd notification. `sd_notify` is just a datagram to
//! `$NOTIFY_SOCKET`; no libsystemd, no `unsafe`.
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;

/// Send a state string (e.g. "READY=1") to systemd if `NOTIFY_SOCKET` is set.
/// Returns `Ok(false)` when not running under systemd.
pub fn notify(state: &str) -> io::Result<bool> {
    let sock = match std::env::var_os("NOTIFY_SOCKET") {
        Some(s) => s,
        None => return Ok(false),
    };
    let bytes = sock.as_bytes();
    // Abstract-namespace sockets are written in the env as "@/path"; on the
    // wire they are a leading NUL followed by the name.
    let path: PathBuf = if bytes.first() == Some(&b'@') {
        let mut v = Vec::with_capacity(bytes.len());
        v.push(0u8);
        v.extend_from_slice(&bytes[1..]);
        PathBuf::from(std::ffi::OsStr::from_bytes(&v))
    } else {
        PathBuf::from(&sock)
    };
    let dg = UnixDatagram::unbound()?;
    dg.send_to(state.as_bytes(), &path)?;
    Ok(true)
}
