//! Kernel uevent listener (`NETLINK_KOBJECT_UEVENT`, multicast group 1).
//! Unprivileged; used to trigger immediate rescans on controller/namespace
//! add/remove/change and to log `NVME_EVENT`/`NVME_AEN` notifications.

use std::collections::BTreeMap;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uevent {
    pub action: String,
    pub devpath: String,
    pub env: BTreeMap<String, String>,
}

impl Uevent {
    pub fn subsystem(&self) -> Option<&str> {
        self.env.get("SUBSYSTEM").map(String::as_str)
    }
    pub fn devname(&self) -> Option<&str> {
        self.env.get("DEVNAME").map(String::as_str).map(|d| d.trim_start_matches("/dev/"))
    }
    /// Events that can change the NVMe topology or carry NVMe notifications.
    pub fn is_nvme_relevant(&self) -> bool {
        match self.subsystem() {
            Some("nvme" | "nvme-subsystem" | "nvme-generic") => true,
            Some("block") => self.devname().is_some_and(|d| d.starts_with("nvme")),
            _ => false,
        }
    }
}

/// Parse one kernel uevent datagram: `action@devpath\0KEY=VALUE\0…`.
/// udev-daemon re-broadcasts (`libudev\0…`) are not accepted.
pub fn parse(buf: &[u8]) -> Option<Uevent> {
    let mut parts = buf.split(|&b| b == 0).filter(|p| !p.is_empty());
    let head = std::str::from_utf8(parts.next()?).ok()?;
    let (action, devpath) = head.split_once('@')?;
    let mut env = BTreeMap::new();
    for p in parts {
        let Ok(s) = std::str::from_utf8(p) else { continue };
        if let Some((k, v)) = s.split_once('=') {
            env.insert(k.to_string(), v.to_string());
        }
    }
    if env.get("ACTION").is_some_and(|a| a != action) {
        return None;
    }
    Some(Uevent { action: action.to_string(), devpath: devpath.to_string(), env })
}

pub struct UeventListener {
    fd: OwnedFd,
}

impl UeventListener {
    pub fn open() -> io::Result<UeventListener> {
        // SAFETY: plain socket(2) call; the fd is owned immediately.
        let raw = unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::NETLINK_KOBJECT_UEVENT)
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a fresh, valid descriptor we own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: zeroed sockaddr_nl is a valid initial value.
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        sa.nl_groups = 1; // kernel events
        // SAFETY: sa is a valid sockaddr_nl of the given length.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(UeventListener { fd })
    }

    /// Wait up to `timeout` for one datagram. `Ok(None)` on timeout or when the
    /// datagram is not a kernel uevent.
    pub fn recv(&self, timeout: Duration) -> io::Result<Option<Uevent>> {
        let mut pfd = libc::pollfd { fd: self.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: one valid pollfd.
        let n = unsafe { libc::poll(&mut pfd, 1, ms) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted { Ok(None) } else { Err(e) };
        }
        if n == 0 {
            return Ok(None);
        }
        let mut buf = vec![0u8; 16384];
        // SAFETY: buf is valid for writes of buf.len() bytes.
        let len = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        if len < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::WouldBlock { Ok(None) } else { Err(e) };
        }
        Ok(parse(&buf[..len as usize]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kernel_event() {
        let raw = b"change@/devices/virtual/nvme-fabrics/ctl/nvme3\0ACTION=change\0DEVPATH=/devices/virtual/nvme-fabrics/ctl/nvme3\0SUBSYSTEM=nvme\0NVME_EVENT=connected\0DEVNAME=nvme3\0";
        let e = parse(raw).expect("event");
        assert_eq!(e.action, "change");
        assert_eq!(e.subsystem(), Some("nvme"));
        assert_eq!(e.env.get("NVME_EVENT").map(String::as_str), Some("connected"));
        assert!(e.is_nvme_relevant());
    }

    #[test]
    fn block_and_irrelevant() {
        let blk = parse(
            b"add@/devices/virtual/nvme-subsystem/nvme-subsys2/nvme2n3\0ACTION=add\0SUBSYSTEM=block\0DEVNAME=nvme2n3\0",
        )
        .expect("ev");
        assert!(blk.is_nvme_relevant());
        let sda = parse(b"add@/devices/x/sda\0ACTION=add\0SUBSYSTEM=block\0DEVNAME=sda\0").expect("ev");
        assert!(!sda.is_nvme_relevant());
        assert!(parse(b"libudev\0\xfe\xed").is_none());
        assert!(parse(b"").is_none());
    }

    #[test]
    fn listener_opens_unprivileged() {
        // Opening and a short timed wait must work without privileges.
        let l = UeventListener::open().expect("uevent socket");
        let _ = l.recv(Duration::from_millis(1)).expect("recv");
    }
}
