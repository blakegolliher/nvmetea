//! Minimal `NETLINK_SOCK_DIAG` client for TCP sockets (`inet_diag_req_v2`).
//!
//! Works unprivileged and sees kernel-owned sockets such as nvme-tcp's
//! (finding F12). Requests `INET_DIAG_INFO`, `_CONG`, `_SKMEMINFO`.

use crate::tcpinfo;
use nvmetea_core::model::{SkMem, SocketSource, TcpSocket, TcpState};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const NETLINK_SOCK_DIAG: libc::c_int = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_HDRLEN: usize = 16;
const INET_DIAG_MSG_LEN: usize = 72;
const INET_DIAG_INFO: u16 = 2;
const INET_DIAG_CONG: u16 = 4;
const INET_DIAG_SKMEMINFO: u16 = 7;
const EXT_MASK: u8 = (1 << (INET_DIAG_INFO - 1)) | (1 << (INET_DIAG_CONG - 1)) | (1 << (INET_DIAG_SKMEMINFO - 1));

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Outcome of a sock_diag dump that failed.
#[derive(Debug)]
pub enum DiagError {
    /// The kernel rejected the request (e.g. inet_diag/tcp_diag unavailable).
    Kernel(io::Error),
    Io(io::Error),
}

impl std::fmt::Display for DiagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiagError::Kernel(e) => write!(f, "sock_diag request rejected: {e}"),
            DiagError::Io(e) => write!(f, "sock_diag socket error: {e}"),
        }
    }
}

impl std::error::Error for DiagError {}

/// Dump all TCP sockets (IPv4 and IPv6) for which `keep(local, remote)` is true.
pub fn dump_tcp(keep: &dyn Fn(&SocketAddr, &SocketAddr) -> bool) -> Result<Vec<TcpSocket>, DiagError> {
    let sock = open()?;
    let mut out = Vec::new();
    for (seq, family) in [(1u32, libc::AF_INET as u8), (2u32, libc::AF_INET6 as u8)] {
        send_request(&sock, seq, family).map_err(DiagError::Io)?;
        recv_dump(&sock, seq, keep, &mut out)?;
    }
    Ok(out)
}

fn open() -> Result<OwnedFd, DiagError> {
    // SAFETY: plain socket(2); fd owned immediately.
    let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, NETLINK_SOCK_DIAG) };
    if raw < 0 {
        return Err(DiagError::Io(io::Error::last_os_error()));
    }
    // SAFETY: raw is a valid descriptor we own.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
    // SAFETY: valid option pointer and length.
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    Ok(fd)
}

fn send_request(fd: &OwnedFd, seq: u32, family: u8) -> io::Result<()> {
    let total = NLMSG_HDRLEN + 56;
    let mut b = vec![0u8; total];
    b[0..4].copy_from_slice(&(total as u32).to_ne_bytes());
    b[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    b[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    b[8..12].copy_from_slice(&seq.to_ne_bytes());
    // inet_diag_req_v2
    b[16] = family;
    b[17] = libc::IPPROTO_TCP as u8;
    b[18] = EXT_MASK;
    b[20..24].copy_from_slice(&0x0fffu32.to_ne_bytes()); // all TCP states
    // SAFETY: zeroed sockaddr_nl addresses the kernel (pid 0).
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: buffer and address are valid for the given lengths.
    let n = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            b.as_ptr().cast(),
            b.len(),
            0,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn recv_dump(
    fd: &OwnedFd,
    seq: u32,
    keep: &dyn Fn(&SocketAddr, &SocketAddr) -> bool,
    out: &mut Vec<TcpSocket>,
) -> Result<(), DiagError> {
    let mut buf = vec![0u8; 65536];
    loop {
        // SAFETY: buf valid for writes of buf.len() bytes.
        let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(DiagError::Io(io::Error::last_os_error()));
        }
        match parse_messages(&buf[..n as usize], seq, keep, out) {
            Parsed::More => continue,
            Parsed::Done => return Ok(()),
            Parsed::Error(errno) => return Err(DiagError::Kernel(io::Error::from_raw_os_error(errno))),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Parsed {
    More,
    Done,
    Error(i32),
}

/// Parse one datagram of netlink messages; exposed for tests.
pub(crate) fn parse_messages(
    mut b: &[u8],
    seq: u32,
    keep: &dyn Fn(&SocketAddr, &SocketAddr) -> bool,
    out: &mut Vec<TcpSocket>,
) -> Parsed {
    while b.len() >= NLMSG_HDRLEN {
        let len = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) as usize;
        let ty = u16::from_ne_bytes([b[4], b[5]]);
        let mseq = u32::from_ne_bytes([b[8], b[9], b[10], b[11]]);
        if len < NLMSG_HDRLEN || len > b.len() {
            return Parsed::Error(libc::EPROTO);
        }
        let payload = &b[NLMSG_HDRLEN..len];
        if mseq == seq {
            match ty {
                NLMSG_DONE => return Parsed::Done,
                NLMSG_ERROR => {
                    let err = payload
                        .get(0..4)
                        .map(|s| i32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
                        .unwrap_or(-libc::EPROTO);
                    if err != 0 {
                        return Parsed::Error(-err);
                    }
                }
                SOCK_DIAG_BY_FAMILY => {
                    if let Some(s) = parse_diag_msg(payload, keep) {
                        out.push(s);
                    }
                }
                _ => {}
            }
        }
        let adv = align4(len);
        if adv >= b.len() {
            break;
        }
        b = &b[adv..];
    }
    Parsed::More
}

fn sockaddr(family: u8, addr: &[u8], port_be: [u8; 2]) -> Option<SocketAddr> {
    let port = u16::from_be_bytes(port_be);
    let ip = match family as i32 {
        libc::AF_INET => IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
        libc::AF_INET6 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&addr[..16]);
            nvmetea_topology::address::normalize_ip(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

fn parse_diag_msg(p: &[u8], keep: &dyn Fn(&SocketAddr, &SocketAddr) -> bool) -> Option<TcpSocket> {
    if p.len() < INET_DIAG_MSG_LEN {
        return None;
    }
    let family = p[0];
    let local = sockaddr(family, &p[8..24], [p[4], p[5]])?;
    let remote = sockaddr(family, &p[24..40], [p[6], p[7]])?;
    if !keep(&local, &remote) {
        return None;
    }
    let u32_at = |o: usize| u32::from_ne_bytes([p[o], p[o + 1], p[o + 2], p[o + 3]]);
    let cookie = u64::from(u32_at(44)) | (u64::from(u32_at(48)) << 32);
    let mut s = TcpSocket {
        local,
        remote,
        state: TcpState::from_kernel(p[1]),
        cookie: Some(cookie),
        inode: u64::from(u32_at(68)),
        uid: u32_at(64),
        recv_q: u32_at(56),
        send_q: u32_at(60),
        info: None,
        congestion: None,
        skmem: None,
        source: SocketSource::SockDiag,
    };
    let mut a = &p[INET_DIAG_MSG_LEN..];
    while a.len() >= 4 {
        let alen = u16::from_ne_bytes([a[0], a[1]]) as usize;
        let aty = u16::from_ne_bytes([a[2], a[3]]) & 0x3fff;
        if alen < 4 || alen > a.len() {
            break;
        }
        let data = &a[4..alen];
        match aty {
            INET_DIAG_INFO => s.info = tcpinfo::decode(data),
            INET_DIAG_CONG => {
                let end = data.iter().position(|&c| c == 0).unwrap_or(data.len());
                s.congestion = std::str::from_utf8(&data[..end]).ok().map(str::to_string);
            }
            INET_DIAG_SKMEMINFO => s.skmem = decode_skmem(data),
            _ => {}
        }
        let adv = align4(alen);
        if adv >= a.len() {
            break;
        }
        a = &a[adv..];
    }
    Some(s)
}

fn decode_skmem(d: &[u8]) -> Option<SkMem> {
    let v = |i: usize| d.get(i * 4..i * 4 + 4).map(|s| u32::from_ne_bytes([s[0], s[1], s[2], s[3]]));
    Some(SkMem {
        rmem_alloc: v(0)?,
        rcvbuf: v(1)?,
        wmem_alloc: v(2)?,
        sndbuf: v(3)?,
        fwd_alloc: v(4)?,
        wmem_queued: v(5)?,
        optmem: v(6)?,
        backlog: v(7),
        drops: v(8),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one SOCK_DIAG_BY_FAMILY message like the kernel would.
    fn diag_msg(seq: u32, sport: u16, dport: u16, src: [u8; 4], dst: [u8; 4], cookie: u64, info: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; INET_DIAG_MSG_LEN];
        p[0] = libc::AF_INET as u8;
        p[1] = 1;
        p[4..6].copy_from_slice(&sport.to_be_bytes());
        p[6..8].copy_from_slice(&dport.to_be_bytes());
        p[8..12].copy_from_slice(&src);
        p[24..28].copy_from_slice(&dst);
        p[44..48].copy_from_slice(&(cookie as u32).to_ne_bytes());
        p[48..52].copy_from_slice(&((cookie >> 32) as u32).to_ne_bytes());
        p[56..60].copy_from_slice(&7u32.to_ne_bytes());
        p[68..72].copy_from_slice(&230650u32.to_ne_bytes());
        let alen = 4 + info.len();
        p.extend_from_slice(&(alen as u16).to_ne_bytes());
        p.extend_from_slice(&INET_DIAG_INFO.to_ne_bytes());
        p.extend_from_slice(info);
        while p.len() % 4 != 0 {
            p.push(0);
        }
        let cong = b"cubic\0";
        p.extend_from_slice(&((4 + cong.len()) as u16).to_ne_bytes());
        p.extend_from_slice(&INET_DIAG_CONG.to_ne_bytes());
        p.extend_from_slice(cong);
        while p.len() % 4 != 0 {
            p.push(0);
        }
        let mut m = Vec::new();
        m.extend_from_slice(&((NLMSG_HDRLEN + p.len()) as u32).to_ne_bytes());
        m.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        m.extend_from_slice(&0u16.to_ne_bytes());
        m.extend_from_slice(&seq.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.extend_from_slice(&p);
        m
    }

    fn done(seq: u32) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&20u32.to_ne_bytes());
        m.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        m.extend_from_slice(&0u16.to_ne_bytes());
        m.extend_from_slice(&seq.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.extend_from_slice(&0i32.to_ne_bytes());
        m
    }

    #[test]
    fn parses_message_attrs_and_filter() {
        let mut info = vec![0u8; 248];
        info[68..72].copy_from_slice(&153u32.to_ne_bytes());
        let mut dgram = diag_msg(1, 38616, 4420, [192, 0, 2, 9], [192, 0, 2, 1], 0x2001, &info);
        dgram.extend(diag_msg(1, 22, 50000, [192, 0, 2, 9], [192, 0, 2, 7], 0x2002, &info));
        dgram.extend(done(1));
        let keep = |_: &SocketAddr, r: &SocketAddr| r.port() == 4420;
        let mut out = vec![];
        assert_eq!(parse_messages(&dgram, 1, &keep, &mut out), Parsed::Done);
        assert_eq!(out.len(), 1);
        let s = &out[0];
        assert_eq!(s.local, "192.0.2.9:38616".parse().expect("addr"));
        assert_eq!(s.remote, "192.0.2.1:4420".parse().expect("addr"));
        assert_eq!(s.cookie, Some(0x2001));
        assert_eq!(s.recv_q, 7);
        assert_eq!(s.inode, 230650);
        assert_eq!(s.congestion.as_deref(), Some("cubic"));
        assert_eq!(s.info.as_ref().map(|i| i.rtt_us), Some(153));
    }

    #[test]
    fn kernel_error_and_truncation() {
        let mut m = Vec::new();
        m.extend_from_slice(&36u32.to_ne_bytes());
        m.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
        m.extend_from_slice(&0u16.to_ne_bytes());
        m.extend_from_slice(&3u32.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.extend_from_slice(&(-libc::ENOENT).to_ne_bytes());
        m.extend_from_slice(&[0u8; 16]);
        let mut out = vec![];
        assert_eq!(parse_messages(&m, 3, &|_, _| true, &mut out), Parsed::Error(libc::ENOENT));
        // a length field larger than the datagram is a protocol error, not a panic
        let mut bad = done(4);
        bad[0..4].copy_from_slice(&999u32.to_ne_bytes());
        assert_eq!(parse_messages(&bad, 4, &|_, _| true, &mut out), Parsed::Error(libc::EPROTO));
        // short garbage is ignored
        assert_eq!(parse_messages(&[1, 2, 3], 4, &|_, _| true, &mut out), Parsed::More);
    }

    #[test]
    fn live_dump_works_unprivileged() {
        // Read-only query of the running kernel; must not error on a normal system.
        let r = dump_tcp(&|_, _| true);
        assert!(r.is_ok(), "{r:?}");
    }
}

#[cfg(test)]
mod robustness {
    use super::*;
    use nvmetea_core::testrng::Rng;

    /// Netlink datagrams from the kernel: corrupted lengths, types, attributes
    /// and truncations never panic and never read out of bounds.
    #[test]
    fn netlink_survives_garbage() {
        let info = vec![0u8; 248];
        let mut seed = tests_seed(&info);
        seed.extend(tests_seed(&info));
        let mut r = Rng::new(12);
        for _ in 0..50_000 {
            let b = if r.below(5) == 0 { r.bytes(1024) } else { r.mutate(&seed) };
            let mut out = Vec::new();
            let _ = parse_messages(&b, 7, &|_, _| true, &mut out);
            assert!(out.len() <= b.len() / NLMSG_HDRLEN + 1);
        }
    }

    fn tests_seed(info: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; INET_DIAG_MSG_LEN];
        p[0] = libc::AF_INET as u8;
        p[1] = 1;
        let alen = 4 + info.len();
        p.extend_from_slice(&(alen as u16).to_ne_bytes());
        p.extend_from_slice(&INET_DIAG_INFO.to_ne_bytes());
        p.extend_from_slice(info);
        let mut m = Vec::new();
        m.extend_from_slice(&((NLMSG_HDRLEN + p.len()) as u32).to_ne_bytes());
        m.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        m.extend_from_slice(&0u16.to_ne_bytes());
        m.extend_from_slice(&7u32.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.extend_from_slice(&p);
        m
    }
}
