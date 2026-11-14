//! `/proc/net/tcp` and `/proc/net/tcp6` fallback (no RTT / congestion data).

use nvmetea_core::model::{SocketSource, TcpSocket, TcpState};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

/// The kernel prints each 32-bit word of the (network-order) address with
/// `%08X` of its native-endian value, so `to_ne_bytes` recovers the bytes on
/// any architecture.
fn parse_addr(s: &str) -> Option<SocketAddr> {
    let (a, p) = s.split_once(':')?;
    if !a.is_ascii() {
        return None; // the kernel prints hex; byte slicing below assumes ASCII
    }
    let port = u16::from_str_radix(p, 16).ok()?;
    let ip = match a.len() {
        8 => {
            let w = u32::from_str_radix(a, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(w.to_ne_bytes()))
        }
        32 => {
            let mut o = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(&a[i * 8..i * 8 + 8], 16).ok()?;
                o[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
            }
            nvmetea_topology::address::normalize_ip(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Parse one `/proc/net/tcp*` table. Malformed rows are skipped and counted.
pub fn parse(text: &str, keep: &dyn Fn(&SocketAddr, &SocketAddr) -> bool) -> (Vec<TcpSocket>, usize) {
    let mut out = Vec::new();
    let mut bad = 0;
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            if !line.trim().is_empty() {
                bad += 1;
            }
            continue;
        }
        let (Some(local), Some(remote)) = (parse_addr(f[1]), parse_addr(f[2])) else {
            bad += 1;
            continue;
        };
        if !keep(&local, &remote) {
            continue;
        }
        let st = u8::from_str_radix(f[3], 16).unwrap_or(0);
        let (tx, rx) = f[4].split_once(':').unwrap_or(("0", "0"));
        out.push(TcpSocket {
            local,
            remote,
            state: TcpState::from_kernel(st),
            cookie: None,
            inode: f[9].parse().unwrap_or(0),
            uid: f[7].parse().unwrap_or(0),
            recv_q: u32::from_str_radix(rx, 16).unwrap_or(0),
            send_q: u32::from_str_radix(tx, 16).unwrap_or(0),
            info: None,
            congestion: None,
            skmem: None,
            source: SocketSource::ProcNet,
        });
    }
    (out, bad)
}

pub fn read(proc_root: &Path, keep: &dyn Fn(&SocketAddr, &SocketAddr) -> bool) -> std::io::Result<Vec<TcpSocket>> {
    let mut all = Vec::new();
    let mut any = false;
    let mut last_err = None;
    for f in ["net/tcp", "net/tcp6"] {
        match std::fs::read_to_string(proc_root.join(f)) {
            Ok(t) => {
                any = true;
                all.extend(parse(&t, keep).0);
            }
            // tcp6 is absent when IPv6 is disabled: not an error for IPv4 results
            Err(e) => last_err = Some(e),
        }
    }
    match (any, last_err) {
        (false, Some(e)) => Err(e),
        _ => Ok(all),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_and_ipv6_rows() {
        let v4 = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 5F6433C6:96D8 010200C0:1144 01 00000010:00000020 00:00000000 00000000     0        0 230650 1 0000000000000000 20 4 30 10 -1\n\
   1: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234 1 0000000000000000 100 0 0 10 0\n\
   2: garbage\n";
        let (s, bad) = parse(v4, &|_, r| r.port() == 4420);
        assert_eq!(bad, 1);
        assert_eq!(s.len(), 1);
        if cfg!(target_endian = "little") {
            assert_eq!(s[0].local, "198.51.100.95:38616".parse().expect("addr"));
            assert_eq!(s[0].remote, "192.0.2.1:4420".parse().expect("addr"));
        }
        assert_eq!((s[0].send_q, s[0].recv_q, s[0].inode), (16, 32, 230650));
        assert_eq!(s[0].state, TcpState::Established);

        let v6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0000000000000000FFFF00005F6433C6:96D8 0000000000000000FFFF0000010200C0:1144 01 00000000:00000000 00:00000000 00000000     0        0 99 1 0000000000000000 20 4 30 10 -1\n";
        let (s6, _) = parse(v6, &|_, _| true);
        assert_eq!(s6.len(), 1);
        if cfg!(target_endian = "little") {
            assert_eq!(s6[0].remote, "192.0.2.1:4420".parse().expect("v4-mapped normalised"));
        }
    }
}
