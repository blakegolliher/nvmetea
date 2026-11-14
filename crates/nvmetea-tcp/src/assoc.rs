//! Controller ↔ TCP socket association by endpoint (Level 0).
//!
//! A socket belongs to a controller when its remote address and port equal the
//! controller's `traddr`/`trsvcid` and, when known, its local address equals
//! the controller's `host_traddr` (configured) or `src_addr` (reported).
//! Matching is never done on remote IP alone (spec §10). A socket that matches
//! more than one controller is reported as ambiguous and assigned to none.
//! Queue-level ownership needs the BPF iterator (T1) and is not claimed here.

use nvmetea_core::model::{Controller, TcpSocket, Topology};
use nvmetea_core::quality::{Quality, Reason};
use nvmetea_topology::address::parse_ip;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub remote: SocketAddr,
    /// Local address constraint, if the controller exposes one.
    pub local: Option<IpAddr>,
}

pub fn controller_endpoint(c: &Controller) -> Option<Endpoint> {
    if !c.is_tcp() {
        return None;
    }
    let a = c.address.as_ref()?;
    let ip = parse_ip(a.traddr.as_deref()?)?;
    let port: u16 = a.trsvcid.as_deref()?.parse().ok()?;
    let local = a.host_traddr.as_deref().or(a.src_addr.as_deref()).and_then(parse_ip);
    Some(Endpoint { remote: SocketAddr::new(ip, port), local })
}

/// Remote ports used by the topology's TCP controllers (pre-filter for dumps).
pub fn nvme_tcp_ports(topo: &Topology) -> BTreeSet<u16> {
    topo.tcp_controllers().filter_map(controller_endpoint).map(|e| e.remote.port()).collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct ControllerSockets {
    /// Indices into the socket slice.
    pub sockets: Vec<usize>,
    pub quality: Quality,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    /// Other controllers that share this controller's endpoint.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ambiguous_with: Vec<String>,
    /// Expected connections when live: `queue_count` (admin + I/O queues).
    pub expected: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Association {
    pub by_controller: BTreeMap<String, ControllerSockets>,
    /// Sockets to an NVMe/TCP port that match no controller endpoint.
    pub unassociated: Vec<usize>,
    /// Sockets matching more than one controller.
    pub ambiguous: Vec<usize>,
}

pub fn associate(topo: &Topology, sockets: &[TcpSocket]) -> Association {
    let eps: Vec<(&Controller, Option<Endpoint>)> =
        topo.tcp_controllers().map(|c| (c, controller_endpoint(c))).collect();
    let mut owners: Vec<Vec<usize>> = vec![Vec::new(); sockets.len()];
    for (i, s) in sockets.iter().enumerate() {
        for (ci, (_, ep)) in eps.iter().enumerate() {
            let Some(ep) = ep else { continue };
            if s.remote == ep.remote && ep.local.is_none_or(|l| l == s.local.ip()) {
                owners[i].push(ci);
            }
        }
    }
    let ports: BTreeSet<u16> = eps.iter().filter_map(|(_, e)| e.as_ref().map(|e| e.remote.port())).collect();
    let mut a = Association::default();
    let mut ambiguous_pairs: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for (ci, (c, ep)) in eps.iter().enumerate() {
        let (quality, reason) = match ep {
            Some(_) => (Quality::Derived, None),
            None => (Quality::Unavailable, Some(Reason::MissingInterface)),
        };
        let expected = if c.state.is_live() { c.queue_count } else { None };
        a.by_controller.insert(
            c.name.clone(),
            ControllerSockets { sockets: Vec::new(), quality, reason, ambiguous_with: Vec::new(), expected },
        );
        let _ = ci;
    }
    for (i, o) in owners.iter().enumerate() {
        match o.as_slice() {
            [] => {
                if ports.contains(&sockets[i].remote.port()) {
                    a.unassociated.push(i);
                }
            }
            [ci] => {
                if let Some(cs) = a.by_controller.get_mut(&eps[*ci].0.name) {
                    cs.sockets.push(i);
                }
            }
            many => {
                a.ambiguous.push(i);
                for &ci in many {
                    ambiguous_pairs.entry(ci).or_default().extend(many.iter().copied().filter(|&x| x != ci));
                }
            }
        }
    }
    for (ci, others) in ambiguous_pairs {
        if let Some(cs) = a.by_controller.get_mut(&eps[ci].0.name) {
            cs.quality = Quality::Unavailable;
            cs.reason = Some(Reason::Ambiguous);
            cs.ambiguous_with = others.into_iter().map(|o| eps[o].0.name.clone()).collect();
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvmetea_core::model::{SocketSource, TcpState};
    use nvmetea_topology::fixture::tcp_multipath_host;
    use nvmetea_topology::{SysRoot, scan};

    fn sock(local: &str, remote: &str) -> TcpSocket {
        TcpSocket {
            local: local.parse().expect("local"),
            remote: remote.parse().expect("remote"),
            state: TcpState::Established,
            cookie: Some(1),
            inode: 1,
            uid: 0,
            recv_q: 0,
            send_q: 0,
            info: None,
            congestion: None,
            skmem: None,
            source: SocketSource::SockDiag,
        }
    }

    #[test]
    fn unique_endpoints() {
        let f = tcp_multipath_host("assoc", 2, 1);
        let topo = scan(&SysRoot::new(f.as_path()));
        let mut socks = Vec::new();
        for q in 0..9 {
            socks.push(sock(&format!("198.51.100.5:{}", 40000 + q), "192.0.2.1:4420"));
            socks.push(sock(&format!("198.51.100.5:{}", 41000 + q), "192.0.2.2:4420"));
        }
        socks.push(sock("198.51.100.5:42000", "192.0.2.77:4420")); // unknown target, NVMe port
        socks.push(sock("198.51.100.6:42001", "192.0.2.1:4420")); // wrong local address
        socks.push(sock("198.51.100.5:22", "192.0.2.1:22")); // not NVMe
        let a = associate(&topo, &socks);
        let c2 = &a.by_controller["nvme2"];
        assert_eq!(c2.sockets.len(), 9);
        assert_eq!(c2.expected, Some(9));
        assert_eq!(c2.quality, Quality::Derived);
        assert_eq!(a.by_controller["nvme3"].sockets.len(), 9);
        assert_eq!(a.unassociated.len(), 2);
        assert!(a.ambiguous.is_empty());
        assert!(!a.by_controller.contains_key("nvme0")); // PCIe
    }

    #[test]
    fn shared_endpoint_is_ambiguous() {
        let f = tcp_multipath_host("assoc2", 2, 1);
        // second controller to the same target from the same host address
        f.write("class/nvme/nvme3/address", "traddr=192.0.2.1,trsvcid=4420,src_addr=198.51.100.5");
        let topo = scan(&SysRoot::new(f.as_path()));
        let socks = vec![sock("198.51.100.5:40000", "192.0.2.1:4420")];
        let a = associate(&topo, &socks);
        assert_eq!(a.ambiguous, [0]);
        let c2 = &a.by_controller["nvme2"];
        assert!(c2.sockets.is_empty());
        assert_eq!(c2.reason, Some(Reason::Ambiguous));
        assert_eq!(c2.ambiguous_with, ["nvme3"]);
    }

    #[test]
    fn ipv6_and_no_local_constraint() {
        let f = tcp_multipath_host("assoc3", 1, 1);
        f.write("class/nvme/nvme2/address", "traddr=2001:db8::1,trsvcid=8009");
        let topo = scan(&SysRoot::new(f.as_path()));
        let socks =
            vec![sock("[2001:db8::9]:5000", "[2001:db8::1]:8009"), sock("[2001:db8::8]:5001", "[2001:db8::1]:8009")];
        let a = associate(&topo, &socks);
        assert_eq!(a.by_controller["nvme2"].sockets, [0, 1]);
        assert_eq!(nvme_tcp_ports(&topo).into_iter().collect::<Vec<_>>(), [8009]);
    }
}
