//! nvmetea TCP transport collector (Level 0: unprivileged).
//!
//! Primary source is `NETLINK_SOCK_DIAG` with `tcp_info`; `/proc/net/tcp{,6}`
//! is the fallback (queues and states only, no RTT). Sockets are associated to
//! controllers by endpoint; queue-level association needs BPF (Phase 3).

pub mod assoc;
pub mod procnet;
pub mod sockdiag;
pub mod tcpinfo;

use nvmetea_core::model::{TcpSocket, Topology};
use nvmetea_core::quality::Reason;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpBackend {
    SockDiag,
    ProcNet,
    None,
}

#[derive(Debug, Clone, Serialize)]
pub struct TcpSample {
    pub backend: TcpBackend,
    /// Why the preferred backend was not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded: Option<Reason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub sockets: Vec<TcpSocket>,
}

/// Collect sockets whose remote port is one of the topology's NVMe/TCP ports.
pub fn collect(topo: &Topology, proc_root: &Path, use_sock_diag: bool) -> TcpSample {
    let ports: BTreeSet<u16> = assoc::nvme_tcp_ports(topo);
    collect_ports(&ports, proc_root, use_sock_diag)
}

/// `use_sock_diag = false` forces the `/proc/net/tcp` fallback (tests, or an
/// operator who wants to avoid netlink).
pub fn collect_ports(ports: &BTreeSet<u16>, proc_root: &Path, use_sock_diag: bool) -> TcpSample {
    if ports.is_empty() {
        return TcpSample { backend: TcpBackend::None, degraded: None, error: None, sockets: Vec::new() };
    }
    let keep = |_: &std::net::SocketAddr, r: &std::net::SocketAddr| ports.contains(&r.port());
    let diag = if use_sock_diag {
        sockdiag::dump_tcp(&keep)
    } else {
        Err(sockdiag::DiagError::Kernel(std::io::Error::other("disabled by option")))
    };
    match diag {
        Ok(sockets) => TcpSample { backend: TcpBackend::SockDiag, degraded: None, error: None, sockets },
        Err(e) => {
            let err = e.to_string();
            match procnet::read(proc_root, &keep) {
                Ok(sockets) => TcpSample {
                    backend: TcpBackend::ProcNet,
                    degraded: Some(Reason::InetDiagUnavailable),
                    error: Some(err),
                    sockets,
                },
                Err(e2) => TcpSample {
                    backend: TcpBackend::None,
                    degraded: Some(Reason::InetDiagUnavailable),
                    error: Some(format!("{err}; /proc/net/tcp: {e2}")),
                    sockets: Vec::new(),
                },
            }
        }
    }
}
