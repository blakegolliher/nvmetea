//! TCP connection state for NVMe/TCP sockets.

use serde::{Serialize, Serializer};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TcpState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    NewSynRecv,
    Unknown(u8),
}

impl TcpState {
    /// Linux `TCP_*` state numbers (include/net/tcp_states.h).
    pub fn from_kernel(v: u8) -> TcpState {
        match v {
            1 => TcpState::Established,
            2 => TcpState::SynSent,
            3 => TcpState::SynRecv,
            4 => TcpState::FinWait1,
            5 => TcpState::FinWait2,
            6 => TcpState::TimeWait,
            7 => TcpState::Close,
            8 => TcpState::CloseWait,
            9 => TcpState::LastAck,
            10 => TcpState::Listen,
            11 => TcpState::Closing,
            12 => TcpState::NewSynRecv,
            x => TcpState::Unknown(x),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            TcpState::Established => "ESTAB",
            TcpState::SynSent => "SYN-SENT",
            TcpState::SynRecv => "SYN-RECV",
            TcpState::FinWait1 => "FIN-WAIT-1",
            TcpState::FinWait2 => "FIN-WAIT-2",
            TcpState::TimeWait => "TIME-WAIT",
            TcpState::Close => "CLOSE",
            TcpState::CloseWait => "CLOSE-WAIT",
            TcpState::LastAck => "LAST-ACK",
            TcpState::Listen => "LISTEN",
            TcpState::Closing => "CLOSING",
            TcpState::NewSynRecv => "NEW-SYN-RECV",
            TcpState::Unknown(_) => "UNKNOWN",
        }
    }
}

impl Serialize for TcpState {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketSource {
    /// NETLINK_SOCK_DIAG with `tcp_info`.
    SockDiag,
    /// `/proc/net/tcp{,6}` fallback: no RTT/congestion data.
    ProcNet,
}

/// Decoded `struct tcp_info`. Fields after `total_retrans` are optional because
/// older kernels return a shorter structure; the decoder gates each one on the
/// returned length.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TcpInfo {
    pub state: u8,
    pub ca_state: u8,
    pub retransmits: u8,
    pub probes: u8,
    pub backoff: u8,
    pub options: u8,
    pub snd_wscale: u8,
    pub rcv_wscale: u8,
    pub rto_us: u32,
    pub ato_us: u32,
    pub snd_mss: u32,
    pub rcv_mss: u32,
    pub unacked: u32,
    pub sacked: u32,
    pub lost: u32,
    pub retrans: u32,
    pub last_data_sent_ms: u32,
    pub last_data_recv_ms: u32,
    pub last_ack_recv_ms: u32,
    pub pmtu: u32,
    pub rcv_ssthresh: u32,
    pub rtt_us: u32,
    pub rttvar_us: u32,
    pub snd_ssthresh: u32,
    pub snd_cwnd: u32,
    pub advmss: u32,
    pub reordering: u32,
    pub rcv_rtt_us: u32,
    pub rcv_space: u32,
    pub total_retrans: u32,
    pub pacing_rate: Option<u64>,
    pub max_pacing_rate: Option<u64>,
    pub bytes_acked: Option<u64>,
    pub bytes_received: Option<u64>,
    pub segs_out: Option<u32>,
    pub segs_in: Option<u32>,
    pub notsent_bytes: Option<u32>,
    pub min_rtt_us: Option<u32>,
    pub data_segs_in: Option<u32>,
    pub data_segs_out: Option<u32>,
    pub delivery_rate: Option<u64>,
    pub busy_time_us: Option<u64>,
    pub rwnd_limited_us: Option<u64>,
    pub sndbuf_limited_us: Option<u64>,
    pub delivered: Option<u32>,
    pub delivered_ce: Option<u32>,
    pub bytes_sent: Option<u64>,
    pub bytes_retrans: Option<u64>,
    pub dsack_dups: Option<u32>,
    pub reord_seen: Option<u32>,
    pub rcv_ooopack: Option<u32>,
    pub snd_wnd: Option<u32>,
    pub rcv_wnd: Option<u32>,
    pub rehash: Option<u32>,
    pub total_rto: Option<u16>,
    pub total_rto_recoveries: Option<u16>,
    pub total_rto_time_ms: Option<u32>,
}

/// `INET_DIAG_SKMEMINFO` (`SK_MEMINFO_*`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SkMem {
    pub rmem_alloc: u32,
    pub rcvbuf: u32,
    pub wmem_alloc: u32,
    pub sndbuf: u32,
    pub fwd_alloc: u32,
    pub wmem_queued: u32,
    pub optmem: u32,
    pub backlog: Option<u32>,
    pub drops: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TcpSocket {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: TcpState,
    /// Kernel socket cookie (unique per boot); the join key with BPF (finding F12).
    pub cookie: Option<u64>,
    pub inode: u64,
    pub uid: u32,
    /// Bytes not yet read by the application (nvme-tcp) / not yet acknowledged.
    pub recv_q: u32,
    pub send_q: u32,
    pub info: Option<TcpInfo>,
    pub congestion: Option<String>,
    pub skmem: Option<SkMem>,
    pub source: SocketSource,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states() {
        assert_eq!(TcpState::from_kernel(1), TcpState::Established);
        assert_eq!(TcpState::from_kernel(99), TcpState::Unknown(99));
        assert_eq!(TcpState::Established.as_str(), "ESTAB");
    }
}

/// One NVMe/TCP queue's connection, as identified in the kernel by the
/// `iter/tcp` program (T1): `sk_user_data → nvme_tcp_queue → sock → sk`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueueSocket {
    pub cookie: u64,
    /// Controller instance (`N` of `nvmeN`).
    pub instance: u32,
    pub qid: u16,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: TcpState,
    /// `queue->io_cpu`; `None` when the queue's worker is unbound.
    pub io_cpu: Option<u32>,
    pub hdr_digest: bool,
    pub data_digest: bool,
    /// `None` when the kernel's nvme-tcp has no TLS support field.
    pub tls: Option<bool>,
}

/// Cumulative transport events on one queue socket (T3-T7), by cookie.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SockEventCounters {
    pub instance: u32,
    pub qid: u16,
    /// `tcp_retransmit_skb` events: retransmitted skbs (one skb can carry
    /// several segments; `tcp_info.total_retrans` counts segments).
    pub retrans: u64,
    pub rst_rx: u64,
    pub rst_tx: u64,
    pub state_changes: u64,
    pub loss_entries: u64,
    pub recovery_entries: u64,
    pub cwr_entries: u64,
    pub errors: u64,
    pub last_event_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TcpEventKind {
    Retransmit,
    State {
        from: TcpState,
        to: TcpState,
    },
    ResetReceived,
    ResetSent,
    /// Entered a congestion state: 2 = CWR, 3 = Recovery, 4 = Loss.
    Congestion {
        ca_state: u8,
    },
    Error {
        errno: i32,
    },
}

/// A timestamped transport event on an NVMe/TCP queue socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TcpEvent {
    /// CLOCK_MONOTONIC ns.
    pub t_ns: u64,
    pub cookie: u64,
    pub instance: u32,
    pub qid: u16,
    pub kind: TcpEventKind,
}

impl TcpEventKind {
    pub fn describe(&self) -> String {
        match self {
            TcpEventKind::Retransmit => "retransmission".into(),
            TcpEventKind::State { from, to } => format!("state {} -> {}", from.as_str(), to.as_str()),
            TcpEventKind::ResetReceived => "RST received".into(),
            TcpEventKind::ResetSent => "RST sent".into(),
            TcpEventKind::Congestion { ca_state } => match ca_state {
                2 => "congestion: CWR".into(),
                3 => "congestion: fast recovery".into(),
                4 => "congestion: loss (RTO)".into(),
                x => format!("congestion state {x}"),
            },
            TcpEventKind::Error { errno } => format!("socket error {errno}"),
        }
    }
}
