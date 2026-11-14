//! Telemetry engine (Level 0): turns two snapshots into interval views.
//!
//! Inputs are core model types only; collectors fill a [`Snapshot`], presentation
//! reads the views. Rates are differences of cumulative kernel counters; nothing
//! is ever reset. A controller whose generation changed between snapshots, or a
//! socket whose cookie disappeared, yields `counter_reset` / `first_interval`.

use crate::model::{
    BlockRates, Controller, DiskCounters, Namespace, NsAccounting, NsKind, TcpSocket, TcpState, Topology,
};
use crate::quality::{Obs, Reason};
use crate::rate;
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::{Instant, SystemTime};

/// Everything collected at one instant.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub taken: Instant,
    pub wall: SystemTime,
    pub topology: Topology,
    pub disk: BTreeMap<String, DiskCounters>,
    pub sockets: Vec<TcpSocket>,
    /// controller name → indices into `sockets` (endpoint association).
    pub socket_owner: BTreeMap<String, Vec<usize>>,
}

/// Namespace totals and how they were obtained (finding F7).
#[derive(Debug, Clone, PartialEq)]
pub struct NsTotals {
    pub accounting: NsAccounting,
    pub counters: Option<DiskCounters>,
}

/// Namespace totals: the device's own counters when they count I/O, otherwise
/// (multipath head without head accounting) the sum of its paths.
pub fn namespace_totals(ns: &Namespace, counters: &BTreeMap<String, DiskCounters>) -> NsTotals {
    let own = counters.get(&ns.name).copied();
    if ns.kind == NsKind::Direct {
        return match own {
            Some(c) => NsTotals { accounting: NsAccounting::Device, counters: Some(c) },
            None => NsTotals { accounting: NsAccounting::Unavailable, counters: None },
        };
    }
    let mut sum: Option<DiskCounters> = None;
    for p in &ns.paths {
        if let Some(c) = counters.get(&p.name) {
            sum.get_or_insert_with(DiskCounters::default).add(c);
        }
    }
    match (own, sum) {
        (Some(o), Some(s)) if o.is_idle_since_boot() && !s.is_idle_since_boot() => {
            NsTotals { accounting: NsAccounting::SumOfPaths, counters: Some(s) }
        }
        (Some(o), _) => NsTotals { accounting: NsAccounting::Device, counters: Some(o) },
        (None, Some(s)) => NsTotals { accounting: NsAccounting::SumOfPaths, counters: Some(s) },
        (None, None) => NsTotals { accounting: NsAccounting::Unavailable, counters: None },
    }
}

/// A controller's I/O = the sum over its path devices / direct namespaces.
pub fn controller_totals(
    topo: &Topology,
    ctrl: &str,
    counters: &BTreeMap<String, DiskCounters>,
) -> Option<DiskCounters> {
    let mut sum: Option<DiskCounters> = None;
    for dev in topo.controller_block_devices(ctrl) {
        if let Some(c) = counters.get(dev) {
            sum.get_or_insert_with(DiskCounters::default).add(c);
        }
    }
    sum
}

fn dt(prev: Option<&Snapshot>, cur: &Snapshot) -> Option<f64> {
    prev.map(|p| cur.taken.saturating_duration_since(p.taken).as_secs_f64()).filter(|d| *d > 0.0)
}

fn block_rates(prev: Option<DiskCounters>, cur: Option<DiskCounters>, dt_s: Option<f64>) -> BlockRates {
    match (prev, cur, dt_s) {
        (_, None, _) => BlockRates::unavailable(Reason::MissingInterface),
        (Some(p), Some(c), Some(d)) => BlockRates::between(&p, &c, d),
        (_, Some(c), _) => {
            let mut r = BlockRates::unavailable(Reason::FirstInterval);
            r.in_flight = Obs::measured(c.in_flight, &["diskstats"]);
            r
        }
    }
}

/// Aggregated TCP view of one controller's connections.
#[derive(Debug, Clone, Serialize)]
pub struct TcpSummary {
    pub sockets: usize,
    pub established: usize,
    /// `queue_count` when the controller is live (admin + I/O queues).
    pub expected: Option<u32>,
    pub rtt_min_us: Obs<u32>,
    pub rtt_max_us: Obs<u32>,
    pub rtt_median_us: Obs<u32>,
    pub rttvar_max_us: Obs<u32>,
    pub retrans_segments_per_s: Obs<f64>,
    pub tx_bytes_per_s: Obs<f64>,
    pub rx_bytes_per_s: Obs<f64>,
    /// Sum over sockets of currently-lost segments (`tcpi_lost`).
    pub lost_segments: Obs<u64>,
    pub unacked_segments: Obs<u64>,
    pub send_q_bytes: Obs<u64>,
    pub recv_q_bytes: Obs<u64>,
}

/// Per-socket interval values.
#[derive(Debug, Clone, Serialize)]
pub struct SocketInterval {
    pub index: usize,
    pub retrans_segments_per_s: Obs<f64>,
    pub tx_bytes_per_s: Obs<f64>,
    pub rx_bytes_per_s: Obs<f64>,
    pub busy_pct: Obs<f64>,
    pub rwnd_limited_pct: Obs<f64>,
    pub sndbuf_limited_pct: Obs<f64>,
}

fn socket_key(s: &TcpSocket) -> (Option<u64>, std::net::SocketAddr, std::net::SocketAddr, u64) {
    (s.cookie, s.local, s.remote, s.inode)
}

const SOCK_SRC: &[&str] = &["sock_diag"];

fn usec_pct(prev: Option<u64>, cur: Option<u64>, dt_s: f64) -> Obs<f64> {
    rate::rate_opt(prev, cur, dt_s, SOCK_SRC).map(|us_per_s| us_per_s / 1e6 * 100.0)
}

/// Interval values for every socket in `cur` (matched to `prev` by cookie /
/// 4-tuple / inode; a new socket is `first_interval`).
pub fn socket_intervals(prev: Option<&Snapshot>, cur: &Snapshot) -> Vec<SocketInterval> {
    let d = dt(prev, cur);
    let prev_map: BTreeMap<_, &TcpSocket> =
        prev.map(|p| p.sockets.iter().map(|s| (socket_key(s), s)).collect()).unwrap_or_default();
    cur.sockets
        .iter()
        .enumerate()
        .map(|(index, s)| {
            let p = prev_map.get(&socket_key(s));
            let (ci, pi) = (s.info.as_ref(), p.and_then(|p| p.info.as_ref()));
            let none = |r| SocketInterval {
                index,
                retrans_segments_per_s: Obs::unavailable(r),
                tx_bytes_per_s: Obs::unavailable(r),
                rx_bytes_per_s: Obs::unavailable(r),
                busy_pct: Obs::unavailable(r),
                rwnd_limited_pct: Obs::unavailable(r),
                sndbuf_limited_pct: Obs::unavailable(r),
            };
            match (ci, pi, d) {
                (None, _, _) => none(Reason::InetDiagUnavailable),
                (Some(_), None, _) | (Some(_), Some(_), None) => none(Reason::FirstInterval),
                (Some(c), Some(p), Some(d)) => SocketInterval {
                    index,
                    retrans_segments_per_s: rate::rate(
                        u64::from(p.total_retrans),
                        u64::from(c.total_retrans),
                        d,
                        SOCK_SRC,
                    ),
                    tx_bytes_per_s: rate::rate_opt(p.bytes_acked, c.bytes_acked, d, SOCK_SRC),
                    rx_bytes_per_s: rate::rate_opt(p.bytes_received, c.bytes_received, d, SOCK_SRC),
                    busy_pct: usec_pct(p.busy_time_us, c.busy_time_us, d),
                    rwnd_limited_pct: usec_pct(p.rwnd_limited_us, c.rwnd_limited_us, d),
                    sndbuf_limited_pct: usec_pct(p.sndbuf_limited_us, c.sndbuf_limited_us, d),
                },
            }
        })
        .collect()
}

fn sum_obs(vals: impl Iterator<Item = Obs<f64>>) -> Obs<f64> {
    let mut total = 0.0;
    let mut any = false;
    let mut reason = None;
    for v in vals {
        match v.value {
            Some(x) => {
                total += x;
                any = true;
            }
            None => reason = reason.or(v.reason),
        }
    }
    // Partial sums would understate: report only when every socket contributed.
    match (any, reason) {
        (true, None) => Obs::derived(total, SOCK_SRC),
        (_, Some(r)) => Obs::unavailable(r),
        (false, None) => Obs::unavailable(Reason::NoSamples),
    }
}

fn tcp_summary(c: &Controller, cur: &Snapshot, sock_iv: &[SocketInterval]) -> TcpSummary {
    let idx: &[usize] = cur.socket_owner.get(&c.name).map(Vec::as_slice).unwrap_or(&[]);
    let socks: Vec<&TcpSocket> = idx.iter().filter_map(|&i| cur.sockets.get(i)).collect();
    let mut rtts: Vec<u32> = socks.iter().filter_map(|s| s.info.as_ref().map(|i| i.rtt_us)).collect();
    rtts.sort_unstable();
    let have_info = !rtts.is_empty();
    let unav = if socks.is_empty() { Reason::NoSamples } else { Reason::InetDiagUnavailable };
    let pick = |v: Option<u32>| match v {
        Some(x) => Obs::derived(x, SOCK_SRC),
        None => Obs::unavailable(unav),
    };
    let sum_u64 = |f: &dyn Fn(&TcpSocket) -> Option<u64>| -> Obs<u64> {
        if !have_info {
            return Obs::unavailable(unav);
        }
        Obs::derived(socks.iter().filter_map(|s| f(s)).sum(), SOCK_SRC)
    };
    let ivs: Vec<&SocketInterval> = idx.iter().filter_map(|&i| sock_iv.iter().find(|v| v.index == i)).collect();
    TcpSummary {
        sockets: socks.len(),
        established: socks.iter().filter(|s| s.state == TcpState::Established).count(),
        expected: if c.state.is_live() { c.queue_count } else { None },
        rtt_min_us: pick(rtts.first().copied()),
        rtt_max_us: pick(rtts.last().copied()),
        rtt_median_us: pick(rtts.get(rtts.len() / 2).copied()),
        rttvar_max_us: pick(socks.iter().filter_map(|s| s.info.as_ref().map(|i| i.rttvar_us)).max()),
        retrans_segments_per_s: if ivs.is_empty() {
            Obs::unavailable(unav)
        } else {
            sum_obs(ivs.iter().map(|v| v.retrans_segments_per_s.clone()))
        },
        tx_bytes_per_s: if ivs.is_empty() {
            Obs::unavailable(unav)
        } else {
            sum_obs(ivs.iter().map(|v| v.tx_bytes_per_s.clone()))
        },
        rx_bytes_per_s: if ivs.is_empty() {
            Obs::unavailable(unav)
        } else {
            sum_obs(ivs.iter().map(|v| v.rx_bytes_per_s.clone()))
        },
        lost_segments: sum_u64(&|s| s.info.as_ref().map(|i| u64::from(i.lost))),
        unacked_segments: sum_u64(&|s| s.info.as_ref().map(|i| u64::from(i.unacked))),
        send_q_bytes: if socks.is_empty() {
            Obs::unavailable(Reason::NoSamples)
        } else {
            Obs::measured(socks.iter().map(|s| u64::from(s.send_q)).sum(), SOCK_SRC)
        },
        recv_q_bytes: if socks.is_empty() {
            Obs::unavailable(Reason::NoSamples)
        } else {
            Obs::measured(socks.iter().map(|s| u64::from(s.recv_q)).sum(), SOCK_SRC)
        },
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ControllerInterval {
    pub name: String,
    pub generation: Option<u64>,
    pub epoch: Option<u64>,
    pub state: crate::model::CtrlState,
    pub io: BlockRates,
    pub tcp: Option<TcpSummary>,
}

pub fn controller_intervals(prev: Option<&Snapshot>, cur: &Snapshot) -> Vec<ControllerInterval> {
    let d = dt(prev, cur);
    let sock_iv = socket_intervals(prev, cur);
    cur.topology
        .controllers
        .iter()
        .map(|c| {
            let pc = prev.and_then(|p| p.topology.controller(&c.name));
            let same_gen = match (pc, c.generation) {
                (Some(p), Some(g)) => p.generation == Some(g),
                (Some(_), None) => true,
                (None, _) => false,
            };
            let cur_tot = controller_totals(&cur.topology, &c.name, &cur.disk);
            let io = if prev.is_some() && pc.is_some() && !same_gen {
                BlockRates::unavailable(Reason::CounterReset)
            } else {
                let prev_tot = prev.filter(|_| same_gen).and_then(|p| controller_totals(&p.topology, &c.name, &p.disk));
                block_rates(prev_tot, cur_tot, d)
            };
            ControllerInterval {
                name: c.name.clone(),
                generation: c.generation,
                epoch: c.epoch,
                state: c.state.clone(),
                io,
                tcp: c.is_tcp().then(|| tcp_summary(c, cur, &sock_iv)),
            }
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct NamespaceInterval {
    pub name: String,
    pub accounting: NsAccounting,
    pub io: BlockRates,
}

pub fn namespace_intervals(prev: Option<&Snapshot>, cur: &Snapshot) -> Vec<NamespaceInterval> {
    let d = dt(prev, cur);
    cur.topology
        .namespaces
        .iter()
        .map(|ns| {
            let ct = namespace_totals(ns, &cur.disk);
            let pt = prev.and_then(|p| p.topology.namespace(&ns.name).map(|pns| namespace_totals(pns, &p.disk)));
            // switching between head counters and path sums is a different series
            let io = match pt {
                Some(p) if p.accounting != ct.accounting => BlockRates::unavailable(Reason::CounterReset),
                Some(p) => block_rates(p.counters, ct.counters, d),
                None => block_rates(None, ct.counters, d),
            };
            NamespaceInterval { name: ns.name.clone(), accounting: ct.accounting, io }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CtrlState, FabricAddress, SocketSource, TcpInfo};
    use std::time::Duration;

    fn ctrl(name: &str, gen_: u64) -> Controller {
        Controller {
            name: name.into(),
            instance: 2,
            subsystem: None,
            subsysnqn: None,
            transport: Some("tcp".into()),
            address: Some(FabricAddress::default()),
            state: CtrlState::Live,
            cntlid: None,
            queue_count: Some(2),
            sqsize: Some(31),
            kato_s: None,
            ctrl_loss_tmo: None,
            reconnect_delay: None,
            fast_io_fail_tmo: None,
            numa_node: None,
            hostnqn: None,
            hostid: None,
            model: None,
            serial: None,
            firmware_rev: None,
            cntrltype: None,
            dctype: None,
            paths: vec!["nvme2c2n1".into()],
            namespaces: vec![],
            generation: Some(gen_),
            epoch: Some(1),
        }
    }

    fn sock(cookie: u64, rtt: u32, retrans: u32, acked: u64) -> TcpSocket {
        TcpSocket {
            local: "198.51.100.5:40000".parse().expect("a"),
            remote: "192.0.2.1:4420".parse().expect("a"),
            state: TcpState::Established,
            cookie: Some(cookie),
            inode: cookie,
            uid: 0,
            recv_q: 0,
            send_q: 10,
            info: Some(TcpInfo {
                rtt_us: rtt,
                total_retrans: retrans,
                bytes_acked: Some(acked),
                bytes_received: Some(0),
                ..Default::default()
            }),
            congestion: None,
            skmem: None,
            source: SocketSource::SockDiag,
        }
    }

    fn snap(t: Instant, gen_: u64, reads: u64, socks: Vec<TcpSocket>) -> Snapshot {
        let mut disk = BTreeMap::new();
        disk.insert("nvme2c2n1".to_string(), DiskCounters { reads, read_sectors: reads * 8, ..Default::default() });
        let n = socks.len();
        let mut owner = BTreeMap::new();
        owner.insert("nvme2".to_string(), (0..n).collect());
        Snapshot {
            taken: t,
            wall: SystemTime::UNIX_EPOCH,
            topology: Topology { controllers: vec![ctrl("nvme2", gen_)], ..Default::default() },
            disk,
            sockets: socks,
            socket_owner: owner,
        }
    }

    #[test]
    fn controller_rates_and_tcp() {
        let t0 = Instant::now();
        let a = snap(t0, 1, 100, vec![sock(1, 100, 5, 1000), sock(2, 300, 0, 0)]);
        let b = snap(t0 + Duration::from_secs(2), 1, 300, vec![sock(1, 120, 9, 3000), sock(2, 280, 0, 0)]);
        let v = controller_intervals(Some(&a), &b);
        assert_eq!(v[0].io.read_iops.value, Some(100.0));
        let t = v[0].tcp.as_ref().expect("tcp");
        assert_eq!((t.sockets, t.established, t.expected), (2, 2, Some(2)));
        assert_eq!(t.rtt_min_us.value, Some(120));
        assert_eq!(t.rtt_max_us.value, Some(280));
        assert_eq!(t.retrans_segments_per_s.value, Some(2.0));
        assert_eq!(t.tx_bytes_per_s.value, Some(1000.0));
        assert_eq!(t.send_q_bytes.value, Some(20));
    }

    #[test]
    fn generation_change_is_reset_and_new_socket_is_first_interval() {
        let t0 = Instant::now();
        let a = snap(t0, 1, 100, vec![sock(1, 100, 5, 1000)]);
        let b = snap(t0 + Duration::from_secs(1), 2, 10, vec![sock(7, 100, 0, 0)]);
        let v = controller_intervals(Some(&a), &b);
        assert_eq!(v[0].io.read_iops.reason, Some(Reason::CounterReset));
        let t = v[0].tcp.as_ref().expect("tcp");
        assert_eq!(t.retrans_segments_per_s.reason, Some(Reason::FirstInterval));
        // first snapshot ever
        let v = controller_intervals(None, &a);
        assert_eq!(v[0].io.read_iops.reason, Some(Reason::FirstInterval));
        assert_eq!(v[0].io.in_flight.value, Some(0));
    }
}

/// One NVMe/TCP queue's connection with its transport telemetry for the
/// interval: `tcp_info` (sock_diag) joined by socket cookie with the kernel's
/// queue ↔ socket table (T1) and BPF transport-event counters (T3-T7).
#[derive(Debug, Clone, Serialize)]
pub struct QueueConnection {
    pub controller: String,
    pub instance: u32,
    pub qid: u16,
    pub cookie: u64,
    pub local: std::net::SocketAddr,
    pub remote: std::net::SocketAddr,
    pub state: TcpState,
    pub io_cpu: Option<u32>,
    pub hdr_digest: bool,
    pub data_digest: bool,
    pub tls: Option<bool>,
    /// Queue ownership: identified in the kernel (measured).
    pub association: crate::quality::Quality,
    /// The connection was in the previous queue table and is gone from the
    /// current one: it closed (or left its queue) during the interval. Its
    /// event counts cover the interval up to that point; `state` is the last
    /// state seen and `tcp_info` is unavailable unless the socket still exists.
    pub closed: bool,
    pub rtt_us: Obs<u32>,
    pub rttvar_us: Obs<u32>,
    pub min_rtt_us: Obs<u32>,
    pub rto_ms: Obs<u32>,
    pub cwnd: Obs<u32>,
    pub unacked: Obs<u32>,
    pub lost: Obs<u32>,
    pub total_retrans: Obs<u32>,
    pub notsent_bytes: Obs<u32>,
    pub send_q_bytes: Obs<u32>,
    pub recv_q_bytes: Obs<u32>,
    pub interval: Option<SocketInterval>,
    /// BPF transport events in the interval (unavailable without the TCP object).
    pub retransmit_events: Obs<u64>,
    pub resets: Obs<u64>,
    pub loss_entries: Obs<u64>,
    pub recovery_entries: Obs<u64>,
    pub socket_errors: Obs<u64>,
    pub state_changes: Obs<u64>,
}

const EV_SRC: &[&str] = &["bpf:T3-T7"];

/// Cumulative per-socket event counters at the previous (if any) and current sample.
pub type SockEventMap = BTreeMap<u64, crate::model::SockEventCounters>;
pub type EventCounterPair<'a> = (Option<&'a SockEventMap>, &'a SockEventMap);

/// Join queue sockets with sock_diag data and event counters.
/// `queue_sockets` is `(previous, current)` queue tables: connections present
/// before but gone now are reported as `closed`, so the events that ended them
/// (RST, socket error, state changes) stay visible. `events` is
/// `(previous, current)` cumulative counters; `None` when the event hooks are
/// not running.
pub fn queue_connections(
    prev: Option<&Snapshot>,
    cur: &Snapshot,
    queue_sockets: (Option<&[crate::model::QueueSocket]>, &[crate::model::QueueSocket]),
    events: Option<EventCounterPair<'_>>,
) -> Vec<QueueConnection> {
    let ivs = socket_intervals(prev, cur);
    let by_cookie: BTreeMap<u64, usize> =
        cur.sockets.iter().enumerate().filter_map(|(i, s)| s.cookie.map(|c| (c, i))).collect();
    let (prev_qs, cur_qs) = queue_sockets;
    let live: std::collections::BTreeSet<u64> = cur_qs.iter().map(|q| q.cookie).collect();
    let gone = prev_qs.unwrap_or(&[]).iter().filter(|q| !live.contains(&q.cookie)).map(|q| (q, true));
    cur_qs
        .iter()
        .map(|q| (q, false))
        .chain(gone)
        .map(|(q, closed)| {
            let idx = by_cookie.get(&q.cookie).copied();
            let s = idx.and_then(|i| cur.sockets.get(i));
            let info = s.and_then(|s| s.info.as_ref());
            let r = match (s.is_some(), closed) {
                (false, true) => Reason::ConnectionClosed,
                (false, false) => Reason::DependencyUnavailable,
                (true, _) => Reason::InetDiagUnavailable,
            };
            let f = |v: Option<u32>| match v {
                Some(x) => Obs::measured(x, SOCK_SRC),
                None => Obs::unavailable(r),
            };
            let ev = |pick: fn(&crate::model::SockEventCounters) -> u64| -> Obs<u64> {
                match events {
                    None => Obs::unavailable(Reason::DependencyUnavailable),
                    Some((None, _)) => Obs::unavailable(Reason::FirstInterval),
                    Some((Some(p), c)) => {
                        let cv = c.get(&q.cookie).map(pick).unwrap_or(0);
                        let pv = p.get(&q.cookie).map(pick).unwrap_or(0);
                        match cv.checked_sub(pv) {
                            Some(d) => Obs::measured(d, EV_SRC),
                            None => Obs::unavailable(Reason::CounterReset),
                        }
                    }
                }
            };
            QueueConnection {
                controller: format!("nvme{}", q.instance),
                instance: q.instance,
                qid: q.qid,
                cookie: q.cookie,
                local: q.local,
                remote: q.remote,
                state: q.state,
                io_cpu: q.io_cpu,
                hdr_digest: q.hdr_digest,
                data_digest: q.data_digest,
                tls: q.tls,
                association: crate::quality::Quality::Measured,
                closed,
                rtt_us: f(info.map(|i| i.rtt_us)),
                rttvar_us: f(info.map(|i| i.rttvar_us)),
                min_rtt_us: f(info.and_then(|i| i.min_rtt_us)),
                rto_ms: f(info.map(|i| i.rto_us / 1000)),
                cwnd: f(info.map(|i| i.snd_cwnd)),
                unacked: f(info.map(|i| i.unacked)),
                lost: f(info.map(|i| i.lost)),
                total_retrans: f(info.map(|i| i.total_retrans)),
                notsent_bytes: f(info.and_then(|i| i.notsent_bytes)),
                send_q_bytes: f(s.map(|s| s.send_q)),
                recv_q_bytes: f(s.map(|s| s.recv_q)),
                interval: idx.and_then(|i| ivs.get(i).cloned()),
                retransmit_events: ev(|c| c.retrans),
                resets: ev(|c| c.rst_rx + c.rst_tx),
                loss_entries: ev(|c| c.loss_entries),
                recovery_entries: ev(|c| c.recovery_entries),
                socket_errors: ev(|c| c.errors),
                state_changes: ev(|c| c.state_changes),
            }
        })
        .collect()
}

#[cfg(test)]
mod queue_conn_tests {
    use super::*;
    use crate::model::{QueueSocket, SockEventCounters, SocketSource, TcpInfo};
    use std::time::{Duration, Instant};

    fn qs(cookie: u64, qid: u16) -> QueueSocket {
        QueueSocket {
            cookie,
            instance: 2,
            qid,
            local: "198.51.100.5:40000".parse().expect("a"),
            remote: "192.0.2.1:4420".parse().expect("a"),
            state: TcpState::Established,
            io_cpu: Some(5),
            hdr_digest: false,
            data_digest: false,
            tls: Some(false),
        }
    }

    fn snap(t: Instant, retrans: u32) -> Snapshot {
        let s = TcpSocket {
            local: "198.51.100.5:40000".parse().expect("a"),
            remote: "192.0.2.1:4420".parse().expect("a"),
            state: TcpState::Established,
            cookie: Some(7),
            inode: 1,
            uid: 0,
            recv_q: 0,
            send_q: 120,
            info: Some(TcpInfo {
                rtt_us: 150,
                total_retrans: retrans,
                bytes_acked: Some(0),
                bytes_received: Some(0),
                ..Default::default()
            }),
            congestion: None,
            skmem: None,
            source: SocketSource::SockDiag,
        };
        Snapshot {
            taken: t,
            wall: std::time::SystemTime::UNIX_EPOCH,
            topology: Topology::default(),
            disk: BTreeMap::new(),
            sockets: vec![s],
            socket_owner: BTreeMap::new(),
        }
    }

    #[test]
    fn join_by_cookie_with_event_deltas() {
        let t0 = Instant::now();
        let a = snap(t0, 4);
        let b = snap(t0 + Duration::from_secs(2), 10);
        let mut pe = BTreeMap::new();
        pe.insert(7u64, SockEventCounters { retrans: 3, ..Default::default() });
        let mut ce = pe.clone();
        ce.insert(7, SockEventCounters { retrans: 5, rst_rx: 1, ..Default::default() });
        let v = queue_connections(Some(&a), &b, (None, &[qs(7, 3), qs(99, 4)]), Some((Some(&pe), &ce)));
        let q3 = &v[0];
        assert_eq!(q3.rtt_us.value, Some(150));
        assert_eq!(q3.send_q_bytes.value, Some(120));
        assert_eq!(q3.interval.as_ref().and_then(|i| i.retrans_segments_per_s.value), Some(3.0));
        assert_eq!(q3.retransmit_events.value, Some(2));
        assert_eq!(q3.resets.value, Some(1));
        // queue socket not (yet) in the sock_diag dump: unavailable, not zero
        let q4 = &v[1];
        assert_eq!(q4.rtt_us.reason, Some(Reason::DependencyUnavailable));
        assert_eq!(q4.retransmit_events.value, Some(0)); // hooks ran: a real zero
        let none = queue_connections(None, &b, (None, &[qs(7, 3)]), None);
        assert_eq!(none[0].retransmit_events.reason, Some(Reason::DependencyUnavailable));
    }

    #[test]
    fn connection_closed_during_interval_keeps_its_events() {
        let t0 = Instant::now();
        let a = snap(t0, 0);
        let b = snap(t0 + Duration::from_secs(2), 0);
        let mut pe = BTreeMap::new();
        pe.insert(50u64, SockEventCounters { state_changes: 1, ..Default::default() });
        let mut ce = pe.clone();
        // the reset socket stays in the BPF map after it left the queue table
        ce.insert(50, SockEventCounters { state_changes: 2, rst_tx: 1, errors: 1, ..Default::default() });
        let prev_qs = [qs(7, 3), qs(50, 4)];
        let v = queue_connections(Some(&a), &b, (Some(&prev_qs), &[qs(7, 3)]), Some((Some(&pe), &ce)));
        assert_eq!(v.len(), 2);
        assert!(!v[0].closed);
        let gone = &v[1];
        assert!(gone.closed);
        assert_eq!(gone.qid, 4);
        assert_eq!(gone.resets.value, Some(1));
        assert_eq!(gone.socket_errors.value, Some(1));
        assert_eq!(gone.state_changes.value, Some(1));
        assert_eq!(gone.rtt_us.reason, Some(Reason::ConnectionClosed));
        // without a previous table nothing can be reported as closed
        let v = queue_connections(Some(&a), &b, (None, &[qs(7, 3)]), Some((Some(&pe), &ce)));
        assert_eq!(v.len(), 1);
    }
}
