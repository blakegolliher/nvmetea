//! Level 3 collector: loads `bpf/tcp_sock.bpf.c`. Provides the queue ↔ socket
//! table (T1, an `iter/tcp` program read on demand) and timestamped transport
//! events on NVMe/TCP queue sockets (T3-T7).

#[allow(
    clippy::all,
    clippy::unwrap_used,
    dead_code,
    unused_imports,
    unsafe_op_in_unsafe_fn,
    non_camel_case_types,
    non_snake_case
)]
mod skel {
    include!(concat!(env!("OUT_DIR"), "/tcp_sock.skel.rs"));
}

use crate::core::{LoadError, LoadReport, ProgramStatus, capture_libbpf, is_perm, last_lines, pod, take_log};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Iter, Link, MapCore, MapFlags, PrintLevel, RingBuffer, RingBufferBuilder};
use nvmetea_core::model::{QueueSocket, SockEventCounters, TcpEvent, TcpEventKind, TcpState, Topology};
use serde::Serialize;
use skel::types;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Read;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::time::Instant;

const _: () = assert!(std::mem::size_of::<types::nvt_qsock>() == 64);
const _: () = assert!(std::mem::size_of::<types::nvt_sstats>() == 80);
const _: () = assert!(std::mem::size_of::<types::nvt_ev_tcp>() == 40);

#[derive(Debug, Clone, Serialize)]
pub struct TcpSockConfig {
    pub sstats_entries: u32,
    pub events_per_cpu_per_s: u32,
    pub iterator: bool,
}

impl TcpSockConfig {
    pub fn from_topology(topo: &Topology) -> TcpSockConfig {
        let queues: u64 = topo.tcp_controllers().map(|c| u64::from(c.queue_count.unwrap_or(65))).sum();
        TcpSockConfig {
            // reconnects create new sockets (new cookies); LRU keeps the newest
            sstats_entries: (4 * queues).clamp(1024, 65_536) as u32,
            events_per_cpu_per_s: 50,
            iterator: true,
        }
    }
}

/// Collector-health counters of the TCP object.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct TcpBpfHealth {
    /// Events on NVMe/TCP queue sockets (all counted in `sstats`).
    pub nvme_events: u64,
    /// Events not delivered to userspace (rate budget or ring buffer full);
    /// still counted per socket.
    pub events_dropped: u64,
    /// Events on sockets without a cookie yet (counted under cookie 0).
    pub without_cookie: u64,
    /// Every TCP event the hooks saw on the host, before the NVMe filter.
    pub seen_all: u64,
}

pub struct TcpSockCollector {
    skel: skel::TcpSockSkel<'static>,
    _links: Vec<Link>,
    iter_link: Option<Link>,
    ringbuf: Option<RingBuffer<'static>>,
    pending: Rc<RefCell<Vec<TcpEvent>>>,
    pub report: LoadReport,
    /// Why the queue ↔ socket iterator is not available, if it is not.
    pub iterator_error: Option<String>,
    possible_cpus: u32,
}

fn possible_cpus() -> u32 {
    // "0-127" or "0-3,8-11"
    let s = std::fs::read_to_string("/sys/devices/system/cpu/possible").unwrap_or_default();
    let mut max = 0;
    for part in s.trim().split(',') {
        let hi = part.rsplit('-').next().and_then(|x| x.parse::<u32>().ok()).unwrap_or(0);
        max = max.max(hi + 1);
    }
    max.max(1)
}

fn ip(family: u16, b: &[u8; 16]) -> Option<IpAddr> {
    match family {
        2 => Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
        10 => {
            let v6 = Ipv6Addr::from(*b);
            let o = v6.octets();
            if o[..10].iter().all(|&x| x == 0) && o[10] == 0xff && o[11] == 0xff {
                Some(IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15])))
            } else {
                Some(IpAddr::V6(v6))
            }
        }
        _ => None,
    }
}

impl TcpSockCollector {
    pub fn start(cfg: &TcpSockConfig) -> Result<TcpSockCollector, LoadError> {
        match Self::start_once(cfg) {
            Err(LoadError::Load { error, log }) if cfg.iterator => {
                let mut c2 = cfg.clone();
                c2.iterator = false;
                let mut c = Self::start_once(&c2)?;
                c.iterator_error = Some(format!("{error}: {}", last_lines(&log, 6)));
                Ok(c)
            }
            r => r,
        }
    }

    fn start_once(cfg: &TcpSockConfig) -> Result<TcpSockCollector, LoadError> {
        libbpf_rs::set_print(Some((PrintLevel::Warn, capture_libbpf)));
        let _ = take_log();
        let t0 = Instant::now();
        let storage: &'static mut MaybeUninit<libbpf_rs::OpenObject> = Box::leak(Box::new(MaybeUninit::uninit()));
        let mut open = skel::TcpSockSkelBuilder::default()
            .open(storage)
            .map_err(|e| LoadError::Load { error: format!("open: {e}"), log: take_log() })?;
        open.maps
            .sstats
            .set_max_entries(cfg.sstats_entries)
            .map_err(|e| LoadError::Load { error: format!("resize map: {e}"), log: take_log() })?;
        if !cfg.iterator {
            open.progs.nvt_iter_tcp.set_autoload(false);
        }
        let mut skel = open.load().map_err(|e| {
            let log = take_log();
            if is_perm(&e) {
                LoadError::PermissionDenied(e.to_string())
            } else {
                LoadError::Load { error: e.to_string(), log }
            }
        })?;
        let load_ms = t0.elapsed().as_secs_f64() * 1e3;
        if let Some(bss) = skel.maps.bss_data.as_deref_mut() {
            bss.events_per_cpu_per_s = cfg.events_per_cpu_per_s;
            bss.armed = false;
        }
        let t1 = Instant::now();
        let mut links = Vec::new();
        let mut programs = Vec::new();
        let mut iter_link = None;
        let mut iterator_error = None;
        {
            let p = &skel.progs;
            if cfg.iterator {
                match p.nvt_iter_tcp.attach() {
                    Ok(l) => {
                        iter_link = Some(l);
                        programs.push(ProgramStatus {
                            program: "nvt_iter_tcp",
                            attach: "iter/tcp".into(),
                            required: false,
                            attached: true,
                            error: None,
                        });
                    }
                    Err(e) => {
                        iterator_error = Some(e.to_string());
                        programs.push(ProgramStatus {
                            program: "nvt_iter_tcp",
                            attach: "iter/tcp".into(),
                            required: false,
                            attached: false,
                            error: Some(e.to_string()),
                        });
                    }
                }
            }
            let mut attempt = |name: &'static str, tp: &'static str, r: libbpf_rs::Result<Link>| match r {
                Ok(l) => {
                    links.push(l);
                    programs.push(ProgramStatus {
                        program: name,
                        attach: format!("raw_tp/{tp}"),
                        required: false,
                        attached: true,
                        error: None,
                    });
                }
                Err(e) => programs.push(ProgramStatus {
                    program: name,
                    attach: format!("raw_tp/{tp}"),
                    required: false,
                    attached: false,
                    error: Some(e.to_string()),
                }),
            };
            attempt(
                "nvt_tcp_retransmit",
                "tcp_retransmit_skb",
                p.nvt_tcp_retransmit.attach_raw_tracepoint("tcp_retransmit_skb"),
            );
            attempt(
                "nvt_sock_state",
                "inet_sock_set_state",
                p.nvt_sock_state.attach_raw_tracepoint("inet_sock_set_state"),
            );
            attempt(
                "nvt_cong_state",
                "tcp_cong_state_set",
                p.nvt_cong_state.attach_raw_tracepoint("tcp_cong_state_set"),
            );
            attempt("nvt_rst_rx", "tcp_receive_reset", p.nvt_rst_rx.attach_raw_tracepoint("tcp_receive_reset"));
            attempt("nvt_rst_tx", "tcp_send_reset", p.nvt_rst_tx.attach_raw_tracepoint("tcp_send_reset"));
            attempt(
                "nvt_sk_error",
                "inet_sk_error_report",
                p.nvt_sk_error.attach_raw_tracepoint("inet_sk_error_report"),
            );
        }
        let attach_ms = t1.elapsed().as_secs_f64() * 1e3;
        let report = LoadReport { programs, maps: vec![("sstats".into(), cfg.sstats_entries)], load_ms, attach_ms };
        if iter_link.is_none() && links.is_empty() {
            let error = report.programs.iter().filter_map(|p| p.error.clone()).next().unwrap_or_default();
            return Err(LoadError::Attach { error, report });
        }
        let pending: Rc<RefCell<Vec<TcpEvent>>> = Rc::new(RefCell::new(Vec::new()));
        let sink = pending.clone();
        let mut rb = RingBufferBuilder::new();
        let added = rb
            .add(&skel.maps.tevents, move |data: &[u8]| {
                if let Some(ev) = parse_event(data) {
                    if let Ok(mut v) = sink.try_borrow_mut() {
                        if v.len() < 100_000 {
                            v.push(ev);
                        }
                    }
                }
                0
            })
            .is_ok();
        let ringbuf = if added { rb.build().ok() } else { None };
        if let Some(bss) = skel.maps.bss_data.as_deref_mut() {
            bss.armed = true;
        }
        Ok(TcpSockCollector {
            skel,
            _links: links,
            iter_link,
            ringbuf,
            pending,
            report,
            iterator_error,
            possible_cpus: possible_cpus(),
        })
    }

    pub fn has_iterator(&self) -> bool {
        self.iter_link.is_some()
    }

    /// Walk the kernel's TCP sockets and return the NVMe/TCP queue sockets.
    /// Run a sock_diag dump first so that every socket has a cookie (the
    /// program also generates missing ones).
    pub fn queue_sockets(&self) -> Result<Vec<QueueSocket>, String> {
        let link = self
            .iter_link
            .as_ref()
            .ok_or_else(|| self.iterator_error.clone().unwrap_or_else(|| "iterator not attached".into()))?;
        let mut it = Iter::new(link).map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        it.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for chunk in buf.chunks_exact(std::mem::size_of::<types::nvt_qsock>()) {
            let Some(r) = pod::<types::nvt_qsock>(chunk) else { continue };
            let (Some(l), Some(rm)) = (ip(r.family, &r.laddr), ip(r.family, &r.raddr)) else { continue };
            out.push(QueueSocket {
                cookie: r.cookie,
                instance: r.inst,
                qid: r.qid,
                local: SocketAddr::new(l, r.lport),
                remote: SocketAddr::new(rm, r.rport),
                state: TcpState::from_kernel(r.state),
                io_cpu: (r.io_cpu >= 0 && (r.io_cpu as u32) < self.possible_cpus).then_some(r.io_cpu as u32),
                hdr_digest: r.flags & 1 != 0,
                data_digest: r.flags & 2 != 0,
                tls: if r.flags & 8 != 0 { None } else { Some(r.flags & 4 != 0) },
            });
        }
        out.sort_by_key(|q| (q.instance, q.qid));
        Ok(out)
    }

    /// Cumulative per-socket event counters, by cookie.
    pub fn counters(&self) -> BTreeMap<u64, SockEventCounters> {
        let mut out = BTreeMap::new();
        let m = &self.skel.maps.sstats;
        for k in m.keys() {
            let (Some(cookie), Ok(Some(v))) = (pod::<u64>(&k), m.lookup(&k, MapFlags::ANY)) else { continue };
            let Some(s) = pod::<types::nvt_sstats>(&v) else { continue };
            out.insert(
                cookie,
                SockEventCounters {
                    instance: s.inst,
                    qid: s.qid,
                    retrans: s.retrans,
                    rst_rx: s.rst_rx,
                    rst_tx: s.rst_tx,
                    state_changes: s.state_changes,
                    loss_entries: s.loss_entries,
                    recovery_entries: s.recovery_entries,
                    cwr_entries: s.cwr_entries,
                    errors: s.errors,
                    last_event_ns: s.last_event_ns,
                },
            );
        }
        out
    }

    pub fn health(&self) -> TcpBpfHealth {
        let mut c = [0u64; 4];
        for (i, slot) in c.iter_mut().enumerate() {
            if let Ok(Some(per_cpu)) = self.skel.maps.tcounters.lookup_percpu(&(i as u32).to_ne_bytes(), MapFlags::ANY)
            {
                *slot = per_cpu.iter().filter_map(|v| pod::<u64>(v)).sum();
            }
        }
        TcpBpfHealth { nvme_events: c[0], events_dropped: c[1], without_cookie: c[2], seen_all: c[3] }
    }

    pub fn drain_events(&mut self) -> Vec<TcpEvent> {
        if let Some(rb) = &self.ringbuf {
            let _ = rb.consume();
        }
        std::mem::take(&mut *self.pending.borrow_mut())
    }
}

fn parse_event(d: &[u8]) -> Option<TcpEvent> {
    let e = pod::<types::nvt_ev_tcp>(d)?;
    if e.kind != 3 {
        return None;
    }
    let kind = match e.tkind {
        1 => TcpEventKind::Retransmit,
        2 => TcpEventKind::State { from: TcpState::from_kernel(e.a as u8), to: TcpState::from_kernel(e.b as u8) },
        3 => TcpEventKind::ResetReceived,
        4 => TcpEventKind::ResetSent,
        5 => TcpEventKind::Congestion { ca_state: e.a as u8 },
        6 => TcpEventKind::Error { errno: e.a },
        _ => return None,
    };
    Some(TcpEvent { t_ns: e.t, cookie: e.cookie, instance: e.inst, qid: e.qid, kind })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&[198, 51, 100, 95]);
        assert_eq!(ip(2, &b), Some("198.51.100.95".parse().expect("ip")));
        let mut m = [0u8; 16];
        m[10] = 0xff;
        m[11] = 0xff;
        m[12..].copy_from_slice(&[10, 0, 0, 1]);
        assert_eq!(ip(10, &m), Some("10.0.0.1".parse().expect("ip")));
        assert_eq!(ip(99, &m), None);
    }

    #[test]
    fn event_parse() {
        let ev = types::nvt_ev_tcp { kind: 3, tkind: 2, t: 5, cookie: 9, inst: 3, qid: 4, pad: 0, a: 1, b: 4 };
        // SAFETY: plain #[repr(C)] integers.
        let bytes = unsafe { std::slice::from_raw_parts((&ev as *const types::nvt_ev_tcp).cast::<u8>(), 40) };
        let e = parse_event(bytes).expect("event");
        assert_eq!((e.instance, e.qid, e.cookie), (3, 4, 9));
        assert_eq!(e.kind, TcpEventKind::State { from: TcpState::Established, to: TcpState::FinWait1 });
    }
}
