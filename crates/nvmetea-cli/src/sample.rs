//! Wiring of the collectors into one snapshot.

use nvmetea_bpf::core::{CoreCollector, CoreConfig, CoreEvent, LoadError};
use nvmetea_bpf::tcpsock::{TcpBpfHealth, TcpSockCollector, TcpSockConfig};
use nvmetea_core::Reason;
use nvmetea_core::engine::Snapshot;
use nvmetea_core::model::{NvmeSample, QueueSocket, ScanIssue, SockEventCounters, TcpEvent, Topology};
use nvmetea_tcp::assoc::{self, Association};
use nvmetea_tcp::{TcpBackend, TcpSample};
use nvmetea_topology::{SysRoot, Tracker, Transition, TransitionSource, diskstats, scan};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Instant, SystemTime};

/// State of the Level 1 BPF collector.
pub enum Bpf {
    /// The command does not use BPF (or it was not started yet).
    NotStarted,
    Disabled,
    Active(Box<CoreCollector>),
    Unavailable {
        reason: Reason,
        detail: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct BpfStatus {
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Optional lifecycle programs that are not running, and why.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<String>,
}

/// State of the Level 3 (TCP) BPF collector.
pub enum TcpBpf {
    NotStarted,
    Disabled,
    Active(Box<TcpSockCollector>),
    Unavailable { reason: Reason, detail: String },
}

pub struct Collector {
    pub sys: SysRoot,
    pub proc_root: PathBuf,
    pub tracker: Tracker,
    pub use_sock_diag: bool,
    pub bpf: Bpf,
    pub tcp_bpf: TcpBpf,
}

#[derive(Debug, Clone, Serialize)]
pub struct TcpMeta {
    pub backend: TcpBackend,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded: Option<nvmetea_core::Reason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct Sampled {
    pub snap: Snapshot,
    pub transitions: Vec<Transition>,
    pub disk_issues: Vec<ScanIssue>,
    pub disk_error: Option<String>,
    pub tcp: TcpMeta,
    pub assoc: Association,
    pub nvme: Option<NvmeSample>,
    pub events: Vec<CoreEvent>,
    /// Kernel-identified queue sockets (T1); `Err` holds why they are unavailable.
    pub queue_sockets: Result<Vec<QueueSocket>, (Reason, String)>,
    /// Cumulative transport-event counters by socket cookie (T3-T7).
    pub sock_events: Option<BTreeMap<u64, SockEventCounters>>,
    pub tcp_events: Vec<TcpEvent>,
    pub tcp_bpf_health: Option<TcpBpfHealth>,
    /// Sockets whose kernel-identified controller differs from the endpoint match.
    pub assoc_disagreements: usize,
}

fn classify(e: &LoadError) -> (Reason, String) {
    match e {
        LoadError::PermissionDenied(d) => (Reason::PermissionDenied, d.clone()),
        LoadError::Load { error, log } => {
            let no_sys_admin = nvmetea_bpf::discovery::privileges().missing_capabilities.contains(&"CAP_SYS_ADMIN");
            let r = if log.contains("CO-RE relocation") && no_sys_admin {
                // libbpf can only enumerate module BTF (nvme_core, nvme_tcp)
                // with CAP_SYS_ADMIN; without it module types look missing
                return (
                    Reason::PermissionDenied,
                    format!("{error}: kernel module BTF (nvme_core, nvme_tcp) can only be read with CAP_SYS_ADMIN"),
                );
            } else if log.contains("CO-RE relocation") {
                Reason::BtfMismatch
            } else if log.contains("BEGIN PROG LOAD LOG") {
                Reason::VerifierRejected
            } else if log.contains("vmlinux BTF") || log.contains("kernel BTF") {
                Reason::BtfVmlinuxMissing
            } else {
                Reason::MissingInterface
            };
            (r, error.clone())
        }
        LoadError::Attach { error, .. } => (Reason::AttachFailed, error.clone()),
    }
}

impl Collector {
    pub fn new(sys: SysRoot, proc_root: PathBuf) -> Collector {
        Collector {
            sys,
            proc_root,
            tracker: Tracker::default(),
            use_sock_diag: true,
            bpf: Bpf::NotStarted,
            tcp_bpf: TcpBpf::NotStarted,
        }
    }

    /// Start the Level 3 (TCP) collector. Idempotent; independent of Level 1.
    pub fn enable_tcp_bpf(&mut self, topo: &Topology) {
        if !matches!(self.tcp_bpf, TcpBpf::NotStarted) {
            return;
        }
        if topo.tcp_controllers().next().is_none() {
            self.tcp_bpf = TcpBpf::Unavailable { reason: Reason::NoSamples, detail: "no NVMe/TCP controllers".into() };
            return;
        }
        self.tcp_bpf = match TcpSockCollector::start(&TcpSockConfig::from_topology(topo)) {
            Ok(c) => TcpBpf::Active(Box::new(c)),
            Err(e) => {
                let (reason, detail) = classify(&e);
                TcpBpf::Unavailable { reason, detail }
            }
        };
    }

    pub fn tcp_bpf_status(&self) -> BpfStatus {
        match &self.tcp_bpf {
            TcpBpf::NotStarted => BpfStatus { state: "not_started", reason: None, detail: None, lifecycle: None },
            TcpBpf::Disabled => {
                BpfStatus { state: "disabled", reason: Some(Reason::DisabledByUser), detail: None, lifecycle: None }
            }
            TcpBpf::Active(c) => {
                BpfStatus { state: "active", reason: None, detail: c.iterator_error.clone(), lifecycle: None }
            }
            TcpBpf::Unavailable { reason, detail } => {
                BpfStatus { state: "unavailable", reason: Some(*reason), detail: Some(detail.clone()), lifecycle: None }
            }
        }
    }

    /// Start both BPF collectors (Level 1 and Level 3), sized for `topo`.
    pub fn enable_all_bpf(&mut self, topo: &Topology) {
        self.enable_bpf(topo);
        self.enable_tcp_bpf(topo);
    }

    /// Start the Level 1 collector, sized for `topo`. Idempotent.
    pub fn enable_bpf(&mut self, topo: &Topology) {
        if !matches!(self.bpf, Bpf::NotStarted) {
            return;
        }
        if topo.tcp_controllers().next().is_none() {
            self.bpf = Bpf::Unavailable { reason: Reason::NoSamples, detail: "no NVMe/TCP controllers".into() };
            return;
        }
        self.bpf = match CoreCollector::start(&CoreConfig::from_topology(topo)) {
            Ok(c) => Bpf::Active(Box::new(c)),
            Err(e) => {
                let (reason, detail) = classify(&e);
                Bpf::Unavailable { reason, detail }
            }
        };
    }

    pub fn bpf_status(&self) -> BpfStatus {
        match &self.bpf {
            Bpf::NotStarted => BpfStatus { state: "not_started", reason: None, detail: None, lifecycle: None },
            Bpf::Disabled => {
                BpfStatus { state: "disabled", reason: Some(Reason::DisabledByUser), detail: None, lifecycle: None }
            }
            Bpf::Active(c) => {
                BpfStatus { state: "active", reason: None, detail: None, lifecycle: c.lifecycle_error.clone() }
            }
            Bpf::Unavailable { reason, detail } => {
                BpfStatus { state: "unavailable", reason: Some(*reason), detail: Some(detail.clone()), lifecycle: None }
            }
        }
    }

    pub fn bpf_mut(&mut self) -> Option<&mut CoreCollector> {
        match &mut self.bpf {
            Bpf::Active(c) => Some(c),
            _ => None,
        }
    }

    pub fn sample(&mut self, source: TransitionSource) -> Sampled {
        let wall = SystemTime::now();
        let mut topo = scan(&self.sys);
        let transitions = self.tracker.observe(&mut topo, wall, source);
        let taken = Instant::now();
        let (disk, disk_issues, disk_error) = match diskstats::read(&self.proc_root) {
            Ok((d, i)) => (d, i, None),
            Err(e) => (Default::default(), Vec::new(), Some(format!("/proc/diskstats: {e}"))),
        };
        // device numbers of hidden path disks come from diskstats
        for ns in &mut topo.namespaces {
            if ns.dev.is_none() {
                ns.dev = disk.get(&ns.name).map(|d| format!("{}:{}", d.major, d.minor));
            }
            for p in &mut ns.paths {
                if p.dev.is_none() {
                    p.dev = disk.get(&p.name).map(|d| format!("{}:{}", d.major, d.minor));
                }
            }
        }
        let (nvme, events) = match &mut self.bpf {
            Bpf::Active(c) => {
                use nvmetea_topology::tracker::Change;
                if transitions.iter().any(|t| matches!(t.change, Change::Added { .. } | Change::Removed { .. })) {
                    c.invalidate_caches();
                }
                (Some(c.sample()), c.drain_events())
            }
            _ => (None, Vec::new()),
        };
        let TcpSample { backend, degraded, error, sockets } =
            nvmetea_tcp::collect(&topo, &self.proc_root, self.use_sock_diag);
        let assoc = assoc::associate(&topo, &sockets);
        let mut socket_owner: BTreeMap<String, Vec<usize>> =
            assoc.by_controller.iter().map(|(k, v)| (k.clone(), v.sockets.clone())).collect();
        // after the sock_diag dump (which generates socket cookies): T1 and T3-T7
        let (queue_sockets, sock_events, tcp_events, tcp_bpf_health) = match &mut self.tcp_bpf {
            TcpBpf::Active(c) => {
                let qs = c.queue_sockets().map_err(|e| (Reason::DependencyUnavailable, e));
                (qs, Some(c.counters()), c.drain_events(), Some(c.health()))
            }
            TcpBpf::Unavailable { reason, detail } => (Err((*reason, detail.clone())), None, Vec::new(), None),
            TcpBpf::Disabled => (Err((Reason::DisabledByUser, "BPF disabled".into())), None, Vec::new(), None),
            TcpBpf::NotStarted => {
                (Err((Reason::DependencyUnavailable, "TCP BPF collector not started".into())), None, Vec::new(), None)
            }
        };
        let mut assoc_disagreements = 0;
        if let Ok(qs) = &queue_sockets {
            // the kernel's own queue -> socket link replaces the endpoint match
            let idx: BTreeMap<u64, usize> =
                sockets.iter().enumerate().filter_map(|(i, s)| s.cookie.map(|c| (c, i))).collect();
            let mut measured: BTreeMap<String, Vec<usize>> = BTreeMap::new();
            for q in qs {
                if let Some(&i) = idx.get(&q.cookie) {
                    let name = format!("nvme{}", q.instance);
                    if !assoc.by_controller.get(&name).is_some_and(|c| c.sockets.contains(&i)) {
                        assoc_disagreements += 1;
                    }
                    measured.entry(name).or_default().push(i);
                }
            }
            socket_owner = measured;
        }
        Sampled {
            snap: Snapshot { taken, wall, topology: topo, disk, sockets, socket_owner },
            transitions,
            disk_issues,
            disk_error,
            tcp: TcpMeta { backend, degraded, error },
            assoc,
            nvme,
            events,
            queue_sockets,
            sock_events,
            tcp_events,
            tcp_bpf_health,
            assoc_disagreements,
        }
    }
}
