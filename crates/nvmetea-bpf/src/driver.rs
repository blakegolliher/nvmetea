//! Level 2 collector: loads `bpf/tcp_driver.bpf.c` (NVMe/TCP driver stage
//! boundaries of sampled commands, worker accounting, timeouts).
//!
//! Each driver hook is built in two flavours. `Flavour::Kprobe` works on every
//! kernel with kprobes; `Flavour::Fentry` is cheaper per call but its attach can
//! stall on busy hosts (finding F15), so callers use it only after
//! [`crate::preflight`] passed. Programs whose probe is unavailable on this
//! kernel (discovery rule F4) are not loaded; their boundaries stay missing and
//! the affected stages merge (latency model rule R2).

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
    include!(concat!(env!("OUT_DIR"), "/tcp_driver.skel.rs"));
}

use crate::bpfstats::{ProgRun, prog_run};
use crate::core::{LoadError, LoadReport, ProgramStatus, capture_libbpf, is_perm, pod, take_log};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Link, MapCore, MapFlags, PrintLevel, RingBuffer, RingBufferBuilder};
use nvmetea_core::model::{Boundaries, StageRecord, Topology};
use serde::Serialize;
use skel::types;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::rc::Rc;
use std::time::Instant;

const _: () = assert!(std::mem::size_of::<types::nvt_prof>() == 208);
const _: () = assert!(std::mem::size_of::<types::nvt_ev_prof>() == 216);
const _: () = assert!(std::mem::size_of::<types::nvt_ev_timeout>() == 32);
const _: () = assert!(std::mem::size_of::<types::nvt_wstats>() == 32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Flavour {
    Fentry,
    Kprobe,
}

impl Flavour {
    pub fn as_str(self) -> &'static str {
        match self {
            Flavour::Fentry => "fentry",
            Flavour::Kprobe => "kprobe",
        }
    }
}

/// One program of the object.
struct ProgDef {
    name: &'static str,
    /// Probe id in the catalog (`docs/kernel-compatibility.md` §5).
    id: &'static str,
    /// `None`: both flavours (raw tracepoints).
    flavour: Option<Flavour>,
    /// Without it the object is not useful (staging needs these boundaries).
    required: bool,
}

const fn p(name: &'static str, id: &'static str, flavour: Option<Flavour>, required: bool) -> ProgDef {
    ProgDef { name, id, flavour, required }
}
const K: Option<Flavour> = Some(Flavour::Kprobe);
const F: Option<Flavour> = Some(Flavour::Fentry);

const PROGS: &[ProgDef] = &[
    p("nvt_d_setup", "P1", None, true),
    p("nvt_d_complete_rq", "P2", None, true),
    p("nvt_d_blk_complete", "P3", None, true),
    p("kp_io_work", "D6", K, false),
    p("kr_io_work", "D6", K, false),
    p("kp_cmd_pdu", "D1", K, true),
    p("kr_cmd_pdu", "D1", K, true),
    p("kp_send_data", "D2a", K, true),
    p("kr_send_data", "D2a", K, true),
    p("kp_ddgst", "D2b", K, false),
    p("kr_ddgst", "D2b", K, false),
    p("kp_data_pdu", "D3", K, false),
    p("kp_h2c_setup", "D4", K, false),
    p("kp_recv_skb", "D7", K, true),
    p("kr_recv_skb", "D7", K, true),
    p("kp_copy", "D8a", K, false),
    p("kp_copy_hash", "D8b", K, false),
    p("kp_complete_remote", "D9", K, true),
    p("kp_data_ready", "D10f", K, true),
    p("kp_timeout", "D12", K, false),
    p("fe_io_work", "D6", F, false),
    p("fx_io_work", "D6", F, false),
    p("fe_cmd_pdu", "D1", F, true),
    p("fx_cmd_pdu", "D1", F, true),
    p("fe_send_data", "D2a", F, true),
    p("fx_send_data", "D2a", F, true),
    p("fx_ddgst", "D2b", F, false),
    p("fe_data_pdu", "D3", F, false),
    p("fe_h2c_setup", "D4", F, false),
    p("fe_recv_skb", "D7", F, true),
    p("fx_recv_skb", "D7", F, true),
    p("fe_copy", "D8a", F, false),
    p("fe_copy_hash", "D8b", F, false),
    p("fe_complete_remote", "D9", F, true),
    p("fe_data_ready", "D10f", F, true),
    p("fe_timeout", "D12", F, false),
];

#[derive(Debug, Clone, Serialize)]
pub struct DriverConfig {
    pub flavour: Flavour,
    /// 1 in N commands get a stage record (1 = every command).
    pub sample_every: u32,
    /// Only this controller instance (nvmeN), or every NVMe/TCP controller.
    pub only_instance: Option<u32>,
    pub prof_entries: u32,
    pub queue_entries: u32,
    /// Probe ids not to load (unavailable on this kernel for this flavour).
    pub skip: BTreeSet<String>,
}

impl DriverConfig {
    pub fn from_topology(topo: &Topology, flavour: Flavour, sample_every: u32) -> DriverConfig {
        let tcp: Vec<_> = topo.tcp_controllers().collect();
        let depth: u64 = tcp
            .iter()
            .map(|c| u64::from(c.io_queues().unwrap_or(64)) * u64::from(c.io_queue_depth().unwrap_or(128)))
            .sum();
        let queues: u64 = tcp.iter().map(|c| u64::from(c.queue_count.unwrap_or(65))).sum();
        let sample_every = sample_every.max(1);
        DriverConfig {
            flavour,
            sample_every,
            only_instance: None,
            // every in-flight command may be sampled at --sample 1
            prof_entries: (2 * depth / u64::from(sample_every)).clamp(1024, 262_144) as u32,
            queue_entries: (4 * queues).clamp(256, 16_384) as u32,
            skip: BTreeSet::new(),
        }
    }
}

/// Collector-health counters (cumulative).
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct DriverHealth {
    pub sampled: u64,
    pub emitted: u64,
    pub events_lost: u64,
    pub map_full: u64,
    pub stale: u64,
    pub retried: u64,
    pub tx_ctx_lost: u64,
    pub seq_unresolved: u64,
    pub c2h_unmatched: u64,
    pub h2c_continuations: u64,
    pub timeouts: u64,
    pub parsed_outside_receive: u64,
    /// io_work runs not counted in the worker stats (another run interleaved on the CPU).
    pub worker_ctx_lost: u64,
}

impl DriverHealth {
    pub fn since(&self, prev: &DriverHealth) -> DriverHealth {
        DriverHealth {
            sampled: self.sampled.saturating_sub(prev.sampled),
            emitted: self.emitted.saturating_sub(prev.emitted),
            events_lost: self.events_lost.saturating_sub(prev.events_lost),
            map_full: self.map_full.saturating_sub(prev.map_full),
            stale: self.stale.saturating_sub(prev.stale),
            retried: self.retried.saturating_sub(prev.retried),
            tx_ctx_lost: self.tx_ctx_lost.saturating_sub(prev.tx_ctx_lost),
            seq_unresolved: self.seq_unresolved.saturating_sub(prev.seq_unresolved),
            c2h_unmatched: self.c2h_unmatched.saturating_sub(prev.c2h_unmatched),
            h2c_continuations: self.h2c_continuations.saturating_sub(prev.h2c_continuations),
            timeouts: self.timeouts.saturating_sub(prev.timeouts),
            parsed_outside_receive: self.parsed_outside_receive.saturating_sub(prev.parsed_outside_receive),
            worker_ctx_lost: self.worker_ctx_lost.saturating_sub(prev.worker_ctx_lost),
        }
    }
}

/// Cumulative io_work accounting of one queue.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct WorkerCounters {
    pub runs: u64,
    /// Elapsed time inside io_work (includes preemption and interrupts).
    pub busy_ns: u64,
    /// Runs that used the whole 1 ms quota.
    pub quota_runs: u64,
    pub max_ns: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimeoutEvent {
    pub t_ns: u64,
    pub instance: u32,
    pub qid: u16,
    pub cid: u16,
    pub opcode: u8,
    pub age_ns: Option<u64>,
    pub sampled: bool,
}

// Records dominate (up to ~300k/s at --sample 1) and timeouts are rare: boxing
// the record would add an allocation per command.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum DriverEvent {
    Command(StageRecord),
    Timeout(TimeoutEvent),
}

pub struct DriverCollector {
    skel: skel::TcpDriverSkel<'static>,
    _links: Vec<Link>,
    ringbuf: Option<RingBuffer<'static>>,
    pending: Rc<RefCell<Vec<DriverEvent>>>,
    pub report: LoadReport,
    pub config: DriverConfig,
    /// Probe ids whose programs were dropped after failing to load or attach.
    pub dropped: BTreeMap<String, String>,
    possible_cpus: u32,
}

fn possible_cpus() -> u32 {
    let s = std::fs::read_to_string("/sys/devices/system/cpu/possible").unwrap_or_default();
    let mut max = 0;
    for part in s.trim().split(',') {
        let hi = part.rsplit('-').next().and_then(|x| x.parse::<u32>().ok()).unwrap_or(0);
        max = max.max(hi + 1);
    }
    max.max(1)
}

/// The verifier's last lines for a failed program (they say why it was rejected).
fn verifier_tail(log: &str, n: usize) -> String {
    let end = log.rfind("-- END PROG LOAD LOG --").unwrap_or(log.len());
    let body = &log[..end];
    let lines: Vec<&str> =
        body.lines().map(|l| l.trim_start_matches("libbpf: ").trim()).filter(|l| !l.is_empty()).collect();
    lines[lines.len().saturating_sub(n)..].join(" | ")
}

/// The program a failed load is about: libbpf logs "prog 'NAME': ...".
fn failing_program(log: &str) -> Option<String> {
    let i = log.rfind("prog '")?;
    let rest = &log[i + 6..];
    Some(rest[..rest.find('\'')?].to_string())
}

impl DriverCollector {
    /// Load and attach the configured flavour. Optional programs that fail to
    /// load are dropped and the object is loaded again (one failing program
    /// fails the whole object otherwise); a required one fails the load.
    pub fn start(cfg: &DriverConfig) -> Result<DriverCollector, LoadError> {
        let mut dropped: BTreeMap<String, String> = BTreeMap::new();
        for _ in 0..8 {
            match Self::start_once(cfg, &dropped) {
                Ok(mut c) => {
                    c.dropped = dropped;
                    return Ok(c);
                }
                Err(LoadError::Load { error, log }) => {
                    let Some(name) = failing_program(&log) else {
                        return Err(LoadError::Load { error, log });
                    };
                    let def = PROGS.iter().find(|d| d.name == name);
                    match def {
                        Some(d) if !d.required && !dropped.contains_key(d.id) => {
                            dropped.insert(d.id.to_string(), format!("{error}: {}", verifier_tail(&log, 3)));
                        }
                        _ => return Err(LoadError::Load { error, log }),
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Err(LoadError::Load { error: "too many program load failures".into(), log: String::new() })
    }

    fn wanted(cfg: &DriverConfig, dropped: &BTreeMap<String, String>, d: &ProgDef) -> bool {
        d.flavour.is_none_or(|f| f == cfg.flavour) && !cfg.skip.contains(d.id) && !dropped.contains_key(d.id)
    }

    fn start_once(cfg: &DriverConfig, dropped: &BTreeMap<String, String>) -> Result<DriverCollector, LoadError> {
        if let Some(d) =
            PROGS.iter().find(|d| d.required && d.flavour.is_none_or(|f| f == cfg.flavour) && cfg.skip.contains(d.id))
        {
            return Err(LoadError::Load {
                error: format!("required probe {} ({}) is unavailable on this kernel", d.id, d.name),
                log: String::new(),
            });
        }
        libbpf_rs::set_print(Some((PrintLevel::Warn, capture_libbpf)));
        let _ = take_log();
        let t0 = Instant::now();
        let storage: &'static mut MaybeUninit<libbpf_rs::OpenObject> = Box::leak(Box::new(MaybeUninit::uninit()));
        let mut open = skel::TcpDriverSkelBuilder::default()
            .open(storage)
            .map_err(|e| LoadError::Load { error: format!("open: {e}"), log: take_log() })?;
        let sizes = [
            (&mut open.maps.prof, cfg.prof_entries),
            (&mut open.maps.bycid, cfg.prof_entries),
            (&mut open.maps.nring, cfg.queue_entries),
            (&mut open.maps.qcache, cfg.queue_entries),
            (&mut open.maps.wstats, cfg.queue_entries),
        ];
        let mut maps = Vec::new();
        for (m, n) in sizes {
            m.set_max_entries(n).map_err(|e| LoadError::Load { error: format!("resize map: {e}"), log: take_log() })?;
            maps.push((m.name().to_string_lossy().into_owned(), n));
        }
        for mut prog in open.open_object_mut().progs_mut() {
            let name = prog.name().to_string_lossy().into_owned();
            let want = PROGS.iter().find(|d| d.name == name).is_some_and(|d| Self::wanted(cfg, dropped, d));
            prog.set_autoload(want);
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
            bss.armed = false;
            bss.sample_every = cfg.sample_every.max(1);
            bss.only_inst = cfg.only_instance.map(|i| i as i32).unwrap_or(-1);
            bss.sampled_inflight = 0;
        }

        let t1 = Instant::now();
        let mut links = Vec::new();
        let mut programs = Vec::new();
        for prog in skel.object_mut().progs_mut() {
            let name = prog.name().to_string_lossy().into_owned();
            let Some(d) = PROGS.iter().find(|d| d.name == name) else { continue };
            if !Self::wanted(cfg, dropped, d) {
                continue;
            }
            let attach = prog.section().to_string_lossy().into_owned();
            match prog.attach() {
                Ok(l) => {
                    links.push(l);
                    programs.push(ProgramStatus {
                        program: d.name,
                        attach,
                        required: d.required,
                        attached: true,
                        error: None,
                    });
                }
                Err(e) => programs.push(ProgramStatus {
                    program: d.name,
                    attach,
                    required: d.required,
                    attached: false,
                    error: Some(e.to_string()),
                }),
            }
        }
        let attach_ms = t1.elapsed().as_secs_f64() * 1e3;
        let report = LoadReport { programs, maps, load_ms, attach_ms };
        if let Some(bad) = report.programs.iter().find(|p| p.required && !p.attached) {
            let error = format!("{} ({}): {}", bad.program, bad.attach, bad.error.clone().unwrap_or_default());
            drop(links);
            return Err(LoadError::Attach { error, report });
        }

        let pending: Rc<RefCell<Vec<DriverEvent>>> = Rc::new(RefCell::new(Vec::new()));
        let sink = pending.clone();
        let cpus = possible_cpus();
        let mut rb = RingBufferBuilder::new();
        let added = rb
            .add(&skel.maps.devents, move |data: &[u8]| {
                if let Some(ev) = parse_event(data, cpus) {
                    if let Ok(mut v) = sink.try_borrow_mut() {
                        if v.len() < 1_000_000 {
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
        Ok(DriverCollector {
            skel,
            _links: links,
            ringbuf,
            pending,
            report,
            config: cfg.clone(),
            dropped: BTreeMap::new(),
            possible_cpus: cpus,
        })
    }

    /// Probe ids whose programs are attached.
    pub fn active_probes(&self) -> BTreeSet<&'static str> {
        let attached: BTreeSet<&str> = self.report.programs.iter().filter(|p| p.attached).map(|p| p.program).collect();
        PROGS.iter().filter(|d| attached.contains(d.name)).map(|d| d.id).collect()
    }

    pub fn drain_events(&mut self) -> Vec<DriverEvent> {
        if let Some(rb) = &self.ringbuf {
            let _ = rb.consume();
        }
        std::mem::take(&mut *self.pending.borrow_mut())
    }

    /// Sampled commands currently in flight (records under construction).
    pub fn sampled_inflight(&self) -> i64 {
        self.skel.maps.bss_data.as_deref().map(|b| b.sampled_inflight).unwrap_or(0)
    }

    pub fn health(&self) -> DriverHealth {
        let mut c = [0u64; 16];
        if let Ok(Some(per_cpu)) = self.skel.maps.dcounters.lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY) {
            for v in per_cpu {
                if let Some(x) = pod::<types::nvt_dcounters>(&v) {
                    for (a, b) in c.iter_mut().zip(x.c.iter()) {
                        *a += *b;
                    }
                }
            }
        }
        DriverHealth {
            sampled: c[0],
            emitted: c[1],
            events_lost: c[2],
            map_full: c[3],
            stale: c[4],
            retried: c[5],
            tx_ctx_lost: c[6],
            seq_unresolved: c[7],
            c2h_unmatched: c[8],
            h2c_continuations: c[9],
            timeouts: c[10],
            parsed_outside_receive: c[11],
            worker_ctx_lost: c[12],
        }
    }

    /// Cumulative worker accounting per (controller instance, qid).
    pub fn workers(&self) -> BTreeMap<(u32, u16), WorkerCounters> {
        let mut out = BTreeMap::new();
        let m = &self.skel.maps.wstats;
        for k in m.keys() {
            let (Some(key), Ok(Some(v))) = (pod::<types::nvt_qkey>(&k), m.lookup(&k, MapFlags::ANY)) else { continue };
            let Some(w) = pod::<types::nvt_wstats>(&v) else { continue };
            out.insert(
                (u32::from(key.inst), key.qid),
                WorkerCounters { runs: w.runs, busy_ns: w.busy_ns, quota_runs: w.quota_runs, max_ns: w.max_ns },
            );
        }
        out
    }

    /// Run-time statistics of this object's programs (meaningful while
    /// BPF run-time stats are enabled).
    pub fn prog_runs(&self) -> Vec<ProgRun> {
        let mut v = Vec::new();
        for prog in self.skel.object().progs() {
            if !prog.autoload() {
                continue;
            }
            if let Some((cnt, ns, miss)) = prog_run(prog.as_fd()) {
                v.push(ProgRun {
                    object: "tcp_driver",
                    program: prog.name().to_string_lossy().into_owned(),
                    run_cnt: cnt,
                    run_time_ns: ns,
                    recursion_misses: miss,
                });
            }
        }
        v
    }

    pub fn possible_cpus(&self) -> u32 {
        self.possible_cpus
    }
}

fn nz(v: u64) -> Option<u64> {
    (v != 0).then_some(v)
}

pub(crate) fn record_from(r: &types::nvt_prof, cpus: u32) -> StageRecord {
    StageRecord {
        seq: r.seq,
        instance: u32::from(r.inst),
        qid: r.qid,
        cid: r.cid,
        opcode: r.opcode,
        nsid: r.nsid,
        bytes: r.bytes,
        status: r.status,
        retries: r.retries,
        r2ts: r.r2ts,
        io_cpu: (r.io_cpu >= 0 && (r.io_cpu as u32) < cpus).then_some(r.io_cpu as u32),
        cpu_submit: r.cpu_submit,
        cpu_complete: r.cpu_complete,
        h2c_calls: r.h2c_calls,
        c2h_copies: r.c2h_copies,
        flags: r.flags,
        t: Boundaries {
            start: nz(r.t_start),
            setup: nz(r.t_setup),
            tx_start: nz(r.t_tx_start),
            cmd_sent: nz(r.t_cmd_sent),
            r2t_notify: nz(r.t_r2t_notify),
            r2t_start: nz(r.t_r2t_start),
            r2t_proc: nz(r.t_r2t_proc),
            h2c_start: nz(r.t_h2c_start),
            h2c_sent: nz(r.t_h2c_sent),
            rx_notify: nz(r.t_rx_notify),
            rx_start: nz(r.t_rx_start),
            c2h_first: nz(r.t_c2h_first),
            c2h_last: nz(r.t_c2h_last),
            rsp_notify: nz(r.t_rsp_notify),
            rsp_start: nz(r.t_rsp_start),
            rsp_parsed: nz(r.t_rsp_parsed),
            nvme: nz(r.t_nvme),
            blk: nz(r.t_blk),
        },
        busy_h2c_ns: r.busy_h2c,
        busy_c2h_ns: r.busy_c2h,
    }
}

fn parse_event(d: &[u8], cpus: u32) -> Option<DriverEvent> {
    let kind = pod::<u32>(d)?;
    match kind {
        4 => {
            let e = pod::<types::nvt_ev_prof>(d)?;
            Some(DriverEvent::Command(record_from(&e.rec, cpus)))
        }
        5 => {
            let e = pod::<types::nvt_ev_timeout>(d)?;
            Some(DriverEvent::Timeout(TimeoutEvent {
                t_ns: e.t,
                instance: e.inst,
                qid: e.qid,
                cid: e.cid,
                opcode: e.opcode,
                age_ns: nz(e.age_ns),
                sampled: e.sampled != 0,
            }))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failing_program_from_libbpf_log() {
        let log = "libbpf: prog 'kp_copy': BPF program load failed: Invalid argument\nlibbpf: prog 'kp_copy': -- BEGIN PROG LOAD LOG --";
        assert_eq!(failing_program(log).as_deref(), Some("kp_copy"));
        assert_eq!(failing_program("nothing here"), None);
    }

    #[test]
    fn every_flavour_has_the_required_probes() {
        for fl in [Flavour::Kprobe, Flavour::Fentry] {
            let ids: BTreeSet<&str> =
                PROGS.iter().filter(|d| d.required && d.flavour.is_none_or(|f| f == fl)).map(|d| d.id).collect();
            for id in ["P1", "P2", "P3", "D1", "D2a", "D7", "D9", "D10f"] {
                assert!(ids.contains(id), "{fl:?} lacks {id}");
            }
        }
    }

    #[test]
    fn record_conversion_maps_zero_to_missing() {
        // SAFETY: nvt_prof is plain #[repr(C)] integers; all-zero is valid.
        let mut r: types::nvt_prof = unsafe { std::mem::zeroed() };
        r.t_start = 10;
        r.t_blk = 50;
        r.io_cpu = -1;
        r.opcode = 2;
        let s = record_from(&r, 128);
        assert_eq!(s.t.start, Some(10));
        assert_eq!(s.t.cmd_sent, None);
        assert_eq!(s.io_cpu, None);
        assert_eq!(s.e2e_ns(), Some(40));
    }
}
