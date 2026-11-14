//! Level 1 collector: loads `bpf/core.bpf.c`, attaches its programs one by one,
//! and reads its maps (cumulative; never reset) and ring buffer.

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
    include!(concat!(env!("OUT_DIR"), "/core.skel.rs"));
}

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Link, MapCore, MapFlags, PrintLevel, RingBuffer, RingBufferBuilder};
use nvmetea_core::model::{BpfCounters, Histogram, LatMetric, NvmeSample, Op, QueueCounters, Topology};
use serde::Serialize;
use skel::types;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::mem::MaybeUninit;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::Instant;

/// Histograms per hardware queue in `qhist` (ops x metrics), as `NVT_HPQ` in `bpf/nvmetea.h`.
const HPQ: u32 = 5 * 4;

/// Map sizes and tunables, computed from the topology at load time.
#[derive(Debug, Clone, Serialize)]
pub struct CoreConfig {
    /// Slots of the in-flight array: each hardware queue's tag space takes
    /// `nr_tags` of them on first sight (see `bpf/core.bpf.c`).
    pub slots: u32,
    /// Hardware queues (indexes of the per-queue counter arrays).
    pub max_queues: u32,
    /// Queue indexes with per-queue histograms (≤ `max_queues`, bounded by
    /// `QHIST_BUDGET`). Queues beyond it are counted in `map_full_hist` and
    /// are missing from the histograms.
    pub hist_queues: u32,
    pub path_hist_entries: u32,
    /// 0 disables slow-command events.
    pub slow_ns: u64,
    pub slow_per_cpu_per_s: u32,
    pub lifecycle: bool,
}

/// Kernel memory for per-queue histograms (an array: preallocated). Each queue
/// index takes `HPQ` histograms of 232 buckets (37,120 B), so the budget covers
/// 903 queues.
pub const QHIST_BUDGET: u64 = 32 << 20;

fn clamp(v: u64, lo: u32, hi: u32) -> u32 {
    v.clamp(lo as u64, hi as u64) as u32
}

impl CoreConfig {
    pub fn from_topology(topo: &Topology) -> CoreConfig {
        let tcp: Vec<_> = topo.tcp_controllers().collect();
        // Tags of every hardware queue (+ the admin queue). Regions are keyed by
        // queue and reused across resets, reconnects and a recreated controller,
        // so headroom is only for controllers that appear later (or a queue
        // whose depth changes): +25 % and 4 Ki slots.
        let depth: u64 = tcp
            .iter()
            .map(|c| u64::from(c.io_queues().unwrap_or(64)) * u64::from(c.io_queue_depth().unwrap_or(128)) + 32)
            .sum();
        let queues: u64 = tcp.iter().map(|c| u64::from(c.queue_count.unwrap_or(65))).sum();
        let paths: u64 = tcp.iter().map(|c| (c.paths.len() + c.namespaces.len()) as u64).sum();
        let max_queues = clamp(queues + 64, 128, 16_384);
        let hist_bytes_per_queue = u64::from(HPQ) * 8 * 232;
        CoreConfig {
            // ≤ 512 Ki slots × 80 B = 40 MiB
            slots: clamp(depth + depth / 4 + 4096, 8192, 1 << 19),
            // +64 for controllers that appear later
            max_queues,
            hist_queues: max_queues.min((QHIST_BUDGET / hist_bytes_per_queue) as u32),
            path_hist_entries: clamp(2 * paths * 5, 256, 8192),
            slow_ns: 0,
            slow_per_cpu_per_s: 4,
            lifecycle: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProgramStatus {
    pub program: &'static str,
    pub attach: String,
    pub required: bool,
    pub attached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadReport {
    pub programs: Vec<ProgramStatus>,
    pub maps: Vec<(String, u32)>,
    pub load_ms: f64,
    pub attach_ms: f64,
}

#[derive(Debug)]
pub enum LoadError {
    /// EPERM/EACCES: privileges or lockdown.
    PermissionDenied(String),
    /// Open, CO-RE relocation or verifier failure; `log` holds libbpf's output.
    Load { error: String, log: String },
    /// A required program could not be attached.
    Attach { error: String, report: LoadReport },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::PermissionDenied(e) => {
                write!(f, "permission denied loading BPF ({e}); run as root or grant CAP_BPF,CAP_PERFMON")
            }
            LoadError::Load { error, .. } => write!(f, "BPF load failed: {error}"),
            LoadError::Attach { error, .. } => write!(f, "BPF attach failed: {error}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// A command that exceeded the slow threshold (one ring buffer record).
#[derive(Debug, Clone, Serialize)]
pub struct SlowCommand {
    pub seq: u64,
    pub inst: u32,
    pub qid: u16,
    pub cid: u16,
    pub op: Op,
    pub opcode: u8,
    pub nsid: u32,
    pub bytes: u32,
    pub dev: u32,
    pub submit_cpu: u16,
    pub complete_cpu: u32,
    pub retries: u8,
    pub nvme_status: u16,
    pub blk_error: i32,
    /// monotonic ns
    pub t_start_ns: Option<u64>,
    pub t_setup_ns: u64,
    pub t_nvme_done_ns: Option<u64>,
    pub t_blk_done_ns: u64,
}

impl SlowCommand {
    pub fn request_ns(&self) -> Option<u64> {
        self.t_start_ns.and_then(|s| self.t_blk_done_ns.checked_sub(s))
    }
    pub fn stage_a_ns(&self) -> Option<u64> {
        self.t_start_ns.and_then(|s| self.t_setup_ns.checked_sub(s))
    }
    pub fn command_ns(&self) -> Option<u64> {
        self.t_nvme_done_ns.and_then(|n| n.checked_sub(self.t_setup_ns))
    }
    pub fn stage_e2_ns(&self) -> Option<u64> {
        self.t_nvme_done_ns.and_then(|n| self.t_blk_done_ns.checked_sub(n))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StateChange {
    pub inst: u32,
    pub t_ns: u64,
    pub old_state: u32,
    pub new_state: u32,
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CoreEvent {
    Slow(SlowCommand),
    State(StateChange),
}

/// Kernel `enum nvme_ctrl_state` names (stable since 5.x; DELETING_NOIO 5.4+).
pub fn ctrl_state_name(v: u32) -> &'static str {
    match v {
        0 => "new",
        1 => "live",
        2 => "resetting",
        3 => "connecting",
        4 => "deleting",
        5 => "deleting (no IO)",
        6 => "dead",
        _ => "unknown",
    }
}

pub(crate) static LIBBPF_LOG: Mutex<String> = Mutex::new(String::new());

pub(crate) fn capture_libbpf(level: PrintLevel, msg: String) {
    if matches!(level, PrintLevel::Debug) {
        return;
    }
    if let Ok(mut l) = LIBBPF_LOG.lock() {
        if l.len() < 1 << 20 {
            l.push_str(&msg);
        }
    }
}

pub(crate) fn take_log() -> String {
    LIBBPF_LOG.lock().map(|mut l| std::mem::take(&mut *l)).unwrap_or_default()
}

pub(crate) fn is_perm(e: &libbpf_rs::Error) -> bool {
    let s = e.to_string();
    s.contains("Operation not permitted")
        || s.contains("Permission denied")
        || s.contains("EPERM")
        || s.contains("EACCES")
}

/// Plain-old-data conversion of a map value. The skeleton's `types` are
/// generated from the BPF object's BTF, so layouts cannot drift.
pub(crate) fn pod<T: Copy>(b: &[u8]) -> Option<T> {
    if b.len() < std::mem::size_of::<T>() {
        return None;
    }
    // SAFETY: T is a #[repr(C)] Copy type made only of integers; length checked.
    Some(unsafe { std::ptr::read_unaligned(b.as_ptr().cast::<T>()) })
}

pub struct CoreCollector {
    skel: skel::CoreSkel<'static>,
    _links: Vec<Link>,
    ringbuf: Option<RingBuffer<'static>>,
    pending: Rc<RefCell<Vec<CoreEvent>>>,
    pub report: LoadReport,
    pub config: CoreConfig,
    /// Why the optional lifecycle programs are not running, if they are not.
    pub lifecycle_error: Option<String>,
}

/// Add a queue's counters from one BPF record.
fn add_counters(c: &mut QueueCounters, q: &types::nvt_qstats) {
    let add = |a: &mut [u64], b: &[u64]| {
        for (x, y) in a.iter_mut().zip(b) {
            *x += *y;
        }
    };
    add(&mut c.dispatched, &q.dispatched);
    add(&mut c.bytes, &q.bytes);
    add(&mut c.completed, &q.completed);
    add(&mut c.nvme_errors, &q.nvme_errors);
    add(&mut c.cmd_lat_sum_ns, &q.cmd_lat_sum_ns);
    add(&mut c.cmd_lat_cnt, &q.cmd_lat_cnt);
    add(&mut c.req_lat_sum_ns, &q.req_lat_sum_ns);
    add(&mut c.req_lat_cnt, &q.req_lat_cnt);
    add(&mut c.status_type, &q.status_type);
    c.retries += q.retries;
    c.requeues += q.requeues;
    c.failovers += q.failovers;
    c.retried_completed += q.retried_completed;
    c.error_completed += q.error_completed;
}

pub(crate) fn last_lines(s: &str, n: usize) -> String {
    let v: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    v[v.len().saturating_sub(n)..].join(" | ")
}

impl CoreCollector {
    /// Load and attach. If the optional lifecycle programs fail to load (e.g. a
    /// CO-RE relocation they need is missing on this kernel), the object is
    /// loaded again without them, so the latency programs still run; the
    /// reason is kept in `lifecycle_error`.
    pub fn start(cfg: &CoreConfig) -> Result<CoreCollector, LoadError> {
        match Self::start_once(cfg) {
            Err(LoadError::Load { error, log }) if cfg.lifecycle => {
                let mut c2 = cfg.clone();
                c2.lifecycle = false;
                let mut c = Self::start_once(&c2)?;
                c.lifecycle_error = Some(format!("{error}: {}", last_lines(&log, 6)));
                Ok(c)
            }
            r => r,
        }
    }

    fn start_once(cfg: &CoreConfig) -> Result<CoreCollector, LoadError> {
        libbpf_rs::set_print(Some((PrintLevel::Warn, capture_libbpf)));
        let _ = take_log();
        let t0 = Instant::now();
        // The open object must outlive the skeleton; it lives for the process.
        let storage: &'static mut MaybeUninit<libbpf_rs::OpenObject> = Box::leak(Box::new(MaybeUninit::uninit()));
        let mut open = skel::CoreSkelBuilder::default()
            .open(storage)
            .map_err(|e| LoadError::Load { error: format!("open: {e}"), log: take_log() })?;
        let sizes = [
            (&mut open.maps.slots, cfg.slots),
            (&mut open.maps.qstats, cfg.max_queues),
            (&mut open.maps.qinfo, cfg.max_queues),
            (&mut open.maps.qhist, cfg.hist_queues.max(1) * HPQ),
            (&mut open.maps.phist, cfg.path_hist_entries),
        ];
        let mut maps = Vec::new();
        for (m, n) in sizes {
            m.set_max_entries(n).map_err(|e| LoadError::Load { error: format!("resize map: {e}"), log: take_log() })?;
            maps.push((m.name().to_string_lossy().into_owned(), n));
        }
        if !cfg.lifecycle {
            open.progs.nvt_state_enter.set_autoload(false);
            open.progs.nvt_state_exit.set_autoload(false);
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
            bss.slow_ns = cfg.slow_ns;
            bss.slow_per_cpu_per_s = cfg.slow_per_cpu_per_s;
            bss.epoch = 1;
            bss.nslots = cfg.slots;
            bss.next_slot = 0;
            bss.max_queues = cfg.max_queues;
            bss.next_queue = 0;
            bss.cache_epoch = 1;
            bss.armed = false;
        }

        let t1 = Instant::now();
        let mut links = Vec::new();
        let mut programs = Vec::new();
        {
            let p = &skel.progs;
            let mut attempt = |name: &'static str, attach: String, required: bool, r: libbpf_rs::Result<Link>| match r {
                Ok(l) => {
                    links.push(l);
                    programs.push(ProgramStatus { program: name, attach, required, attached: true, error: None });
                }
                Err(e) => programs.push(ProgramStatus {
                    program: name,
                    attach,
                    required,
                    attached: false,
                    error: Some(e.to_string()),
                }),
            };
            attempt(
                "nvt_setup_cmd",
                "raw_tp/nvme_setup_cmd".into(),
                true,
                p.nvt_setup_cmd.attach_raw_tracepoint("nvme_setup_cmd"),
            );
            attempt(
                "nvt_complete_rq",
                "raw_tp/nvme_complete_rq".into(),
                true,
                p.nvt_complete_rq.attach_raw_tracepoint("nvme_complete_rq"),
            );
            attempt(
                "nvt_blk_complete",
                "raw_tp/block_rq_complete".into(),
                true,
                p.nvt_blk_complete.attach_raw_tracepoint("block_rq_complete"),
            );
            attempt(
                "nvt_requeue",
                "raw_tp/block_rq_requeue".into(),
                false,
                p.nvt_requeue.attach_raw_tracepoint("block_rq_requeue"),
            );
            if cfg.lifecycle {
                attempt(
                    "nvt_state_enter",
                    "kprobe/nvme_change_ctrl_state".into(),
                    false,
                    p.nvt_state_enter.attach_kprobe(false, "nvme_change_ctrl_state"),
                );
                attempt(
                    "nvt_state_exit",
                    "kretprobe/nvme_change_ctrl_state".into(),
                    false,
                    p.nvt_state_exit.attach_kprobe(true, "nvme_change_ctrl_state"),
                );
            }
        }
        let attach_ms = t1.elapsed().as_secs_f64() * 1e3;
        let report = LoadReport { programs, maps, load_ms, attach_ms };
        if let Some(bad) = report.programs.iter().find(|p| p.required && !p.attached) {
            let error = format!("{} ({}): {}", bad.program, bad.attach, bad.error.clone().unwrap_or_default());
            drop(links);
            return Err(LoadError::Attach { error, report });
        }

        let pending: Rc<RefCell<Vec<CoreEvent>>> = Rc::new(RefCell::new(Vec::new()));
        let sink = pending.clone();
        let mut rb = RingBufferBuilder::new();
        let added = rb
            .add(&skel.maps.events, move |data: &[u8]| {
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

        // Arm last: every program is attached, so no command gets a partial record.
        if let Some(bss) = skel.maps.bss_data.as_deref_mut() {
            bss.armed = true;
        }
        Ok(CoreCollector { skel, _links: links, ringbuf, pending, report, config: cfg.clone(), lifecycle_error: None })
    }

    pub fn set_slow_ns(&mut self, ns: u64) {
        if let Some(bss) = self.skel.maps.bss_data.as_deref_mut() {
            bss.slow_ns = ns;
        }
        self.config.slow_ns = ns;
    }

    /// Read every map. Also advances the high-watermark epoch, so the next
    /// sample's `inflight_max` covers the interval since this one.
    pub fn sample(&mut self) -> NvmeSample {
        let taken = Instant::now();
        let epoch = self.skel.maps.bss_data.as_deref().map(|b| b.epoch).unwrap_or(0);
        let mut queues = BTreeMap::new();
        // per-queue arrays, indexed by the queue index assigned at registration;
        // a (controller, qid) re-registered with another depth has two indexes: summed
        let nq = self.skel.maps.bss_data.as_deref().map(|b| b.next_queue.min(b.max_queues)).unwrap_or(0);
        let hist_queues = self.config.hist_queues;
        let mut hists = BTreeMap::new();
        for i in 0..nq {
            let k = i.to_ne_bytes();
            let Ok(Some(v)) = self.skel.maps.qinfo.lookup(&k, MapFlags::ANY) else { continue };
            let Some(qi) = pod::<types::nvt_qinfo>(&v) else { continue };
            if qi.valid == 0 {
                continue;
            }
            let id = (u32::from(qi.inst), qi.qid);
            if let Ok(Some(v)) = self.skel.maps.qstats.lookup(&k, MapFlags::ANY) {
                if let Some(q) = pod::<types::nvt_qstats>(&v) {
                    let c = queues.entry(id).or_insert_with(QueueCounters::default);
                    add_counters(c, &q);
                    c.inflight += q.inflight;
                    if q.inflight_epoch >= c.inflight_epoch {
                        c.inflight_max = if q.inflight_epoch == c.inflight_epoch {
                            c.inflight_max.max(q.inflight_max)
                        } else {
                            q.inflight_max
                        };
                        c.inflight_epoch = q.inflight_epoch;
                    }
                }
            }
            for op in 0..5u32 {
                for metric in 0..4u32 {
                    if i >= hist_queues {
                        break; // beyond the histogram budget (counted in map_full_hist)
                    }
                    let hk = (i * HPQ + op * 4 + metric).to_ne_bytes();
                    let Ok(Some(v)) = self.skel.maps.qhist.lookup(&hk, MapFlags::ANY) else { continue };
                    let (Some(op), Some(metric), Some(h)) =
                        (Op::from_index(op as usize), LatMetric::from_index(metric as u8), pod::<types::nvt_hist>(&v))
                    else {
                        continue;
                    };
                    let h = Histogram::from_slice(&h.b);
                    if h.count() > 0 {
                        hists.entry((id.0, id.1, op, metric)).or_insert_with(Histogram::default).add(&h);
                    }
                }
            }
        }
        let mut path_hists = BTreeMap::new();
        let m = &self.skel.maps.phist;
        for k in m.keys() {
            let (Some(key), Ok(Some(v))) = (pod::<types::nvt_pkey>(&k), m.lookup(&k, MapFlags::ANY)) else { continue };
            let (Some(op), Some(h)) = (Op::from_index(key.op as usize), pod::<types::nvt_hist>(&v)) else { continue };
            path_hists.insert((key.dev, op), Histogram::from_slice(&h.b));
        }
        let mut c = [0u64; 16];
        if let Ok(Some(per_cpu)) = self.skel.maps.counters.lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY) {
            for v in per_cpu {
                if let Some(x) = pod::<types::nvt_counters>(&v) {
                    for (a, b) in c.iter_mut().zip(x.c.iter()) {
                        *a += *b;
                    }
                }
            }
        }
        if let Some(bss) = self.skel.maps.bss_data.as_deref_mut() {
            bss.epoch = epoch + 1;
        }
        if let Some(rb) = &self.ringbuf {
            let _ = rb.consume();
        }
        NvmeSample {
            taken,
            queues,
            hists,
            path_hists,
            counters: BpfCounters {
                dispatches_tcp: c[0],
                untracked_completions: c[1],
                cid_mismatches: c[2],
                stale_replaced: c[3],
                map_full_inflight: c[4],
                map_full_qstats: c[5],
                map_full_hist: c[6],
                events_lost: c[7],
                slow_suppressed: c[8],
                start_missing: c[9],
                order_violations: c[10],
                async_events: c[11],
            },
            epoch,
        }
    }

    /// Events received since the last call.
    /// Run-time statistics of this object's programs (meaningful while BPF
    /// run-time stats are enabled, see [`crate::bpfstats`]).
    pub fn prog_runs(&self) -> Vec<crate::bpfstats::ProgRun> {
        use libbpf_rs::skel::Skel;
        use std::os::fd::AsFd;
        let mut v = Vec::new();
        for prog in self.skel.object().progs() {
            if !prog.autoload() {
                continue;
            }
            if let Some((cnt, ns, miss)) = crate::bpfstats::prog_run(prog.as_fd()) {
                v.push(crate::bpfstats::ProgRun {
                    object: "core",
                    program: prog.name().to_string_lossy().into_owned(),
                    run_cnt: cnt,
                    run_time_ns: ns,
                    recursion_misses: miss,
                });
            }
        }
        v
    }

    pub fn drain_events(&mut self) -> Vec<CoreEvent> {
        if let Some(rb) = &self.ringbuf {
            let _ = rb.consume();
        }
        std::mem::take(&mut *self.pending.borrow_mut())
    }

    /// Current number of tracked in-flight entries (map pressure).
    /// Tracked commands in flight (sum of the per-queue counts).
    pub fn inflight_entries(&self) -> usize {
        let nq = self.skel.maps.bss_data.as_deref().map(|b| b.next_queue.min(b.max_queues)).unwrap_or(0);
        (0..nq)
            .filter_map(|i| self.skel.maps.qstats.lookup(&i.to_ne_bytes(), MapFlags::ANY).ok().flatten())
            .filter_map(|v| pod::<types::nvt_qstats>(&v))
            .map(|q| q.inflight.max(0) as usize)
            .sum()
    }

    /// Slots handed out to hardware-queue regions, and the capacity.
    pub fn slot_usage(&self) -> (u32, u32) {
        self.skel.maps.bss_data.as_deref().map(|b| (b.next_slot.min(b.nslots), b.nslots)).unwrap_or((0, 0))
    }

    /// Recompute the per-hardware-queue facts cached in the kernel (qid, path
    /// device). Call when a controller or namespace appears or goes away: a
    /// recreated queue may reuse the old one's addresses. Slot regions are
    /// keyed by tag set and stay valid.
    pub fn invalidate_caches(&mut self) {
        if let Some(bss) = self.skel.maps.bss_data.as_deref_mut() {
            bss.cache_epoch = bss.cache_epoch.wrapping_add(1);
        }
    }
}

fn parse_event(d: &[u8]) -> Option<CoreEvent> {
    let kind = u32::from_ne_bytes(d.get(0..4)?.try_into().ok()?);
    match kind {
        1 => {
            let e = pod::<types::nvt_ev_slow>(d)?;
            let r = e.rec;
            Some(CoreEvent::Slow(SlowCommand {
                seq: r.seq,
                inst: u32::from(r.inst),
                qid: r.qid,
                cid: r.cid,
                op: Op::from_index(r.op as usize).unwrap_or(Op::Other),
                opcode: r.opcode,
                nsid: r.nsid,
                bytes: r.bytes,
                dev: r.dev,
                submit_cpu: r.cpu,
                complete_cpu: e.cpu,
                retries: r.retries,
                nvme_status: r.status,
                blk_error: e.blk_error,
                t_start_ns: (r.t_start != 0).then_some(r.t_start),
                t_setup_ns: r.t_setup,
                t_nvme_done_ns: (r.t_nvme != 0).then_some(r.t_nvme),
                t_blk_done_ns: e.t_blk,
            }))
        }
        2 => {
            let e = pod::<types::nvt_ev_state>(d)?;
            Some(CoreEvent::State(StateChange {
                inst: e.inst,
                t_ns: e.t,
                old_state: e.old_state,
                new_state: e.new_state,
                accepted: e.accepted != 0,
            }))
        }
        _ => None,
    }
}

const _: () = assert!(std::mem::size_of::<types::nvt_inflight>() == 72);
const _: () = assert!(std::mem::size_of::<types::nvt_ev_slow>() == 96);
const _: () = assert!(std::mem::size_of::<types::nvt_ev_state>() == 32);

#[cfg(test)]
mod tests {
    use nvmetea_core::model::nvme::{HIST_USED, bucket_index};

    unsafe extern "C" {
        fn nvt_bucket_native(v: u64) -> u32;
    }

    fn native(v: u64) -> usize {
        // SAFETY: pure function compiled from bpf/hist.bpf.h.
        unsafe { nvt_bucket_native(v) as usize }
    }

    #[test]
    fn bpf_bucket_function_equals_rust_mirror() {
        let mut edges = vec![0u64, 1, 255, 256, 257, u64::MAX, (1 << 36) - 1, 1 << 36];
        for k in 8..37 {
            for s in 0..9u64 {
                let v = (1u64 << k) + s * (1u64 << (k - 3));
                edges.extend([v.saturating_sub(1), v, v + 1]);
            }
        }
        for v in edges {
            assert_eq!(native(v), bucket_index(v), "value {v}");
        }
        // xorshift over the whole range
        let mut x: u64 = 0x9e3779b97f4a7c15;
        for _ in 0..1_000_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let v = x >> (x % 40); // spread across magnitudes
            let b = native(v);
            assert!(b < HIST_USED);
            assert_eq!(b, bucket_index(v), "value {v}");
        }
    }

    fn tcp_hosts(controllers: u32, queue_count: u32, sqsize: u32) -> nvmetea_core::model::Topology {
        use nvmetea_core::model::{Controller, CtrlState, Topology};
        let c = |i: u32| Controller {
            name: format!("nvme{i}"),
            instance: i,
            subsystem: None,
            subsysnqn: None,
            transport: Some("tcp".into()),
            address: None,
            state: CtrlState::Live,
            cntlid: None,
            queue_count: Some(queue_count),
            sqsize: Some(sqsize),
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
            paths: vec![],
            namespaces: vec![],
            generation: Some(1),
            epoch: Some(1),
        };
        Topology { controllers: (0..controllers).map(c).collect(), ..Default::default() }
    }

    /// Kernel memory of the sized maps: slots (80 B) and per-queue histograms
    /// stay bounded on very large hosts (architecture §7.2: < 64 MiB).
    #[test]
    fn map_sizes_are_bounded() {
        let mib = |c: &super::CoreConfig| {
            (u64::from(c.slots) * 80 + u64::from(c.hist_queues) * u64::from(super::HPQ) * 8 * 232) >> 20
        };
        // the development host: 6 controllers x 8 I/O queues, depth 32
        let dev = super::CoreConfig::from_topology(&tcp_hosts(6, 9, 31));
        assert_eq!((dev.slots, dev.max_queues, dev.hist_queues), (8192, 128, 128));
        assert!(mib(&dev) < 8, "{} MiB", mib(&dev));
        // the userspace budget host: 64 controllers x 32 I/O queues, depth 128
        let big = super::CoreConfig::from_topology(&tcp_hosts(64, 33, 127));
        assert_eq!(big.max_queues, 64 * 33 + 64);
        assert_eq!(big.hist_queues, 903);
        assert!(big.slots as u64 >= 64 * (32 * 128 + 32), "every queue gets a region");
        assert!(mib(&big) <= 64, "{} MiB", mib(&big));
        // extreme: capped
        let huge = super::CoreConfig::from_topology(&tcp_hosts(512, 129, 1023));
        assert_eq!(huge.slots, 1 << 19);
        assert!(mib(&huge) <= 72, "{} MiB", mib(&huge));
    }
}
