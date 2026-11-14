//! Prometheus text exposition (format 0.0.4) of one snapshot
//! (`docs/architecture.md` §10).
//!
//! Rules:
//! - Rendering never triggers collection; it formats what the sampler
//!   published.
//! - A metric whose source is unavailable is **absent**, never 0. Its absence is
//!   explained by `nvmetea_capability_status` / `nvmetea_collector_up`.
//! - BPF counters are cumulative in the kernel and never reset, so they are
//!   exported as Prometheus counters directly.
//! - Histogram buckets are a fixed subset of the internal log-linear edges (two
//!   per octave, 2^10 ns ≈ 1 µs … 2^36 ns ≈ 68.7 s). Every exported bucket is
//!   an exact sum of measured buckets.
//! - Cardinality is bounded: at most `max_controllers` controllers (others
//!   dropped, counted) and `max_queues` queues per controller (the rest are
//!   aggregated into `qid="other"`, counted). There are no ids, pointers,
//!   cookies or ports as labels.

use nvmetea_core::model::{
    DiskCounters, Histogram, LatMetric, NvmeSample, Op, QueueSocket, SockEventCounters, TcpSocket, Topology,
    nvme::bucket_bounds,
};
use std::collections::BTreeMap;
use std::fmt::Write;

/// State of one collector.
#[derive(Debug, Clone)]
pub struct CollectorStatus {
    pub name: &'static str,
    pub up: bool,
}

/// One capability of the plan with its status and the reason when not usable.
#[derive(Debug, Clone)]
pub struct Capability {
    pub name: &'static str,
    /// "active", "disabled", "unavailable", "degraded".
    pub status: String,
    /// Reason code (`nvmetea_core::Reason::as_str`), "" when none.
    pub reason: String,
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessStats {
    pub cpu_seconds: f64,
    pub resident_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_controllers: usize,
    pub max_queues: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_controllers: 64, max_queues: 128 }
    }
}

/// Everything one exposition is rendered from.
pub struct PromInput<'a> {
    pub version: &'a str,
    pub topology: &'a Topology,
    pub disk: &'a BTreeMap<String, DiskCounters>,
    /// Level 1 counters and histograms (`None`: BPF not running).
    pub nvme: Option<&'a NvmeSample>,
    pub sockets: &'a [TcpSocket],
    /// Kernel-identified queue sockets (T1); `None`: not available.
    pub queue_sockets: Option<&'a [QueueSocket]>,
    /// Cumulative transport events by cookie (T3–T7); `None`: not running.
    pub sock_events: Option<&'a BTreeMap<u64, SockEventCounters>>,
    pub collectors: &'a [CollectorStatus],
    pub capabilities: &'a [Capability],
    /// Cumulative controller state transitions seen by this process: (controller, to_state).
    pub transitions: &'a BTreeMap<(String, String), u64>,
    pub process: Option<ProcessStats>,
    pub limits: Limits,
}

#[derive(Debug, Clone, Default)]
pub struct Rendered {
    pub text: String,
    /// Series dropped or aggregated by the cardinality limits (cumulative is
    /// the caller's business; this is for this rendering).
    pub series_dropped: u64,
}

/// One metric family.
struct Family {
    name: &'static str,
    kind: &'static str,
    help: &'static str,
    lines: Vec<String>,
}

impl Family {
    fn new(name: &'static str, kind: &'static str, help: &'static str) -> Family {
        Family { name, kind, help, lines: Vec::new() }
    }
    fn sample(&mut self, labels: &[(&str, &str)], value: f64) {
        self.sample_named(self.name, labels, value);
    }
    fn sample_named(&mut self, name: &str, labels: &[(&str, &str)], value: f64) {
        let mut l = String::from(name);
        if !labels.is_empty() {
            l.push('{');
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    l.push(',');
                }
                let _ = write!(l, "{k}=\"{}\"", escape(v));
            }
            l.push('}');
        }
        let _ = write!(l, " {}", num(value));
        self.lines.push(l);
    }
    fn histogram(&mut self, labels: &[(&str, &str)], h: &Histogram, sum_ns: Option<u64>) {
        let mut cum = 0u64;
        let mut idx = 0usize;
        let n = h.buckets.len();
        let bucket = format!("{}_bucket", self.name);
        for edge in edges() {
            while idx < n {
                match bucket_bounds(idx).1 {
                    Some(hi) if hi <= edge => {
                        cum += h.buckets[idx];
                        idx += 1;
                    }
                    _ => break,
                }
            }
            let le = num(edge as f64 / 1e9);
            let mut lb: Vec<(&str, &str)> = labels.to_vec();
            lb.push(("le", &le));
            self.sample_named(&bucket, &lb, cum as f64);
        }
        let total = h.count();
        let mut lb: Vec<(&str, &str)> = labels.to_vec();
        lb.push(("le", "+Inf"));
        self.sample_named(&bucket, &lb, total as f64);
        if let Some(s) = sum_ns {
            self.sample_named(&format!("{}_sum", self.name), labels, s as f64 / 1e9);
        }
        self.sample_named(&format!("{}_count", self.name), labels, total as f64);
    }
}

/// Exported `le` edges in ns: 2^k and 1.5·2^k for k = 10..35, then 2^36.
pub fn edges() -> Vec<u64> {
    let mut v = Vec::new();
    for k in 10..36 {
        v.push(1u64 << k);
        v.push((1u64 << k) + (1u64 << (k - 1)));
    }
    v.push(1u64 << 36);
    v
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn num(v: f64) -> String {
    if v.is_nan() {
        "NaN".into()
    } else if v.is_infinite() {
        if v > 0.0 { "+Inf".into() } else { "-Inf".into() }
    } else if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

const OPS: [Op; 5] = [Op::Read, Op::Write, Op::Flush, Op::Other, Op::Admin];

pub fn render(inp: &PromInput) -> Rendered {
    let mut fams: Vec<Family> = Vec::new();
    let mut dropped = 0u64;
    let topo = inp.topology;

    // controllers within the cardinality limit (NVMe/TCP first, by instance)
    let mut ctrls: Vec<&nvmetea_core::model::Controller> = topo.controllers.iter().collect();
    ctrls.sort_by_key(|c| (!c.is_tcp(), c.instance));
    if ctrls.len() > inp.limits.max_controllers {
        dropped += (ctrls.len() - inp.limits.max_controllers) as u64;
        ctrls.truncate(inp.limits.max_controllers);
    }
    let allowed: BTreeMap<u32, &str> = ctrls.iter().map(|c| (c.instance, c.name.as_str())).collect();

    let mut f = Family::new("nvmetea_build_info", "gauge", "nvmetea build.");
    f.sample(&[("version", inp.version)], 1.0);
    fams.push(f);

    let mut f = Family::new("nvmetea_collector_up", "gauge", "1 when a collector is producing data.");
    for c in inp.collectors {
        f.sample(&[("collector", c.name)], if c.up { 1.0 } else { 0.0 });
    }
    fams.push(f);

    let mut f = Family::new(
        "nvmetea_capability_status",
        "gauge",
        "Capability status (1 = this status). Metrics of an unavailable capability are absent, not zero.",
    );
    for c in inp.capabilities {
        f.sample(&[("capability", c.name), ("status", &c.status), ("reason", &c.reason)], 1.0);
    }
    fams.push(f);

    // ---- topology
    let mut f = Family::new("nvmetea_subsystem_info", "gauge", "NVMe subsystem.");
    for s in &topo.subsystems {
        f.sample(
            &[
                ("subsystem", &s.name),
                ("subsystem_nqn", s.nqn.as_deref().unwrap_or("")),
                ("iopolicy", s.iopolicy.as_deref().unwrap_or("")),
            ],
            1.0,
        );
    }
    fams.push(f);

    let mut info = Family::new("nvmetea_controller_info", "gauge", "NVMe controller and its fabric address.");
    let mut state = Family::new("nvmetea_controller_state", "gauge", "Controller state (state set: 1 = current).");
    let mut gen_f = Family::new(
        "nvmetea_controller_generation",
        "gauge",
        "Controller object generation (changes when the controller is deleted and recreated).",
    );
    let mut epoch_f = Family::new(
        "nvmetea_controller_epoch",
        "gauge",
        "Connection epoch (increments each time the controller enters live).",
    );
    let mut queues_f = Family::new("nvmetea_controller_queues", "gauge", "Queues of a controller by type.");
    let mut depth_f = Family::new("nvmetea_controller_queue_depth", "gauge", "I/O queue depth (sqsize + 1).");
    const STATES: [&str; 7] = ["new", "live", "resetting", "connecting", "deleting", "deleting (no IO)", "dead"];
    for c in &ctrls {
        let a = c.address.as_ref();
        info.sample(
            &[
                ("controller", &c.name),
                ("subsystem_nqn", c.subsysnqn.as_deref().unwrap_or("")),
                ("transport", c.transport.as_deref().unwrap_or("")),
                ("traddr", a.and_then(|a| a.traddr.as_deref()).unwrap_or("")),
                ("trsvcid", a.and_then(|a| a.trsvcid.as_deref()).unwrap_or("")),
                ("host_traddr", a.and_then(|a| a.host_traddr.as_deref().or(a.src_addr.as_deref())).unwrap_or("")),
            ],
            1.0,
        );
        let cur = c.state.as_str();
        for s in STATES {
            state.sample(&[("controller", &c.name), ("state", s)], if s == cur { 1.0 } else { 0.0 });
        }
        if !STATES.contains(&cur) {
            state.sample(&[("controller", &c.name), ("state", cur)], 1.0);
        }
        if let Some(g) = c.generation {
            gen_f.sample(&[("controller", &c.name)], g as f64);
        }
        if let Some(e) = c.epoch {
            epoch_f.sample(&[("controller", &c.name)], e as f64);
        }
        if let Some(q) = c.io_queues() {
            queues_f.sample(&[("controller", &c.name), ("type", "io")], f64::from(q));
        }
        if let Some(d) = c.io_queue_depth() {
            depth_f.sample(&[("controller", &c.name)], f64::from(d));
        }
    }
    fams.extend([info, state, gen_f, epoch_f, queues_f, depth_f]);

    let mut f = Family::new(
        "nvmetea_controller_state_transitions_total",
        "counter",
        "Controller state transitions seen since nvmetea started.",
    );
    for ((c, to), n) in inp.transitions {
        f.sample(&[("controller", c), ("to_state", to)], *n as f64);
    }
    fams.push(f);

    let mut ns_f = Family::new("nvmetea_namespace_info", "gauge", "Namespace (multipath head or direct).");
    let mut path_f = Family::new("nvmetea_path_info", "gauge", "Path of a namespace through a controller.");
    let mut usable_f = Family::new(
        "nvmetea_path_usable",
        "gauge",
        "1 when the path's controller is live and ANA (if any) allows I/O.",
    );
    let mut ana_f = Family::new("nvmetea_path_ana_state", "gauge", "ANA state of a path (state set), when reported.");
    for n in &topo.namespaces {
        let nsid = n.nsid.map(|v| v.to_string()).unwrap_or_default();
        let nqn = n.subsystem.as_deref().and_then(|s| topo.subsystem(s)).and_then(|s| s.nqn.as_deref()).unwrap_or("");
        ns_f.sample(
            &[
                ("namespace", &n.name),
                ("subsystem_nqn", nqn),
                ("nsid", &nsid),
                ("wwid", n.wwid.as_deref().unwrap_or("")),
            ],
            1.0,
        );
        for p in &n.paths {
            path_f.sample(&[("path", &p.name), ("namespace", &n.name), ("controller", &p.controller)], 1.0);
            let live = topo.controller(&p.controller).is_some_and(|c| c.state.is_live());
            let ana_ok = p.ana_state.as_deref().is_none_or(|a| a == "optimized" || a == "non-optimized");
            usable_f.sample(&[("path", &p.name)], if live && ana_ok { 1.0 } else { 0.0 });
            if let Some(a) = &p.ana_state {
                ana_f.sample(&[("path", &p.name), ("state", a)], 1.0);
            }
        }
    }
    fams.extend([ns_f, path_f, usable_f, ana_f]);

    // ---- block layer (diskstats) for NVMe/TCP namespaces and paths
    let mut devs: Vec<&str> = Vec::new();
    for n in &topo.namespaces {
        let tcp = n.paths.iter().any(|p| topo.controller(&p.controller).is_some_and(|c| c.is_tcp()))
            || n.controller.as_deref().and_then(|c| topo.controller(c)).is_some_and(|c| c.is_tcp());
        if !tcp {
            continue;
        }
        devs.push(&n.name);
        devs.extend(n.paths.iter().map(|p| p.name.as_str()));
    }
    let mut ios = Family::new("nvmetea_block_ios_total", "counter", "Completed block I/Os (/proc/diskstats).");
    let mut bytes = Family::new("nvmetea_block_bytes_total", "counter", "Bytes of completed block I/O.");
    let mut time =
        Family::new("nvmetea_block_time_seconds_total", "counter", "Time spent on block I/O (diskstats ms).");
    let mut infl = Family::new("nvmetea_block_inflight", "gauge", "Block I/Os in flight (diskstats).");
    for d in devs {
        let Some(c) = inp.disk.get(d) else { continue };
        for (op, n, sect, ms) in
            [("read", c.reads, c.read_sectors, c.read_ms), ("write", c.writes, c.write_sectors, c.write_ms)]
        {
            ios.sample(&[("device", d), ("op", op)], n as f64);
            bytes.sample(&[("device", d), ("op", op)], (sect * 512) as f64);
            time.sample(&[("device", d), ("op", op)], ms as f64 / 1e3);
        }
        infl.sample(&[("device", d)], c.in_flight as f64);
    }
    fams.extend([ios, bytes, time, infl]);

    // ---- Level 1
    if let Some(nv) = inp.nvme {
        render_nvme(nv, &allowed, inp.limits, &mut fams, &mut dropped);
    }

    // ---- Level 3 queue sockets + sock_diag
    if let Some(qs) = inp.queue_sockets {
        render_tcp(inp, qs, &allowed, inp.limits, &mut fams, &mut dropped);
    }

    if let Some(p) = inp.process {
        let mut f = Family::new("nvmetea_process_cpu_seconds_total", "counter", "CPU time of the nvmetea process.");
        f.sample(&[], p.cpu_seconds);
        fams.push(f);
        let mut f = Family::new("nvmetea_process_resident_memory_bytes", "gauge", "Resident memory of nvmetea.");
        f.sample(&[], p.resident_bytes as f64);
        fams.push(f);
    }
    let mut f = Family::new(
        "nvmetea_prom_series_dropped",
        "gauge",
        "Series dropped or aggregated into qid=\"other\" by the cardinality limits in this exposition.",
    );
    f.sample(&[], dropped as f64);
    fams.push(f);

    let mut text = String::new();
    for f in fams.iter().filter(|f| !f.lines.is_empty()) {
        let _ = writeln!(text, "# HELP {} {}", f.name, f.help);
        let _ = writeln!(text, "# TYPE {} {}", f.name, f.kind);
        for l in &f.lines {
            text.push_str(l);
            text.push('\n');
        }
    }
    Rendered { text, series_dropped: dropped }
}

/// The age line, added at scrape time.
pub fn age_line(age_s: f64) -> String {
    format!(
        "# HELP nvmetea_snapshot_age_seconds Age of the snapshot this scrape was rendered from.\n\
         # TYPE nvmetea_snapshot_age_seconds gauge\nnvmetea_snapshot_age_seconds {}\n",
        num((age_s * 1000.0).round() / 1000.0)
    )
}

fn qlabel(qid: u16, rank: usize, limits: Limits) -> String {
    if rank < limits.max_queues { qid.to_string() } else { "other".into() }
}

fn render_nvme(
    nv: &NvmeSample,
    allowed: &BTreeMap<u32, &str>,
    limits: Limits,
    fams: &mut Vec<Family>,
    dropped: &mut u64,
) {
    let mut cmds =
        Family::new("nvmetea_nvme_commands_total", "counter", "NVMe commands dispatched (incl. retries), by op.");
    let mut cbytes = Family::new("nvmetea_nvme_bytes_total", "counter", "Bytes of first dispatches, by op.");
    let mut errs =
        Family::new("nvmetea_nvme_errors_total", "counter", "NVMe completions with a non-zero status, by op.");
    let mut sct = Family::new(
        "nvmetea_nvme_error_status_total",
        "counter",
        "NVMe error completions by status code type (0 generic, 1 command specific, 2 media, 3 path, 7 vendor).",
    );
    let mut retr =
        Family::new("nvmetea_nvme_retries_total", "counter", "Commands dispatched again after a retryable status.");
    let mut fo = Family::new("nvmetea_nvme_failovers_total", "counter", "Requests failed over to another path.");
    let mut req_q = Family::new("nvmetea_nvme_requeues_total", "counter", "Requests requeued by blk-mq.");
    let mut cmd_h = Family::new(
        "nvmetea_nvme_command_latency_seconds",
        "histogram",
        "nvme_setup_cmd -> nvme_complete_rq per dispatch (retried/failed-over excluded).",
    );
    let mut req_h = Family::new(
        "nvmetea_request_latency_seconds",
        "histogram",
        "Block request start -> block completion on the path (retried/failed-over excluded).",
    );
    let mut q_cmds = Family::new("nvmetea_queue_commands_total", "counter", "Commands dispatched per queue and op.");
    let mut q_bytes = Family::new("nvmetea_queue_bytes_total", "counter", "Bytes dispatched per queue and op.");
    let mut q_infl = Family::new("nvmetea_queue_inflight", "gauge", "Commands in flight on a queue.");
    let mut q_max = Family::new(
        "nvmetea_queue_inflight_max",
        "gauge",
        "Largest in-flight count on a queue between the last two samples.",
    );
    // A summary without quantiles: _sum and _count only (per-queue histograms
    // are not exported; see docs/metrics.md).
    let mut q_lat = Family::new(
        "nvmetea_queue_latency_seconds",
        "summary",
        "Request latency per queue and op (sum and count; mean = rate(_sum) / rate(_count)).",
    );

    // per controller: sum queues
    struct Acc {
        disp: [u64; 5],
        bytes: [u64; 5],
        errs: [u64; 5],
        sct: [u64; 8],
        retries: u64,
        failovers: u64,
        requeues: u64,
        cmd_sum: [u64; 5],
        req_sum: [u64; 5],
    }
    let mut acc: BTreeMap<u32, Acc> = BTreeMap::new();
    let mut ranks: BTreeMap<u32, usize> = BTreeMap::new();
    let mut other: BTreeMap<(u32, usize), (u64, u64, i64)> = BTreeMap::new();
    for ((inst, qid), q) in &nv.queues {
        let Some(&cname) = allowed.get(inst) else {
            *dropped += 1;
            continue;
        };
        let a = acc.entry(*inst).or_insert(Acc {
            disp: [0; 5],
            bytes: [0; 5],
            errs: [0; 5],
            sct: [0; 8],
            retries: 0,
            failovers: 0,
            requeues: 0,
            cmd_sum: [0; 5],
            req_sum: [0; 5],
        });
        for i in 0..5 {
            a.disp[i] += q.dispatched[i];
            a.bytes[i] += q.bytes[i];
            a.errs[i] += q.nvme_errors[i];
            a.cmd_sum[i] += q.cmd_lat_sum_ns[i];
            a.req_sum[i] += q.req_lat_sum_ns[i];
        }
        for i in 0..8 {
            a.sct[i] += q.status_type[i];
        }
        a.retries += q.retries;
        a.failovers += q.failovers;
        a.requeues += q.requeues;
        let rank = {
            let r = ranks.entry(*inst).or_insert(0);
            *r += 1;
            *r - 1
        };
        let ql = qlabel(*qid, rank, limits);
        if ql == "other" {
            *dropped += 1;
            for (i, op) in OPS.iter().enumerate() {
                let e = other.entry((*inst, i)).or_default();
                e.0 += q.dispatched[i];
                e.1 += q.bytes[i];
                let _ = op;
            }
            other.entry((*inst, 99)).or_default().2 += q.inflight;
            continue;
        }
        for (i, op) in OPS.iter().enumerate() {
            if q.dispatched[i] == 0 && q.req_lat_cnt[i] == 0 {
                continue;
            }
            let l = [("controller", cname), ("qid", ql.as_str()), ("op", op.as_str())];
            q_cmds.sample(&l, q.dispatched[i] as f64);
            q_bytes.sample(&l, q.bytes[i] as f64);
            if *qid != 0 {
                q_lat.sample_named("nvmetea_queue_latency_seconds_sum", &l, q.req_lat_sum_ns[i] as f64 / 1e9);
                q_lat.sample_named("nvmetea_queue_latency_seconds_count", &l, q.req_lat_cnt[i] as f64);
            }
        }
        let l = [("controller", cname), ("qid", ql.as_str())];
        q_infl.sample(&l, q.inflight.max(0) as f64);
        if q.inflight_epoch == nv.epoch {
            q_max.sample(&l, q.inflight_max as f64);
        }
    }
    for ((inst, i), (d, b, inf)) in &other {
        let Some(&cname) = allowed.get(inst) else { continue };
        if *i == 99 {
            q_infl.sample(&[("controller", cname), ("qid", "other")], (*inf).max(0) as f64);
        } else if *d > 0 {
            let l = [("controller", cname), ("qid", "other"), ("op", OPS[*i].as_str())];
            q_cmds.sample(&l, *d as f64);
            q_bytes.sample(&l, *b as f64);
        }
    }
    for (inst, a) in &acc {
        let Some(&cname) = allowed.get(inst) else { continue };
        for (i, op) in OPS.iter().enumerate() {
            if a.disp[i] == 0 {
                continue;
            }
            let l = [("controller", cname), ("op", op.as_str())];
            cmds.sample(&l, a.disp[i] as f64);
            cbytes.sample(&l, a.bytes[i] as f64);
            errs.sample(&l, a.errs[i] as f64);
        }
        for (i, n) in a.sct.iter().enumerate() {
            if *n > 0 {
                sct.sample(&[("controller", cname), ("status_type", &i.to_string())], *n as f64);
            }
        }
        let l = [("controller", cname)];
        retr.sample(&l, a.retries as f64);
        fo.sample(&l, a.failovers as f64);
        req_q.sample(&l, a.requeues as f64);
    }
    // histograms per (controller, op): sum the queues' histograms
    let mut hsum: BTreeMap<(u32, Op, LatMetric), Histogram> = BTreeMap::new();
    for ((inst, _q, op, m), h) in &nv.hists {
        if !allowed.contains_key(inst) || !matches!(m, LatMetric::Command | LatMetric::Request) {
            continue;
        }
        hsum.entry((*inst, *op, *m)).or_default().add(h);
    }
    for ((inst, op, m), h) in &hsum {
        if h.count() == 0 {
            continue;
        }
        let cname = allowed[inst];
        let l = [("controller", cname), ("op", op.as_str())];
        let sum =
            acc.get(inst).map(|a| if *m == LatMetric::Command { a.cmd_sum[op.index()] } else { a.req_sum[op.index()] });
        match m {
            LatMetric::Command => cmd_h.histogram(&l, h, sum),
            _ => req_h.histogram(&l, h, sum),
        }
    }
    let c = &nv.counters;
    let mut lost = Family::new("nvmetea_bpf_events_lost_total", "counter", "BPF ring-buffer events not delivered.");
    lost.sample(&[("kind", "ringbuf")], c.events_lost as f64);
    lost.sample(&[("kind", "slow_suppressed")], c.slow_suppressed as f64);
    let mut full =
        Family::new("nvmetea_bpf_map_full_total", "counter", "BPF map insertions that failed for lack of space.");
    full.sample(&[("map", "inflight")], c.map_full_inflight as f64);
    full.sample(&[("map", "qstats")], c.map_full_qstats as f64);
    full.sample(&[("map", "hist")], c.map_full_hist as f64);
    let mut rec = Family::new(
        "nvmetea_records_total",
        "counter",
        "Command records by outcome (untracked: completed but not seen dispatched).",
    );
    rec.sample(&[("outcome", "dispatched")], c.dispatches_tcp as f64);
    rec.sample(&[("outcome", "untracked")], c.untracked_completions as f64);
    rec.sample(&[("outcome", "mismatch")], c.cid_mismatches as f64);
    rec.sample(&[("outcome", "stale_replaced")], c.stale_replaced as f64);
    rec.sample(&[("outcome", "order_violation")], c.order_violations as f64);
    rec.sample(&[("outcome", "start_missing")], c.start_missing as f64);
    fams.extend([cmds, cbytes, errs, sct, retr, fo, req_q, cmd_h, req_h, q_cmds, q_bytes, q_infl, q_max, q_lat]);
    fams.extend([lost, full, rec]);
}

fn render_tcp(
    inp: &PromInput,
    qs: &[QueueSocket],
    allowed: &BTreeMap<u32, &str>,
    limits: Limits,
    fams: &mut Vec<Family>,
    dropped: &mut u64,
) {
    let by_cookie: BTreeMap<u64, &TcpSocket> = inp.sockets.iter().filter_map(|s| Some((s.cookie?, s))).collect();
    let mut f_cpu = Family::new("nvmetea_queue_io_cpu", "gauge", "CPU of the queue's worker (-1 = unbound).");
    let mut rtt = Family::new("nvmetea_tcp_rtt_seconds", "gauge", "Smoothed RTT of the queue's connection.");
    let mut rttvar =
        Family::new("nvmetea_tcp_rtt_variance_seconds", "gauge", "RTT variance of the queue's connection.");
    let mut minrtt = Family::new("nvmetea_tcp_min_rtt_seconds", "gauge", "Minimum RTT of the queue's connection.");
    let mut rto = Family::new("nvmetea_tcp_rto_seconds", "gauge", "Retransmission timeout of the queue's connection.");
    let mut retr = Family::new(
        "nvmetea_tcp_retransmitted_segments_total",
        "counter",
        "Retransmitted segments (tcp_info; resets when the connection is replaced).",
    );
    let mut rbytes = Family::new("nvmetea_tcp_retransmitted_bytes_total", "counter", "Retransmitted bytes (tcp_info).");
    let mut sent = Family::new("nvmetea_tcp_bytes_sent_total", "counter", "Bytes sent on the queue's connection.");
    let mut recv =
        Family::new("nvmetea_tcp_bytes_received_total", "counter", "Bytes received on the queue's connection.");
    let mut unacked = Family::new("nvmetea_tcp_unacked_segments", "gauge", "Unacknowledged segments.");
    let mut lost = Family::new("nvmetea_tcp_lost_segments", "gauge", "Segments considered lost.");
    let mut cwnd = Family::new("nvmetea_tcp_cwnd_segments", "gauge", "Congestion window.");
    let mut ssth = Family::new("nvmetea_tcp_ssthresh_segments", "gauge", "Slow-start threshold.");
    let mut sndq = Family::new("nvmetea_tcp_send_queue_bytes", "gauge", "Send queue (sock_diag).");
    let mut rcvq = Family::new("nvmetea_tcp_receive_queue_bytes", "gauge", "Receive queue (sock_diag).");
    let mut notsent = Family::new("nvmetea_tcp_notsent_bytes", "gauge", "Bytes queued but not yet sent.");
    let mut limited = Family::new(
        "nvmetea_tcp_limited_seconds_total",
        "counter",
        "Time the connection was busy or limited by the receive window or send buffer (tcp_info).",
    );
    let mut ev_retr = Family::new(
        "nvmetea_tcp_retransmit_events_total",
        "counter",
        "Retransmitted skbs on the queue's connection (BPF tcp_retransmit_skb).",
    );
    let mut ev_cong = Family::new(
        "nvmetea_tcp_congestion_events_total",
        "counter",
        "Entries into a congestion state (BPF tcp_cong_state_set).",
    );
    let mut ev_rst = Family::new("nvmetea_tcp_resets_total", "counter", "RSTs sent or received (BPF).");
    let mut ev_err =
        Family::new("nvmetea_tcp_socket_errors_total", "counter", "Socket errors (BPF inet_sk_error_report).");
    let mut ranks: BTreeMap<u32, usize> = BTreeMap::new();
    let mut sorted: Vec<&QueueSocket> = qs.iter().collect();
    sorted.sort_by_key(|q| (q.instance, q.qid));
    for q in sorted {
        let Some(&cname) = allowed.get(&q.instance) else {
            *dropped += 1;
            continue;
        };
        let rank = {
            let r = ranks.entry(q.instance).or_insert(0);
            *r += 1;
            *r - 1
        };
        if rank >= limits.max_queues {
            *dropped += 1; // per-connection gauges are not aggregatable into "other"
            continue;
        }
        let qid = q.qid.to_string();
        let l = [("controller", cname), ("qid", qid.as_str())];
        f_cpu.sample(&l, q.io_cpu.map(f64::from).unwrap_or(-1.0));
        if let Some(ev) = inp.sock_events.and_then(|m| m.get(&q.cookie)) {
            ev_retr.sample(&l, ev.retrans as f64);
            ev_cong.sample(&[("controller", cname), ("qid", qid.as_str()), ("state", "loss")], ev.loss_entries as f64);
            ev_cong.sample(
                &[("controller", cname), ("qid", qid.as_str()), ("state", "recovery")],
                ev.recovery_entries as f64,
            );
            ev_cong.sample(&[("controller", cname), ("qid", qid.as_str()), ("state", "cwr")], ev.cwr_entries as f64);
            ev_rst.sample(&l, (ev.rst_rx + ev.rst_tx) as f64);
            ev_err.sample(&l, ev.errors as f64);
        } else if inp.sock_events.is_some() {
            // hooks running, nothing seen on this connection yet: a measured zero
            ev_retr.sample(&l, 0.0);
            ev_rst.sample(&l, 0.0);
            ev_err.sample(&l, 0.0);
        }
        let Some(s) = by_cookie.get(&q.cookie) else { continue };
        sndq.sample(&l, f64::from(s.send_q));
        rcvq.sample(&l, f64::from(s.recv_q));
        let Some(i) = s.info.as_ref() else { continue };
        rtt.sample(&l, f64::from(i.rtt_us) / 1e6);
        rttvar.sample(&l, f64::from(i.rttvar_us) / 1e6);
        if let Some(m) = i.min_rtt_us {
            minrtt.sample(&l, f64::from(m) / 1e6);
        }
        rto.sample(&l, f64::from(i.rto_us) / 1e6);
        retr.sample(&l, f64::from(i.total_retrans));
        if let Some(b) = i.bytes_retrans {
            rbytes.sample(&l, b as f64);
        }
        if let Some(b) = i.bytes_sent.or(i.bytes_acked) {
            sent.sample(&l, b as f64);
        }
        if let Some(b) = i.bytes_received {
            recv.sample(&l, b as f64);
        }
        unacked.sample(&l, f64::from(i.unacked));
        lost.sample(&l, f64::from(i.lost));
        cwnd.sample(&l, f64::from(i.snd_cwnd));
        if i.snd_ssthresh < 0x7fff_ffff {
            ssth.sample(&l, f64::from(i.snd_ssthresh));
        }
        if let Some(n) = i.notsent_bytes {
            notsent.sample(&l, f64::from(n));
        }
        for (reason, v) in [("busy", i.busy_time_us), ("rwnd", i.rwnd_limited_us), ("sndbuf", i.sndbuf_limited_us)] {
            if let Some(us) = v {
                limited.sample(&[("controller", cname), ("qid", qid.as_str()), ("reason", reason)], us as f64 / 1e6);
            }
        }
    }
    fams.extend([
        f_cpu, rtt, rttvar, minrtt, rto, retr, rbytes, sent, recv, unacked, lost, cwnd, ssth, sndq, rcvq, notsent,
        limited, ev_retr, ev_cong, ev_rst, ev_err,
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvmetea_core::model::{QueueCounters, nvme::bucket_index};

    fn sample_input(t: &Topology, nv: &NvmeSample) -> String {
        let disk = BTreeMap::new();
        let tr = BTreeMap::from([(("nvme2".to_string(), "resetting".to_string()), 1u64)]);
        let inp = PromInput {
            version: "0.1.0",
            topology: t,
            disk: &disk,
            nvme: Some(nv),
            sockets: &[],
            queue_sockets: None,
            sock_events: None,
            collectors: &[CollectorStatus { name: "bpf_core", up: true }],
            capabilities: &[Capability {
                name: "queue_sockets",
                status: "unavailable".into(),
                reason: "permission_denied".into(),
            }],
            transitions: &tr,
            process: None,
            limits: Limits { max_controllers: 64, max_queues: 2 },
        };
        render(&inp).text
    }

    fn nvme() -> NvmeSample {
        let mut queues = BTreeMap::new();
        let mut hists = BTreeMap::new();
        for qid in 1..=3u16 {
            let mut c = QueueCounters::default();
            c.dispatched[Op::Read.index()] = 10;
            c.bytes[Op::Read.index()] = 4096 * 10;
            c.req_lat_cnt[Op::Read.index()] = 10;
            c.req_lat_sum_ns[Op::Read.index()] = 10 * 1500;
            c.inflight = 2;
            queues.insert((2, qid), c);
            let mut h = Histogram::default();
            for _ in 0..10 {
                h.record(1500);
            }
            hists.insert((2, qid, Op::Read, LatMetric::Request), h);
        }
        NvmeSample {
            taken: std::time::Instant::now(),
            queues,
            hists,
            path_hists: BTreeMap::new(),
            counters: Default::default(),
            epoch: 1,
        }
    }

    #[test]
    fn edges_are_internal_bucket_boundaries() {
        for e in edges() {
            // an edge is the lower bound of some internal bucket: no bucket straddles it
            let i = bucket_index(e);
            assert_eq!(bucket_bounds(i).0, e, "edge {e}");
        }
        assert_eq!(edges().len(), 53);
    }

    #[test]
    fn exposition_is_well_formed() {
        let topo = nvmetea_topology_fixture();
        let text = sample_input(&topo, &nvme());
        let mut typed = std::collections::BTreeSet::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                typed.insert(rest.split(' ').next().unwrap_or("").to_string());
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            // name{labels} value
            let (name, value) = line.rsplit_once(' ').expect("value");
            assert!(value.parse::<f64>().is_ok() || value == "+Inf", "{line}");
            let base = name.split('{').next().unwrap_or("");
            let fam = ["_bucket", "_sum", "_count"].iter().fold(base.to_string(), |b, s| {
                if typed.contains(&b) { b } else { b.strip_suffix(s).unwrap_or(&b).to_string() }
            });
            assert!(typed.contains(&fam) || typed.contains(base), "sample before its TYPE: {line}");
        }
        // queue limit 2: qid 3 aggregated into "other"
        assert!(
            text.contains(r#"nvmetea_queue_commands_total{controller="nvme2",qid="other",op="read"} 10"#),
            "{text}"
        );
        assert!(text.contains(r#"nvmetea_prom_series_dropped 1"#));
        // histogram: cumulative, ends at the count, sum exact
        assert!(text.contains(r#"nvmetea_request_latency_seconds_bucket{controller="nvme2",op="read",le="+Inf"} 30"#));
        assert!(text.contains(r#"nvmetea_request_latency_seconds_count{controller="nvme2",op="read"} 30"#));
        assert!(text.contains(r#"nvmetea_request_latency_seconds_sum{controller="nvme2",op="read"} 0.000045"#));
        assert!(
            text.contains(r#"nvmetea_request_latency_seconds_bucket{controller="nvme2",op="read",le="0.000001024"} 0"#)
        );
        assert!(
            text.contains(
                r#"nvmetea_request_latency_seconds_bucket{controller="nvme2",op="read",le="0.000001536"} 30"#
            )
        );
        // unavailable sources are absent, not zero
        assert!(!text.contains("nvmetea_tcp_rtt_seconds"));
        assert!(text.contains(
            r#"nvmetea_capability_status{capability="queue_sockets",status="unavailable",reason="permission_denied"} 1"#
        ));
        assert!(
            text.contains(r#"nvmetea_controller_state_transitions_total{controller="nvme2",to_state="resetting"} 1"#)
        );
    }

    fn nvmetea_topology_fixture() -> Topology {
        use nvmetea_core::model::{Controller, CtrlState};
        let c = Controller {
            name: "nvme2".into(),
            instance: 2,
            subsystem: None,
            subsysnqn: Some("nqn.test".into()),
            transport: Some("tcp".into()),
            address: None,
            state: CtrlState::Live,
            cntlid: None,
            queue_count: Some(4),
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
            paths: vec![],
            namespaces: vec![],
            generation: Some(1),
            epoch: Some(1),
        };
        Topology { controllers: vec![c], ..Default::default() }
    }

    #[test]
    fn labels_are_escaped() {
        let mut f = Family::new("x", "gauge", "h");
        f.sample(&[("a", "q\"uo\\te\n")], 1.5);
        assert_eq!(f.lines[0], r#"x{a="q\"uo\\te\n"} 1.5"#);
        assert_eq!(num(3.0), "3");
        assert_eq!(num(f64::INFINITY), "+Inf");
    }
}
