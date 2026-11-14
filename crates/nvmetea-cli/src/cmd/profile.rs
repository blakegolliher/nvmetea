//! `nvmetea profile`: where the time of NVMe/TCP commands goes, stage by stage
//! (Level 2 driver hooks on sampled commands; root).
//!
//! Every sampled command is split into local submission (A), initiator
//! transmit (B), remote/transport (C), initiator receive (D) and local
//! completion (E) stages (`docs/latency-model.md` §5). Tables use complete
//! records only (rule R3); shares add up to 100 % of the request latency of the
//! same records. Level 1 runs alongside for totals over all commands (R7).

use crate::Ctx;
use crate::fmt::{Table, emit, emit_json, lat};
use anyhow::{Context, bail};
use nvmetea_bpf::bpfstats::{ProgRun, enable_run_stats};
use nvmetea_bpf::discovery::{Status, discover};
use nvmetea_bpf::driver::{
    DriverCollector, DriverConfig, DriverEvent, DriverHealth, Flavour, TimeoutEvent, WorkerCounters,
};
use nvmetea_bpf::preflight::{self, Preflight};
use nvmetea_core::Obs;
use nvmetea_core::model::{Op, Topology};
use nvmetea_core::nvme_engine::nvme_intervals;
use nvmetea_profile::{Dist, Excluded, FAMILIES, Group, GroupKey, Profile, Span, Timeline, size_class_label};
use nvmetea_topology::TransitionSource;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

pub struct Args {
    pub interval: f64,
    pub sample: u32,
    pub flavour: String,
    pub slowest: usize,
    pub bpf_stats: bool,
}

#[derive(Serialize)]
struct StageRow {
    stage: &'static str,
    family: String,
    label: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    bound: Option<&'static str>,
    samples: u64,
    mean_us: Option<f64>,
    p50_us: Option<f64>,
    p99_us: Option<f64>,
    /// Share of the request latency of the same (complete) records.
    share_pct: Option<f64>,
}

#[derive(Serialize)]
struct UnclassifiedRow {
    from: String,
    to: String,
    samples: u64,
    mean_us: Option<f64>,
}

#[derive(Serialize)]
struct GroupRow {
    /// "all" or nvmeN.
    controller: String,
    op: Op,
    variant: &'static str,
    size_class: String,
    complete: u64,
    excluded: Excluded,
    request_mean_us: Option<f64>,
    request_p50_us: Option<f64>,
    request_p99_us: Option<f64>,
    stages: Vec<StageRow>,
    /// Mean per stage family (A, B, C, D, E) over the complete records.
    families: BTreeMap<String, f64>,
    /// R2T writes: mean time in send calls inside B4 (the rest is transmit wait).
    #[serde(skip_serializing_if = "Option::is_none")]
    b4_busy_mean_us: Option<f64>,
    unclassified: Vec<UnclassifiedRow>,
}

#[derive(Serialize)]
struct SpanRow {
    stage: &'static str,
    from: &'static str,
    to: &'static str,
    us: f64,
}

#[derive(Serialize)]
struct TimelineRow {
    controller: String,
    qid: u16,
    op: Op,
    variant: &'static str,
    bytes: u32,
    request_us: f64,
    flags: Vec<&'static str>,
    io_cpu: Option<u32>,
    cpu_submit: u16,
    cpu_complete: u16,
    spans: Vec<SpanRow>,
}

#[derive(Serialize)]
struct QueueRow {
    controller: String,
    qid: u16,
    io_cpu: Option<u32>,
    /// Complete records of this queue (all operations).
    complete: u64,
    request_mean_us: Option<f64>,
    /// Mean per stage family: A, B, C, D, E.
    families: BTreeMap<String, f64>,
}

#[derive(Serialize)]
struct WorkerRow {
    controller: String,
    qid: u16,
    runs_per_s: f64,
    /// Elapsed time inside io_work as % of one CPU (includes preemption).
    busy_pct: f64,
    /// Runs that used the whole 1 ms quota, per second.
    quota_runs_per_s: f64,
    max_run_us: f64,
}

#[derive(Serialize)]
struct Level1Row {
    controller: String,
    op: Op,
    /// All commands (Level 1), not only the sampled ones.
    completed_per_s: Obs<f64>,
    request_mean_us: Obs<f64>,
    /// Mean request latency of this controller's sampled records (complete or not).
    sampled_request_mean_us: Option<f64>,
    sampled: u64,
}

#[derive(Serialize)]
struct RunRow {
    object: &'static str,
    program: String,
    runs_per_s: f64,
    ns_per_run: Option<f64>,
    /// % of one CPU.
    cpu_pct: f64,
    /// Runs skipped by the kernel's BPF recursion protection in the interval.
    recursion_misses: u64,
}

#[derive(Serialize)]
struct BpfStatsReport {
    /// Host-wide BPF run-time statistics were enabled for the run (closed after).
    note: &'static str,
    programs: Vec<RunRow>,
    total_cpu_pct: f64,
    /// All nvmetea programs' run time divided by Level 1 completions.
    ns_per_completed_command: Option<f64>,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    host: nvmetea_bpf::discovery::HostIdentity,
    interval_s: f64,
    sample_every: u32,
    flavour: Flavour,
    #[serde(skip_serializing_if = "Option::is_none")]
    preflight: Option<Preflight>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fallback: Option<String>,
    probes: BTreeSet<&'static str>,
    /// Probes not running, and why.
    dropped: BTreeMap<String, String>,
    health: DriverHealth,
    records: u64,
    no_end_to_end: u64,
    sum_check_failures: u64,
    order_violations: u64,
    groups: Vec<GroupRow>,
    slowest: Vec<TimelineRow>,
    queues: Vec<QueueRow>,
    workers: Vec<WorkerRow>,
    level1: Vec<Level1Row>,
    timeouts: Vec<TimeoutEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bpf_stats: Option<BpfStatsReport>,
}

const FOOTNOTE: &str = "\
Stages (docs/latency-model.md §5): A block submission, B initiator transmit, C remote/transport (network +
target), D initiator receive, E completion. C ends at the first receive notification that covers the PDU,
so C is an upper bound (it includes NIC/softirq delivery) and the wakeup after it a lower bound (marked ^ / v).
Means are exact; percentiles are histogram upper bucket edges (<= 12.5 % high). Sampled commands only;
retried, timed-out and failed commands are excluded; partial records (a boundary missing) are counted apart.";

fn us(ns: f64) -> f64 {
    ns / 1e3
}

fn pctl(d: &Dist, p: f64) -> Option<f64> {
    d.hist.percentile(p).map(|x| us(x.ns as f64))
}

fn lat_us(v: Option<f64>) -> String {
    lat(&match v {
        Some(x) => Obs::derived(x, &[]),
        None => Obs::unavailable(nvmetea_core::Reason::NoSamples),
    })
}

fn group_row(k: &GroupKey, g: &Group) -> GroupRow {
    let e2e = g.e2e.mean_ns();
    let mut families: BTreeMap<String, f64> = BTreeMap::new();
    let stages = g
        .stages
        .iter()
        .map(|(st, d)| {
            let mean = d.mean_ns();
            if let Some(m) = mean {
                *families.entry(st.family().to_string()).or_default() += us(m);
            }
            StageRow {
                stage: st.id(),
                family: st.family().to_string(),
                label: st.label(k.variant),
                bound: st.bound(),
                samples: d.samples,
                mean_us: mean.map(us),
                p50_us: pctl(d, 0.5),
                p99_us: pctl(d, 0.99),
                share_pct: match (mean, e2e) {
                    (Some(m), Some(e)) if e > 0.0 => Some(100.0 * m / e),
                    _ => None,
                },
            }
        })
        .collect();
    GroupRow {
        controller: k.instance.map(|i| format!("nvme{i}")).unwrap_or_else(|| "all".into()),
        op: k.op,
        variant: k.variant.as_str(),
        size_class: size_class_label(k.size_class),
        complete: g.complete,
        excluded: g.excluded,
        request_mean_us: e2e.map(us),
        request_p50_us: pctl(&g.e2e, 0.5),
        request_p99_us: pctl(&g.e2e, 0.99),
        stages,
        families,
        b4_busy_mean_us: (g.b4_busy.samples > 0).then(|| g.b4_busy.mean_ns().map(us)).flatten(),
        unclassified: g
            .unclassified
            .iter()
            .map(|((f, t), d)| UnclassifiedRow {
                from: f.clone(),
                to: t.clone(),
                samples: d.samples,
                mean_us: d.mean_ns().map(us),
            })
            .collect(),
    }
}

fn timeline_row(t: &Timeline) -> TimelineRow {
    TimelineRow {
        controller: format!("nvme{}", t.instance),
        qid: t.qid,
        op: t.op,
        variant: t.variant.as_str(),
        bytes: t.bytes,
        request_us: us(t.e2e_ns as f64),
        flags: t.flags.clone(),
        io_cpu: t.io_cpu,
        cpu_submit: t.cpu_submit,
        cpu_complete: t.cpu_complete,
        spans: t
            .spans
            .iter()
            .map(|s: &Span| SpanRow { stage: s.stage.id(), from: s.from, to: s.to, us: us(s.ns as f64) })
            .collect(),
    }
}

/// Probe ids this kernel cannot run in `flavour` (discovery rule F4).
pub(crate) fn skip_set(proc_root: &std::path::Path, flavour: Flavour) -> BTreeSet<String> {
    let disc = discover(proc_root);
    disc.probes
        .iter()
        .filter(|p| p.id.starts_with('D'))
        .filter(|p| {
            let st = match flavour {
                Flavour::Fentry => p.btf_flavour,
                Flavour::Kprobe => p.kprobe_flavour.unwrap_or(Status::Unavailable),
            };
            st == Status::Unavailable
        })
        .map(|p| p.id.to_string())
        .collect()
}

fn all_runs(ctx: &mut Ctx, drv: &DriverCollector) -> Vec<ProgRun> {
    let mut v = drv.prog_runs();
    if let Some(c) = ctx.collector.bpf_mut() {
        v.extend(c.prog_runs());
    }
    v
}

pub(crate) fn start_driver(cfg: &DriverConfig) -> anyhow::Result<DriverCollector> {
    DriverCollector::start(cfg).map_err(|e| {
        let extra = match &e {
            nvmetea_bpf::core::LoadError::Load { log, .. } if !log.is_empty() => {
                let l: Vec<&str> = log.lines().filter(|l| !l.trim().is_empty()).collect();
                format!("\n{}", l[l.len().saturating_sub(8)..].join("\n"))
            }
            _ => String::new(),
        };
        anyhow::anyhow!("loading the Level 2 driver hooks ({} flavour): {e}{extra}", cfg.flavour.as_str())
    })
}

pub fn run(ctx: &mut Ctx, a: Args) -> anyhow::Result<()> {
    if ctx.no_bpf {
        bail!("profile needs the BPF driver hooks; remove --no-bpf");
    }
    let topo: Topology = nvmetea_topology::scan(&ctx.collector.sys);
    ctx.filter.validate(&topo)?;
    let ctrls: Vec<u32> = topo.tcp_controllers().filter(|c| ctx.filter.controller(c)).map(|c| c.instance).collect();
    if ctrls.is_empty() {
        bail!("no NVMe/TCP controller matches the filter");
    }
    let sample = a.sample.max(1);
    let (mut flavour, preflight) = match a.flavour.as_str() {
        "kprobe" => (Flavour::Kprobe, None),
        "fentry" => (Flavour::Fentry, None),
        "auto" => {
            let pf = preflight::check(Duration::from_secs(2));
            (if pf.fentry_ok() { Flavour::Fentry } else { Flavour::Kprobe }, Some(pf))
        }
        x => bail!("unknown --flavour {x} (auto, fentry, kprobe)"),
    };
    let mut cfg = DriverConfig::from_topology(&topo, flavour, sample);
    if ctx.filter.controller.is_some() && ctrls.len() == 1 {
        cfg.only_instance = Some(ctrls[0]);
    }
    cfg.skip = skip_set(&ctx.collector.proc_root, flavour);
    let stats = if a.bpf_stats { Some(enable_run_stats().context("enabling BPF run-time statistics")?) } else { None };
    let mut fallback = None;
    let mut drv = match start_driver(&cfg) {
        Ok(d) => d,
        Err(e) if flavour == Flavour::Fentry && a.flavour == "auto" => {
            fallback = Some(format!("fentry failed, using kprobes: {e}"));
            flavour = Flavour::Kprobe;
            cfg.flavour = flavour;
            cfg.skip = skip_set(&ctx.collector.proc_root, flavour);
            start_driver(&cfg)?
        }
        Err(e) => return Err(e),
    };
    // Level 1 attaches after the driver object: programs on one tracepoint run in
    // attach order, so the driver's E_SETUP / E_NVME_DONE / E_BLK_DONE stamps are
    // not delayed by the Level 1 programs' own run time.
    ctx.collector.enable_bpf(&topo);
    if !ctx.json {
        let pf = match &preflight {
            Some(Preflight::Passed { attach_ms, .. }) => format!(" (preflight attach {attach_ms:.1} ms)"),
            Some(p) => format!(" (preflight: {p:?})"),
            None => String::new(),
        };
        eprintln!(
            "profiling {:.0} s, 1 in {sample} commands, {} hooks{pf}{} (Ctrl-C reports early)",
            a.interval,
            flavour.as_str(),
            if a.bpf_stats { ", BPF run-time stats on" } else { "" }
        );
        for (id, why) in &drv.dropped {
            eprintln!("note: probe {id} not running: {why}");
        }
    }

    let s0 = ctx.collector.sample(TransitionSource::Poll);
    let runs0 = all_runs(ctx, &drv);
    let h0 = drv.health();
    let w0 = drv.workers();
    let mut prof = Profile::new(a.slowest);
    let mut timeouts = Vec::new();
    let mut sampled_e2e: BTreeMap<u32, Dist> = BTreeMap::new();
    let t0 = Instant::now();
    let dur = Duration::from_secs_f64(a.interval.max(0.2));
    let mut consume = |evs: Vec<DriverEvent>, prof: &mut Profile, timeouts: &mut Vec<TimeoutEvent>| {
        for e in evs {
            match e {
                DriverEvent::Command(r) => {
                    if let Some(ns) = r.e2e_ns() {
                        sampled_e2e.entry(r.instance).or_default().add(ns);
                    }
                    prof.add(&r);
                }
                DriverEvent::Timeout(t) => timeouts.push(t),
            }
        }
    };
    let _ = drv.drain_events(); // records of commands sampled before the first sample
    crate::signal::install(); // Ctrl-C: report what was sampled so far
    while t0.elapsed() < dur && !crate::signal::requested() {
        std::thread::sleep(Duration::from_millis(20));
        consume(drv.drain_events(), &mut prof, &mut timeouts);
    }
    let s1 = ctx.collector.sample(TransitionSource::Poll);
    let elapsed = t0.elapsed().as_secs_f64();
    consume(drv.drain_events(), &mut prof, &mut timeouts);
    let runs1 = all_runs(ctx, &drv);
    let h1 = drv.health();
    let w1 = drv.workers();
    drop(stats);

    // Level 1 (all commands)
    let iv = match (&s0.nvme, &s1.nvme) {
        (Some(p0), Some(p1)) => Some(nvme_intervals(p0, &s0.snap.topology, p1, &s1.snap.topology)),
        _ => None,
    };
    let mut level1 = Vec::new();
    let mut completed_total = 0.0;
    if let Some(v) = &iv {
        for c in v.controllers.iter().filter(|c| ctrls.contains(&c.instance)) {
            for o in c.ops.iter().filter(|o| matches!(o.op, Op::Read | Op::Write)) {
                if o.completed_per_s.value.unwrap_or(0.0) <= 0.0 {
                    continue;
                }
                completed_total += o.completed_per_s.value.unwrap_or(0.0) * v.interval_s;
                let sd = sampled_e2e.get(&c.instance);
                level1.push(Level1Row {
                    controller: c.controller.clone(),
                    op: o.op,
                    completed_per_s: o.completed_per_s.clone(),
                    request_mean_us: o.request.mean_us.clone(),
                    sampled_request_mean_us: sd.and_then(|d| d.mean_ns()).map(us),
                    sampled: sd.map(|d| d.samples).unwrap_or(0),
                });
            }
        }
    }

    let mut workers = Vec::new();
    for (k, w) in &w1 {
        if !ctrls.contains(&k.0) {
            continue;
        }
        let p = w0.get(k).copied().unwrap_or(WorkerCounters::default());
        let runs = w.runs.saturating_sub(p.runs) as f64;
        if runs == 0.0 {
            continue;
        }
        workers.push(WorkerRow {
            controller: format!("nvme{}", k.0),
            qid: k.1,
            runs_per_s: runs / elapsed,
            busy_pct: 100.0 * w.busy_ns.saturating_sub(p.busy_ns) as f64 / (elapsed * 1e9),
            quota_runs_per_s: w.quota_runs.saturating_sub(p.quota_runs) as f64 / elapsed,
            max_run_us: us(w.max_ns as f64),
        });
    }

    let bpf_stats = a.bpf_stats.then(|| {
        let before: BTreeMap<(&str, String), (u64, u64, u64)> = runs0
            .iter()
            .map(|r| ((r.object, r.program.clone()), (r.run_cnt, r.run_time_ns, r.recursion_misses)))
            .collect();
        let mut rows = Vec::new();
        let mut total_ns = 0u64;
        for r in &runs1 {
            let (c0, t0, m0) = before.get(&(r.object, r.program.clone())).copied().unwrap_or((0, 0, 0));
            let (dc, dt) = (r.run_cnt.saturating_sub(c0), r.run_time_ns.saturating_sub(t0));
            total_ns += dt;
            rows.push(RunRow {
                object: r.object,
                program: r.program.clone(),
                runs_per_s: dc as f64 / elapsed,
                ns_per_run: (dc > 0).then(|| dt as f64 / dc as f64),
                cpu_pct: 100.0 * dt as f64 / (elapsed * 1e9),
                recursion_misses: r.recursion_misses.saturating_sub(m0),
            });
        }
        rows.sort_by(|a, b| b.cpu_pct.total_cmp(&a.cpu_pct));
        BpfStatsReport {
            note: "BPF_ENABLE_STATS was held for the run: run time of every BPF program on the host was counted \
                   (two clock reads per program run) and stopped when nvmetea released it. Run time covers the \
                   program body only, not the kprobe or trampoline dispatch around it",
            programs: rows,
            total_cpu_pct: 100.0 * total_ns as f64 / (elapsed * 1e9),
            ns_per_completed_command: (completed_total > 0.0).then(|| total_ns as f64 / completed_total),
        }
    });

    let mut keys: Vec<&GroupKey> = prof.groups.keys().collect();
    keys.sort_by_key(|k| (k.instance.is_some(), k.instance, k.op, k.variant, k.size_class));
    let groups: Vec<GroupRow> = keys
        .into_iter()
        .filter(|k| prof.groups[k].complete > 0 || k.instance.is_none())
        .map(|k| group_row(k, &prof.groups[k]))
        .collect();
    let report = Report {
        schema: "nvmetea.profile/1",
        host: nvmetea_bpf::discovery::host_identity(),
        interval_s: elapsed,
        sample_every: sample,
        flavour,
        preflight,
        fallback,
        probes: drv.active_probes(),
        dropped: drv.dropped.clone(),
        health: h1.since(&h0),
        records: prof.records,
        no_end_to_end: prof.no_e2e,
        sum_check_failures: prof.sum_check_failures,
        order_violations: prof.order_violations,
        groups,
        slowest: prof.slowest.iter().map(timeline_row).collect(),
        queues: prof
            .queues
            .iter()
            .map(|((i, q), a)| QueueRow {
                controller: format!("nvme{i}"),
                qid: *q,
                io_cpu: a.io_cpu,
                complete: a.complete,
                request_mean_us: a.e2e_mean_ns().map(us),
                families: FAMILIES
                    .iter()
                    .enumerate()
                    .filter_map(|(n, f)| a.mean_ns(n).map(|v| (f.to_string(), us(v))))
                    .collect(),
            })
            .collect(),
        workers,
        level1,
        timeouts,
        bpf_stats,
    };
    if ctx.json {
        return emit_json(&report);
    }
    emit(&render(&report));
    Ok(())
}

fn render(r: &Report) -> String {
    let mut out = String::new();
    let h = &r.health;
    out.push_str(&format!(
        "{} sampled commands in {:.1} s (1 in {}, {} hooks): sum check failures {}, without end-to-end {}, \
         order violations {}, ring buffer lost {}, notification unresolved {}\n",
        r.records,
        r.interval_s,
        r.sample_every,
        r.flavour.as_str(),
        r.sum_check_failures,
        r.no_end_to_end,
        r.order_violations,
        h.events_lost,
        h.seq_unresolved
    ));
    if let Some(f) = &r.fallback {
        out.push_str(&format!("note: {f}\n"));
    }
    for g in r.groups.iter().filter(|g| g.controller == "all" && g.complete > 0) {
        out.push_str(&format!(
            "\nALL CONTROLLERS  {}  {}: {} complete, {} partial, {} excluded; request mean {}, p50 {}, p99 {}\n",
            g.variant.to_uppercase(),
            g.size_class,
            g.complete,
            g.excluded.partial,
            g.excluded.retried + g.excluded.timed_out + g.excluded.error_status,
            lat_us(g.request_mean_us),
            lat_us(g.request_p50_us),
            lat_us(g.request_p99_us)
        ));
        let mut t = Table::new(&["STAGE", "WHAT", "MEAN", "SHARE", "p50", "p99"], 2).indent(2);
        for s in &g.stages {
            let mark = match s.bound {
                Some("upper bound") => " ^",
                Some("lower bound") => " v",
                _ => "",
            };
            t.push(vec![
                s.stage.to_string(),
                format!("{}{mark}", s.label),
                lat_us(s.mean_us),
                s.share_pct.map(|p| format!("{p:.1}%")).unwrap_or_else(|| "-".into()),
                lat_us(s.p50_us),
                lat_us(s.p99_us),
            ]);
        }
        out.push_str(&t.render());
        let fam = |f: &str| g.families.get(f).copied();
        let e2e = g.request_mean_us.unwrap_or(0.0);
        let share =
            |f: &str| fam(f).filter(|_| e2e > 0.0).map(|v| format!("{:.1}%", 100.0 * v / e2e)).unwrap_or("-".into());
        out.push_str(&format!(
            "  local: A {}  B {}  D {}  E {}   remote/transport: C {}\n",
            share("A"),
            share("B"),
            share("D"),
            share("E"),
            share("C")
        ));
        if let Some(b) = g.b4_busy_mean_us {
            out.push_str(&format!("  B4 data transmit: {} in send calls, the rest waiting to send\n", lat_us(Some(b))));
        }
        for u in &g.unclassified {
            out.push_str(&format!(
                "  partial: {} records with {} -> {} merged (mean {})\n",
                u.samples,
                u.from,
                u.to,
                lat_us(u.mean_us)
            ));
        }
    }

    let per: Vec<&GroupRow> = r.groups.iter().filter(|g| g.controller != "all" && g.complete > 0).collect();
    if !per.is_empty() {
        out.push_str("\nPER CONTROLLER (stage family means, complete records)\n");
        let mut t = Table::new(&["CTRL", "VARIANT", "SIZE", "N", "REQ mean", "A", "B", "C", "D", "E", "C share"], 3);
        for g in per {
            let f = |k: &str| lat_us(g.families.get(k).copied());
            let cs = match (g.families.get("C"), g.request_mean_us) {
                (Some(c), Some(e)) if e > 0.0 => format!("{:.1}%", 100.0 * c / e),
                _ => "-".into(),
            };
            t.push(vec![
                g.controller.clone(),
                g.variant.into(),
                g.size_class.clone(),
                g.complete.to_string(),
                lat_us(g.request_mean_us),
                f("A"),
                f("B"),
                f("C"),
                f("D"),
                f("E"),
                cs,
            ]);
        }
        out.push_str(&t.render());
    }

    if !r.slowest.is_empty() {
        out.push_str("\nSLOWEST SAMPLED COMMANDS\n");
        for s in &r.slowest {
            let parts: Vec<String> = s
                .spans
                .iter()
                .map(|x| {
                    let st = if x.stage == "?" { format!("?({}->{})", x.from, x.to) } else { x.stage.to_string() };
                    format!("{st} {}", lat_us(Some(x.us)))
                })
                .collect();
            out.push_str(&format!(
                "  {}/q{} {} {}KiB {} (cpu {}->{}, io_cpu {}){}: {}\n",
                s.controller,
                s.qid,
                s.op.as_str(),
                s.bytes / 1024,
                lat_us(Some(s.request_us)),
                s.cpu_submit,
                s.cpu_complete,
                s.io_cpu.map(|c| c.to_string()).unwrap_or("-".into()),
                if s.flags.is_empty() { String::new() } else { format!(" [{}]", s.flags.join(",")) },
                parts.join(" | ")
            ));
        }
    }

    let mut local: Vec<&QueueRow> = r.queues.iter().filter(|q| q.complete >= 20).collect();
    let loc = |q: &QueueRow| q.families.get("B").copied().unwrap_or(0.0) + q.families.get("D").copied().unwrap_or(0.0);
    local.sort_by(|a, b| loc(b).total_cmp(&loc(a)));
    if !local.is_empty() {
        out.push_str("\nQUEUES WITH THE MOST LOCAL TRANSMIT + RECEIVE TIME (B + D means, complete records)\n");
        let mut t = Table::new(&["CTRL", "QID", "IO_CPU", "N", "REQ mean", "B", "D", "C"], 3);
        for q in local.iter().take(5) {
            let f = |k: &str| lat_us(q.families.get(k).copied());
            t.push(vec![
                q.controller.clone(),
                q.qid.to_string(),
                q.io_cpu.map(|c| c.to_string()).unwrap_or("-".into()),
                q.complete.to_string(),
                lat_us(q.request_mean_us),
                f("B"),
                f("D"),
                f("C"),
            ]);
        }
        out.push_str(&t.render());
    }

    if !r.workers.is_empty() {
        out.push_str("\nQUEUE WORKERS (io_work, all runs)\n");
        let mut by: BTreeMap<&str, Vec<&WorkerRow>> = BTreeMap::new();
        for w in &r.workers {
            by.entry(w.controller.as_str()).or_default().push(w);
        }
        let mut t =
            Table::new(&["CTRL", "RUNS/s", "BUSY% (sum)", "BUSIEST QUEUE", "BUSY%", "QUOTA RUNS/s", "MAX RUN"], 1);
        for (c, ws) in by {
            let runs: f64 = ws.iter().map(|w| w.runs_per_s).sum();
            let busy: f64 = ws.iter().map(|w| w.busy_pct).sum();
            let quota: f64 = ws.iter().map(|w| w.quota_runs_per_s).sum();
            let top = ws.iter().max_by(|a, b| a.busy_pct.total_cmp(&b.busy_pct)).copied();
            let max = ws.iter().map(|w| w.max_run_us).fold(0.0, f64::max);
            t.push(vec![
                c.to_string(),
                format!("{runs:.0}"),
                format!("{busy:.1}"),
                top.map(|w| format!("q{}", w.qid)).unwrap_or_default(),
                top.map(|w| format!("{:.1}", w.busy_pct)).unwrap_or_default(),
                format!("{quota:.1}"),
                lat_us(Some(max)),
            ]);
        }
        out.push_str(&t.render());
    }

    if !r.level1.is_empty() {
        out.push_str("\nLEVEL 1 CROSS-CHECK (all commands vs sampled)\n");
        let mut t = Table::new(&["CTRL", "OP", "IOPS (all)", "REQ mean (all)", "REQ mean (sampled)", "SAMPLED"], 2);
        for l in &r.level1 {
            t.push(vec![
                l.controller.clone(),
                l.op.as_str().into(),
                crate::fmt::count(&l.completed_per_s),
                lat(&l.request_mean_us),
                lat_us(l.sampled_request_mean_us),
                l.sampled.to_string(),
            ]);
        }
        out.push_str(&t.render());
    }

    if !r.timeouts.is_empty() {
        out.push_str(&format!("\n{} command timeouts (D12)\n", r.timeouts.len()));
    }

    if let Some(b) = &r.bpf_stats {
        out.push_str(&format!(
            "\nBPF RUN TIME (nvmetea programs): {:.2}% of one CPU in total{}\n",
            b.total_cpu_pct,
            b.ns_per_completed_command.map(|n| format!(", {n:.0} ns per completed command")).unwrap_or_default()
        ));
        let mut t = Table::new(&["OBJECT", "PROGRAM", "RUNS/s", "ns/RUN", "CPU%", "MISSED"], 2);
        for p in b.programs.iter().filter(|p| p.runs_per_s > 0.0) {
            t.push(vec![
                p.object.into(),
                p.program.clone(),
                format!("{:.0}", p.runs_per_s),
                p.ns_per_run.map(|n| format!("{n:.0}")).unwrap_or("-".into()),
                format!("{:.2}", p.cpu_pct),
                p.recursion_misses.to_string(),
            ]);
        }
        out.push_str(&t.render());
        out.push_str(&format!("  {}\n", b.note));
    }
    out.push('\n');
    out.push_str(FOOTNOTE);
    out.push('\n');
    out
}
