//! `nvmetea record`: write a `nvmetea.capture/1` file (`docs/schema/capture-v1.md`)
//! for later `nvmetea compare`.
//!
//! The capture holds:
//! - topology at start and end, and transitions;
//! - per-interval rates;
//! - Level 1 window histograms (end − start of cumulative ones) and queue
//!   counters;
//! - optionally the Level 2 stage aggregates (`--sample N`, default 100;
//!   0 disables them);
//! - events and quality counters.

use crate::Ctx;
use crate::cmd::profile::{skip_set, start_driver};
use crate::cmd::top::{event_ns, event_text, mono_to_wall, transition_text, ts};
use crate::sample::{Bpf, Sampled};
use anyhow::{Context, bail};
use nvmetea_bpf::driver::{DriverCollector, DriverConfig, DriverEvent, DriverHealth, Flavour};
use nvmetea_bpf::preflight;
use nvmetea_core::engine::controller_intervals;
use nvmetea_core::model::{Histogram, LatMetric, Op, Topology};
use nvmetea_core::nvme_engine::nvme_intervals;
use nvmetea_export::capture::{self, *};
use nvmetea_profile::Profile;
use nvmetea_topology::TransitionSource;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

pub struct Args {
    pub duration: f64,
    pub interval: f64,
    pub output: Option<PathBuf>,
    pub sample: u32,
    pub flavour: String,
}

const MAX_EVENTS: usize = 20_000;

fn key(c: &nvmetea_core::model::Controller) -> ControllerKey {
    let a = c.address.as_ref();
    ControllerKey {
        subsysnqn: c.subsysnqn.clone(),
        transport: c.transport.clone(),
        traddr: a.and_then(|a| a.traddr.clone()),
        trsvcid: a.and_then(|a| a.trsvcid.clone()),
        host_traddr: a.and_then(|a| a.host_traddr.clone()),
    }
}

fn topology(t: &Topology, ctx: &Ctx) -> CaptureTopology {
    CaptureTopology {
        controllers: t
            .controllers
            .iter()
            .filter(|c| ctx.filter.controller(c))
            .map(|c| CaptureController {
                name: c.name.clone(),
                key: key(c),
                state: c.state.as_str().to_string(),
                generation: c.generation,
                epoch: c.epoch,
                io_queues: c.io_queues(),
                queue_depth: c.io_queue_depth(),
            })
            .collect(),
        namespaces: t
            .namespaces
            .iter()
            .filter(|n| ctx.filter.namespace(n, t))
            .map(|n| CaptureNamespace {
                name: n.name.clone(),
                nsid: n.nsid,
                wwid: n.wwid.clone(),
                paths: n
                    .paths
                    .iter()
                    .map(|p| CapturePath {
                        name: p.name.clone(),
                        controller: p.controller.clone(),
                        ana_state: p.ana_state.clone(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn op_name(i: usize) -> &'static str {
    Op::from_index(i).map(|o| o.as_str()).unwrap_or("other")
}

fn dist_of(d: &nvmetea_profile::Dist) -> capture::Dist {
    capture::Dist { count: d.samples, sum_ns: u64::try_from(d.sum_ns).ok(), hist: SparseHist::from_hist(&d.hist) }
}

fn max_rss() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let l = s.lines().find(|l| l.starts_with("VmHWM:"))?;
    Some(l.split_whitespace().nth(1)?.parse::<u64>().ok()? * 1024)
}

fn cpu_seconds() -> Option<f64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let rest = &stat[stat.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    let t: f64 = f.get(11)?.parse::<f64>().ok()? + f.get(12)?.parse::<f64>().ok()?;
    // SAFETY: sysconf has no preconditions.
    Some(t / (unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64).max(1.0))
}

fn interval_summary(prev: &Sampled, cur: &Sampled, t0: Instant, ctx: &Ctx) -> IntervalSummary {
    let civ = controller_intervals(Some(&prev.snap), &cur.snap);
    let nv = match (&prev.nvme, &cur.nvme) {
        (Some(a), Some(b)) => Some(nvme_intervals(a, &prev.snap.topology, b, &cur.snap.topology)),
        _ => None,
    };
    let mut controllers = Vec::new();
    for c in civ {
        let Some(tc) = cur.snap.topology.controller(&c.name) else { continue };
        if !ctx.filter.controller(tc) {
            continue;
        }
        let n = nv.as_ref().and_then(|v| v.controllers.iter().find(|x| x.controller == c.name));
        let mean = |op: Op| n.and_then(|n| n.ops.iter().find(|o| o.op == op)).and_then(|o| o.request.mean_us.value);
        controllers.push(ControllerRates {
            controller: c.name.clone(),
            state: c.state.as_str().to_string(),
            read_iops: c.io.read_iops.value,
            write_iops: c.io.write_iops.value,
            read_bytes_per_s: c.io.read_bytes_per_s.value,
            write_bytes_per_s: c.io.write_bytes_per_s.value,
            read_mean_us: mean(Op::Read),
            write_mean_us: mean(Op::Write),
            inflight: n.and_then(|n| n.inflight.value),
            tcp_rtt_median_us: c.tcp.as_ref().and_then(|t| t.rtt_median_us.value),
            tcp_retrans_segments_per_s: c.tcp.as_ref().and_then(|t| t.retrans_segments_per_s.value),
        });
    }
    IntervalSummary {
        t_s: cur.snap.taken.duration_since(t0).as_secs_f64(),
        interval_s: cur.snap.taken.duration_since(prev.snap.taken).as_secs_f64(),
        controllers,
    }
}

fn health_map(h: &DriverHealth) -> BTreeMap<String, u64> {
    serde_json::to_value(h)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .map(|m| m.into_iter().filter_map(|(k, v)| Some((k, v.as_u64()?))).collect())
        .unwrap_or_default()
}

pub fn run(ctx: &mut Ctx, a: Args) -> anyhow::Result<()> {
    let topo0 = nvmetea_topology::scan(&ctx.collector.sys);
    ctx.filter.validate(&topo0)?;
    let duration = Duration::from_secs_f64(a.duration.max(1.0));
    let interval = Duration::from_secs_f64(a.interval.clamp(0.25, 3600.0).min(duration.as_secs_f64()));
    let host = nvmetea_bpf::discovery::host_identity();
    let out = a.output.clone().unwrap_or_else(|| {
        let t = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        PathBuf::from(format!("nvmetea-capture-{t}.json"))
    });
    // fail early if the output cannot be written
    let tmp = out.with_extension("json.partial");
    std::fs::write(&tmp, b"").with_context(|| format!("cannot write {}", tmp.display()))?;

    // Level 2 first: programs on one tracepoint run in attach order
    let mut driver: Option<DriverCollector> = None;
    let mut sig: BTreeMap<String, String> = BTreeMap::new();
    let mut notes: Vec<String> = Vec::new();
    if !ctx.no_bpf && a.sample > 0 {
        let flavour = match a.flavour.as_str() {
            "kprobe" => Flavour::Kprobe,
            "fentry" => Flavour::Fentry,
            "auto" => {
                if preflight::check(Duration::from_secs(2)).fentry_ok() {
                    Flavour::Fentry
                } else {
                    Flavour::Kprobe
                }
            }
            x => bail!("unknown --flavour {x} (auto, fentry, kprobe)"),
        };
        let mut cfg = DriverConfig::from_topology(&topo0, flavour, a.sample);
        cfg.skip = skip_set(&ctx.collector.proc_root, flavour);
        let started = match start_driver(&cfg) {
            Err(_) if flavour == Flavour::Fentry && a.flavour == "auto" => {
                cfg.flavour = Flavour::Kprobe;
                cfg.skip = skip_set(&ctx.collector.proc_root, Flavour::Kprobe);
                start_driver(&cfg)
            }
            r => r,
        };
        match started {
            Ok(d) => {
                let probes: Vec<&str> = d.active_probes().into_iter().collect();
                sig.insert(
                    "stages".into(),
                    format!(
                        "tcp_driver {} [{}]; sequence-mapped notification; 1 in {}",
                        cfg.flavour.as_str(),
                        probes.join(","),
                        a.sample
                    ),
                );
                driver = Some(d);
            }
            Err(e) => notes.push(format!("stage profile unavailable: {e}")),
        }
    }
    if !ctx.no_bpf {
        ctx.collector.enable_all_bpf(&topo0);
        crate::cmd::queues::warn_bpf(ctx);
    }
    if matches!(ctx.collector.bpf, Bpf::Active(_)) {
        sig.insert("request".into(), "raw_tp nvme_setup_cmd (rq->start_time_ns) .. block_rq_complete".into());
        sig.insert("command".into(), "raw_tp nvme_setup_cmd .. nvme_complete_rq".into());
    }
    if !ctx.json {
        eprintln!(
            "recording {:.0} s (interval {:.1} s){} to {} (Ctrl-C stops early and writes the capture)",
            duration.as_secs_f64(),
            interval.as_secs_f64(),
            if driver.is_some() { format!(", stage profile 1 in {}", a.sample) } else { String::new() },
            out.display()
        );
    }

    crate::signal::install();
    let start_wall = ts(SystemTime::now());
    let t0 = Instant::now();
    let s0 = ctx.collector.sample(TransitionSource::Poll);
    sig.insert("tcp".into(), format!("{:?}", s0.tcp.backend).to_lowercase());
    let h0 = driver.as_ref().map(|d| d.health());
    if let Some(d) = driver.as_mut() {
        let _ = d.drain_events(); // records of commands sampled before the first sample
    }
    let mut prof = Profile::new(0);
    let mut events: Vec<CaptureEvent> = Vec::new();
    let mut events_dropped = 0u64;
    let mut transitions = Vec::new();
    let mut intervals = Vec::new();
    let mut push_ev = |events: &mut Vec<CaptureEvent>, at: f64, kind: &str, text: String| {
        if events.len() < MAX_EVENTS {
            events.push(CaptureEvent { at_unix_s: at, kind: kind.into(), text });
        } else {
            events_dropped += 1;
        }
    };
    let mut prev = s0;
    let mut first: Option<Sampled> = None;
    let mut next = t0 + interval;
    let end = t0 + duration;
    loop {
        let now = Instant::now();
        let stop = crate::signal::requested();
        if now >= next || now >= end || stop {
            let s = ctx.collector.sample(TransitionSource::Poll);
            for t in &s.transitions {
                transitions.push(CaptureTransition {
                    at_unix_s: ts(t.at),
                    controller: t.controller.clone(),
                    change: transition_text(t),
                    source: format!("{:?}", t.source).to_lowercase(),
                });
            }
            for e in &s.events {
                let kind = if matches!(e, nvmetea_bpf::core::CoreEvent::Slow(_)) { "slow" } else { "state" };
                push_ev(&mut events, mono_to_wall(event_ns(e)), kind, event_text(e));
            }
            for e in &s.tcp_events {
                push_ev(
                    &mut events,
                    mono_to_wall(e.t_ns),
                    "tcp",
                    format!("nvme{}/q{}: {}", e.instance, e.qid, e.kind.describe()),
                );
            }
            intervals.push(interval_summary(&prev, &s, t0, ctx));
            if first.is_none() {
                first = Some(std::mem::replace(&mut prev, s));
            } else {
                prev = s;
            }
            next += interval;
            if Instant::now() >= end || stop {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20).min(next.saturating_duration_since(Instant::now())));
        if let Some(d) = driver.as_mut() {
            for e in d.drain_events() {
                match e {
                    DriverEvent::Command(r) => prof.add(&r),
                    DriverEvent::Timeout(t) => push_ev(
                        &mut events,
                        mono_to_wall(t.t_ns),
                        "timeout",
                        format!("nvme{}/q{} command {:#x} opcode {:#x} timed out", t.instance, t.qid, t.cid, t.opcode),
                    ),
                }
            }
        }
    }
    let end_wall = ts(SystemTime::now());
    // `first` holds the start sample (moved out at the first interval), `prev` the last
    write_capture(
        ctx,
        &out,
        &tmp,
        CaptureParts {
            host,
            sig,
            notes,
            start_wall,
            end_wall,
            duration_s: t0.elapsed().as_secs_f64(),
            interval_s: interval.as_secs_f64(),
            first: first.as_ref(),
            last: &prev,
            transitions,
            intervals,
            prof: driver.as_ref().map(|d| (d, &prof)),
            h0,
            events,
            events_dropped,
            sample: a.sample,
        },
    )
}

struct CaptureParts<'a> {
    host: nvmetea_bpf::discovery::HostIdentity,
    sig: BTreeMap<String, String>,
    notes: Vec<String>,
    start_wall: f64,
    end_wall: f64,
    duration_s: f64,
    interval_s: f64,
    /// The first sample of the capture (window start).
    first: Option<&'a Sampled>,
    last: &'a Sampled,
    transitions: Vec<CaptureTransition>,
    intervals: Vec<IntervalSummary>,
    prof: Option<(&'a DriverCollector, &'a Profile)>,
    h0: Option<DriverHealth>,
    events: Vec<CaptureEvent>,
    events_dropped: u64,
    sample: u32,
}

fn write_capture(ctx: &Ctx, out: &std::path::Path, tmp: &std::path::Path, p: CaptureParts) -> anyhow::Result<()> {
    let start = p.first.unwrap_or(p.last);
    let end = p.last;
    let names: BTreeMap<u32, (&str, ControllerKey)> = end
        .snap
        .topology
        .controllers
        .iter()
        .chain(start.snap.topology.controllers.iter())
        .filter(|c| ctx.filter.controller(c))
        .map(|c| (c.instance, (c.name.as_str(), key(c))))
        .collect();

    // Level 1 window: end − start
    let mut latency = Vec::new();
    let mut queues = Vec::new();
    let mut controllers: BTreeMap<u32, ControllerWindow> = BTreeMap::new();
    let mut l1_quality = BTreeMap::new();
    if let (Some(a0), Some(a1)) = (&start.nvme, &end.nvme) {
        let mut sums: BTreeMap<(u32, usize, &str), (u64, u64)> = BTreeMap::new();
        for ((inst, qid), q1) in &a1.queues {
            let Some((name, k)) = names.get(inst) else { continue };
            let q0 = a0.queues.get(&(*inst, *qid)).cloned().unwrap_or_default();
            let w = controllers.entry(*inst).or_insert_with(|| ControllerWindow {
                controller: name.to_string(),
                key: k.clone(),
                ..Default::default()
            });
            w.retries += q1.retries.saturating_sub(q0.retries);
            w.failovers += q1.failovers.saturating_sub(q0.failovers);
            w.requeues += q1.requeues.saturating_sub(q0.requeues);
            for i in 0..5 {
                let d = |a: u64, b: u64| a.saturating_sub(b);
                w.nvme_errors += d(q1.nvme_errors[i], q0.nvme_errors[i]);
                let disp = d(q1.dispatched[i], q0.dispatched[i]);
                if disp > 0 || d(q1.completed[i], q0.completed[i]) > 0 {
                    queues.push(QueueWindow {
                        controller: name.to_string(),
                        qid: *qid,
                        op: op_name(i).into(),
                        dispatched: disp,
                        bytes: d(q1.bytes[i], q0.bytes[i]),
                        completed: d(q1.completed[i], q0.completed[i]),
                        nvme_errors: d(q1.nvme_errors[i], q0.nvme_errors[i]),
                    });
                }
                let e = sums.entry((*inst, i, "command")).or_default();
                e.0 += d(q1.cmd_lat_sum_ns[i], q0.cmd_lat_sum_ns[i]);
                e.1 += d(q1.cmd_lat_cnt[i], q0.cmd_lat_cnt[i]);
                let e = sums.entry((*inst, i, "request")).or_default();
                e.0 += d(q1.req_lat_sum_ns[i], q0.req_lat_sum_ns[i]);
                e.1 += d(q1.req_lat_cnt[i], q0.req_lat_cnt[i]);
            }
        }
        let mut hists: BTreeMap<(u32, Op, LatMetric), Histogram> = BTreeMap::new();
        for (k1, h1) in &a1.hists {
            if !names.contains_key(&k1.0) {
                continue;
            }
            let w = match a0.hists.get(k1) {
                Some(h0) => h1.since(h0),
                None => Some(h1.clone()),
            };
            if let Some(w) = w {
                hists.entry((k1.0, k1.2, k1.3)).or_default().add(&w);
            }
        }
        for ((inst, op, m), h) in hists {
            if h.count() == 0 {
                continue;
            }
            let (name, k) = &names[&inst];
            let metric = match m {
                LatMetric::Command => "command",
                LatMetric::Request => "request",
                LatMetric::StageA => "stage_a",
                LatMetric::StageE2 => "stage_e2",
            };
            let sum_ns = sums.get(&(inst, op.index(), metric)).map(|s| s.0);
            latency.push(LatencyGroup {
                controller: name.to_string(),
                key: k.clone(),
                op: op.as_str().into(),
                metric: metric.into(),
                dist: capture::Dist { count: h.count(), sum_ns, hist: SparseHist::from_hist(&h) },
            });
        }
        let (c0, c1) = (&a0.counters, &a1.counters);
        for (n, a, b) in [
            ("untracked_completions", c0.untracked_completions, c1.untracked_completions),
            ("cid_mismatches", c0.cid_mismatches, c1.cid_mismatches),
            ("stale_replaced", c0.stale_replaced, c1.stale_replaced),
            ("map_full_inflight", c0.map_full_inflight, c1.map_full_inflight),
            ("map_full_qstats", c0.map_full_qstats, c1.map_full_qstats),
            ("map_full_hist", c0.map_full_hist, c1.map_full_hist),
            ("events_lost", c0.events_lost, c1.events_lost),
            ("slow_suppressed", c0.slow_suppressed, c1.slow_suppressed),
            ("start_missing", c0.start_missing, c1.start_missing),
            ("order_violations", c0.order_violations, c1.order_violations),
        ] {
            l1_quality.insert(n.to_string(), b.saturating_sub(a));
        }
    }
    // TCP retransmitted segments per controller over the window (same cookies only)
    let retr = |s: &Sampled| -> BTreeMap<u64, (String, u32)> {
        let mut m = BTreeMap::new();
        for (c, idx) in &s.snap.socket_owner {
            for &i in idx {
                if let Some(sk) = s.snap.sockets.get(i) {
                    if let (Some(ck), Some(info)) = (sk.cookie, sk.info.as_ref()) {
                        m.insert(ck, (c.clone(), info.total_retrans));
                    }
                }
            }
        }
        m
    };
    let (r0, r1) = (retr(start), retr(end));
    let mut retrans: BTreeMap<String, u64> = BTreeMap::new();
    for (ck, (c, v1)) in &r1 {
        if let Some((_, v0)) = r0.get(ck) {
            *retrans.entry(c.clone()).or_default() += u64::from(v1.saturating_sub(*v0));
        }
    }
    for w in controllers.values_mut() {
        w.tcp_retrans_segments = retrans.get(&w.controller).copied();
    }

    // Level 2 stages
    let (stages, l2_quality) = match p.prof {
        Some((d, prof)) => {
            let mut groups = Vec::new();
            for (k, g) in &prof.groups {
                let (controller, key) = match k.instance {
                    Some(i) => match names.get(&i) {
                        Some((n, key)) => (Some(n.to_string()), Some(key.clone())),
                        None => continue,
                    },
                    None => (None, None),
                };
                groups.push(StageGroup {
                    controller,
                    key,
                    op: k.op.as_str().into(),
                    variant: k.variant.as_str().into(),
                    size_class: k.size_class,
                    complete: g.complete,
                    partial: g.excluded.partial,
                    excluded: g.excluded.retried + g.excluded.timed_out + g.excluded.error_status,
                    request: dist_of(&g.e2e),
                    stages: g
                        .stages
                        .iter()
                        .map(|(st, dd)| StageDist {
                            stage: st.id().into(),
                            family: st.family().to_string(),
                            label: st.label(k.variant).into(),
                            bound: st.bound().map(String::from),
                            dist: dist_of(dd),
                        })
                        .collect(),
                });
            }
            let h1 = d.health();
            let hd = p.h0.map(|h0| h1.since(&h0)).unwrap_or(h1);
            (
                Some(StageCapture {
                    sample_every: p.sample,
                    flavour: d.config.flavour.as_str().into(),
                    records: prof.records,
                    sum_check_failures: prof.sum_check_failures,
                    groups,
                }),
                health_map(&hd),
            )
        }
        None => (None, BTreeMap::new()),
    };

    let mut capabilities = vec![];
    let core = ctx.collector.bpf_status();
    capabilities.push(CapabilityStatus {
        capability: "nvme_latency".into(),
        status: core.state.into(),
        reason: core.reason.map(|r| r.as_str().into()),
    });
    let tcp = ctx.collector.tcp_bpf_status();
    capabilities.push(CapabilityStatus {
        capability: "transport_events".into(),
        status: tcp.state.into(),
        reason: tcp.reason.map(|r| r.as_str().into()),
    });
    capabilities.push(CapabilityStatus {
        capability: "stage_profile".into(),
        status: if stages.is_some() { "active".into() } else { "unavailable".into() },
        reason: p.notes.first().cloned(),
    });
    let mut filters = BTreeMap::new();
    for (k, v) in [
        ("controller", &ctx.filter.controller),
        ("subsystem", &ctx.filter.subsystem),
        ("namespace", &ctx.filter.namespace),
    ] {
        if let Some(v) = v {
            filters.insert(k.to_string(), v.clone());
        }
    }
    let cap = Capture {
        schema: SCHEMA.into(),
        tool: Tool { name: "nvmetea".into(), version: env!("CARGO_PKG_VERSION").into() },
        host: Host {
            hostname: p.host.hostname.clone(),
            boot_id: p.host.boot_id.clone(),
            kernel_release: p.host.kernel_release.clone(),
            distribution: match (&p.host.os_name, &p.host.os_version) {
                (Some(n), Some(v)) => Some(format!("{n} {v}")),
                (Some(n), None) => Some(n.clone()),
                _ => None,
            },
            arch: p.host.arch.clone(),
        },
        boundary_signature: p.sig,
        capabilities,
        filters,
        start_unix_s: p.start_wall,
        end_unix_s: p.end_wall,
        duration_s: p.duration_s,
        interval_s: p.interval_s,
        topology_start: topology(&start.snap.topology, ctx),
        topology_end: topology(&end.snap.topology, ctx),
        transitions: p.transitions,
        intervals: p.intervals,
        latency,
        queues,
        controllers: controllers.into_values().collect(),
        stages,
        events: p.events,
        quality: Quality { level1: l1_quality, level2: l2_quality, events_dropped: p.events_dropped },
        self_overhead: Overhead { cpu_seconds: cpu_seconds(), max_rss_bytes: max_rss() },
    };
    let json = serde_json::to_vec(&cap)?;
    std::fs::write(tmp, &json).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(tmp, out).with_context(|| format!("renaming to {}", out.display()))?;
    if ctx.json {
        println!("{}", serde_json::json!({"capture": out, "bytes": json.len()}));
    } else {
        eprintln!(
            "wrote {} ({:.1} KiB): {} intervals, {} latency groups, {} stage groups, {} events{}",
            out.display(),
            json.len() as f64 / 1024.0,
            cap.intervals.len(),
            cap.latency.len(),
            cap.stages.as_ref().map(|s| s.groups.len()).unwrap_or(0),
            cap.events.len(),
            if cap.quality.events_dropped > 0 {
                format!(" ({} dropped)", cap.quality.events_dropped)
            } else {
                String::new()
            }
        );
        for n in &p.notes {
            eprintln!("note: {n}");
        }
    }
    Ok(())
}
