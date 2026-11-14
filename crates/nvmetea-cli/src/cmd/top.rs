//! `nvmetea top`: refreshing summary. Kernel uevents trigger an immediate
//! rescan so controller transitions are logged as they happen.

use crate::Ctx;
use crate::cmd::controllers::{FOOTNOTE, latency_table, rows, table};
use crate::fmt::{Table, count, emit, is_tty, lat, mib_s, ms, obs};
use crate::sample::Sampled;
use nvmetea_bpf::core::{CoreEvent, ctrl_state_name};
use nvmetea_core::Obs;
use nvmetea_core::engine::namespace_intervals;
use nvmetea_core::model::NsAccounting;
use nvmetea_core::model::Op;
use nvmetea_core::nvme_engine::{NvmeIntervals, nvme_intervals};
use nvmetea_topology::tracker::Change;
use nvmetea_topology::uevent::UeventListener;
use nvmetea_topology::{Transition, TransitionSource};
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Serialize, Clone)]
struct EventLine {
    at: f64,
    text: String,
}

pub(crate) fn ts(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn clock(t: f64) -> String {
    let secs = t as i64;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointers to a time_t and a tm.
    unsafe { libc::localtime_r(&secs, &mut tm) };
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

pub(crate) fn transition_text(t: &Transition) -> String {
    match &t.change {
        Change::Added { state } => format!("{} appeared (gen {}, {})", t.controller, t.generation, state.as_str()),
        Change::Removed { last_state } => {
            format!("{} removed (gen {}, was {})", t.controller, t.generation, last_state.as_str())
        }
        Change::State { from, to } => {
            format!("{} {} -> {} (gen {})", t.controller, from.as_str(), to.as_str(), t.generation)
        }
    }
}

pub fn run(ctx: &mut Ctx, interval: f64, count_limit: Option<u64>) -> anyhow::Result<()> {
    let interval = interval.clamp(0.25, 3600.0);
    let (tx, rx) = mpsc::channel::<nvmetea_topology::uevent::Uevent>();
    let uevents_ok = match UeventListener::open() {
        Ok(l) => {
            std::thread::spawn(move || {
                loop {
                    match l.recv(Duration::from_millis(500)) {
                        Ok(Some(ev)) if ev.is_nvme_relevant() => {
                            if tx.send(ev).is_err() {
                                return;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => return,
                    }
                }
            });
            true
        }
        Err(_) => false,
    };
    let mut events: VecDeque<EventLine> = VecDeque::new();
    let mut recent_tcp: VecDeque<nvmetea_core::model::TcpEvent> = VecDeque::new();
    let push = |events: &mut VecDeque<EventLine>, at: f64, text: String| {
        if events.len() == 200 {
            events.pop_front();
        }
        events.push_back(EventLine { at, text });
    };
    let t0 = nvmetea_topology::scan(&ctx.collector.sys);
    ctx.filter.validate(&t0)?;
    ctx.collector.enable_all_bpf(&t0);
    crate::cmd::queues::warn_bpf(ctx);
    let first = ctx.collector.sample(TransitionSource::Poll);
    let mut prev: Sampled = first;
    let mut n = 0u64;
    loop {
        // wait for the interval, or a relevant uevent
        let deadline = Instant::now() + Duration::from_secs_f64(interval);
        let mut source = TransitionSource::Poll;
        if let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match rx.recv_timeout(left) {
                Ok(first) => {
                    // A reconnect emits a burst (the controller plus a change on every
                    // namespace); collect it before sampling so one transition does not
                    // produce a run of millisecond-long rate intervals.
                    let mut batch = vec![(ts(SystemTime::now()), first)];
                    let until = Instant::now() + UEVENT_COALESCE;
                    while let Some(l) = until.checked_duration_since(Instant::now()) {
                        match rx.recv_timeout(l) {
                            Ok(ev) => batch.push((ts(SystemTime::now()), ev)),
                            Err(_) => break,
                        }
                    }
                    for (at, ev) in batch {
                        let name = ev.devname().unwrap_or(ev.devpath.as_str()).to_string();
                        let extra: Vec<String> = ev
                            .env
                            .iter()
                            .filter(|(k, _)| k.starts_with("NVME_"))
                            .map(|(k, v)| format!("{k}={v}"))
                            .collect();
                        push(&mut events, at, format!("uevent {} {} {}", ev.action, name, extra.join(" ")));
                    }
                    source = TransitionSource::Uevent;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => std::thread::sleep(left),
            }
        }
        let cur = ctx.collector.sample(source);
        for t in &cur.transitions {
            push(&mut events, ts(t.at), format!("{} [{:?}]", transition_text(t), t.source));
        }
        for e in &cur.tcp_events {
            if recent_tcp.len() == 20_000 {
                recent_tcp.pop_front();
            }
            recent_tcp.push_back(e.clone());
            push(
                &mut events,
                mono_to_wall(e.t_ns),
                format!("tcp nvme{}/q{}: {}", e.instance, e.qid, e.kind.describe()),
            );
        }
        let tcp_on = matches!(ctx.collector.tcp_bpf, crate::sample::TcpBpf::Active(_));
        let rtts = conn_rtts(&cur);
        for e in &cur.events {
            let mut text = event_text(e);
            if let CoreEvent::Slow(sc) = e {
                text.push_str(&transport_context(sc, &recent_tcp, tcp_on, rtts.get(&(sc.inst, sc.qid)).copied()));
            }
            push(&mut events, mono_to_wall(event_ns(e)), text);
        }
        let nvme = match (&prev.nvme, &cur.nvme) {
            (Some(a), Some(b)) => Some(nvme_intervals(a, &prev.snap.topology, b, &cur.snap.topology)),
            _ => None,
        };
        if let Some(v) = &nvme {
            adapt_slow_threshold(ctx, v);
        }
        render(ctx, &prev, &cur, &events, uevents_ok, nvme.as_ref())?;
        prev = cur;
        n += 1;
        if count_limit.is_some_and(|c| n >= c) {
            return Ok(());
        }
    }
}

fn mono_ns() -> u64 {
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid timespec pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}

/// BPF timestamps are CLOCK_MONOTONIC; convert for display.
pub(crate) fn mono_to_wall(t_ns: u64) -> f64 {
    let now_wall = ts(SystemTime::now());
    now_wall - (mono_ns().saturating_sub(t_ns)) as f64 / 1e9
}

pub(crate) fn event_ns(e: &CoreEvent) -> u64 {
    match e {
        CoreEvent::Slow(s) => s.t_blk_done_ns,
        CoreEvent::State(s) => s.t_ns,
    }
}

fn ns_us(v: Option<u64>) -> String {
    lat(&match v {
        Some(x) => Obs::measured(x as f64 / 1e3, &[]),
        None => Obs::unavailable(nvmetea_core::Reason::MissingInterface),
    })
}

pub(crate) fn event_text(e: &CoreEvent) -> String {
    match e {
        CoreEvent::Slow(s) => format!(
            "slow {} nvme{}/q{} nsid {} {}KiB: request {} (A {}, cmd {}, E2 {}) cpu {}->{}{}",
            s.op.as_str(),
            s.inst,
            s.qid,
            s.nsid,
            s.bytes / 1024,
            ns_us(s.request_ns()),
            ns_us(s.stage_a_ns()),
            ns_us(s.command_ns()),
            ns_us(s.stage_e2_ns()),
            s.submit_cpu,
            s.complete_cpu,
            if s.nvme_status != 0 { format!(" status {:#x}", s.nvme_status) } else { String::new() },
        ),
        CoreEvent::State(c) => format!(
            "nvme{} {} -> {} [bpf{}]",
            c.inst,
            ctrl_state_name(c.old_state),
            ctrl_state_name(c.new_state),
            if c.accepted { "" } else { ", rejected" }
        ),
    }
}

/// Wait this long after a uevent for the rest of its burst before sampling.
const UEVENT_COALESCE: Duration = Duration::from_millis(100);

/// Smoothed and minimum RTT (µs) of each queue's connection at this sample
/// (sock_diag `tcp_info`, joined to the queue by cookie).
fn conn_rtts(s: &Sampled) -> std::collections::BTreeMap<(u32, u16), (u32, Option<u32>)> {
    let Ok(qs) = &s.queue_sockets else {
        return Default::default();
    };
    let info: std::collections::BTreeMap<u64, &nvmetea_core::model::TcpInfo> =
        s.snap.sockets.iter().filter_map(|t| Some((t.cookie?, t.info.as_ref()?))).collect();
    qs.iter().filter_map(|q| info.get(&q.cookie).map(|i| ((q.instance, q.qid), (i.rtt_us, i.min_rtt_us)))).collect()
}

/// Transport context for a slow command: the events on its own queue
/// connection within ±50 ms of its lifetime, and that connection's RTT at the
/// sample. Delay without loss leaves no events, only RTT. Shown as context
/// next to the command; correlation is not presented as cause.
fn transport_context(
    sc: &nvmetea_bpf::core::SlowCommand,
    recent: &VecDeque<nvmetea_core::model::TcpEvent>,
    tcp_on: bool,
    rtt: Option<(u32, Option<u32>)>,
) -> String {
    if !tcp_on {
        return String::new();
    }
    let us = |v: u32| lat(&Obs::measured(v as f64, &[]));
    let rtt = match rtt {
        Some((srtt, Some(min))) => format!(" | conn srtt {} (min {})", us(srtt), us(min)),
        Some((srtt, None)) => format!(" | conn srtt {}", us(srtt)),
        None => String::new(),
    };
    let lo = sc.t_start_ns.unwrap_or(sc.t_setup_ns).saturating_sub(50_000_000);
    let hi = sc.t_blk_done_ns + 50_000_000;
    let near: Vec<&nvmetea_core::model::TcpEvent> =
        recent.iter().filter(|e| e.instance == sc.inst && e.qid == sc.qid && e.t_ns >= lo && e.t_ns <= hi).collect();
    if near.is_empty() {
        return format!("{rtt} | no TCP events on this queue's connection");
    }
    let mut kinds: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for e in near {
        *kinds.entry(e.kind.describe()).or_default() += 1;
    }
    let parts: Vec<String> = kinds.into_iter().map(|(k, n)| format!("{n}x {k}")).collect();
    format!("{rtt} | TCP on this queue's connection: {}", parts.join(", "))
}

/// Slow-command threshold = max(1 ms, worst p99.9 request latency of the
/// interval), so roughly the slowest 0.1 % are reported (BPF rate-limits too).
fn adapt_slow_threshold(ctx: &mut Ctx, v: &NvmeIntervals) {
    let mut n = 0;
    let mut worst = 0.0f64;
    for c in &v.controllers {
        for o in c.ops.iter().filter(|o| matches!(o.op, Op::Read | Op::Write)) {
            n += o.request.samples;
            if let Some(p) = o.request.p999_us.value {
                worst = worst.max(p);
            }
        }
    }
    if n < 1000 {
        return;
    }
    let ns = ((worst * 1e3) as u64).max(1_000_000);
    if let Some(c) = ctx.collector.bpf_mut() {
        let old = c.config.slow_ns;
        if old == 0 || ns.abs_diff(old) * 10 > old {
            c.set_slow_ns(ns);
        }
    }
}

#[derive(Serialize)]
struct NsRow {
    name: String,
    accounting: NsAccounting,
    paths: usize,
    io: nvmetea_core::model::BlockRates,
}

#[derive(Serialize)]
struct TopJson<'a> {
    schema: &'static str,
    t: f64,
    interval_s: f64,
    controllers: Vec<crate::cmd::controllers::CtrlRow>,
    namespaces: Vec<NsRow>,
    events: Vec<EventLine>,
    tcp: &'a crate::sample::TcpMeta,
    bpf: crate::sample::BpfStatus,
    nvme: Option<&'a NvmeIntervals>,
}

fn render(
    ctx: &Ctx,
    prev: &Sampled,
    cur: &Sampled,
    events: &VecDeque<EventLine>,
    uevents_ok: bool,
    nvme: Option<&NvmeIntervals>,
) -> anyhow::Result<()> {
    let topo = &cur.snap.topology;
    let crow = rows(Some(prev), cur, ctx);
    let nsrows: Vec<NsRow> = namespace_intervals(Some(&prev.snap), &cur.snap)
        .into_iter()
        .filter(|n| topo.namespace(&n.name).is_some_and(|ns| ctx.filter.namespace(ns, topo)))
        .map(|n| NsRow {
            paths: topo.namespace(&n.name).map(|x| x.paths.len()).unwrap_or(0),
            name: n.name,
            accounting: n.accounting,
            io: n.io,
        })
        .collect();
    let dt = cur.snap.taken.saturating_duration_since(prev.snap.taken).as_secs_f64();
    if ctx.json {
        let new: Vec<EventLine> = events.iter().filter(|e| e.at >= ts(prev.snap.wall)).cloned().collect();
        let mut s = serde_json::to_string(&TopJson {
            schema: "nvmetea.top/1",
            t: ts(cur.snap.wall),
            interval_s: dt,
            controllers: crow,
            namespaces: nsrows,
            events: new,
            tcp: &cur.tcp,
            bpf: ctx.collector.bpf_status(),
            nvme,
        })?;
        s.push('\n');
        emit(&s);
        return Ok(());
    }
    let mut out = String::new();
    if is_tty() {
        out.push_str("\x1b[H\x1b[2J");
    }
    let h = nvmetea_bpf::discovery::host_identity();
    out.push_str(&format!(
        "nvmetea top — {} — kernel {} — {} — interval {:.1}s — TCP: {:?}{} — uevents: {}\n\n",
        h.hostname.as_deref().unwrap_or("?"),
        h.kernel_release.as_deref().unwrap_or("?"),
        clock(ts(cur.snap.wall)),
        dt,
        cur.tcp.backend,
        if cur.tcp.degraded.is_some() { " (degraded)" } else { "" },
        if uevents_ok { "on" } else { "unavailable (polling only)" },
    ));
    out.push_str(&table(&crow).render());
    out.push('\n');
    match nvme {
        Some(v) => {
            let keep: Vec<_> = v
                .controllers
                .iter()
                .filter(|c| topo.controller(&c.controller).is_some_and(|x| ctx.filter.controller(x)))
                .collect();
            out.push_str("LATENCY (BPF)\n");
            out.push_str(&latency_table(&keep, topo).render());
            out.push('\n');
        }
        None => {
            let st = ctx.collector.bpf_status();
            out.push_str(&format!(
                "LATENCY: unavailable ({}{})\n\n",
                st.reason.map(|r| r.as_str()).unwrap_or(st.state),
                st.reason.map(|r| format!(": {}", r.remediation())).unwrap_or_default()
            ));
        }
    }
    let ns_p = |name: &str, op: Op, p99: bool| -> String {
        let Some(v) = nvme else { return "-".into() };
        v.namespaces
            .iter()
            .find(|n| n.namespace == name && n.op == op)
            .map(|n| lat(if p99 { &n.request.p99_us } else { &n.request.p50_us }))
            .unwrap_or_else(|| "-".into())
    };
    let mut t = Table::new(
        &[
            "NAMESPACE",
            "COUNTED BY",
            "PATHS",
            "r/s",
            "w/s",
            "rMiB/s",
            "wMiB/s",
            "r_ms",
            "w_ms",
            "INFL",
            "R p50",
            "R p99",
            "W p50",
            "W p99",
        ],
        2,
    );
    for n in &nsrows {
        t.push(vec![
            n.name.clone(),
            match n.accounting {
                NsAccounting::Device => "device".into(),
                NsAccounting::SumOfPaths => "sum of paths".into(),
                NsAccounting::Unavailable => "-".into(),
            },
            n.paths.to_string(),
            count(&n.io.read_iops),
            count(&n.io.write_iops),
            mib_s(&n.io.read_bytes_per_s),
            mib_s(&n.io.write_bytes_per_s),
            ms(&n.io.read_await_ms),
            ms(&n.io.write_await_ms),
            obs(&n.io.in_flight),
            ns_p(&n.name, Op::Read, false),
            ns_p(&n.name, Op::Read, true),
            ns_p(&n.name, Op::Write, false),
            ns_p(&n.name, Op::Write, true),
        ]);
    }
    out.push_str(&t.render());
    out.push_str("\nEVENTS\n");
    if events.is_empty() {
        out.push_str("  (none since start)\n");
    }
    for e in events.iter().rev().take(8) {
        out.push_str(&format!("  {}  {}\n", clock(e.at), e.text));
    }
    out.push('\n');
    out.push_str(FOOTNOTE);
    out.push('\n');
    emit(&out);
    Ok(())
}
