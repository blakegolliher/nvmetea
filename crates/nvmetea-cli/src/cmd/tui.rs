//! `nvmetea` (no subcommand, on a terminal): the TUI.
//!
//! A sampler thread owns the collectors (they are not `Send`, so they are
//! created in that thread), samples every interval, builds a
//! `nvmetea_tui::View` and sends it to the UI thread, which draws the newest
//! one and sends back control messages (interval, profiling, filter).

use crate::cmd::profile::{skip_set, start_driver};
use crate::cmd::top::{event_ns, event_text, mono_to_wall, transition_text, ts};
use crate::filter::Filter;
use crate::fmt::{count, lat, mib_s, obs, pct};
use crate::sample::{Bpf, Collector, Sampled, TcpBpf};
use nvmetea_bpf::driver::{DriverCollector, DriverConfig, DriverEvent, Flavour};
use nvmetea_core::Obs;
use nvmetea_core::engine::{controller_intervals, namespace_intervals, queue_connections};
use nvmetea_core::model::Op;
use nvmetea_core::nvme_engine::{NvmeIntervals, nvme_intervals};
use nvmetea_profile::{FAMILIES, Profile, size_class_label};
use nvmetea_topology::{SysRoot, TransitionSource};
use nvmetea_tui::model::{Breakdown, Cell, EventView, SpanView, TableData, TimelineView, View};
use nvmetea_tui::{Control, term};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

pub struct Config {
    pub sys: SysRoot,
    pub proc_root: PathBuf,
    pub use_sock_diag: bool,
    pub no_bpf: bool,
    pub filter: Filter,
    pub interval: f64,
}

fn clock(at: f64) -> String {
    let secs = at as libc::time_t;
    // SAFETY: localtime_r writes into the provided struct only.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointers to a time_t and a tm.
    unsafe { libc::localtime_r(&secs, &mut tm) };
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

fn c<T>(o: &Obs<T>, f: impl Fn(&Obs<T>) -> String) -> Cell {
    match (&o.value, o.reason) {
        (None, Some(r)) => Cell::unavailable(r.as_str()),
        (None, None) => Cell::unavailable("unavailable"),
        (Some(_), _) => Cell::new(f(o)),
    }
}

struct Profiler {
    drv: DriverCollector,
    prof: Profile,
    since: f64,
    flavour: Flavour,
}

struct State {
    collector: Collector,
    filter: Filter,
    interval: Duration,
    events: VecDeque<EventView>,
    profiler: Option<Profiler>,
    profile_note: Option<String>,
    host: String,
}

impl State {
    fn push_event(&mut self, at: f64, kind: &str, text: String) {
        if self.events.len() >= 1000 {
            self.events.pop_front();
        }
        self.events.push_back(EventView { at: clock(at), kind: kind.into(), text });
    }

    fn start_profile(&mut self, topo: &nvmetea_core::model::Topology) {
        let flavour = if nvmetea_bpf::preflight::check(Duration::from_secs(2)).fentry_ok() {
            Flavour::Fentry
        } else {
            Flavour::Kprobe
        };
        let mut cfg = DriverConfig::from_topology(topo, flavour, 100);
        cfg.skip = skip_set(&self.collector.proc_root, flavour);
        let r = start_driver(&cfg).or_else(|_| {
            cfg.flavour = Flavour::Kprobe;
            cfg.skip = skip_set(&self.collector.proc_root, Flavour::Kprobe);
            start_driver(&cfg)
        });
        match r {
            Ok(drv) => {
                self.profiler =
                    Some(Profiler { drv, prof: Profile::new(20), since: ts(SystemTime::now()), flavour: cfg.flavour });
                self.profile_note = None;
            }
            Err(e) => self.profile_note = Some(format!("stage profiling unavailable: {e}")),
        }
    }

    fn drain_profile(&mut self) {
        let mut timeouts = Vec::new();
        if let Some(p) = self.profiler.as_mut() {
            for e in p.drv.drain_events() {
                match e {
                    DriverEvent::Command(r) => p.prof.add(&r),
                    DriverEvent::Timeout(t) => timeouts.push(t),
                }
            }
        }
        for t in timeouts {
            self.push_event(
                mono_to_wall(t.t_ns),
                "timeout",
                format!("nvme{}/q{} command {:#x} opcode {:#x} timed out", t.instance, t.qid, t.cid, t.opcode),
            );
        }
    }
}

fn levels(st: &State, s: &Sampled) -> (String, Vec<String>) {
    let mut warn = Vec::new();
    let tcp = match s.tcp.backend {
        nvmetea_tcp::TcpBackend::SockDiag => "sock_diag",
        nvmetea_tcp::TcpBackend::ProcNet => "procnet (no RTT)",
        nvmetea_tcp::TcpBackend::None => "no TCP data",
    };
    let l1 = match &st.collector.bpf {
        Bpf::Active(_) => "L1 BPF".to_string(),
        Bpf::Disabled => "L1 off (--no-bpf)".to_string(),
        Bpf::Unavailable { reason, detail } => {
            warn.push(format!("Level 1 unavailable ({}): {}", reason.as_str(), detail.lines().next().unwrap_or("")));
            "L1 unavailable".to_string()
        }
        Bpf::NotStarted => "L1 not started".to_string(),
    };
    let l3 = match &st.collector.tcp_bpf {
        TcpBpf::Active(_) => "L3 TCP".to_string(),
        TcpBpf::Unavailable { reason, .. } => {
            warn.push(format!(
                "Level 3 unavailable ({}): queue ↔ connection mapping by endpoint only",
                reason.as_str()
            ));
            "L3 unavailable".to_string()
        }
        _ => "L3 off".to_string(),
    };
    let l2 = match &st.profiler {
        Some(p) => format!("L2 profile 1 in 100 ({})", p.flavour.as_str()),
        None => "L2 profile off (p)".to_string(),
    };
    if let Some(e) = &s.disk_error {
        warn.push(e.clone());
    }
    if let Some(e) = &s.tcp.error {
        warn.push(format!("TCP: {e}"));
    }
    if let Some(n) = &st.profile_note {
        warn.push(n.clone());
    }
    if let Some(p) = &st.profiler {
        for (id, why) in &p.drv.dropped {
            warn.push(format!("probe {id} not running: {}", why.lines().next().unwrap_or("")));
        }
    }
    (format!("L0 sysfs+diskstats+{tcp} · {l1} · {l3} · {l2}"), warn)
}

fn build(st: &State, a: &Sampled, b: &Sampled) -> View {
    let topo = &b.snap.topology;
    let keep = |name: &str| topo.controller(name).is_some_and(|c| st.filter.controller(c));
    let civ = controller_intervals(Some(&a.snap), &b.snap);
    let nv: Option<NvmeIntervals> = match (&a.nvme, &b.nvme) {
        (Some(x), Some(y)) => Some(nvme_intervals(x, &a.snap.topology, y, &b.snap.topology)),
        _ => None,
    };
    let l1_reason = match &st.collector.bpf {
        Bpf::Unavailable { reason, .. } => reason.as_str(),
        Bpf::Disabled => "disabled_by_user",
        _ => "first_interval",
    };
    let (levels, warnings) = levels(st, b);

    // overview
    let mut overview = TableData::new(
        &[
            "CTRL", "STATE", "TARGET", "R IOPS", "W IOPS", "R MiB/s", "W MiB/s", "R p99", "W p99", "INFL", "RTT",
            "RETR/s",
        ],
        3,
    );
    for ci in civ.iter().filter(|c| keep(&c.name)) {
        let ctrl = topo.controller(&ci.name);
        let target = ctrl
            .and_then(|c| c.address.as_ref())
            .map(|a| format!("{}:{}", a.traddr.as_deref().unwrap_or("?"), a.trsvcid.as_deref().unwrap_or("?")))
            .unwrap_or_default();
        let n = nv.as_ref().and_then(|v| v.controllers.iter().find(|x| x.controller == ci.name));
        let p99 = |op: Op| match n.and_then(|n| n.ops.iter().find(|o| o.op == op)) {
            Some(o) => c(&o.request.p99_us, lat),
            None if n.is_some() => Cell::unavailable("no_samples"),
            None => Cell::unavailable(l1_reason),
        };
        let tcp = ci.tcp.as_ref();
        overview.push(
            ci.name.clone(),
            vec![
                ci.name.clone().into(),
                ci.state.as_str().into(),
                target.into(),
                c(&ci.io.read_iops, count),
                c(&ci.io.write_iops, count),
                c(&ci.io.read_bytes_per_s, mib_s),
                c(&ci.io.write_bytes_per_s, mib_s),
                p99(Op::Read),
                p99(Op::Write),
                n.map(|n| c(&n.inflight, obs)).unwrap_or_else(|| Cell::unavailable(l1_reason)),
                tcp.map(|t| c(&t.rtt_median_us, |o| lat(&Obs::derived(o.value.unwrap_or(0) as f64, &[]))))
                    .unwrap_or_else(|| Cell::unavailable("no_tcp_data")),
                tcp.map(|t| c(&t.retrans_segments_per_s, count)).unwrap_or_else(|| Cell::unavailable("no_tcp_data")),
            ],
        );
    }

    // namespaces
    let mut namespaces =
        TableData::new(&["NAMESPACE", "PATHS", "R IOPS", "W IOPS", "R MiB/s", "W MiB/s", "R p99", "W p99"], 2);
    let niv = namespace_intervals(Some(&a.snap), &b.snap);
    for ns in topo.namespaces.iter().filter(|n| st.filter.namespace(n, topo)) {
        let io = niv.iter().find(|x| x.name == ns.name);
        let usable = crate::cmd::status::usable_paths(ns, topo);
        let lat_of = |op: Op| match &nv {
            Some(v) => v
                .namespaces
                .iter()
                .find(|x| x.namespace == ns.name && x.op == op)
                .map(|x| c(&x.request.p99_us, lat))
                .unwrap_or_else(|| Cell::unavailable("no_samples")),
            None => Cell::unavailable(l1_reason),
        };
        namespaces.push(
            ns.name.clone(),
            vec![
                ns.name.clone().into(),
                format!("{usable}/{}", ns.paths.len()).into(),
                io.map(|x| c(&x.io.read_iops, count)).unwrap_or_else(|| Cell::unavailable("no_diskstats")),
                io.map(|x| c(&x.io.write_iops, count)).unwrap_or_else(|| Cell::unavailable("no_diskstats")),
                io.map(|x| c(&x.io.read_bytes_per_s, mib_s)).unwrap_or_else(|| Cell::unavailable("no_diskstats")),
                io.map(|x| c(&x.io.write_bytes_per_s, mib_s)).unwrap_or_else(|| Cell::unavailable("no_diskstats")),
                lat_of(Op::Read),
                lat_of(Op::Write),
            ],
        );
    }

    // subsystems tree
    let mut subsystems = TableData::new(&["OBJECT", "STATE / ANA", "DETAIL"], 3);
    for s in topo.subsystems.iter().filter(|s| st.filter.subsystem(s, topo)) {
        subsystems.push(
            s.name.clone(),
            vec![
                s.name.clone().into(),
                "".into(),
                format!("{} iopolicy={}", s.nqn.as_deref().unwrap_or(""), s.iopolicy.as_deref().unwrap_or("-")).into(),
            ],
        );
        for ns in topo.namespaces.iter().filter(|n| n.subsystem.as_deref() == Some(s.name.as_str())) {
            subsystems.push(
                ns.name.clone(),
                vec![
                    format!("  {}", ns.name).into(),
                    "".into(),
                    format!("nsid {} {}", opt(ns.nsid), ns.wwid.as_deref().unwrap_or("")).into(),
                ],
            );
            for p in &ns.paths {
                let cs = topo.controller(&p.controller).map(|c| c.state.as_str().to_string()).unwrap_or_default();
                subsystems.push(
                    p.name.clone(),
                    vec![
                        format!("    {}", p.name).into(),
                        format!("{cs}{}", p.ana_state.as_deref().map(|a| format!(" / {a}")).unwrap_or_default()).into(),
                        format!("via {}", p.controller).into(),
                    ],
                );
            }
        }
    }

    // controllers + details
    let mut controllers = TableData::new(
        &["CTRL", "STATE", "GEN", "EPOCH", "TRANSPORT", "TARGET", "IO QUEUES", "DEPTH", "KATO", "CONNS"],
        6,
    );
    let mut details = std::collections::BTreeMap::new();
    for ctrl in topo.controllers.iter().filter(|c| st.filter.controller(c)) {
        let a = ctrl.address.as_ref();
        let conns = b.assoc.by_controller.get(&ctrl.name).map(|cs| {
            let est = cs
                .sockets
                .iter()
                .filter_map(|&i| b.snap.sockets.get(i))
                .filter(|x| x.state == nvmetea_core::model::TcpState::Established)
                .count();
            format!("{est}/{}", cs.expected.map(|e| e.to_string()).unwrap_or("?".into()))
        });
        controllers.push(
            ctrl.name.clone(),
            vec![
                ctrl.name.clone().into(),
                ctrl.state.as_str().into(),
                opt(ctrl.generation).into(),
                opt(ctrl.epoch).into(),
                ctrl.transport.clone().unwrap_or_default().into(),
                a.map(|a| format!("{}:{}", a.traddr.as_deref().unwrap_or("?"), a.trsvcid.as_deref().unwrap_or("?")))
                    .unwrap_or_default()
                    .into(),
                opt(ctrl.io_queues()).into(),
                opt(ctrl.io_queue_depth()).into(),
                ctrl.kato_s.map(|k| format!("{k}s")).unwrap_or("-".into()).into(),
                conns.map(Cell::new).unwrap_or_else(|| Cell::unavailable("no_tcp_data")),
            ],
        );
        let mut kv: Vec<(String, String)> = vec![
            ("state".into(), ctrl.state.as_str().into()),
            ("generation / epoch".into(), format!("{} / {}", opt(ctrl.generation), opt(ctrl.epoch))),
            (
                "subsystem".into(),
                format!("{} {}", ctrl.subsystem.as_deref().unwrap_or("-"), ctrl.subsysnqn.as_deref().unwrap_or("")),
            ),
            ("transport".into(), ctrl.transport.clone().unwrap_or_default()),
        ];
        if let Some(a) = a {
            kv.push(("address".into(), a.raw.clone()));
        }
        kv.push(("queues / depth".into(), format!("{} / {}", opt(ctrl.io_queues()), opt(ctrl.io_queue_depth()))));
        kv.push(("kato".into(), ctrl.kato_s.map(|k| format!("{k}s")).unwrap_or("-".into())));
        kv.push(("ctrl_loss_tmo".into(), ctrl.ctrl_loss_tmo.clone().unwrap_or("-".into())));
        kv.push(("reconnect_delay".into(), ctrl.reconnect_delay.clone().unwrap_or("-".into())));
        kv.push(("fast_io_fail_tmo".into(), ctrl.fast_io_fail_tmo.clone().unwrap_or("-".into())));
        kv.push((
            "model / firmware".into(),
            format!("{} / {}", ctrl.model.as_deref().unwrap_or("-"), ctrl.firmware_rev.as_deref().unwrap_or("-")),
        ));
        if let Some(ci) = civ.iter().find(|x| x.name == ctrl.name) {
            if let Some(t) = &ci.tcp {
                kv.push((
                    "TCP RTT min/median/max".into(),
                    format!("{} / {} / {} us", obs(&t.rtt_min_us), obs(&t.rtt_median_us), obs(&t.rtt_max_us)),
                ));
                kv.push(("TCP retrans seg/s".into(), count(&t.retrans_segments_per_s)));
            }
        }
        details.insert(ctrl.name.clone(), kv);
    }

    // queues and latency (Level 1)
    let conns = match &b.queue_sockets {
        Ok(qs) => {
            let prev_qs = a.queue_sockets.as_ref().ok().map(|v| v.as_slice());
            let ev = b.sock_events.as_ref().map(|cur| (a.sock_events.as_ref(), cur));
            queue_connections(Some(&a.snap), &b.snap, (prev_qs, qs), ev)
        }
        Err(_) => Vec::new(),
    };
    let mut queues = TableData::new(
        &[
            "CTRL", "QID", "OP", "IOPS", "MiB/s", "INFL", "MAX/QD", "CMD p50", "CMD p99", "REQ p99", "ERR/s", "IO_CPU",
            "RTT",
        ],
        3,
    );
    let mut latency = TableData::new(
        &[
            "CTRL",
            "OP",
            "N",
            "CMD mean",
            "CMD p50",
            "CMD p99",
            "CMD p99.9",
            "REQ mean",
            "REQ p50",
            "REQ p99",
            "REQ p99.9",
            "A p50",
            "E2 p50",
        ],
        2,
    );
    if let Some(v) = &nv {
        let mut qs: Vec<_> = v.queues.iter().filter(|q| keep(&q.controller)).collect();
        qs.sort_by_key(|q| (nvmetea_topology::names::natural_key(&q.controller), q.qid));
        for q in qs {
            let conn = conns.iter().find(|x| x.controller == q.controller && x.qid == q.qid && !x.closed);
            let maxqd = format!("{}/{}", obs(&q.inflight_max), q.depth.map(|d| d.to_string()).unwrap_or("-".into()));
            for o in q.ops.iter().filter(|o| o.completed_per_s.value.unwrap_or(0.0) > 0.0 || q.qid == 0) {
                queues.push(
                    format!("{}/q{} {}", q.controller, q.qid, o.op.as_str()),
                    vec![
                        q.controller.clone().into(),
                        q.qid.to_string().into(),
                        o.op.as_str().into(),
                        c(&o.completed_per_s, count),
                        c(&o.bytes_per_s, mib_s),
                        c(&q.inflight, obs),
                        maxqd.clone().into(),
                        c(&o.command.p50_us, lat).dim(o.command.samples < 100),
                        c(&o.command.p99_us, lat).dim(o.command.samples < 100),
                        c(&o.request.p99_us, lat).dim(o.request.samples < 100),
                        c(&o.nvme_errors_per_s, count),
                        conn.map(|x| x.io_cpu.map(|c| c.to_string()).unwrap_or("unbound".into()))
                            .map(Cell::new)
                            .unwrap_or_else(|| Cell::unavailable("no_queue_socket")),
                        conn.map(|x| c(&x.rtt_us, obs)).unwrap_or_else(|| Cell::unavailable("no_queue_socket")),
                    ],
                );
            }
        }
        for ctl in v.controllers.iter().filter(|x| keep(&x.controller)) {
            for o in &ctl.ops {
                if o.command.samples == 0 && o.request.samples == 0 {
                    continue;
                }
                let low = o.request.samples < 100 && o.command.samples < 100;
                latency.push(
                    format!("{} {}", ctl.controller, o.op.as_str()),
                    vec![
                        ctl.controller.clone().into(),
                        o.op.as_str().into(),
                        o.command.samples.max(o.request.samples).to_string().into(),
                        c(&o.command.mean_us, lat).dim(low),
                        c(&o.command.p50_us, lat).dim(low),
                        c(&o.command.p99_us, lat).dim(low),
                        c(&o.command.p999_us, lat).dim(low),
                        c(&o.request.mean_us, lat).dim(low),
                        c(&o.request.p50_us, lat).dim(low),
                        c(&o.request.p99_us, lat).dim(low),
                        c(&o.request.p999_us, lat).dim(low),
                        c(&o.stage_a.p50_us, lat).dim(low),
                        c(&o.stage_e2.p50_us, lat).dim(low),
                    ],
                );
            }
        }
    } else {
        queues.note = Some(format!("Level 1 telemetry unavailable ({l1_reason}); run as root, or see `nvmetea probe`"));
        latency.note = queues.note.clone();
    }
    latency.note.get_or_insert_with(|| {
        "percentiles are histogram upper bucket edges (<= 12.5 % high); dim = fewer than 100 samples".into()
    });

    // TCP connections
    let mut tcp = TableData::new(
        &[
            "CTRL", "QID", "IO_CPU", "LPORT", "STATE", "RTT_us", "RTTVAR", "CWND", "UNACK", "RETR/s", "RETR_EV",
            "LOSS", "RECOV", "RST", "SNDQ", "BUSY%",
        ],
        5,
    );
    for x in conns.iter().filter(|x| keep(&x.controller)) {
        let iv = x.interval.as_ref();
        tcp.push(
            format!("{}/q{}", x.controller, x.qid),
            vec![
                x.controller.clone().into(),
                x.qid.to_string().into(),
                x.io_cpu.map(|c| c.to_string()).unwrap_or("unbound".into()).into(),
                x.local.port().to_string().into(),
                if x.closed { format!("CLOSED({})", x.state.as_str()) } else { x.state.as_str().to_string() }.into(),
                c(&x.rtt_us, obs),
                c(&x.rttvar_us, obs),
                c(&x.cwnd, obs),
                c(&x.unacked, obs),
                iv.map(|i| c(&i.retrans_segments_per_s, count)).unwrap_or_else(|| Cell::unavailable("first_interval")),
                c(&x.retransmit_events, obs),
                c(&x.loss_entries, obs),
                c(&x.recovery_entries, obs),
                c(&x.resets, obs),
                c(&x.send_q_bytes, obs),
                iv.map(|i| c(&i.busy_pct, pct)).unwrap_or_else(|| Cell::unavailable("first_interval")),
            ],
        );
    }
    if conns.is_empty() {
        tcp.note = Some(match &b.queue_sockets {
            Err((r, d)) => format!("queue ↔ connection table unavailable ({}): {d}", r.as_str()),
            Ok(_) => "no NVMe/TCP queue connections".into(),
        });
    }

    // breakdown
    let (breakdown, breakdown_hint) = match &st.profiler {
        None => (
            None,
            "Stage profiling (Level 2) is off. Press p to sample 1 in 100 commands and split their time into \
             A submission, B transmit, C remote/transport, D receive and E completion. It costs about 1 µs of CPU \
             per command while on (docs/validation/phase-3-driver.md)."
                .to_string(),
        ),
        Some(p) => {
            let mut groups: Vec<(&nvmetea_profile::GroupKey, &nvmetea_profile::Group)> =
                p.prof.groups.iter().filter(|(k, g)| k.instance.is_none() && g.complete > 0).collect();
            groups.sort_by_key(|g| std::cmp::Reverse(g.1.complete));
            let gt: Vec<(String, TableData)> = groups
                .iter()
                .map(|(k, g)| {
                    let mut t = TableData::new(&["STAGE", "WHAT", "MEAN", "SHARE", "p50", "p99"], 2);
                    let e2e = g.e2e.mean_ns();
                    for (stg, d) in &g.stages {
                        let mark = match stg.bound() {
                            Some("upper bound") => " ^",
                            Some("lower bound") => " v",
                            _ => "",
                        };
                        let m = d.mean_ns();
                        t.push(
                            stg.id(),
                            vec![
                                stg.id().into(),
                                format!("{}{mark}", stg.label(k.variant)).into(),
                                m.map(|v| nvmetea_tui::ui::fmt_us(v / 1e3)).unwrap_or("-".into()).into(),
                                match (m, e2e) {
                                    (Some(m), Some(e)) if e > 0.0 => format!("{:.1}%", 100.0 * m / e),
                                    _ => "-".into(),
                                }
                                .into(),
                                d.hist
                                    .percentile(0.5)
                                    .map(|x| nvmetea_tui::ui::fmt_us(x.ns as f64 / 1e3))
                                    .unwrap_or("-".into())
                                    .into(),
                                d.hist
                                    .percentile(0.99)
                                    .map(|x| nvmetea_tui::ui::fmt_us(x.ns as f64 / 1e3))
                                    .unwrap_or("-".into())
                                    .into(),
                            ],
                        );
                    }
                    let title = format!(
                        "{} {}: {} complete, {} partial, request mean {}",
                        k.variant.as_str().to_uppercase(),
                        size_class_label(k.size_class),
                        g.complete,
                        g.excluded.partial,
                        e2e.map(|v| nvmetea_tui::ui::fmt_us(v / 1e3)).unwrap_or("-".into())
                    );
                    (title, t)
                })
                .collect();
            let mut per = TableData::new(&["CTRL", "QID", "N", "REQ", "A", "B", "C", "D", "E"], 2);
            for ((inst, qid), q) in &p.prof.queues {
                if !keep(&format!("nvme{inst}")) {
                    continue;
                }
                let mut row: Vec<Cell> =
                    vec![format!("nvme{inst}").into(), qid.to_string().into(), q.complete.to_string().into()];
                row.push(q.e2e_mean_ns().map(|v| nvmetea_tui::ui::fmt_us(v / 1e3)).unwrap_or("-".into()).into());
                for i in 0..FAMILIES.len() {
                    row.push(q.mean_ns(i).map(|v| nvmetea_tui::ui::fmt_us(v / 1e3)).unwrap_or("-".into()).into());
                }
                per.push(format!("nvme{inst}/q{qid}"), row);
            }
            let slowest = p
                .prof
                .slowest
                .iter()
                .map(|t| TimelineView {
                    title: format!(
                        "nvme{}/q{} {} {}KiB {}",
                        t.instance,
                        t.qid,
                        t.op.as_str(),
                        t.bytes / 1024,
                        nvmetea_tui::ui::fmt_us(t.e2e_ns as f64 / 1e3)
                    ),
                    detail: format!(
                        "{} · cpu {} -> {} · io_cpu {}{}",
                        t.variant.as_str(),
                        t.cpu_submit,
                        t.cpu_complete,
                        t.io_cpu.map(|c| c.to_string()).unwrap_or("-".into()),
                        if t.flags.is_empty() { String::new() } else { format!(" · {}", t.flags.join(",")) }
                    ),
                    spans: t
                        .spans
                        .iter()
                        .map(|s| SpanView {
                            stage: s.stage.id().into(),
                            label: if s.stage == nvmetea_profile::Stage::Unclassified {
                                format!("unclassified {} -> {}", s.from, s.to)
                            } else {
                                s.stage.label(t.variant).into()
                            },
                            us: s.ns as f64 / 1e3,
                            family: s.stage.family(),
                            bound: s.stage.bound().map(String::from),
                        })
                        .collect(),
                })
                .collect();
            (
                Some(Breakdown {
                    header: format!(
                        "since {}: {} sampled commands (1 in 100, {}), sum-check failures {}. j/k selects a slow command; r resets",
                        clock(p.since),
                        p.prof.records,
                        p.flavour.as_str(),
                        p.prof.sum_check_failures
                    ),
                    groups: gt,
                    per_controller: per,
                    slowest,
                }),
                String::new(),
            )
        }
    };

    View {
        host: st.host.clone(),
        taken: clock(ts(b.snap.wall)),
        interval_s: st.interval.as_secs_f64(),
        levels,
        warnings,
        overview,
        namespaces,
        subsystems,
        controllers,
        details,
        queues,
        latency,
        breakdown,
        breakdown_hint,
        tcp,
        events: st.events.iter().cloned().collect(),
    }
}

fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "-".into())
}

fn sampler(cfg: Config, views: mpsc::Sender<View>, control: mpsc::Receiver<Control>) {
    let mut collector = Collector::new(cfg.sys, cfg.proc_root);
    collector.use_sock_diag = cfg.use_sock_diag;
    let h = nvmetea_bpf::discovery::host_identity();
    let topo = nvmetea_topology::scan(&collector.sys);
    if cfg.no_bpf {
        collector.bpf = Bpf::Disabled;
        collector.tcp_bpf = TcpBpf::Disabled;
    } else {
        collector.enable_all_bpf(&topo);
    }
    let mut st = State {
        collector,
        filter: cfg.filter,
        interval: Duration::from_secs_f64(cfg.interval.clamp(0.25, 60.0)),
        events: VecDeque::new(),
        profiler: None,
        profile_note: None,
        host: format!(
            "{} · {} · nvmetea {}",
            h.hostname.as_deref().unwrap_or("?"),
            h.kernel_release.as_deref().unwrap_or("?"),
            env!("CARGO_PKG_VERSION")
        ),
    };
    let base_filter = st.filter.controller.clone();
    let mut prev = st.collector.sample(TransitionSource::Poll);
    loop {
        let deadline = Instant::now() + st.interval;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match control.recv_timeout(left.min(Duration::from_millis(100))) {
                Ok(Control::Quit) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                Ok(Control::SetInterval(s)) => st.interval = Duration::from_secs_f64(s.clamp(0.25, 60.0)),
                Ok(Control::Profile(true)) if st.profiler.is_none() => {
                    let t = prev.snap.topology.clone();
                    st.start_profile(&t);
                }
                Ok(Control::Profile(false)) => st.profiler = None,
                Ok(Control::ResetProfile) => {
                    if let Some(p) = st.profiler.as_mut() {
                        p.prof = Profile::new(20);
                        p.since = ts(SystemTime::now());
                    }
                }
                Ok(Control::Filter(f)) => st.filter.controller = f.or_else(|| base_filter.clone()),
                Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            st.drain_profile();
        }
        let cur = st.collector.sample(TransitionSource::Poll);
        for t in &cur.transitions {
            st.push_event(ts(t.at), "state", transition_text(t));
        }
        for e in &cur.events {
            let kind = if matches!(e, nvmetea_bpf::core::CoreEvent::Slow(_)) { "slow" } else { "state" };
            st.push_event(mono_to_wall(event_ns(e)), kind, event_text(e));
        }
        for e in &cur.tcp_events {
            st.push_event(mono_to_wall(e.t_ns), "tcp", format!("nvme{}/q{}: {}", e.instance, e.qid, e.kind.describe()));
        }
        let view = build(&st, &prev, &cur);
        if views.send(view).is_err() {
            return;
        }
        prev = cur;
    }
}

/// `nvmetea __tui-snapshot`: sample like the TUI (optionally with stage
/// profiling), then print every tab rendered as text. For testing the TUI on a
/// real host without a terminal.
pub fn snapshot(cfg: Config, profile: bool, width: u16, height: u16) -> anyhow::Result<()> {
    let (vtx, vrx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let interval = cfg.interval;
    let h = std::thread::spawn(move || sampler(cfg, vtx, crx));
    if profile {
        let _ = ctx.send(Control::Profile(true));
    }
    // two views: the second has a full interval of profile records when profiling
    let mut view = vrx.recv_timeout(Duration::from_secs_f64(interval * 3.0 + 10.0))?;
    if profile {
        view = vrx.recv_timeout(Duration::from_secs_f64(interval * 3.0 + 10.0))?;
    }
    let _ = ctx.send(Control::Quit);
    let _ = h.join();
    let mut app = nvmetea_tui::App::new(interval);
    app.profiling = profile;
    app.update(view);
    for (i, name) in nvmetea_tui::app::TABS.iter().enumerate() {
        app.tab = i;
        println!("===== {} {name} =====", i + 1);
        print!("{}", nvmetea_tui::render_text(&app, width, height));
    }
    Ok(())
}

pub fn run(cfg: Config) -> anyhow::Result<()> {
    let interval = cfg.interval;
    let (vtx, vrx) = mpsc::channel();
    let (ctx, crx) = mpsc::channel();
    let h = std::thread::Builder::new().name("nvmetea-sampler".into()).spawn(move || sampler(cfg, vtx, crx))?;
    crate::signal::install(); // SIGTERM (raw mode turns Ctrl-C into a key)
    let r = term::run(vrx, ctx, interval, crate::signal::requested);
    // the sampler exits on Quit or when the channel closes; BPF links detach with the process
    drop(h);
    r.map_err(|e| anyhow::anyhow!("terminal: {e}"))
}
