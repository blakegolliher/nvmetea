//! `nvmetea controllers`: per-controller I/O rates (diskstats of its paths) and
//! TCP connection summary over an interval.

use crate::Ctx;
use crate::cmd::status::target_of;
use crate::fmt::{Table, count, dash, emit, emit_json, lat, mib_s, ms, obs};
use crate::sample::{BpfStatus, Sampled};
use nvmetea_core::engine::{ControllerInterval, controller_intervals};
use nvmetea_core::model::Topology;
use nvmetea_core::nvme_engine::{ControllerNvmeStats, NamespaceLatency, nvme_intervals};
use nvmetea_topology::TransitionSource;
use serde::Serialize;
use std::time::Duration;

#[derive(Serialize)]
pub struct CtrlRow {
    pub target: Option<String>,
    #[serde(flatten)]
    pub interval: ControllerInterval,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    host: nvmetea_bpf::discovery::HostIdentity,
    interval_s: f64,
    io_source: &'static str,
    controllers: Vec<CtrlRow>,
    bpf: BpfStatus,
    /// Level 1 BPF per-controller, per-op command/request latency.
    latency: Option<Vec<ControllerNvmeStats>>,
    namespace_latency: Option<Vec<NamespaceLatency>>,
}

/// Which BPF collectors a command starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfUse {
    None,
    /// Level 3 only: queue <-> socket table and transport events.
    TcpOnly,
    /// Level 1 (command latency) and Level 3.
    All,
}

/// Two samples `interval` apart (or one when 0, in which case rates are
/// unavailable). With `bpf`, the Level 1 collector is started first.
pub fn two_samples(ctx: &mut Ctx, interval: f64, bpf: BpfUse) -> anyhow::Result<(Option<Sampled>, Sampled)> {
    if bpf != BpfUse::None && !ctx.no_bpf {
        let topo = nvmetea_topology::scan(&ctx.collector.sys);
        ctx.filter.validate(&topo)?;
        match bpf {
            BpfUse::All if interval > 0.0 => ctx.collector.enable_all_bpf(&topo),
            BpfUse::All => ctx.collector.enable_tcp_bpf(&topo),
            BpfUse::TcpOnly => ctx.collector.enable_tcp_bpf(&topo),
            BpfUse::None => {}
        }
    }
    let a = ctx.collector.sample(TransitionSource::Poll);
    ctx.filter.validate(&a.snap.topology)?;
    if interval <= 0.0 {
        return Ok((None, a));
    }
    std::thread::sleep(Duration::from_secs_f64(interval));
    let b = ctx.collector.sample(TransitionSource::Poll);
    Ok((Some(a), b))
}

pub fn rows(prev: Option<&Sampled>, cur: &Sampled, ctx: &Ctx) -> Vec<CtrlRow> {
    let topo = &cur.snap.topology;
    controller_intervals(prev.map(|p| &p.snap), &cur.snap)
        .into_iter()
        .filter(|iv| topo.controller(&iv.name).is_some_and(|c| ctx.filter.controller(c)))
        .map(|iv| CtrlRow { target: topo.controller(&iv.name).and_then(target_of), interval: iv })
        .collect()
}

pub fn table(rows: &[CtrlRow]) -> Table {
    let mut t = Table::new(
        &[
            "CTRL",
            "STATE",
            "TARGET",
            "r/s",
            "w/s",
            "rMiB/s",
            "wMiB/s",
            "r_ms",
            "w_ms",
            "INFL",
            "CONN",
            "RTT_us min/med/max",
            "RETR/s",
            "TCP_TX_MiB/s",
            "TCP_RX_MiB/s",
            "SNDQ_B",
            "RCVQ_B",
        ],
        3,
    );
    for r in rows {
        let iv = &r.interval;
        let (conn, rtt, retr, tx, rx, sq, rq) = match &iv.tcp {
            Some(t) => (
                match t.expected {
                    Some(e) => format!("{}/{e}", t.established),
                    None => t.established.to_string(),
                },
                if t.rtt_min_us.is_available() {
                    format!("{}/{}/{}", obs(&t.rtt_min_us), obs(&t.rtt_median_us), obs(&t.rtt_max_us))
                } else {
                    dash()
                },
                count(&t.retrans_segments_per_s),
                mib_s(&t.tx_bytes_per_s),
                mib_s(&t.rx_bytes_per_s),
                obs(&t.send_q_bytes),
                obs(&t.recv_q_bytes),
            ),
            None => (dash(), dash(), dash(), dash(), dash(), dash(), dash()),
        };
        t.push(vec![
            iv.name.clone(),
            iv.state.as_str().to_string(),
            r.target.clone().unwrap_or_else(dash),
            count(&iv.io.read_iops),
            count(&iv.io.write_iops),
            mib_s(&iv.io.read_bytes_per_s),
            mib_s(&iv.io.write_bytes_per_s),
            ms(&iv.io.read_await_ms),
            ms(&iv.io.write_await_ms),
            obs(&iv.io.in_flight),
            conn,
            rtt,
            retr,
            tx,
            rx,
            sq,
            rq,
        ]);
    }
    t
}

pub const FOOTNOTE: &str = "I/O from /proc/diskstats of each controller's path devices (r_ms/w_ms: mean per completed op, ms resolution, includes queueing; not percentiles). TCP from sock_diag tcp_info; RTT is TCP's smoothed RTT, not NVMe command latency.";

/// Per-controller, per-op latency table from Level 1 BPF intervals.
pub fn latency_table(stats: &[&ControllerNvmeStats], topo: &Topology) -> Table {
    let mut t = Table::new(
        &[
            "CTRL",
            "OP",
            "IOPS",
            "REQ mean",
            "REQ p50",
            "REQ p99",
            "REQ p99.9",
            "CMD p50",
            "CMD p99",
            "A p50",
            "E2 p50",
            "BUSIEST Q",
            "MAX/QD",
            "ERR/s",
        ],
        2,
    );
    for c in stats {
        let qd = topo.controller(&c.controller).and_then(|x| x.io_queue_depth());
        for (i, s) in c.ops.iter().enumerate() {
            let first = i == 0;
            t.push(vec![
                if first { c.controller.clone() } else { String::new() },
                s.op.as_str().to_string(),
                count(&s.completed_per_s),
                lat(&s.request.mean_us),
                lat(&s.request.p50_us),
                lat(&s.request.p99_us),
                lat(&s.request.p999_us),
                lat(&s.command.p50_us),
                lat(&s.command.p99_us),
                lat(&s.stage_a.p50_us),
                lat(&s.stage_e2.p50_us),
                if first { c.busiest_queue.map(|q| format!("q{q}")).unwrap_or_else(dash) } else { String::new() },
                if first {
                    format!("{}/{}", obs(&c.busiest_queue_inflight_max), qd.map(|d| d.to_string()).unwrap_or_else(dash))
                } else {
                    String::new()
                },
                count(&s.nvme_errors_per_s),
            ]);
        }
    }
    t
}

pub fn run(ctx: &mut Ctx, interval: f64) -> anyhow::Result<()> {
    let (a, b) = two_samples(ctx, interval, BpfUse::All)?;
    let rows = rows(a.as_ref(), &b, ctx);
    let nvme = match (a.as_ref().and_then(|a| a.nvme.as_ref()), b.nvme.as_ref()) {
        (Some(pa), Some(pb)) => a.as_ref().map(|a| nvme_intervals(pa, &a.snap.topology, pb, &b.snap.topology)),
        _ => None,
    };
    let topo = &b.snap.topology;
    let keep = |name: &str| topo.controller(name).is_some_and(|c| ctx.filter.controller(c));
    let lat_rows: Option<Vec<&ControllerNvmeStats>> =
        nvme.as_ref().map(|v| v.controllers.iter().filter(|c| keep(&c.controller)).collect());
    if ctx.json {
        return emit_json(&Report {
            schema: "nvmetea.controllers/1",
            host: nvmetea_bpf::discovery::host_identity(),
            interval_s: interval,
            io_source: "diskstats",
            controllers: rows,
            bpf: ctx.collector.bpf_status(),
            latency: lat_rows.map(|v| v.into_iter().cloned().collect()),
            namespace_latency: nvme.as_ref().map(|v| v.namespaces.clone()),
        });
    }
    crate::cmd::queues::warn_bpf(ctx);
    let mut out = table(&rows).render();
    if a.is_none() {
        out.push_str("rates need an interval: rerun with --interval N (seconds)\n");
    }
    out.push_str(FOOTNOTE);
    out.push('\n');
    if let Some(l) = &lat_rows {
        out.push_str("\nLATENCY (BPF, this interval)\n");
        out.push_str(&latency_table(l, topo).render());
        out.push_str(crate::cmd::queues::FOOTNOTE);
        out.push('\n');
    }
    emit(&out);
    Ok(())
}
