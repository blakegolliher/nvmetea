//! `nvmetea queues`: per NVMe/TCP queue activity, depth and latency (Level 1 BPF).

use crate::Ctx;
use crate::fmt::{Table, count, dash, emit, emit_json, lat, mib_s, obs};
use crate::sample::{BpfStatus, Sampled};
use nvmetea_core::engine::{QueueConnection, queue_connections};
use nvmetea_core::model::Op;
use nvmetea_core::nvme_engine::{NvmeIntervals, QueueStats, nvme_intervals};
use nvmetea_topology::TransitionSource;
use serde::Serialize;
use std::time::Duration;

#[derive(Serialize)]
struct Report<'a> {
    schema: &'static str,
    host: nvmetea_bpf::discovery::HostIdentity,
    interval_s: f64,
    bpf: BpfStatus,
    queues: Vec<&'a QueueStats>,
    health: Option<&'a nvmetea_core::nvme_engine::BpfHealth>,
    tcp_bpf: BpfStatus,
    /// Each queue's TCP connection (kernel-identified) with transport telemetry.
    connections: Vec<&'a QueueConnection>,
}

pub const FOOTNOTE: &str = "\
CMD = nvme_setup_cmd -> nvme_complete_rq (per dispatch). REQ = block request start -> block completion.
A = block submission (request start -> dispatch). E2 = NVMe completion -> block completion.
Percentiles are histogram upper bucket edges (<= 12.5% high); means are exact. Retried, failed-over and
failed commands are counted but kept out of the latency columns.";

/// Start BPF, take two samples `interval` apart, and compute NVMe intervals.
pub fn bpf_two_samples(ctx: &mut Ctx, interval: f64) -> anyhow::Result<(Sampled, Sampled, Option<NvmeIntervals>)> {
    let topo = nvmetea_topology::scan(&ctx.collector.sys);
    ctx.filter.validate(&topo)?;
    ctx.collector.enable_all_bpf(&topo);
    let a = ctx.collector.sample(TransitionSource::Poll);
    std::thread::sleep(Duration::from_secs_f64(interval.max(0.1)));
    let b = ctx.collector.sample(TransitionSource::Poll);
    let iv = match (&a.nvme, &b.nvme) {
        (Some(pa), Some(pb)) => Some(nvme_intervals(pa, &a.snap.topology, pb, &b.snap.topology)),
        _ => None,
    };
    Ok((a, b, iv))
}

pub fn warn_bpf(ctx: &Ctx) {
    if ctx.json {
        return;
    }
    let s = ctx.collector.bpf_status();
    if s.state == "unavailable" {
        eprintln!(
            "note: per-command telemetry unavailable ({}): {}. {}",
            s.reason.map(|r| r.as_str()).unwrap_or("?"),
            s.detail.as_deref().unwrap_or(""),
            s.reason.map(|r| r.remediation()).unwrap_or("")
        );
    }
    if let Some(l) = &s.lifecycle {
        eprintln!("note: controller state hooks not running: {l}");
    }
}

/// Queue connections for the interval, when the queue <-> socket table is available.
pub fn connections(a: &Sampled, b: &Sampled) -> Option<Vec<QueueConnection>> {
    let qs = b.queue_sockets.as_ref().ok()?;
    let prev_qs = a.queue_sockets.as_ref().ok().map(|v| v.as_slice());
    let events = b.sock_events.as_ref().map(|c| (a.sock_events.as_ref(), c));
    Some(queue_connections(Some(&a.snap), &b.snap, (prev_qs, qs), events))
}

pub fn connections_table(conns: &[&QueueConnection]) -> Table {
    let mut t = Table::new(
        &[
            "CTRL", "QID", "IO_CPU", "LPORT", "STATE", "RTT_us", "RTTVAR", "CWND", "UNACK", "LOST", "RETR/s",
            "RETR_EV", "LOSS", "RECOV", "RST", "ERR", "SNDQ", "NOTSENT", "BUSY%", "RWND%", "SNDBUF%",
        ],
        2,
    );
    for c in conns {
        let iv = c.interval.as_ref();
        let ivf =
            |f: fn(&nvmetea_core::engine::SocketInterval) -> &nvmetea_core::Obs<f64>,
             fmtf: fn(&nvmetea_core::Obs<f64>) -> String| { iv.map(|i| fmtf(f(i))).unwrap_or_else(dash) };
        t.push(vec![
            c.controller.clone(),
            c.qid.to_string(),
            c.io_cpu.map(|x| x.to_string()).unwrap_or_else(|| "unbound".into()),
            c.local.port().to_string(),
            if c.closed { format!("CLOSED({})", c.state.as_str()) } else { c.state.as_str().to_string() },
            obs(&c.rtt_us),
            obs(&c.rttvar_us),
            obs(&c.cwnd),
            obs(&c.unacked),
            obs(&c.lost),
            ivf(|i| &i.retrans_segments_per_s, count),
            obs(&c.retransmit_events),
            obs(&c.loss_entries),
            obs(&c.recovery_entries),
            obs(&c.resets),
            obs(&c.socket_errors),
            obs(&c.send_q_bytes),
            obs(&c.notsent_bytes),
            ivf(|i| &i.busy_pct, crate::fmt::pct),
            ivf(|i| &i.rwnd_limited_pct, crate::fmt::pct),
            ivf(|i| &i.sndbuf_limited_pct, crate::fmt::pct),
        ]);
    }
    t
}

pub fn run(ctx: &mut Ctx, interval: f64, op: Option<String>, queue: Option<u16>) -> anyhow::Result<()> {
    let (a, b, iv) = bpf_two_samples(ctx, interval)?;
    let conns = connections(&a, &b);
    let op = match op.as_deref() {
        None | Some("all") => None,
        Some(o) => Some(
            Op::ALL
                .into_iter()
                .find(|x| x.as_str() == o)
                .ok_or_else(|| anyhow::anyhow!("unknown --op {o} (read, write, flush, other, admin, all)"))?,
        ),
    };
    let topo = &b.snap.topology;
    let empty = Vec::new();
    let queues: Vec<&QueueStats> = iv
        .as_ref()
        .map(|v| &v.queues)
        .unwrap_or(&empty)
        .iter()
        .filter(|q| topo.controller(&q.controller).is_some_and(|c| ctx.filter.controller(c)))
        .filter(|q| queue.is_none_or(|n| n == q.qid))
        .collect();
    if ctx.json {
        return emit_json(&Report {
            schema: "nvmetea.queues/1",
            host: nvmetea_bpf::discovery::host_identity(),
            interval_s: iv.as_ref().map(|v| v.interval_s).unwrap_or(interval),
            bpf: ctx.collector.bpf_status(),
            queues,
            health: iv.as_ref().map(|v| &v.health),
            tcp_bpf: ctx.collector.tcp_bpf_status(),
            connections: conns
                .as_ref()
                .map(|c| {
                    c.iter()
                        .filter(|x| topo.controller(&x.controller).is_some_and(|k| ctx.filter.controller(k)))
                        .filter(|x| queue.is_none_or(|n| n == x.qid))
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
    warn_bpf(ctx);
    let mut t = Table::new(
        &[
            "CTRL",
            "QID",
            "OP",
            "IOPS",
            "MiB/s",
            "INFL",
            "MAX/QD",
            "CMD p50",
            "CMD p99",
            "REQ mean",
            "REQ p50",
            "REQ p99",
            "REQ p99.9",
            "A p50",
            "E2 p50",
            "ERR/s",
        ],
        3,
    );
    let mut sorted = queues.clone();
    sorted.sort_by_key(|q| (nvmetea_topology::names::natural_key(&q.controller), q.qid));
    for q in &sorted {
        let maxqd = format!("{}/{}", obs(&q.inflight_max), q.depth.map(|d| d.to_string()).unwrap_or_else(dash));
        let ops: Vec<_> = q.ops.iter().filter(|s| op.is_none_or(|o| o == s.op)).collect();
        if ops.is_empty() {
            if op.is_none() {
                // a measured zero only when the queue existed in both samples
                let (label, z, zf) =
                    if q.retries_per_s.is_available() { ("idle", "0", "0.0") } else { ("n/a", "-", "-") };
                t.push(vec![
                    q.controller.clone(),
                    q.qid.to_string(),
                    label.into(),
                    z.into(),
                    zf.into(),
                    obs(&q.inflight),
                    maxqd,
                ]);
            }
            continue;
        }
        for (i, s) in ops.iter().enumerate() {
            let first = i == 0;
            t.push(vec![
                if first { q.controller.clone() } else { String::new() },
                if first { q.qid.to_string() } else { String::new() },
                s.op.as_str().to_string(),
                count(&s.completed_per_s),
                mib_s(&s.bytes_per_s),
                if first { obs(&q.inflight) } else { String::new() },
                if first { maxqd.clone() } else { String::new() },
                lat(&s.command.p50_us),
                lat(&s.command.p99_us),
                lat(&s.request.mean_us),
                lat(&s.request.p50_us),
                lat(&s.request.p99_us),
                lat(&s.request.p999_us),
                lat(&s.stage_a.p50_us),
                lat(&s.stage_e2.p50_us),
                count(&s.nvme_errors_per_s),
            ]);
        }
    }
    let mut out = String::new();
    if iv.is_none() {
        out.push_str("No per-queue data (BPF collector not running). Queue inventory from sysfs:\n");
        let mut inv = Table::new(&["CTRL", "IO QUEUES", "DEPTH"], 1);
        for c in topo.tcp_controllers().filter(|c| ctx.filter.controller(c)) {
            inv.push(vec![
                c.name.clone(),
                c.io_queues().map(|v| v.to_string()).unwrap_or_else(dash),
                c.io_queue_depth().map(|v| v.to_string()).unwrap_or_else(dash),
            ]);
        }
        out.push_str(&inv.render());
    } else {
        out.push_str(&t.render());
        if let Some(h) = iv.as_ref().map(|v| &v.health) {
            if h.untracked_completions + h.cid_mismatches + h.stale_replaced + h.map_full + h.events_lost > 0 {
                out.push_str(&format!(
                    "collector: {} completions of commands dispatched before attach, {} cid mismatches, {} stale, {} map-full, {} events lost\n",
                    h.untracked_completions, h.cid_mismatches, h.stale_replaced, h.map_full, h.events_lost
                ));
            }
        }
        out.push_str(FOOTNOTE);
        out.push('\n');
    }
    match &conns {
        Some(c) => {
            let keep: Vec<&QueueConnection> = c
                .iter()
                .filter(|x| topo.controller(&x.controller).is_some_and(|k| ctx.filter.controller(k)))
                .filter(|x| queue.is_none_or(|n| n == x.qid))
                .collect();
            out.push_str("\nQUEUE CONNECTIONS (queue identified in the kernel; TCP from sock_diag; events from TCP tracepoints)\n");
            out.push_str(&connections_table(&keep).render());
            out.push_str("RETR/s = retransmitted segments/s (tcp_info); RETR_EV/LOSS/RECOV/RST/ERR = events in the interval on this queue's socket.\n");
        }
        None => {
            if let Err((r, d)) = &b.queue_sockets {
                out.push_str(&format!("\nqueue connections unavailable ({}: {d})\n", r.as_str()));
            }
        }
    }
    emit(&out);
    Ok(())
}
