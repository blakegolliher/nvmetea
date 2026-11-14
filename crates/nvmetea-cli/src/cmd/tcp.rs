//! `nvmetea tcp`: per-connection transport diagnostics. As root, each
//! connection is identified in the kernel as a specific controller queue (T1)
//! and carries BPF transport-event counts (T3-T7); otherwise connections are
//! matched to controllers by endpoint only.

use crate::Ctx;
use crate::cmd::controllers::{BpfUse, two_samples};
use crate::fmt::{Table, count, dash, emit, emit_json, mib_s, opt, pct};
use nvmetea_core::engine::{SocketInterval, socket_intervals};
use nvmetea_core::model::{QueueSocket, TcpSocket};
use nvmetea_core::quality::{Obs, Reason};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
struct SocketRow<'a> {
    controller: Option<String>,
    /// How the controller was determined: `measured` (kernel queue link) or
    /// `derived` (endpoint match).
    association: &'static str,
    qid: Obs<u16>,
    io_cpu: Obs<u32>,
    #[serde(flatten)]
    socket: &'a TcpSocket,
    interval: &'a SocketInterval,
    /// BPF transport events in the interval: retransmits, resets, socket errors.
    retransmit_events: Obs<u64>,
    resets: Obs<u64>,
    socket_errors: Obs<u64>,
}

#[derive(Serialize)]
struct Report<'a> {
    schema: &'static str,
    host: nvmetea_bpf::discovery::HostIdentity,
    interval_s: f64,
    backend: &'a crate::sample::TcpMeta,
    queue_association: crate::sample::BpfStatus,
    sockets: Vec<SocketRow<'a>>,
    ambiguous: Vec<usize>,
    unassociated: Vec<usize>,
    endpoint_disagreements: usize,
}

pub fn run(ctx: &mut Ctx, interval: f64) -> anyhow::Result<()> {
    let (a, b) = two_samples(ctx, interval, BpfUse::TcpOnly)?;
    let iv = socket_intervals(a.as_ref().map(|s| &s.snap), &b.snap);
    let topo = &b.snap.topology;
    let qmap: Option<BTreeMap<u64, &QueueSocket>> =
        b.queue_sockets.as_ref().ok().map(|v| v.iter().map(|q| (q.cookie, q)).collect());
    let qerr = b.queue_sockets.as_ref().err().map(|e| e.0);
    let mut owner: Vec<Option<String>> = vec![None; b.snap.sockets.len()];
    for (c, idx) in &b.snap.socket_owner {
        for &i in idx {
            if let Some(o) = owner.get_mut(i) {
                *o = Some(c.clone());
            }
        }
    }
    let ev_delta = |cookie: Option<u64>, pick: fn(&nvmetea_core::model::SockEventCounters) -> u64| -> Obs<u64> {
        let (Some(cur), Some(c)) = (b.sock_events.as_ref(), cookie) else {
            return Obs::unavailable(Reason::DependencyUnavailable);
        };
        let Some(prev) = a.as_ref().and_then(|a| a.sock_events.as_ref()) else {
            return Obs::unavailable(Reason::FirstInterval);
        };
        let d = cur.get(&c).map(pick).unwrap_or(0).checked_sub(prev.get(&c).map(pick).unwrap_or(0));
        d.map(|x| Obs::measured(x, &["bpf:T3-T7"])).unwrap_or(Obs::unavailable(Reason::CounterReset))
    };
    let keep = |i: usize| match &owner[i] {
        Some(c) => topo.controller(c).is_some_and(|c| ctx.filter.controller(c)),
        None => ctx.filter.controller.is_none(),
    };
    let mut rows: Vec<SocketRow> = (0..b.snap.sockets.len())
        .filter(|&i| keep(i))
        .map(|i| {
            let s = &b.snap.sockets[i];
            let q = qmap.as_ref().and_then(|m| s.cookie.and_then(|c| m.get(&c)));
            let unav = qerr.unwrap_or(Reason::DependencyUnavailable);
            SocketRow {
                controller: owner[i].clone(),
                association: if qmap.is_some() { "measured" } else { "derived" },
                qid: match (q, &qmap) {
                    (Some(q), _) => Obs::measured(q.qid, &["bpf:T1"]),
                    (None, Some(_)) => Obs::unavailable(Reason::NotApplicable), // not an NVMe queue socket
                    (None, None) => Obs::unavailable(unav),
                },
                io_cpu: match q {
                    Some(q) => q
                        .io_cpu
                        .map(|c| Obs::measured(c, &["bpf:T1"]))
                        .unwrap_or(Obs::unavailable(Reason::NotApplicable)),
                    None => Obs::unavailable(unav),
                },
                socket: s,
                interval: &iv[i],
                retransmit_events: ev_delta(s.cookie, |c| c.retrans),
                resets: ev_delta(s.cookie, |c| c.rst_rx + c.rst_tx),
                socket_errors: ev_delta(s.cookie, |c| c.errors),
            }
        })
        .collect();
    rows.sort_by(|x, y| {
        let k = |r: &SocketRow| {
            (r.controller.as_deref().map(nvmetea_topology::names::natural_key), r.qid.value, r.socket.local.port())
        };
        k(x).cmp(&k(y))
    });
    if ctx.json {
        return emit_json(&Report {
            schema: "nvmetea.tcp/1",
            host: nvmetea_bpf::discovery::host_identity(),
            interval_s: interval,
            backend: &b.tcp,
            queue_association: ctx.collector.tcp_bpf_status(),
            sockets: rows,
            ambiguous: b.assoc.ambiguous.clone(),
            unassociated: b.assoc.unassociated.clone(),
            endpoint_disagreements: b.assoc_disagreements,
        });
    }
    let mut t = Table::new(
        &[
            "CTRL", "QID", "LOCAL", "REMOTE", "STATE", "IO_CPU", "RTT_us", "RTTVAR", "MINRTT", "RTO_ms", "CWND",
            "UNACK", "LOST", "RETRANS", "RETR/s", "RETR_EV", "RST", "ERR", "TX_MiB/s", "RX_MiB/s", "SNDQ", "RCVQ",
            "NOTSENT", "BUSY%", "RWND%", "SNDBUF%",
        ],
        5,
    );
    for r in &rows {
        let s = r.socket;
        let i = s.info.as_ref();
        t.push(vec![
            r.controller.clone().unwrap_or_else(|| "?".into()),
            r.qid.value.map(|q| q.to_string()).unwrap_or_else(dash),
            s.local.to_string(),
            s.remote.to_string(),
            s.state.as_str().to_string(),
            match (&r.io_cpu.value, r.io_cpu.reason) {
                (Some(c), _) => c.to_string(),
                (None, Some(Reason::NotApplicable)) if r.qid.is_available() => "unbound".into(),
                _ => dash(),
            },
            opt(i.map(|i| i.rtt_us)),
            opt(i.map(|i| i.rttvar_us)),
            opt(i.and_then(|i| i.min_rtt_us)),
            opt(i.map(|i| i.rto_us / 1000)),
            opt(i.map(|i| i.snd_cwnd)),
            opt(i.map(|i| i.unacked)),
            opt(i.map(|i| i.lost)),
            opt(i.map(|i| i.total_retrans)),
            count(&r.interval.retrans_segments_per_s),
            opt(r.retransmit_events.value),
            opt(r.resets.value),
            opt(r.socket_errors.value),
            mib_s(&r.interval.tx_bytes_per_s),
            mib_s(&r.interval.rx_bytes_per_s),
            s.send_q.to_string(),
            s.recv_q.to_string(),
            opt(i.and_then(|i| i.notsent_bytes)),
            pct(&r.interval.busy_pct),
            pct(&r.interval.rwnd_limited_pct),
            pct(&r.interval.sndbuf_limited_pct),
        ]);
    }
    let mut out = if t.is_empty() { "No NVMe/TCP connections found.\n".to_string() } else { t.render() };
    out.push_str(&format!("source: {:?}", b.tcp.backend));
    if let Some(e) = &b.tcp.error {
        out.push_str(&format!(" (degraded: {e})"));
    }
    match &b.queue_sockets {
        Ok(q) => out.push_str(&format!(
            ". Queue ownership identified in the kernel for {} connections (iter/tcp). RETRANS/RETR/s are segments (tcp_info); RETR_EV are retransmitted skbs (tracepoint).\n",
            q.len()
        )),
        Err((r, d)) => out.push_str(&format!(
            ". QID/IO_CPU need the BPF queue table ({}: {d}); controllers are matched by endpoint only.\n",
            r.as_str()
        )),
    }
    if b.assoc_disagreements > 0 {
        out.push_str(&format!(
            "warning: {} connection(s) owned by a different controller than the endpoint match suggests.\n",
            b.assoc_disagreements
        ));
    }
    if a.is_none() {
        out.push_str("per-second and event columns need --interval N\n");
    }
    if !b.assoc.ambiguous.is_empty() && b.queue_sockets.is_err() {
        out.push_str(&format!(
            "{} connection(s) match more than one controller endpoint (shown as '?').\n",
            b.assoc.ambiguous.len()
        ));
    }
    if !b.assoc.unassociated.is_empty() && b.queue_sockets.is_err() {
        out.push_str(&format!(
            "{} connection(s) to an NVMe/TCP port match no controller (shown as '?').\n",
            b.assoc.unassociated.len()
        ));
    }
    emit(&out);
    Ok(())
}
