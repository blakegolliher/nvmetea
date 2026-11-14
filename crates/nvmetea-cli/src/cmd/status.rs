//! `nvmetea status`: controller and subsystem health.

use crate::Ctx;
use crate::fmt::{Table, dash, emit, emit_json, opt};
use crate::sample::{Sampled, TcpMeta};
use nvmetea_core::Quality;
use nvmetea_core::model::{Controller, Namespace, ScanIssue, Topology};
use nvmetea_tcp::TcpBackend;
use nvmetea_tcp::assoc::ControllerSockets;
use nvmetea_topology::TransitionSource;
use serde::Serialize;

#[derive(Serialize)]
pub struct Connections {
    pub established: usize,
    pub total: usize,
    pub expected: Option<u32>,
    pub association: Quality,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<nvmetea_core::Reason>,
}

#[derive(Serialize)]
pub struct CtrlStatus {
    pub name: String,
    pub generation: Option<u64>,
    pub state: String,
    pub transport: Option<String>,
    pub target: Option<String>,
    pub host_address: Option<String>,
    pub io_queues: Option<u32>,
    pub io_queue_depth: Option<u32>,
    pub kato_s: Option<u32>,
    pub cntlid: Option<u16>,
    pub ctrl_loss_tmo: Option<String>,
    pub connections: Option<Connections>,
    pub health: String,
}

#[derive(Serialize)]
pub struct NsStatus {
    pub name: String,
    pub nsid: Option<u32>,
    pub paths: usize,
    pub usable_paths: usize,
    pub ana_reported: bool,
}

#[derive(Serialize)]
pub struct SubsysStatus {
    pub name: String,
    pub nqn: Option<String>,
    pub iopolicy: Option<String>,
    pub controllers: Vec<CtrlStatus>,
    pub namespaces: Vec<NsStatus>,
}

#[derive(Serialize)]
pub struct StatusReport {
    pub schema: &'static str,
    pub host: nvmetea_bpf::discovery::HostIdentity,
    pub tcp: TcpMeta,
    pub subsystems: Vec<SubsysStatus>,
    pub issues: Vec<ScanIssue>,
}

pub fn target_of(c: &Controller) -> Option<String> {
    let a = c.address.as_ref()?;
    match (&a.traddr, &a.trsvcid) {
        (Some(t), Some(p)) if t.contains(':') => Some(format!("[{t}]:{p}")),
        (Some(t), Some(p)) => Some(format!("{t}:{p}")),
        (Some(t), None) => Some(t.clone()),
        _ => Some(a.raw.clone()),
    }
}

pub fn host_of(c: &Controller) -> Option<String> {
    let a = c.address.as_ref()?;
    a.host_traddr.clone().or_else(|| a.src_addr.clone()).or_else(|| a.host_iface.clone())
}

fn health(c: &Controller, conn: Option<&Connections>, backend: TcpBackend) -> String {
    if !c.state.is_live() {
        return c.state.as_str().to_string();
    }
    let Some(k) = conn else { return "live".into() };
    if backend == TcpBackend::None {
        return "live (connections unknown)".into();
    }
    if k.reason == Some(nvmetea_core::Reason::Ambiguous) {
        return "live (connections ambiguous)".into();
    }
    match k.expected {
        Some(e) if (k.established as u32) < e => format!("degraded: {}/{} connections", k.established, e),
        _ => "ok".into(),
    }
}

/// A path is usable when its controller is live and ANA (if reported) is
/// optimized or non-optimized.
pub fn usable_paths(ns: &Namespace, topo: &Topology) -> usize {
    ns.paths
        .iter()
        .filter(|p| topo.controller(&p.controller).is_some_and(|c| c.state.is_live()))
        .filter(|p| p.ana_state.as_deref().is_none_or(|a| a == "optimized" || a == "non-optimized"))
        .count()
}

pub fn connections(c: &Controller, s: &Sampled) -> Option<Connections> {
    let cs: &ControllerSockets = s.assoc.by_controller.get(&c.name)?;
    let socks: Vec<_> = cs.sockets.iter().filter_map(|&i| s.snap.sockets.get(i)).collect();
    Some(Connections {
        established: socks.iter().filter(|x| x.state == nvmetea_core::model::TcpState::Established).count(),
        total: socks.len(),
        expected: cs.expected,
        association: cs.quality,
        reason: cs.reason,
    })
}

pub fn build(s: &Sampled, ctx: &Ctx) -> StatusReport {
    let topo = &s.snap.topology;
    let mut subsystems = Vec::new();
    for ss in topo.subsystems.iter().filter(|ss| ctx.filter.subsystem(ss, topo)) {
        let controllers = ss
            .controllers
            .iter()
            .filter_map(|n| topo.controller(n))
            .filter(|c| ctx.filter.controller(c))
            .map(|c| {
                let conn = connections(c, s);
                CtrlStatus {
                    name: c.name.clone(),
                    generation: c.generation,
                    state: c.state.as_str().to_string(),
                    transport: c.transport.clone(),
                    target: target_of(c),
                    host_address: host_of(c),
                    io_queues: c.io_queues(),
                    io_queue_depth: c.io_queue_depth(),
                    kato_s: c.kato_s,
                    cntlid: c.cntlid,
                    ctrl_loss_tmo: c.ctrl_loss_tmo.clone(),
                    health: health(c, conn.as_ref(), s.tcp.backend),
                    connections: conn,
                }
            })
            .collect();
        let namespaces = ss
            .namespaces
            .iter()
            .filter_map(|n| topo.namespace(n))
            .filter(|n| ctx.filter.namespace(n, topo))
            .map(|n| NsStatus {
                name: n.name.clone(),
                nsid: n.nsid,
                paths: n.paths.len(),
                usable_paths: usable_paths(n, topo),
                ana_reported: n.paths.iter().any(|p| p.ana_state.is_some()),
            })
            .collect();
        subsystems.push(SubsysStatus {
            name: ss.name.clone(),
            nqn: ss.nqn.clone(),
            iopolicy: ss.iopolicy.clone(),
            controllers,
            namespaces,
        });
    }
    let mut issues = topo.issues.clone();
    issues.extend(s.disk_issues.iter().cloned());
    StatusReport {
        schema: "nvmetea.status/1",
        host: nvmetea_bpf::discovery::host_identity(),
        tcp: s.tcp.clone(),
        subsystems,
        issues,
    }
}

pub fn run(ctx: &mut Ctx) -> anyhow::Result<()> {
    let s = ctx.collector.sample(TransitionSource::Poll);
    ctx.filter.validate(&s.snap.topology)?;
    let r = build(&s, ctx);
    if ctx.json {
        return emit_json(&r);
    }
    let mut out = String::new();
    if r.subsystems.is_empty() {
        out.push_str(if ctx.filter.all_transports {
            "No NVMe subsystems found.\n"
        } else {
            "No NVMe/TCP controllers found (use --all-transports to include PCIe/RDMA/FC).\n"
        });
    }
    for ss in &r.subsystems {
        let live = ss.controllers.iter().filter(|c| c.state == "live").count();
        out.push_str(&format!(
            "{}  {}  iopolicy={}  controllers={} ({} live)  namespaces={}\n",
            ss.name,
            ss.nqn.as_deref().unwrap_or("-"),
            ss.iopolicy.as_deref().unwrap_or("-"),
            ss.controllers.len(),
            live,
            ss.namespaces.len()
        ));
        let mut t = Table::new(
            &["CTRL", "STATE", "TRANSPORT", "TARGET", "HOST ADDR", "IOQ", "QD", "KATO", "CNTLID", "CONN", "HEALTH"],
            5,
        )
        .indent(2);
        for c in &ss.controllers {
            let conn = c.connections.as_ref().map(|k| match k.expected {
                Some(e) => format!("{}/{e}", k.established),
                None => format!("{}", k.established),
            });
            t.push(vec![
                c.name.clone(),
                c.state.clone(),
                opt(c.transport.as_ref()),
                opt(c.target.as_ref()),
                opt(c.host_address.as_ref()),
                opt(c.io_queues),
                opt(c.io_queue_depth),
                opt(c.kato_s),
                opt(c.cntlid),
                conn.unwrap_or_else(dash),
                c.health.clone(),
            ]);
        }
        out.push_str(&t.render());
        let degraded: Vec<&NsStatus> =
            ss.namespaces.iter().filter(|n| n.usable_paths < n.paths || n.paths == 0).collect();
        if !ss.namespaces.is_empty() {
            let maxp = ss.namespaces.iter().map(|n| n.paths).max().unwrap_or(0);
            if degraded.is_empty() {
                out.push_str(&format!("  namespaces: all {} with {maxp}/{maxp} usable paths", ss.namespaces.len()));
            } else {
                out.push_str("  namespaces with unusable paths:");
                for n in &degraded {
                    out.push_str(&format!(" {} ({}/{})", n.name, n.usable_paths, n.paths));
                }
            }
            if ss.namespaces.iter().all(|n| !n.ana_reported) {
                out.push_str("; ANA not reported by this target");
            }
            out.push('\n');
        }
        out.push('\n');
    }
    if let Some(e) = &r.tcp.error {
        out.push_str(&format!("warning: {e}; TCP data from {:?} (RTT unavailable)\n", r.tcp.backend));
    }
    if !r.issues.is_empty() {
        out.push_str(&format!("{} scan issue(s):\n", r.issues.len()));
        for i in r.issues.iter().take(20) {
            out.push_str(&format!("  {}: {}\n", i.path, i.problem));
        }
    }
    emit(&out);
    Ok(())
}
