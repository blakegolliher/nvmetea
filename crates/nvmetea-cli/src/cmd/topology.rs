//! `nvmetea topology`: subsystem → namespace → path inventory.

use crate::Ctx;
use crate::cmd::status::{host_of, target_of};
use crate::fmt::{bytes, emit, emit_json};
use nvmetea_core::model::{Controller, Namespace, NsKind, ScanIssue, Subsystem};
use nvmetea_topology::TransitionSource;
use serde::Serialize;

#[derive(Serialize)]
struct TopologyReport<'a> {
    schema: &'static str,
    host: nvmetea_bpf::discovery::HostIdentity,
    subsystems: Vec<&'a Subsystem>,
    controllers: Vec<&'a Controller>,
    namespaces: Vec<&'a Namespace>,
    issues: &'a [ScanIssue],
}

pub fn run(ctx: &mut Ctx) -> anyhow::Result<()> {
    let s = ctx.collector.sample(TransitionSource::Poll);
    let topo = &s.snap.topology;
    ctx.filter.validate(topo)?;
    let subsystems: Vec<&Subsystem> = topo.subsystems.iter().filter(|x| ctx.filter.subsystem(x, topo)).collect();
    let controllers: Vec<&Controller> = topo.controllers.iter().filter(|c| ctx.filter.controller(c)).collect();
    let namespaces: Vec<&Namespace> = topo.namespaces.iter().filter(|n| ctx.filter.namespace(n, topo)).collect();
    if ctx.json {
        return emit_json(&TopologyReport {
            schema: "nvmetea.topology/1",
            host: nvmetea_bpf::discovery::host_identity(),
            subsystems,
            controllers,
            namespaces,
            issues: &topo.issues,
        });
    }
    let mut out = String::new();
    for ss in &subsystems {
        out.push_str(&format!(
            "{}  {}\n  type={}  iopolicy={}  model={}  firmware={}\n",
            ss.name,
            ss.nqn.as_deref().unwrap_or("-"),
            ss.subsystype.as_deref().unwrap_or("-"),
            ss.iopolicy.as_deref().unwrap_or("-"),
            ss.model.as_deref().unwrap_or("-"),
            ss.firmware_rev.as_deref().unwrap_or("-"),
        ));
        for cn in &ss.controllers {
            let Some(c) = controllers.iter().find(|c| &c.name == cn) else { continue };
            out.push_str(&format!(
                "  ctrl {:<7} {:<10} {:<5} {} from {}  cntlid={}  queues={}x{}\n",
                c.name,
                c.state.as_str(),
                c.transport.as_deref().unwrap_or("-"),
                target_of(c).unwrap_or_else(|| "-".into()),
                host_of(c).unwrap_or_else(|| "-".into()),
                c.cntlid.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
                c.io_queues().map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
                c.io_queue_depth().map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
            ));
        }
        for nn in &ss.namespaces {
            let Some(ns) = namespaces.iter().find(|n| &n.name == nn) else { continue };
            write_ns(&mut out, ns, topo);
        }
        // direct namespaces (multipath off / PCIe) of this subsystem's controllers
        for ns in
            namespaces.iter().filter(|n| n.kind == NsKind::Direct && n.subsystem.as_deref() == Some(ss.name.as_str()))
        {
            write_ns(&mut out, ns, topo);
        }
        out.push('\n');
    }
    if subsystems.is_empty() {
        out.push_str("No matching NVMe subsystems.\n");
    }
    if !topo.issues.is_empty() {
        out.push_str(&format!("{} scan issue(s); see --json\n", topo.issues.len()));
    }
    emit(&out);
    Ok(())
}

fn write_ns(out: &mut String, ns: &Namespace, topo: &nvmetea_core::model::Topology) {
    let kind = match ns.kind {
        NsKind::MultipathHead => "multipath",
        NsKind::Direct => "direct",
    };
    out.push_str(&format!(
        "  ns {:<9} nsid={:<4} {:<10} {:>11}  lba={}  wwid={}\n",
        ns.name,
        ns.nsid.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
        kind,
        ns.size_bytes.map(bytes).unwrap_or_else(|| "-".into()),
        ns.logical_block_size.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
        ns.wwid.as_deref().unwrap_or("-"),
    ));
    for p in &ns.paths {
        let st = topo.controller(&p.controller).map(|c| c.state.as_str().to_string()).unwrap_or_else(|| "gone".into());
        let tgt = topo.controller(&p.controller).and_then(target_of).unwrap_or_else(|| "-".into());
        out.push_str(&format!(
            "     path {:<11} via {:<7} {:<10} {:<22} ana={}{}\n",
            p.name,
            p.controller,
            st,
            tgt,
            p.ana_state.as_deref().unwrap_or("-"),
            p.ana_grpid.map(|g| format!(" grp={g}")).unwrap_or_default(),
        ));
    }
}
