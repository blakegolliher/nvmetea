//! `nvmetea probe`: passive capability discovery and per-metric-family plan.
//! Loads and attaches nothing (BPF load/attach checks arrive with the loader).

use crate::Ctx;
use crate::fmt::{Table, emit, emit_json};
use nvmetea_bpf::discovery::{Avail, Discovery, ProbeCheck, Status, discover};
use nvmetea_core::engine::namespace_totals;
use nvmetea_core::model::{NsAccounting, NsKind};
use nvmetea_tcp::TcpBackend;
use nvmetea_topology::TransitionSource;
use nvmetea_topology::uevent::UeventListener;
use serde::Serialize;

#[derive(Serialize)]
struct PlanItem {
    family: &'static str,
    backend: String,
    status: &'static str,
    note: String,
}

#[derive(Serialize)]
struct ProbeReport {
    schema: &'static str,
    discovery: Discovery,
    sock_diag: String,
    uevents: String,
    tcp_controllers: usize,
    /// Present with `--load`: what actually happened when loading and attaching.
    #[serde(skip_serializing_if = "Option::is_none")]
    bpf_load: Option<LoadSummary>,
    plan: Vec<PlanItem>,
}

#[derive(Serialize)]
struct TcpLoadSummary {
    status: crate::sample::BpfStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<nvmetea_bpf::core::LoadReport>,
    queue_sockets: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iterator_error: Option<String>,
    iterate_ms: Option<f64>,
}

#[derive(Serialize)]
struct LoadSummary {
    status: crate::sample::BpfStatus,
    tcp: Option<TcpLoadSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<nvmetea_bpf::core::LoadReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<nvmetea_bpf::core::CoreConfig>,
    sample_s: f64,
    commands_observed: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    health: Option<nvmetea_core::nvme_engine::BpfHealth>,
}

/// Load and attach the Level 1 collector, observe briefly, then detach.
fn load_test(ctx: &mut Ctx) -> LoadSummary {
    let topo = nvmetea_topology::scan(&ctx.collector.sys);
    ctx.collector.enable_bpf(&topo);
    ctx.collector.enable_tcp_bpf(&topo);
    let tcp = Some(match &ctx.collector.tcp_bpf {
        crate::sample::TcpBpf::Active(c) => {
            let t = std::time::Instant::now();
            let qs = c.queue_sockets();
            TcpLoadSummary {
                status: ctx.collector.tcp_bpf_status(),
                report: Some(c.report.clone()),
                queue_sockets: qs.as_ref().ok().map(|v| v.len()),
                iterator_error: qs.err(),
                iterate_ms: Some(t.elapsed().as_secs_f64() * 1e3),
            }
        }
        _ => TcpLoadSummary {
            status: ctx.collector.tcp_bpf_status(),
            report: None,
            queue_sockets: None,
            iterator_error: None,
            iterate_ms: None,
        },
    });
    ctx.collector.tcp_bpf = crate::sample::TcpBpf::NotStarted;
    let mut out = LoadSummary {
        status: ctx.collector.bpf_status(),
        tcp,
        report: None,
        config: None,
        sample_s: 0.0,
        commands_observed: 0,
        health: None,
    };
    if let Some(c) = ctx.collector.bpf_mut() {
        out.report = Some(c.report.clone());
        out.config = Some(c.config.clone());
        let a = c.sample();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let b = c.sample();
        out.sample_s = b.taken.saturating_duration_since(a.taken).as_secs_f64();
        out.commands_observed = b.counters.dispatches_tcp.saturating_sub(a.counters.dispatches_tcp);
        out.health = Some(nvmetea_core::nvme_engine::nvme_intervals(&a, &topo, &b, &topo).health);
    }
    // dropping the collector detaches every program
    ctx.collector.bpf = crate::sample::Bpf::NotStarted;
    out
}

fn st(s: Status) -> &'static str {
    match s {
        Status::Eligible => "eligible",
        Status::Unavailable => "unavailable",
        Status::Unknown => "unknown",
    }
}

fn avail(a: &Avail) -> String {
    match a {
        Avail::Present => "present".into(),
        Avail::Absent => "absent".into(),
        Avail::Error(e) => format!("error: {e}"),
    }
}

fn prereq(d: &Discovery, ids: &[&str]) -> (usize, usize, Vec<String>) {
    let ps: Vec<&ProbeCheck> = d.probes.iter().filter(|p| ids.contains(&p.id)).collect();
    let ok =
        ps.iter().filter(|p| p.btf_flavour == Status::Eligible || p.kprobe_flavour == Some(Status::Eligible)).count();
    let bad = ps
        .iter()
        .filter(|p| !(p.btf_flavour == Status::Eligible || p.kprobe_flavour == Some(Status::Eligible)))
        .map(|p| format!("{}({})", p.id, p.reason.map(|r| r.as_str()).unwrap_or("?")))
        .collect();
    (ok, ps.len(), bad)
}

pub fn run(ctx: &mut Ctx, load: bool) -> anyhow::Result<()> {
    let d = discover(&ctx.collector.proc_root);
    let bpf_load = if load && !ctx.no_bpf { Some(load_test(ctx)) } else { None };
    let s = ctx.collector.sample(TransitionSource::Poll);
    let topo = &s.snap.topology;
    let sock_diag = match nvmetea_tcp::sockdiag::dump_tcp(&|_, _| false) {
        Ok(_) => "ok (unprivileged netlink dump succeeded)".to_string(),
        Err(e) => format!("unavailable: {e}"),
    };
    let uevents = match UeventListener::open() {
        Ok(_) => "ok".to_string(),
        Err(e) => format!("unavailable: {e}"),
    };
    let mut plan = Vec::new();
    plan.push(PlanItem {
        family: "inventory, controller state",
        backend: "sysfs (allow-listed)".into(),
        status: "available",
        note: format!(
            "{} controllers ({} TCP), {} issues",
            topo.controllers.len(),
            topo.tcp_controllers().count(),
            topo.issues.len()
        ),
    });
    plan.push(PlanItem {
        family: "state transition events",
        backend: if uevents == "ok" { "uevents + sysfs reconcile".into() } else { "sysfs polling only".into() },
        status: if uevents == "ok" { "available" } else { "degraded" },
        note: "as root, BPF L3 also reports transitions shorter than the poll interval".into(),
    });
    let mut acct: Vec<String> = Vec::new();
    for ss in &topo.subsystems {
        let modes: Vec<NsAccounting> = ss
            .namespaces
            .iter()
            .filter_map(|n| topo.namespace(n))
            .filter(|n| n.kind == NsKind::MultipathHead)
            .map(|n| namespace_totals(n, &s.snap.disk).accounting)
            .collect();
        if !modes.is_empty() {
            let dev = modes.iter().filter(|m| **m == NsAccounting::Device).count();
            let sum = modes.iter().filter(|m| **m == NsAccounting::SumOfPaths).count();
            acct.push(format!("{}: head counters {dev}, sum of paths {sum}", ss.name));
        }
    }
    plan.push(PlanItem {
        family: "namespace / path IOPS, throughput",
        backend: "/proc/diskstats".into(),
        status: if s.disk_error.is_none() { "available" } else { "unavailable" },
        note: if acct.is_empty() {
            "aggregate means only; no percentiles".into()
        } else {
            format!("{}; aggregate means only, no percentiles", acct.join("; "))
        },
    });
    plan.push(PlanItem {
        family: "TCP connection telemetry",
        backend: format!("{:?}", s.tcp.backend),
        status: match s.tcp.backend {
            TcpBackend::SockDiag => "available",
            TcpBackend::ProcNet => "degraded",
            TcpBackend::None => {
                if topo.tcp_controllers().count() == 0 {
                    "idle (no TCP controllers)"
                } else {
                    "unavailable"
                }
            }
        },
        note: format!("{} NVMe/TCP sockets", s.snap.sockets.len()),
    });
    let amb = s.assoc.ambiguous.len();
    plan.push(PlanItem {
        family: "controller ↔ connection",
        backend: "endpoint match".into(),
        status: if amb == 0 { "available (derived)" } else { "partial" },
        note: if amb == 0 { "unique endpoints".into() } else { format!("{amb} connections ambiguous") },
    });
    // CAP_SYS_ADMIN: libbpf reads module BTF (nvme_core, nvme_tcp) for CO-RE.
    let privileged = ["CAP_BPF", "CAP_PERFMON", "CAP_SYS_ADMIN"].iter().all(|c| d.privileges.capabilities.contains(c));
    let l1_status: (&'static str, String) = match &bpf_load {
        Some(l) if l.status.state == "active" => (
            "active (load+attach verified)",
            format!("observed {} NVMe/TCP commands in {:.1}s", l.commands_observed, l.sample_s),
        ),
        Some(l) => (
            "unavailable",
            format!(
                "{}: {}",
                l.status.reason.map(|r| r.as_str()).unwrap_or("?"),
                l.status.detail.clone().unwrap_or_default()
            ),
        ),
        None if privileged => ("available", "run `nvmetea probe --load` to verify load and attach".to_string()),
        None => ("requires privileges", "root, or CAP_BPF+CAP_PERFMON+CAP_SYS_ADMIN (module BTF)".to_string()),
    };
    // After a load, its outcome replaces the static checks (which cannot verify
    // kprobe symbols without CAP_SYSLOG).
    let loaded = bpf_load.as_ref().filter(|l| l.status.state == "active");
    for (fam, ids) in [
        ("command latency P1+P2 (BPF L1)", &["P1", "P2"][..]),
        ("request latency, stages A/E2 P1+P3 (BPF L1)", &["P1", "P3"][..]),
        ("controller state events L3 (BPF L1)", &["L3"][..]),
    ] {
        let (ok, total, bad) = prereq(&d, ids);
        let lifecycle_error = loaded.and_then(|l| l.status.lifecycle.clone()).filter(|_| ids == ["L3"]);
        let (status, note) = match (loaded, lifecycle_error) {
            (Some(_), Some(e)) => ("unavailable", format!("not loaded: {e}")),
            (Some(_), None) => (l1_status.0, l1_status.1.clone()),
            (None, _) if bad.is_empty() => (l1_status.0, l1_status.1.clone()),
            (None, _) => (
                if ok < total && bpf_load.is_none() { "unavailable" } else { l1_status.0 },
                format!("missing: {}", bad.join(" ")),
            ),
        };
        plan.push(PlanItem { family: fam, backend: "core.bpf.o (raw_tp, kprobe)".into(), status, note });
    }
    let tcp_status: (&'static str, String) = match bpf_load.as_ref().and_then(|l| l.tcp.as_ref()) {
        Some(t) if t.status.state == "active" => match (t.queue_sockets, &t.iterator_error) {
            (Some(n), _) => (
                "active (load+attach verified)",
                format!("{n} queue sockets identified in {:.2} ms", t.iterate_ms.unwrap_or(0.0)),
            ),
            (None, e) => ("partial", format!("events only; iterator: {}", e.clone().unwrap_or_default())),
        },
        Some(t) => (
            "unavailable",
            format!(
                "{}: {}",
                t.status.reason.map(|r| r.as_str()).unwrap_or("?"),
                t.status.detail.clone().unwrap_or_default()
            ),
        ),
        None if privileged => ("available", "run `nvmetea probe --load` to verify".to_string()),
        None => ("requires privileges", "root, or CAP_BPF+CAP_PERFMON+CAP_SYS_ADMIN (module BTF)".to_string()),
    };
    for (fam, ids) in
        [("queue ↔ connection T1 (BPF L3)", &["T1"][..]), ("TCP events T3-T7 (BPF L3)", &["T3", "T4", "T5", "T6"][..])]
    {
        let (ok, _total, bad) = prereq(&d, ids);
        plan.push(PlanItem {
            family: fam,
            backend: "tcp_sock.bpf.o (iter/tcp, raw_tp)".into(),
            status: if ok == 0 && bpf_load.is_none() { "unavailable" } else { tcp_status.0 },
            note: if bad.is_empty() {
                tcp_status.1.clone()
            } else {
                format!("{}; missing: {}", tcp_status.1, bad.join(" "))
            },
        });
    }
    let (ok, total, bad) = prereq(&d, &["D1", "D2a", "D3", "D4", "D6", "D7", "D8a", "D9", "D10"]);
    plan.push(PlanItem {
        family: "driver stages, workers (BPF L2)",
        backend: "tcp_driver.bpf.o (fentry or kprobe), on demand".into(),
        status: if ok == 0 {
            "unavailable"
        } else if privileged {
            "on demand"
        } else {
            "requires privileges"
        },
        note: format!(
            "`nvmetea profile`, `record --sample N`, TUI key p; static prerequisites eligible {ok}/{total}{}",
            if bad.is_empty() { String::new() } else { format!("; missing: {}", bad.join(" ")) }
        ),
    });
    let report = ProbeReport {
        schema: "nvmetea.probe/1",
        discovery: d,
        sock_diag,
        uevents,
        tcp_controllers: topo.tcp_controllers().count(),
        bpf_load,
        plan,
    };
    if ctx.json {
        return emit_json(&report);
    }
    emit(&render(&report));
    Ok(())
}

fn render(r: &ProbeReport) -> String {
    let d = &r.discovery;
    let h = &d.host;
    let p = &d.privileges;
    let mut o = String::new();
    o.push_str(&format!(
        "HOST      {}  {} {}  kernel {}  {}  boot_id {}\n",
        h.hostname.as_deref().unwrap_or("?"),
        h.os_name.as_deref().unwrap_or("?"),
        h.os_version.as_deref().unwrap_or(""),
        h.kernel_release.as_deref().unwrap_or("?"),
        h.arch.as_deref().unwrap_or("?"),
        h.boot_id.as_deref().unwrap_or("?"),
    ));
    o.push_str(&format!(
        "PRIVILEGE euid={}  caps=[{}]  missing=[{}]  unprivileged_bpf_disabled={}  kptr_restrict={}  lockdown={}  selinux={}  bpf_jit={}  bpf_stats={}\n",
        p.euid,
        p.capabilities.join(","),
        p.missing_capabilities.join(","),
        p.unprivileged_bpf_disabled.map(|v| v.to_string()).unwrap_or("?".into()),
        p.kptr_restrict.map(|v| v.to_string()).unwrap_or("?".into()),
        p.lockdown.as_deref().unwrap_or("unknown"),
        p.selinux.as_deref().unwrap_or("?"),
        p.bpf_jit_enable.map(|v| v.to_string()).unwrap_or("?".into()),
        p.bpf_stats_enabled.map(|v| v.to_string()).unwrap_or("?".into()),
    ));
    o.push_str(&format!("BTF       vmlinux {}", avail(&d.btf_vmlinux)));
    for (m, s) in &d.modules {
        o.push_str(&format!("  {m}: {} / BTF {}", if s.loaded { "loaded" } else { "not loaded" }, avail(&s.btf)));
    }
    o.push('\n');
    o.push_str(&format!(
        "SYMBOLS   kallsyms {}  ftrace {}  tracefs {} ({})\n",
        avail(&d.kallsyms),
        match &d.filter_functions {
            Avail::Present => "present".into(),
            _ => "not readable (run as root to check fentry eligibility)".to_string(),
        },
        d.tracefs.as_deref().unwrap_or("not mounted"),
        if d.tracefs_readable { "readable" } else { "not readable" },
    ));
    if !d.kernel_config.is_empty() {
        let cfg: Vec<String> =
            d.kernel_config.iter().map(|(k, v)| format!("{}={v}", k.trim_start_matches("CONFIG_"))).collect();
        o.push_str(&format!("CONFIG    {}\n", cfg.join(" ")));
    }
    o.push_str(&format!("NETLINK   sock_diag {}  uevents {}\n\n", r.sock_diag, r.uevents));

    let mut t = Table::new(&["ID", "L", "TARGET", "BTF/FENTRY", "KPROBE", "REASON", "FALLBACK"], 7);
    for pc in &d.probes {
        t.push(vec![
            pc.id.to_string(),
            pc.level.to_string(),
            pc.target.clone(),
            st(pc.btf_flavour).to_string(),
            pc.kprobe_flavour.map(st).unwrap_or("").to_string(),
            pc.reason.map(|r| r.as_str()).unwrap_or("").to_string(),
            pc.fallback.to_string(),
        ]);
    }
    o.push_str(
        "PROBES (static checks: eligible = attach point, BTF and symbol verified. `--load` loads and attaches Levels 1 and 3; Level 2 attaches in `profile`)\n",
    );
    o.push_str(&t.render());
    let missing: Vec<String> = d
        .fields
        .iter()
        .filter(|f| f.present != Some(true))
        .map(|f| {
            format!(
                "{}.{}{}{}",
                f.structure,
                f.member,
                if f.optional { " (optional)" } else { "" },
                if f.present.is_none() { " [no BTF]" } else { "" }
            )
        })
        .collect();
    o.push_str(&format!(
        "\nCO-RE FIELDS  {}/{} present{}\n\n",
        d.fields.iter().filter(|f| f.present == Some(true)).count(),
        d.fields.len(),
        if missing.is_empty() { String::new() } else { format!("; missing: {}", missing.join(", ")) },
    ));
    let mut t = Table::new(&["METRIC FAMILY", "BACKEND", "STATUS", "NOTE"], 4);
    for i in &r.plan {
        t.push(vec![i.family.to_string(), i.backend.clone(), i.status.to_string(), i.note.clone()]);
    }
    if let Some(l) = &r.bpf_load {
        o.push_str("BPF LOAD TEST (--load)\n");
        match &l.report {
            Some(rep) => {
                o.push_str(&format!("  loaded in {:.1} ms, attached in {:.1} ms; maps:", rep.load_ms, rep.attach_ms));
                for (m, n) in &rep.maps {
                    o.push_str(&format!(" {m}={n}"));
                }
                o.push('\n');
                for p in &rep.programs {
                    o.push_str(&format!(
                        "  {:<18} {:<34} {}{}\n",
                        p.program,
                        p.attach,
                        if p.attached { "attached" } else { "FAILED" },
                        p.error.as_deref().map(|e| format!(": {e}")).unwrap_or_default()
                    ));
                }
                if let Some(e) = &l.status.lifecycle {
                    o.push_str(&format!("  lifecycle programs not loaded: {e}\n"));
                }
                o.push_str(&format!("  observed {} NVMe/TCP commands in {:.1}s", l.commands_observed, l.sample_s));
                if let Some(h) = &l.health {
                    o.push_str(&format!(
                        "; untracked {} cid-mismatch {} stale {} map-full {} lost {}",
                        h.untracked_completions, h.cid_mismatches, h.stale_replaced, h.map_full, h.events_lost
                    ));
                }
                o.push_str("; detached\n");
                if let Some(t) = &l.tcp {
                    match &t.report {
                        Some(rep) => {
                            o.push_str(&format!(
                                "  TCP object: loaded in {:.1} ms, attached in {:.1} ms\n",
                                rep.load_ms, rep.attach_ms
                            ));
                            for p in &rep.programs {
                                o.push_str(&format!(
                                    "  {:<18} {:<34} {}{}\n",
                                    p.program,
                                    p.attach,
                                    if p.attached { "attached" } else { "FAILED" },
                                    p.error.as_deref().map(|e| format!(": {e}")).unwrap_or_default()
                                ));
                            }
                            match (t.queue_sockets, &t.iterator_error) {
                                (Some(n), _) => o.push_str(&format!(
                                    "  queue sockets identified: {n} ({:.2} ms); detached\n",
                                    t.iterate_ms.unwrap_or(0.0)
                                )),
                                (None, e) => {
                                    o.push_str(&format!("  iterator unavailable: {}\n", e.clone().unwrap_or_default()))
                                }
                            }
                        }
                        None => o.push_str(&format!(
                            "  TCP object not loaded: {} — {}\n",
                            t.status.reason.map(|r| r.as_str()).unwrap_or("?"),
                            t.status.detail.as_deref().unwrap_or("")
                        )),
                    }
                }
                o.push('\n');
            }
            None => o.push_str(&format!(
                "  not loaded: {} — {}\n  {}\n\n",
                l.status.reason.map(|r| r.as_str()).unwrap_or("?"),
                l.status.detail.as_deref().unwrap_or(""),
                l.status.reason.map(|r| r.remediation()).unwrap_or("")
            )),
        }
    }
    o.push_str("PLAN\n");
    o.push_str(&t.render());
    o
}
