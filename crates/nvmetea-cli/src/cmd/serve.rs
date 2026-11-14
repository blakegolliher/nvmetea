//! `nvmetea serve --listen ADDR:PORT`: Prometheus exposition of the latest
//! snapshot (`docs/architecture.md` §10).
//!
//! The main thread samples every interval and publishes a rendered
//! exposition; an HTTP thread serves `/metrics` and `/healthz` from it. A
//! scrape never triggers collection. `--listen` is required: there is no
//! default port.

use crate::Ctx;
use crate::sample::{Bpf, Sampled, TcpBpf};
use anyhow::{Context, anyhow};
use nvmetea_core::model::Topology;
use nvmetea_export::prom::{self, Capability, CollectorStatus, Limits, ProcessStats, PromInput};
use nvmetea_tcp::TcpBackend;
use nvmetea_topology::TransitionSource;
use nvmetea_topology::tracker::Change;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct Args {
    pub listen: String,
    pub interval: f64,
    pub max_controllers: usize,
    pub max_queues: usize,
}

struct Published {
    text: Arc<String>,
    at: Instant,
}

fn process_stats() -> Option<ProcessStats> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // fields after the ")" of comm: state is field 3; utime/stime are 14/15
    let rest = &stat[stat.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    let utime: f64 = f.get(11)?.parse().ok()?;
    let stime: f64 = f.get(12)?.parse().ok()?;
    // SAFETY: sysconf has no preconditions.
    let tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    // SAFETY: as above.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let rss: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(ProcessStats { cpu_seconds: (utime + stime) / tck.max(1.0), resident_bytes: rss * page })
}

fn filtered(ctx: &Ctx, t: &Topology) -> Topology {
    let mut out = t.clone();
    out.controllers.retain(|c| ctx.filter.controller(c));
    out.subsystems.retain(|s| ctx.filter.subsystem(s, t));
    out.namespaces.retain(|n| ctx.filter.namespace(n, t));
    out
}

fn capabilities(ctx: &Ctx, s: &Sampled) -> (Vec<CollectorStatus>, Vec<Capability>) {
    let reason = |r: Option<nvmetea_core::Reason>| r.map(|r| r.as_str().to_string()).unwrap_or_default();
    let core = ctx.collector.bpf_status();
    let tcp = ctx.collector.tcp_bpf_status();
    let sock_diag = matches!(s.tcp.backend, TcpBackend::SockDiag);
    let collectors = vec![
        CollectorStatus { name: "topology", up: true },
        CollectorStatus { name: "diskstats", up: s.disk_error.is_none() },
        CollectorStatus { name: "sock_diag", up: sock_diag },
        CollectorStatus { name: "bpf_core", up: matches!(ctx.collector.bpf, Bpf::Active(_)) },
        CollectorStatus { name: "bpf_tcp", up: matches!(ctx.collector.tcp_bpf, TcpBpf::Active(_)) },
    ];
    let mut caps = vec![
        Capability { name: "nvme_latency", status: core.state.to_string(), reason: reason(core.reason) },
        Capability {
            name: "tcp_info",
            status: if sock_diag { "active".into() } else { "unavailable".into() },
            reason: if sock_diag { String::new() } else { reason(s.tcp.degraded) },
        },
        Capability { name: "transport_events", status: tcp.state.to_string(), reason: reason(tcp.reason) },
    ];
    match &s.queue_sockets {
        Ok(_) => caps.push(Capability { name: "queue_sockets", status: "active".into(), reason: String::new() }),
        Err((r, _)) => {
            caps.push(Capability { name: "queue_sockets", status: "unavailable".into(), reason: r.as_str().into() })
        }
    }
    (collectors, caps)
}

pub fn run(ctx: &mut Ctx, a: Args) -> anyhow::Result<()> {
    let addr: SocketAddr =
        a.listen.parse().with_context(|| format!("--listen {}: expected ADDR:PORT, e.g. 127.0.0.1:9469", a.listen))?;
    let topo = nvmetea_topology::scan(&ctx.collector.sys);
    ctx.filter.validate(&topo)?;
    let server = tiny_http::Server::http(addr).map_err(|e| anyhow!("cannot listen on {addr}: {e}"))?;
    if !addr.ip().is_loopback() {
        eprintln!(
            "warning: listening on {addr}, not a loopback address: anyone who can reach it can read the \
             host's NVMe/TCP topology, addresses and performance data"
        );
    }
    let interval = Duration::from_secs_f64(a.interval.clamp(0.25, 60.0));
    if !ctx.no_bpf {
        ctx.collector.enable_all_bpf(&topo);
        crate::cmd::queues::warn_bpf(ctx);
    }
    let published: Arc<Mutex<Option<Published>>> = Arc::new(Mutex::new(None));
    let shared = published.clone();
    let stale_after = 3.0 * interval.as_secs_f64();
    std::thread::Builder::new().name("nvmetea-http".into()).spawn(move || {
        for req in server.incoming_requests() {
            let path = req.url().split('?').next().unwrap_or("").to_string();
            let snap = shared.lock().ok().and_then(|g| g.as_ref().map(|p| (p.text.clone(), p.at.elapsed())));
            let resp = match (req.method(), path.as_str(), snap) {
                (tiny_http::Method::Get, "/metrics", Some((text, age))) => {
                    let mut body = String::with_capacity(text.len() + 160);
                    body.push_str(&text);
                    body.push_str(&prom::age_line(age.as_secs_f64()));
                    tiny_http::Response::from_string(body).with_header(
                        tiny_http::Header::from_bytes(
                            &b"Content-Type"[..],
                            &b"text/plain; version=0.0.4; charset=utf-8"[..],
                        )
                        .expect("static header"),
                    )
                }
                (tiny_http::Method::Get, "/metrics", None) => {
                    tiny_http::Response::from_string("no snapshot yet\n").with_status_code(503)
                }
                (tiny_http::Method::Get, "/healthz", Some((_, age))) if age.as_secs_f64() <= stale_after => {
                    tiny_http::Response::from_string("ok\n")
                }
                (tiny_http::Method::Get, "/healthz", _) => {
                    tiny_http::Response::from_string("snapshot missing or stale\n").with_status_code(503)
                }
                _ => tiny_http::Response::from_string("not found: /metrics, /healthz\n").with_status_code(404),
            };
            let _ = req.respond(resp);
        }
    })?;
    eprintln!("serving http://{addr}/metrics (snapshot every {:.2} s; Ctrl-C to stop)", interval.as_secs_f64());

    let limits = Limits { max_controllers: a.max_controllers.max(1), max_queues: a.max_queues.max(1) };
    let version = env!("CARGO_PKG_VERSION");
    let mut transitions: BTreeMap<(String, String), u64> = BTreeMap::new();
    crate::signal::install();
    while !crate::signal::requested() {
        let t0 = Instant::now();
        let s = ctx.collector.sample(TransitionSource::Poll);
        for t in &s.transitions {
            let to = match &t.change {
                Change::State { to, .. } => to.as_str().to_string(),
                Change::Added { state } => state.as_str().to_string(),
                Change::Removed { .. } => "removed".to_string(),
            };
            *transitions.entry((t.controller.clone(), to)).or_default() += 1;
        }
        let topo = filtered(ctx, &s.snap.topology);
        let (collectors, caps) = capabilities(ctx, &s);
        let rendered = prom::render(&PromInput {
            version,
            topology: &topo,
            disk: &s.snap.disk,
            nvme: s.nvme.as_ref(),
            sockets: &s.snap.sockets,
            queue_sockets: s.queue_sockets.as_ref().ok().map(|v| v.as_slice()),
            sock_events: s.sock_events.as_ref(),
            collectors: &collectors,
            capabilities: &caps,
            transitions: &transitions,
            process: process_stats(),
            limits,
        });
        if let Ok(mut g) = published.lock() {
            *g = Some(Published { text: Arc::new(rendered.text), at: Instant::now() });
        }
        while let Some(left) = interval.checked_sub(t0.elapsed()) {
            if crate::signal::requested() {
                break;
            }
            std::thread::sleep(left.min(Duration::from_millis(100)));
        }
    }
    eprintln!("stopping");
    Ok(())
}
