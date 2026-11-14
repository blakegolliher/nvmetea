//! Load the Level 1 object, observe for N seconds, cross-check against diskstats.
//! Read-only: attaches tracepoints and a kprobe; generates no I/O.
use nvmetea_bpf::core::{CoreCollector, CoreConfig, CoreEvent};
use nvmetea_core::model::{LatMetric, Op};
use std::collections::BTreeMap;
use std::time::Duration;

fn diskstats_done(prefix_paths: &[String]) -> (u64, u64) {
    let t = std::fs::read_to_string("/proc/diskstats").unwrap_or_default();
    let (mut ios, mut ms) = (0u64, 0u64);
    for l in t.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() > 10 && prefix_paths.iter().any(|p| p == f[2]) {
            let n = |i: usize| f[i].parse::<u64>().unwrap_or(0);
            ios += n(3) + n(7);
            ms += n(6) + n(10);
        }
    }
    (ios, ms)
}

fn main() {
    let secs: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(5);
    let topo = nvmetea_topology::scan(&nvmetea_topology::SysRoot::system());
    let paths: Vec<String> =
        topo.tcp_controllers().flat_map(|c| c.paths.iter().chain(c.namespaces.iter()).cloned()).collect();
    let mut cfg = CoreConfig::from_topology(&topo);
    cfg.slow_ns = 20_000_000; // 20 ms
    println!("config: {cfg:?}");
    let mut c = match CoreCollector::start(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("start failed: {e}");
            if let nvmetea_bpf::core::LoadError::Load { log, .. } = &e {
                eprintln!("{}", &log[log.len().saturating_sub(4000)..]);
            }
            if let nvmetea_bpf::core::LoadError::Attach { report, .. } = &e {
                eprintln!("{report:#?}");
            }
            std::process::exit(1);
        }
    };
    println!("load {:.1} ms, attach {:.1} ms", c.report.load_ms, c.report.attach_ms);
    if let Some(e) = &c.lifecycle_error {
        println!("lifecycle programs disabled: {e}");
    }
    for p in &c.report.programs {
        println!("  {:<18} {:<34} attached={} {}", p.program, p.attach, p.attached, p.error.as_deref().unwrap_or(""));
    }
    let a = c.sample();
    let (d0, ms0) = diskstats_done(&paths);
    std::thread::sleep(Duration::from_secs(secs));
    let b = c.sample();
    let (d1, ms1) = diskstats_done(&paths);
    let mut per_ctrl: BTreeMap<u32, (u64, u64, u64)> = BTreeMap::new();
    let (mut done, mut req_sum, mut req_cnt) = (0u64, 0u64, 0u64);
    for (k, q) in &b.queues {
        let p = a.queues.get(k).cloned().unwrap_or_default();
        let e = per_ctrl.entry(k.0).or_default();
        for op in [Op::Read, Op::Write, Op::Flush, Op::Other] {
            let i = op.index();
            let dc = q.completed[i] - p.completed[i];
            e.0 += dc;
            done += dc;
            req_sum += q.req_lat_sum_ns[i] - p.req_lat_sum_ns[i];
            req_cnt += q.req_lat_cnt[i] - p.req_lat_cnt[i];
        }
        e.1 += q.dispatched[Op::Admin.index()] - p.dispatched[Op::Admin.index()];
        e.2 = e.2.max(q.inflight_max);
    }
    println!("\nper controller (I/O completions, admin dispatches, max inflight on a queue):");
    for (inst, v) in &per_ctrl {
        println!("  nvme{inst}: {v:?}");
    }
    println!("\nBPF I/O completions: {done}   diskstats path completions: {}", d1 - d0);
    if req_cnt > 0 {
        println!(
            "BPF mean request latency: {:.1} us over {req_cnt}   diskstats mean (ticks): {:.1} us",
            req_sum as f64 / req_cnt as f64 / 1e3,
            (ms1 - ms0) as f64 * 1e3 / (d1 - d0).max(1) as f64
        );
    }
    let mut all = nvmetea_core::model::Histogram::default();
    for ((_, _, op, m), h) in &b.hists {
        if *m == LatMetric::Request && *op == Op::Read || *m == LatMetric::Request && *op == Op::Write {
            all.add(h);
        }
    }
    for (q, p) in [(0.5, "p50"), (0.99, "p99"), (0.999, "p99.9")] {
        if let Some(v) = all.percentile(q) {
            println!("cumulative request latency {p}: <= {:.1} us", v.ns as f64 / 1e3);
        }
    }
    println!("counters: {:?}", b.counters);
    let ev = c.drain_events();
    println!(
        "events: {} ({} slow, {} state)",
        ev.len(),
        ev.iter().filter(|e| matches!(e, CoreEvent::Slow(_))).count(),
        ev.iter().filter(|e| matches!(e, CoreEvent::State(_))).count()
    );
    if let Some(CoreEvent::Slow(s)) = ev.iter().find(|e| matches!(e, CoreEvent::Slow(_))) {
        println!(
            "  example slow: {:?} req={:?}ns A={:?} cmd={:?} E2={:?}",
            s.op,
            s.request_ns(),
            s.stage_a_ns(),
            s.command_ns(),
            s.stage_e2_ns()
        );
    }
    println!("tracked inflight entries now: {}", c.inflight_entries());
    let keys: Vec<String> =
        b.path_hists.keys().take(6).map(|(d, op)| format!("{}:{} {:?}", d >> 20, d & 0xfffff, op)).collect();
    println!("path_hists: {} keys, e.g. {keys:?}", b.path_hists.len());
}
// (debug helper appended) print a few path histogram keys
#[allow(dead_code)]
fn _unused() {}
